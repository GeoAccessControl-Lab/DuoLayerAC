package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"polylock-thesis/go-bridge/polylock"
)

type setupConfig struct {
	UniverseSize      int      `json:"universe_size"`
	DMax              int      `json:"d_max"`
	MaxCardinality    int      `json:"max_cardinality"`
	Dependencies      [][2]int `json:"dependencies"`
	Exclusions        [][2]int `json:"exclusions"`
	LegalProfiles     [][]int  `json:"legal_profiles,omitempty"`
	SecurityProfile   string   `json:"security_profile"`
	DecompositionBase uint32   `json:"decomposition_base"`
	ErrorEta          uint32   `json:"error_eta"`
}

type systemMetadata struct {
	LegalSpaceSize       int   `json:"legal_space_size"`
	PublicParameterBytes int64 `json:"public_parameter_bytes"`
	MasterSecretBytes    int64 `json:"master_secret_bytes"`
}

type policyMetadata struct {
	BucketCount int `json:"bucket_count"`
}

type result struct {
	Run                    int
	SecurityProfile        string
	LegalSpaceSize         int
	BucketCount            int
	AuthorizedProfileIndex int
	LockBytes              int64
	PublicParameterBytes   int64
	MasterSecretBytes      int64
	UserKeyBytes           int64
	SetupMS                float64
	KeyGenMS               float64
	PreResolveMS           float64
	DataEncMS              float64
	EncapsMS               float64
	DecapsMS               float64
	UnauthorizedDecapsMS   float64
	AuthorizedRecovery     bool
	UnauthorizedRejection  bool
}

func elapsedMS(start time.Time) float64 {
	return float64(time.Since(start).Nanoseconds()) / 1e6
}

func encryptData(key, plaintext, aad []byte) (polylock.DataCiphertext, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return polylock.DataCiphertext{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return polylock.DataCiphertext{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return polylock.DataCiphertext{}, err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	return polylock.DataCiphertext{
		NonceHex:      hex.EncodeToString(nonce),
		CiphertextHex: hex.EncodeToString(sealed),
		AADHex:        hex.EncodeToString(aad),
	}, nil
}

func decodeJSON(raw string, target any) error {
	if err := json.Unmarshal([]byte(raw), target); err != nil {
		return fmt.Errorf("decode Rust metadata: %w", err)
	}
	return nil
}

func syntheticProfiles(universeSize, legalSpaceSize int, selectivity float64) ([][]int, int, error) {
	if universeSize < 2 || legalSpaceSize < 2 {
		return nil, 0, fmt.Errorf("universe-size and legal-space-size must both be at least 2")
	}
	selected := int(math.Round(selectivity * float64(legalSpaceSize)))
	if selected < 1 || selected >= legalSpaceSize {
		return nil, 0, fmt.Errorf("selectivity must leave at least one authorized and one unauthorized profile")
	}
	identifierBits := 0
	for (1 << identifierBits) < legalSpaceSize {
		identifierBits++
	}
	if identifierBits+1 > universeSize {
		return nil, 0, fmt.Errorf("universe-size=%d cannot encode %d distinct controlled profiles", universeSize, legalSpaceSize)
	}
	profiles := make([][]int, legalSpaceSize)
	for index := 0; index < legalSpaceSize; index++ {
		profile := make([]int, universeSize)
		if index < selected {
			profile[0] = 1
		}
		for bit := 0; bit < identifierBits; bit++ {
			profile[bit+1] = (index >> bit) & 1
		}
		profiles[index] = profile
	}
	return profiles, selected, nil
}

func byteProfile(profile []int) []uint8 {
	output := make([]uint8, len(profile))
	for index, value := range profile {
		output[index] = uint8(value)
	}
	return output
}

// stratifiedAuthorizedIndex selects the midpoint of one of sampleCount equal
// strata in the authorized-profile population.  Across the formal runs this
// avoids benchmarking the same hash/bucket position repeatedly while keeping
// the workload deterministic and reproducible.
func stratifiedAuthorizedIndex(run, sampleCount, selected int) int {
	if run < 1 || sampleCount < 1 || selected < 1 {
		return 0
	}
	index := ((2*run - 1) * selected) / (2 * sampleCount)
	if index >= selected {
		return selected - 1
	}
	return index
}

func runOnce(run, sampleCount, objectBytes, universeSize, legalSpaceSize, dMax int, selectivity float64, securityProfile string) (result, error) {
	profiles, selected, err := syntheticProfiles(universeSize, legalSpaceSize, selectivity)
	if err != nil {
		return result{}, err
	}
	config := setupConfig{
		UniverseSize:      universeSize,
		DMax:              dMax,
		MaxCardinality:    universeSize,
		Dependencies:      [][2]int{},
		Exclusions:        [][2]int{},
		LegalProfiles:     profiles,
		SecurityProfile:   securityProfile,
		DecompositionBase: 32,
		ErrorEta:          4,
	}

	started := time.Now()
	system, err := polylock.Setup(config)
	setupMS := elapsedMS(started)
	if err != nil {
		return result{}, err
	}
	defer system.Close()

	authorizedProfileIndex := stratifiedAuthorizedIndex(run, sampleCount, selected)
	started = time.Now()
	authorized, err := system.KeyGen(byteProfile(profiles[authorizedProfileIndex]))
	keyGenMS := elapsedMS(started)
	if err != nil {
		return result{}, err
	}
	defer authorized.Close()
	unauthorized, err := system.KeyGen(byteProfile(profiles[selected]))
	if err != nil {
		return result{}, err
	}
	defer unauthorized.Close()

	policy := map[string]any{"op": "attr", "index": 0}
	started = time.Now()
	resolved, err := system.PreResolve(policy)
	preResolveMS := elapsedMS(started)
	if err != nil {
		return result{}, err
	}
	defer resolved.Close()

	seed := make([]byte, 16)
	if _, err := rand.Read(seed); err != nil {
		return result{}, err
	}
	payload := make([]byte, objectBytes)
	if _, err := rand.Read(payload); err != nil {
		return result{}, err
	}
	aad := []byte("cid:benchmark")
	key, err := polylock.DeriveDataKey(seed, aad)
	if err != nil {
		return result{}, err
	}
	started = time.Now()
	data, err := encryptData(key, payload, aad)
	dataEncMS := elapsedMS(started)
	if err != nil {
		return result{}, err
	}

	started = time.Now()
	lock, err := system.Encaps(resolved, hex.EncodeToString(seed))
	encapsMS := elapsedMS(started)
	if err != nil {
		return result{}, err
	}
	defer lock.Close()

	started = time.Now()
	recovered, authorizedOK, err := system.Decaps(authorized, lock, data)
	decapsMS := elapsedMS(started)
	if err != nil {
		return result{}, err
	}
	started = time.Now()
	_, unauthorizedOK, err := system.Decaps(unauthorized, lock, data)
	unauthorizedDecapsMS := elapsedMS(started)
	if err != nil {
		return result{}, err
	}

	var systemInfo systemMetadata
	raw, err := system.Metadata()
	if err != nil {
		return result{}, fmt.Errorf("read system metadata: %w", err)
	}
	if err := decodeJSON(raw, &systemInfo); err != nil {
		return result{}, err
	}
	var policyInfo policyMetadata
	raw, err = resolved.Metadata()
	if err != nil {
		return result{}, fmt.Errorf("read policy metadata: %w", err)
	}
	if err := decodeJSON(raw, &policyInfo); err != nil {
		return result{}, err
	}

	return result{
		Run:                    run,
		SecurityProfile:        securityProfile,
		LegalSpaceSize:         systemInfo.LegalSpaceSize,
		BucketCount:            policyInfo.BucketCount,
		AuthorizedProfileIndex: authorizedProfileIndex,
		LockBytes:              lock.SerializedSize(),
		PublicParameterBytes:   systemInfo.PublicParameterBytes,
		MasterSecretBytes:      systemInfo.MasterSecretBytes,
		UserKeyBytes:           authorized.SerializedSize(),
		SetupMS:                setupMS,
		KeyGenMS:               keyGenMS,
		PreResolveMS:           preResolveMS,
		DataEncMS:              dataEncMS,
		EncapsMS:               encapsMS,
		DecapsMS:               decapsMS,
		UnauthorizedDecapsMS:   unauthorizedDecapsMS,
		AuthorizedRecovery:     authorizedOK && recovered == hex.EncodeToString(key),
		UnauthorizedRejection:  !unauthorizedOK,
	}, nil
}

func mean(values []float64) float64 {
	var sum float64
	for _, value := range values {
		sum += value
	}
	return sum / float64(len(values))
}

func sampleStd(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	avg := mean(values)
	var sum float64
	for _, value := range values {
		delta := value - avg
		sum += delta * delta
	}
	return math.Sqrt(sum / float64(len(values)-1))
}

func column(results []result, selectValue func(result) float64) []float64 {
	values := make([]float64, len(results))
	for index, item := range results {
		values[index] = selectValue(item)
	}
	return values
}

func writeCSV(path string, results []result) error {
	if directory := filepath.Dir(path); directory != "." {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return err
		}
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	if err := writer.Write([]string{
		"Run", "SecurityProfile", "LegalSpaceSize", "BucketCount", "AuthorizedProfileIndex", "LockBytes", "PublicParameterBytes", "MasterSecretBytes", "UserKeyBytes", "SetupMS", "KeyGenMS", "PreResolveMS",
		"DataEncMS", "EncapsMS", "DecapsMS", "UnauthorizedDecapsMS", "AuthorizedRecovery", "UnauthorizedRejection",
	}); err != nil {
		return err
	}
	for _, item := range results {
		if err := writer.Write([]string{
			strconv.Itoa(item.Run), item.SecurityProfile, strconv.Itoa(item.LegalSpaceSize), strconv.Itoa(item.BucketCount), strconv.Itoa(item.AuthorizedProfileIndex), strconv.FormatInt(item.LockBytes, 10),
			strconv.FormatInt(item.PublicParameterBytes, 10), strconv.FormatInt(item.MasterSecretBytes, 10), strconv.FormatInt(item.UserKeyBytes, 10),
			fmt.Sprintf("%.6f", item.SetupMS), fmt.Sprintf("%.6f", item.KeyGenMS),
			fmt.Sprintf("%.6f", item.PreResolveMS), fmt.Sprintf("%.6f", item.DataEncMS), fmt.Sprintf("%.6f", item.EncapsMS),
			fmt.Sprintf("%.6f", item.DecapsMS), fmt.Sprintf("%.6f", item.UnauthorizedDecapsMS),
			strconv.FormatBool(item.AuthorizedRecovery), strconv.FormatBool(item.UnauthorizedRejection),
		}); err != nil {
			return err
		}
	}
	return writer.Error()
}

func main() {
	runs := flag.Int("runs", 10, "number of independent prototype runs")
	warmupRuns := flag.Int("warmup-runs", 3, "untimed warm-up runs excluded from the CSV")
	objectBytes := flag.Int("object-bytes", 128, "AES-GCM payload size in bytes")
	universeSize := flag.Int("universe-size", 100, "attribute universe size")
	legalSpaceSize := flag.Int("legal-space-size", 1000, "controlled legal profile-space size")
	selectivity := flag.Float64("selectivity", 0.30, "authorized fraction of the legal profile space")
	dMax := flag.Int("d-max", 4, "fixed maximum roots per low-degree vanishing-polynomial bucket")
	securityProfile := flag.String("security-profile", "ring128", "fixed cryptographic profile: ring100 or ring128")
	output := flag.String("output", "polylock_lwe_results.csv", "raw CSV output path")
	flag.Parse()
	if *runs < 1 || *warmupRuns < 0 || *objectBytes < 1 || *dMax < 1 {
		log.Fatal("runs, object-bytes and d-max must be positive; warmup-runs must be nonnegative")
	}
	for warmup := 1; warmup <= *warmupRuns; warmup++ {
		item, err := runOnce(warmup, *warmupRuns, *objectBytes, *universeSize, *legalSpaceSize, *dMax, *selectivity, *securityProfile)
		if err != nil {
			log.Fatalf("warm-up run %d failed: %v", warmup, err)
		}
		if !item.AuthorizedRecovery || !item.UnauthorizedRejection {
			log.Fatalf("warm-up run %d violated authorization correctness", warmup)
		}
		fmt.Printf("Warm-up %d/%d complete\n", warmup, *warmupRuns)
	}

	results := make([]result, 0, *runs)
	for run := 1; run <= *runs; run++ {
		item, err := runOnce(run, *runs, *objectBytes, *universeSize, *legalSpaceSize, *dMax, *selectivity, *securityProfile)
		if err != nil {
			log.Fatalf("run %d failed: %v", run, err)
		}
		if !item.AuthorizedRecovery || !item.UnauthorizedRejection {
			log.Fatalf("run %d violated authorization correctness", run)
		}
		results = append(results, item)
		fmt.Printf("Run %d/%d complete\n", run, *runs)
	}
	if err := writeCSV(*output, results); err != nil {
		log.Fatal(err)
	}

	metrics := []struct {
		name        string
		selectValue func(result) float64
	}{
		{"SETUP_MS", func(item result) float64 { return item.SetupMS }},
		{"KEYGEN_MS", func(item result) float64 { return item.KeyGenMS }},
		{"PRERESOLVE_MS", func(item result) float64 { return item.PreResolveMS }},
		{"DATA_ENC_MS", func(item result) float64 { return item.DataEncMS }},
		{"ENCAPS_MS", func(item result) float64 { return item.EncapsMS }},
		{"ENCRYPT_MS", func(item result) float64 { return item.PreResolveMS + item.EncapsMS }},
		{"DECAPS_MS", func(item result) float64 { return item.DecapsMS }},
		{"UNAUTHORIZED_DECAPS_MS", func(item result) float64 { return item.UnauthorizedDecapsMS }},
	}
	fmt.Println("================ EXPERIMENT_SUMMARY_BEGIN ================")
	fmt.Println("EXPERIMENT=PolyLockLWECore")
	fmt.Printf("NUM_RUNS=%d\n", *runs)
	fmt.Printf("WARMUP_RUNS=%d\n", *warmupRuns)
	fmt.Println("AUTHORIZED_PROFILE_SAMPLING=stratified_midpoint")
	fmt.Printf("DATA_OBJECT_BYTES=%d\n", *objectBytes)
	fmt.Printf("SECURITY_PROFILE=%s\n", *securityProfile)
	fmt.Printf("UNIVERSE_SIZE=%d\n", *universeSize)
	fmt.Printf("SELECTIVITY=%.6f\n", *selectivity)
	fmt.Printf("D_MAX=%d\n", *dMax)
	fmt.Printf("LEGAL_SPACE_SIZE=%d\n", results[0].LegalSpaceSize)
	fmt.Printf("BUCKET_COUNT=%d\n", results[0].BucketCount)
	fmt.Printf("LOCK_MB=%.6f\n", float64(results[0].LockBytes)/1_000_000.0)
	fmt.Printf("PUBLIC_PARAMETER_KB=%.6f\n", float64(results[0].PublicParameterBytes)/1_000.0)
	fmt.Printf("MASTER_SECRET_KB=%.6f\n", float64(results[0].MasterSecretBytes)/1_000.0)
	fmt.Printf("USER_KEY_KB=%.6f\n", float64(results[0].UserKeyBytes)/1_000.0)
	for _, metric := range metrics {
		values := column(results, metric.selectValue)
		fmt.Printf("%s_MEAN=%.6f\n", metric.name, mean(values))
		fmt.Printf("%s_STD=%.6f\n", metric.name, sampleStd(values))
	}
	fmt.Println("AUTHORIZED_RECOVERY_ALL=true")
	fmt.Println("UNAUTHORIZED_REJECTION_ALL=true")
	fmt.Printf("CSV=%s\n", *output)
	fmt.Println("================= EXPERIMENT_SUMMARY_END =================")
}
