package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"polylock-thesis/go-bridge/polylock"
)

const dataMagic = "PLD1"

type setupConfig struct {
	UniverseSize      int      `json:"universe_size"`
	DMax              int      `json:"d_max"`
	MaxCardinality    int      `json:"max_cardinality"`
	Dependencies      [][2]int `json:"dependencies"`
	Exclusions        [][2]int `json:"exclusions"`
	LegalProfiles     [][]int  `json:"legal_profiles"`
	SecurityProfile   string   `json:"security_profile"`
	DecompositionBase uint32   `json:"decomposition_base"`
	ErrorEta          uint32   `json:"error_eta"`
}

type policyMetadata struct {
	BucketCount int `json:"bucket_count"`
}

type manifest struct {
	RunID                  string  `json:"run_id"`
	SecurityProfile        string  `json:"security_profile"`
	UniverseSize           int     `json:"universe_size"`
	LegalSpaceSize         int     `json:"legal_space_size"`
	Selectivity            float64 `json:"selectivity"`
	AuthorizedProfileIndex int     `json:"authorized_profile_index"`
	ObjectBytes            int     `json:"object_bytes"`
	BucketCount            int     `json:"bucket_count"`
	LockBytes              int     `json:"lock_bytes"`
	DataBytes              int     `json:"data_bytes"`
	LockCID                string  `json:"lock_cid"`
	DataCID                string  `json:"data_cid"`
	UserKeyFile            string  `json:"user_key_file"`
	ExpectedKeyHex         string  `json:"expected_key_hex"`
	PublisherCSV           string  `json:"publisher_csv"`
	TerminalCSV            string  `json:"terminal_csv"`
}

type resourceSnapshot struct {
	wall  time.Time
	usage syscall.Rusage
}

type resourceMetrics struct {
	wallMS   float64
	cpuMS    float64
	avgCPU   float64
	quotaCPU float64
	maxRSSMB float64
}

type binaryDataCiphertext struct {
	nonce      []byte
	ciphertext []byte
	aad        []byte
}

func envString(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil {
		return fallback
	}
	return value
}

func envFloat(key string, fallback float64) float64 {
	value, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(key)), 64)
	if err != nil {
		return fallback
	}
	return value
}

func elapsedMS(start time.Time) float64 {
	return float64(time.Since(start).Nanoseconds()) / 1e6
}

func timevalSeconds(value syscall.Timeval) float64 {
	return float64(value.Sec) + float64(value.Usec)/1e6
}

func resourceStart() resourceSnapshot {
	var usage syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	return resourceSnapshot{wall: time.Now(), usage: usage}
}

func resourceFinish(start resourceSnapshot, cpus float64) resourceMetrics {
	var usage syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	wallSeconds := time.Since(start.wall).Seconds()
	cpuSeconds := timevalSeconds(usage.Utime) + timevalSeconds(usage.Stime) -
		timevalSeconds(start.usage.Utime) - timevalSeconds(start.usage.Stime)
	avgCPU := 0.0
	if wallSeconds > 0 {
		avgCPU = 100 * cpuSeconds / wallSeconds
	}
	quotaCPU := avgCPU
	if cpus > 0 {
		quotaCPU = avgCPU / cpus
	}
	return resourceMetrics{
		wallMS:   1000 * wallSeconds,
		cpuMS:    1000 * cpuSeconds,
		avgCPU:   avgCPU,
		quotaCPU: quotaCPU,
		maxRSSMB: float64(usage.Maxrss) / 1024,
	}
}

func syntheticProfiles(universeSize, legalSpaceSize int, selectivity float64) ([][]int, int, error) {
	if universeSize < 2 || legalSpaceSize < 2 {
		return nil, 0, fmt.Errorf("universe and legal-space sizes must both be at least two")
	}
	selected := int(math.Round(selectivity * float64(legalSpaceSize)))
	if selected < 1 || selected >= legalSpaceSize {
		return nil, 0, fmt.Errorf("selectivity must leave authorized and unauthorized profiles")
	}
	identifierBits := 0
	for (1 << identifierBits) < legalSpaceSize {
		identifierBits++
	}
	if identifierBits+1 > universeSize {
		return nil, 0, fmt.Errorf("universe size cannot encode the controlled profile identifiers")
	}
	profiles := make([][]int, legalSpaceSize)
	for index := range profiles {
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
	result := make([]uint8, len(profile))
	for index, value := range profile {
		result[index] = uint8(value)
	}
	return result
}

// stratifiedAuthorizedIndex selects the midpoint of one of sampleCount equal
// strata in the authorized-profile population.  Repeated deployment runs thus
// cover different authorized users deterministically instead of measuring the
// bucket position of profiles[0] in every run.
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

func encryptData(key, plaintext, aad []byte) (binaryDataCiphertext, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return binaryDataCiphertext{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return binaryDataCiphertext{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return binaryDataCiphertext{}, err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	return binaryDataCiphertext{
		nonce:      nonce,
		ciphertext: sealed,
		aad:        append([]byte(nil), aad...),
	}, nil
}

func writeDataPackage(output io.Writer, data binaryDataCiphertext) error {
	if _, err := io.WriteString(output, dataMagic); err != nil {
		return err
	}
	for _, value := range [][]byte{data.nonce, data.aad, data.ciphertext} {
		if err := binary.Write(output, binary.LittleEndian, uint64(len(value))); err != nil {
			return err
		}
		if _, err := output.Write(value); err != nil {
			return err
		}
	}
	return nil
}

func decodeDataPackage(input []byte) (polylock.DataCiphertext, error) {
	if len(input) < 4 || string(input[:4]) != dataMagic {
		return polylock.DataCiphertext{}, fmt.Errorf("invalid encrypted-data package")
	}
	reader := bytes.NewReader(input[4:])
	parts := make([][]byte, 3)
	for index := range parts {
		var length uint64
		if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
			return polylock.DataCiphertext{}, err
		}
		if length > uint64(reader.Len()) {
			return polylock.DataCiphertext{}, fmt.Errorf("encrypted-data package length is invalid")
		}
		parts[index] = make([]byte, int(length))
		if _, err := io.ReadFull(reader, parts[index]); err != nil {
			return polylock.DataCiphertext{}, err
		}
	}
	if reader.Len() != 0 {
		return polylock.DataCiphertext{}, fmt.Errorf("encrypted-data package has trailing bytes")
	}
	return polylock.DataCiphertext{
		NonceHex:      hex.EncodeToString(parts[0]),
		AADHex:        hex.EncodeToString(parts[1]),
		CiphertextHex: hex.EncodeToString(parts[2]),
	}, nil
}

func waitForIPFS(api string) error {
	deadline := time.Now().Add(2 * time.Minute)
	endpoint := "http://" + api + "/api/v0/id"
	for time.Now().Before(deadline) {
		response, err := http.Post(endpoint, "application/octet-stream", nil)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("IPFS API %s did not become ready", api)
}

func ipfsAddReader(api, name string, payload io.Reader) (string, error) {
	bodyReader, bodyWriter := io.Pipe()
	multipartWriter := multipart.NewWriter(bodyWriter)
	contentType := multipartWriter.FormDataContentType()
	go func() {
		part, err := multipartWriter.CreateFormFile("file", name)
		if err == nil {
			_, err = io.Copy(part, payload)
		}
		if closeErr := multipartWriter.Close(); err == nil {
			err = closeErr
		}
		_ = bodyWriter.CloseWithError(err)
	}()
	request, err := http.NewRequest(
		http.MethodPost,
		"http://"+api+"/api/v0/add?pin=true&quieter=true",
		bodyReader,
	)
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", contentType)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(response.Body)
		return "", fmt.Errorf("IPFS add failed: %s: %s", response.Status, message)
	}
	var result struct {
		Hash string `json:"Hash"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.Hash == "" {
		return "", fmt.Errorf("IPFS add returned no CID")
	}
	return result.Hash, nil
}

func ipfsAdd(api, name string, payload []byte) (string, error) {
	return ipfsAddReader(api, name, bytes.NewReader(payload))
}

func ipfsAddFile(api, name, path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	return ipfsAddReader(api, name, file)
}

func ipfsCat(api, cid string, expectedBytes int) ([]byte, error) {
	if expectedBytes < 0 {
		return nil, fmt.Errorf("expected IPFS object size must be nonnegative")
	}
	endpoint := "http://" + api + "/api/v0/cat?arg=" + url.QueryEscape(cid)
	response, err := http.Post(endpoint, "application/octet-stream", nil)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(response.Body)
		return nil, fmt.Errorf("IPFS cat failed: %s: %s", response.Status, message)
	}
	payload := make([]byte, expectedBytes)
	if _, err := io.ReadFull(response.Body, payload); err != nil {
		return nil, fmt.Errorf("IPFS object was shorter than the manifest size: %w", err)
	}
	var trailing [1]byte
	count, trailingErr := response.Body.Read(trailing[:])
	if count != 0 || (trailingErr != nil && trailingErr != io.EOF) {
		return nil, fmt.Errorf("IPFS object was longer than the manifest size")
	}
	return payload, nil
}

func appendCSV(path string, header, row []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	needHeader := true
	if info, err := os.Stat(path); err == nil && info.Size() > 0 {
		needHeader = false
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	if needHeader {
		if err := writer.Write(header); err != nil {
			return err
		}
	}
	if err := writer.Write(row); err != nil {
		return err
	}
	writer.Flush()
	return writer.Error()
}

func f(value float64) string { return strconv.FormatFloat(value, 'f', 6, 64) }

func publisher() error {
	shared := envString("SHARED_DIR", "/shared")
	runID := envString("RUN_ID", strconv.FormatInt(time.Now().UnixNano(), 10))
	api := envString("IPFS_API", "ipfs:5001")
	profile := envString("SECURITY_PROFILE", "ring128")
	universe := envInt("UNIVERSE_SIZE", 100)
	legalSpace := envInt("LEGAL_SPACE_SIZE", 20000)
	selectivity := envFloat("SELECTIVITY", 0.49)
	dMax := envInt("D_MAX", 4)
	objectMB := envInt("OBJECT_MB", 10)
	authorizedSampleRun := envInt("AUTHORIZED_SAMPLE_RUN", 1)
	authorizedSampleCount := envInt("AUTHORIZED_SAMPLE_COUNT", 1)
	cpus := envFloat("PUBLISHER_CPUS", 2)
	if objectMB < 1 {
		return fmt.Errorf("OBJECT_MB must be positive")
	}
	if authorizedSampleRun < 1 || authorizedSampleCount < 1 || authorizedSampleRun > authorizedSampleCount {
		return fmt.Errorf("authorized sample run/count must satisfy 1 <= run <= count")
	}
	if err := waitForIPFS(api); err != nil {
		return err
	}
	profiles, selected, err := syntheticProfiles(universe, legalSpace, selectivity)
	if err != nil {
		return err
	}
	config := setupConfig{
		UniverseSize:      universe,
		DMax:              dMax,
		MaxCardinality:    universe,
		Dependencies:      [][2]int{},
		Exclusions:        [][2]int{},
		LegalProfiles:     profiles,
		SecurityProfile:   profile,
		DecompositionBase: 32,
		ErrorEta:          4,
	}

	resources := resourceStart()
	started := time.Now()
	system, err := polylock.Setup(config)
	setupMS := elapsedMS(started)
	if err != nil {
		return err
	}
	defer system.Close()
	authorizedProfileIndex := stratifiedAuthorizedIndex(
		authorizedSampleRun, authorizedSampleCount, selected,
	)
	started = time.Now()
	key, err := system.KeyGen(byteProfile(profiles[authorizedProfileIndex]))
	keyGenMS := elapsedMS(started)
	if err != nil {
		return err
	}
	defer key.Close()
	keyBytes, err := key.Serialize()
	if err != nil {
		return err
	}
	keyFile := filepath.Join(shared, "user_key_"+runID+".bin")
	if err := os.WriteFile(keyFile, keyBytes, 0o600); err != nil {
		return err
	}

	started = time.Now()
	resolved, err := system.PreResolve(map[string]any{"op": "attr", "index": 0})
	preResolveMS := elapsedMS(started)
	if err != nil {
		return err
	}
	defer resolved.Close()
	var policyInfo policyMetadata
	metadataJSON, err := resolved.Metadata()
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(metadataJSON), &policyInfo); err != nil {
		return err
	}

	seed := make([]byte, 16)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	aad := []byte("polylock:" + runID)
	dataKey, err := polylock.DeriveDataKey(seed, aad)
	if err != nil {
		return err
	}
	payload := make([]byte, objectMB*1_000_000)
	objectBytes := len(payload)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	started = time.Now()
	encryptedData, err := encryptData(dataKey, payload, aad)
	dataEncMS := elapsedMS(started)
	if err != nil {
		return err
	}
	// The plaintext is no longer needed after AES-GCM encryption. Releasing it
	// before serializing and publishing the ciphertext keeps the 1 GB test case
	// within the publisher's 4 GB resource envelope without changing the wire
	// format or any measured cryptographic operation.
	payload = nil
	runtime.GC()
	debug.FreeOSMemory()
	started = time.Now()
	lock, err := system.Encaps(resolved, hex.EncodeToString(seed))
	encapsMS := elapsedMS(started)
	if err != nil {
		return err
	}
	defer lock.Close()
	started = time.Now()
	lockBytes, err := lock.Serialize()
	if err != nil {
		return err
	}
	dataFile, err := os.CreateTemp("", "polylock-data-*.bin")
	if err != nil {
		return err
	}
	dataPath := dataFile.Name()
	defer os.Remove(dataPath)
	if err := writeDataPackage(dataFile, encryptedData); err != nil {
		_ = dataFile.Close()
		return err
	}
	if err := dataFile.Close(); err != nil {
		return err
	}
	dataInfo, err := os.Stat(dataPath)
	if err != nil {
		return err
	}
	dataBytesLen := int(dataInfo.Size())
	encryptedData = binaryDataCiphertext{}
	runtime.GC()
	debug.FreeOSMemory()
	serializeMS := elapsedMS(started)
	publisherResources := resourceFinish(resources, cpus)

	started = time.Now()
	dataCID, err := ipfsAddFile(api, "encrypted_data.bin", dataPath)
	uploadDataMS := elapsedMS(started)
	if err != nil {
		return err
	}
	started = time.Now()
	lockCID, err := ipfsAdd(api, "polylock.bin", lockBytes)
	uploadLockMS := elapsedMS(started)
	if err != nil {
		return err
	}
	publisherCSV := filepath.Join(shared, "publisher_metrics.csv")
	terminalCSV := filepath.Join(shared, "terminal_metrics.csv")
	row := []string{
		runID, profile, strconv.Itoa(universe), strconv.Itoa(legalSpace), f(selectivity),
		strconv.Itoa(objectMB), strconv.Itoa(policyInfo.BucketCount), strconv.Itoa(len(lockBytes)),
		strconv.Itoa(dataBytesLen), f(setupMS), f(keyGenMS), f(preResolveMS), f(encapsMS),
		f(preResolveMS + encapsMS), f(dataEncMS), f(serializeMS), f(uploadDataMS),
		f(uploadLockMS), f(uploadDataMS + uploadLockMS), f(publisherResources.wallMS),
		f(publisherResources.cpuMS), f(publisherResources.avgCPU), f(publisherResources.quotaCPU),
		f(publisherResources.maxRSSMB), strconv.Itoa(selected), strconv.Itoa(authorizedProfileIndex),
	}
	header := []string{
		"RunID", "SecurityProfile", "UniverseSize", "LegalSpaceSize", "Selectivity",
		"ObjectMB", "BucketCount", "LockBytes", "EncryptedDataBytes", "SetupMS", "KeyGenMS",
		"PreResolveMS", "EncapsMS", "EncryptMS", "DataEncMS", "SerializeMS", "UploadDataMS",
		"UploadLockMS", "UploadTotalMS", "ActiveWallMS", "CPUMS",
		"AvgCPUPct", "QuotaCPUPct", "MaxRSSMB", "AuthorizedProfiles", "AuthorizedProfileIndex",
	}
	if err := appendCSV(publisherCSV, header, row); err != nil {
		return err
	}
	entry := manifest{
		RunID: runID, SecurityProfile: profile, UniverseSize: universe,
		LegalSpaceSize: legalSpace, Selectivity: selectivity, ObjectBytes: objectBytes,
		AuthorizedProfileIndex: authorizedProfileIndex,
		BucketCount: policyInfo.BucketCount, LockBytes: len(lockBytes), DataBytes: dataBytesLen,
		LockCID: lockCID, DataCID: dataCID, UserKeyFile: keyFile,
		ExpectedKeyHex: hex.EncodeToString(dataKey), PublisherCSV: publisherCSV, TerminalCSV: terminalCSV,
	}
	encodedManifest, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	temporary := filepath.Join(shared, "manifest_"+runID+".json.tmp")
	final := filepath.Join(shared, "manifest_"+runID+".json")
	if err := os.WriteFile(temporary, encodedManifest, 0o644); err != nil {
		return err
	}
	if err := os.Rename(temporary, final); err != nil {
		return err
	}
	fmt.Printf("PUBLISHER_COMPLETE run=%s lock_cid=%s data_cid=%s\n", runID, lockCID, dataCID)
	return nil
}

func waitForManifest(path string) ([]byte, error) {
	deadline := time.Now().Add(20 * time.Minute)
	for time.Now().Before(deadline) {
		content, err := os.ReadFile(path)
		if err == nil {
			return content, nil
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
		time.Sleep(time.Second)
	}
	return nil, fmt.Errorf("timed out waiting for %s", path)
}

func terminal() error {
	shared := envString("SHARED_DIR", "/shared")
	runID := envString("RUN_ID", "run")
	api := envString("IPFS_API", "ipfs:5001")
	cpus := envFloat("TERMINAL_CPUS", 2)
	if err := waitForIPFS(api); err != nil {
		return err
	}
	content, err := waitForManifest(filepath.Join(shared, "manifest_"+runID+".json"))
	if err != nil {
		return err
	}
	var entry manifest
	if err := json.Unmarshal(content, &entry); err != nil {
		return err
	}
	context, err := polylock.NewDecapsulationContext(entry.SecurityProfile)
	if err != nil {
		return err
	}
	defer context.Close()
	keyBytes, err := os.ReadFile(entry.UserKeyFile)
	if err != nil {
		return err
	}
	key, err := polylock.DeserializeUserKey(keyBytes)
	if err != nil {
		return err
	}
	defer key.Close()

	started := time.Now()
	lockBytes, err := ipfsCat(api, entry.LockCID, entry.LockBytes)
	downloadLockMS := elapsedMS(started)
	if err != nil {
		return err
	}
	started = time.Now()
	dataBytes, err := ipfsCat(api, entry.DataCID, entry.DataBytes)
	downloadDataMS := elapsedMS(started)
	if err != nil {
		return err
	}

	resources := resourceStart()
	started = time.Now()
	encryptedData, err := decodeDataPackage(dataBytes)
	deserializeMS := elapsedMS(started)
	if err != nil {
		return err
	}
	started = time.Now()
	recovered, authorized, err := context.DecapsSerialized(key, lockBytes, encryptedData)
	decapsMS := elapsedMS(started)
	if err != nil {
		return err
	}
	terminalResources := resourceFinish(resources, cpus)
	correct := authorized && recovered == entry.ExpectedKeyHex
	header := []string{
		"RunID", "SecurityProfile", "UniverseSize", "LegalSpaceSize", "Selectivity", "ObjectMB",
		"BucketCount", "LockBytes", "EncryptedDataBytes", "DownloadLockMS", "DownloadDataMS",
		"DownloadTotalMS", "DeserializeMS", "DecapsMS", "DecryptTotalMS", "ActiveWallMS",
		"CPUMS", "AvgCPUPct", "QuotaCPUPct", "MaxRSSMB", "AuthorizedRecovery",
	}
	row := []string{
		entry.RunID, entry.SecurityProfile, strconv.Itoa(entry.UniverseSize), strconv.Itoa(entry.LegalSpaceSize),
		f(entry.Selectivity), f(float64(entry.ObjectBytes) / 1_000_000), strconv.Itoa(entry.BucketCount),
		strconv.Itoa(entry.LockBytes), strconv.Itoa(entry.DataBytes), f(downloadLockMS), f(downloadDataMS),
		f(downloadLockMS + downloadDataMS), f(deserializeMS), f(decapsMS), f(deserializeMS + decapsMS),
		f(terminalResources.wallMS), f(terminalResources.cpuMS), f(terminalResources.avgCPU),
		f(terminalResources.quotaCPU), f(terminalResources.maxRSSMB), strconv.FormatBool(correct),
	}
	if err := appendCSV(entry.TerminalCSV, header, row); err != nil {
		return err
	}
	if !correct {
		return fmt.Errorf("authorized terminal failed to recover the deployed data key")
	}
	fmt.Printf("TERMINAL_COMPLETE run=%s authorized_recovery=true\n", runID)
	return nil
}

func main() {
	role := envString("ROLE", "")
	var err error
	switch role {
	case "publisher":
		err = publisher()
	case "terminal":
		err = terminal()
	default:
		err = fmt.Errorf("ROLE must be publisher or terminal")
	}
	if err != nil {
		log.Fatal(err)
	}
}
