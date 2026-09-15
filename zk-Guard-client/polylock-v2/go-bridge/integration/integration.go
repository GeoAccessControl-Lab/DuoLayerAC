package integration

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"polylock-thesis/go-bridge/polylock"
)

const (
	SecurityProfile = "ring100"
	SystemDir       = "polylock_state/system"
	PublicFile      = "polylock_public_v2.bin"
	MasterFile      = "polylock_master_v2.bin"
	ConfigFile      = "polylock_config_v2.sha256"
	UserKeyFormat   = "zkguard-polylock-usk-v2"
)

type SetupConfig struct {
	UniverseSize      int      `json:"universe_size"`
	DMax              int      `json:"d_max"`
	MaxCardinality    int      `json:"max_cardinality"`
	Dependencies      [][2]int `json:"dependencies,omitempty"`
	Exclusions        [][2]int `json:"exclusions,omitempty"`
	LegalProfiles     [][]int  `json:"legal_profiles"`
	SecurityProfile   string   `json:"security_profile"`
	DecompositionBase int      `json:"decomposition_base"`
	ErrorEta          int      `json:"error_eta"`
}

type UserKeyDisk struct {
	Format              string `json:"format"`
	Username            string `json:"username"`
	PID                 string `json:"pid"`
	AttrNum             int    `json:"attr_num"`
	AttrHash            string `json:"attr_hash"`
	UserCommit          string `json:"user_commit,omitempty"`
	AttrRand            string `json:"attr_rand,omitempty"`
	AttrRandBase64      string `json:"attr_rand_base64,omitempty"`
	Version             uint64 `json:"version"`
	SecurityProfile     string `json:"security_profile"`
	SerializedKeyBase64 string `json:"serialized_key_base64"`
	AttrVector          []int  `json:"attr_vector"`
	CreatedAt           string `json:"created_at"`
}

type ResolvedMetadata struct {
	BucketCount          int   `json:"bucket_count"`
	BucketSizes          []int `json:"bucket_sizes"`
	CoefficientDimension int   `json:"coefficient_dimension"`
	EffectiveRoots       int   `json:"-"`
	BucketDegree         int   `json:"-"`
}

type DataCiphertext struct {
	Nonce      []byte
	Ciphertext []byte
	AAD        []byte
}

func normalizeConfig(config SetupConfig) SetupConfig {
	if config.SecurityProfile == "" {
		config.SecurityProfile = SecurityProfile
	}
	if config.DecompositionBase == 0 {
		config.DecompositionBase = 32
	}
	if config.ErrorEta == 0 {
		config.ErrorEta = 4
	}
	sort.Slice(config.Dependencies, func(i, j int) bool {
		if config.Dependencies[i][0] != config.Dependencies[j][0] {
			return config.Dependencies[i][0] < config.Dependencies[j][0]
		}
		return config.Dependencies[i][1] < config.Dependencies[j][1]
	})
	sort.Slice(config.Exclusions, func(i, j int) bool {
		if config.Exclusions[i][0] != config.Exclusions[j][0] {
			return config.Exclusions[i][0] < config.Exclusions[j][0]
		}
		return config.Exclusions[i][1] < config.Exclusions[j][1]
	})
	return config
}

func SetupAndSave(config SetupConfig, stateDir string) (*polylock.System, error) {
	config = normalizeConfig(config)
	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	configDigest := fmt.Sprintf("%x", sha256.Sum256(configJSON))
	storedDigest, digestErr := os.ReadFile(filepath.Join(stateDir, ConfigFile))
	if digestErr == nil && string(storedDigest) == configDigest {
		if system, err := LoadAuthority(stateDir); err == nil {
			return system, nil
		}
	}
	system, err := polylock.Setup(config)
	if err != nil {
		return nil, err
	}
	public, err := system.SerializePublic()
	if err != nil {
		system.Close()
		return nil, err
	}
	master, err := system.SerializeMasterSecret()
	if err != nil {
		system.Close()
		return nil, err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		system.Close()
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(stateDir, PublicFile), public, 0o644); err != nil {
		system.Close()
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(stateDir, MasterFile), master, 0o600); err != nil {
		system.Close()
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(stateDir, ConfigFile), []byte(configDigest), 0o644); err != nil {
		system.Close()
		return nil, err
	}
	return system, nil
}

func LoadPublic(stateDir string) (*polylock.System, error) {
	public, err := os.ReadFile(filepath.Join(stateDir, PublicFile))
	if err != nil {
		return nil, fmt.Errorf("read PolyLock public parameters: %w", err)
	}
	return polylock.LoadPublicSystem(public)
}

func LoadAuthority(stateDir string) (*polylock.System, error) {
	public, err := os.ReadFile(filepath.Join(stateDir, PublicFile))
	if err != nil {
		return nil, fmt.Errorf("read PolyLock public parameters: %w", err)
	}
	master, err := os.ReadFile(filepath.Join(stateDir, MasterFile))
	if err != nil {
		return nil, fmt.Errorf("read PolyLock master secret: %w", err)
	}
	return polylock.LoadAuthoritySystem(public, master)
}

func IntBits(bits []int) ([]uint8, error) {
	out := make([]uint8, len(bits))
	for i, bit := range bits {
		if bit != 0 && bit != 1 {
			return nil, fmt.Errorf("attribute %d is not binary", i)
		}
		out[i] = uint8(bit)
	}
	return out, nil
}

func VersionedProfiles(profiles [][]int, versions []uint64) ([]polylock.VersionedProfile, error) {
	if len(profiles) != len(versions) {
		return nil, fmt.Errorf("profile/version length mismatch: %d != %d", len(profiles), len(versions))
	}
	out := make([]polylock.VersionedProfile, len(profiles))
	for i := range profiles {
		bits, err := IntBits(profiles[i])
		if err != nil {
			return nil, err
		}
		out[i] = polylock.VersionedProfile{Attributes: bits, Version: versions[i]}
	}
	return out, nil
}

func Metadata(resolved *polylock.ResolvedPolicy) (ResolvedMetadata, error) {
	raw, err := resolved.Metadata()
	if err != nil {
		return ResolvedMetadata{}, err
	}
	var metadata ResolvedMetadata
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
		return ResolvedMetadata{}, fmt.Errorf("parse resolved metadata: %w", err)
	}
	for _, size := range metadata.BucketSizes {
		metadata.EffectiveRoots += size
		if size > metadata.BucketDegree {
			metadata.BucketDegree = size
		}
	}
	return metadata, nil
}

func SaveUserKey(path string, disk UserKeyDisk, key *polylock.UserKey) error {
	encoded, err := key.Serialize()
	if err != nil {
		return err
	}
	disk.Format = UserKeyFormat
	if disk.SecurityProfile == "" {
		disk.SecurityProfile = SecurityProfile
	}
	disk.SerializedKeyBase64 = base64.StdEncoding.EncodeToString(encoded)
	data, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func LoadUserKey(path string) (UserKeyDisk, *polylock.UserKey, error) {
	var disk UserKeyDisk
	raw, err := os.ReadFile(path)
	if err != nil {
		return disk, nil, err
	}
	if err := json.Unmarshal(raw, &disk); err != nil {
		return disk, nil, err
	}
	if disk.Format != UserKeyFormat {
		return disk, nil, fmt.Errorf("unexpected PolyLock user-key format %q", disk.Format)
	}
	encoded, err := base64.StdEncoding.DecodeString(disk.SerializedKeyBase64)
	if err != nil {
		return disk, nil, err
	}
	key, err := polylock.DeserializeUserKey(encoded)
	return disk, key, err
}

func NewSeed() ([]byte, error) {
	seed := make([]byte, 16)
	_, err := rand.Read(seed)
	return seed, err
}

func EncryptData(seed, plaintext, aad []byte) (DataCiphertext, []byte, error) {
	key, err := polylock.DeriveDataKey(seed, aad)
	if err != nil {
		return DataCiphertext{}, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return DataCiphertext{}, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return DataCiphertext{}, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return DataCiphertext{}, nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	payload := append(append([]byte(nil), nonce...), ciphertext...)
	return DataCiphertext{Nonce: nonce, Ciphertext: ciphertext, AAD: append([]byte(nil), aad...)}, payload, nil
}

func ParseDataPayload(payload, aad []byte) (DataCiphertext, error) {
	const nonceSize = 12
	if len(payload) < nonceSize {
		return DataCiphertext{}, fmt.Errorf("data ciphertext is shorter than the GCM nonce")
	}
	return DataCiphertext{
		Nonce:      append([]byte(nil), payload[:nonceSize]...),
		Ciphertext: append([]byte(nil), payload[nonceSize:]...),
		AAD:        append([]byte(nil), aad...),
	}, nil
}

func CoreDataCiphertext(data DataCiphertext) polylock.DataCiphertext {
	return polylock.DataCiphertext{
		NonceHex:      hex.EncodeToString(data.Nonce),
		CiphertextHex: hex.EncodeToString(data.Ciphertext),
		AADHex:        hex.EncodeToString(data.AAD),
	}
}

func DecryptData(keyHex string, data DataCiphertext) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, data.Nonce, data.Ciphertext, data.AAD)
}
