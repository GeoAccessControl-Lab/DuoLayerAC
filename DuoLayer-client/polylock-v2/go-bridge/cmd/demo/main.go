package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"

	"polylock-thesis/go-bridge/polylock"
)

type setupConfig struct {
	UniverseSize      int       `json:"universe_size"`
	DMax              int       `json:"d_max"`
	MaxCardinality    int       `json:"max_cardinality"`
	Dependencies      [][2]int  `json:"dependencies"`
	Exclusions        [][2]int  `json:"exclusions"`
	LegalProfiles     [][]uint8 `json:"legal_profiles,omitempty"`
	SecurityProfile   string    `json:"security_profile"`
	DecompositionBase uint32    `json:"decomposition_base"`
	ErrorEta          uint32    `json:"error_eta"`
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

func mustPrettyJSON(raw string) string {
	var value any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return raw
	}
	encoded, _ := json.MarshalIndent(value, "", "  ")
	return string(encoded)
}

func main() {
	config := setupConfig{
		UniverseSize:      4,
		DMax:              4,
		MaxCardinality:    3,
		Dependencies:      [][2]int{{0, 1}},
		Exclusions:        [][2]int{{2, 3}},
		SecurityProfile:   "ring128",
		DecompositionBase: 32,
		ErrorEta:          4,
	}
	system, err := polylock.Setup(config)
	if err != nil {
		log.Fatal(err)
	}
	defer system.Close()

	policy := map[string]any{
		"op": "and",
		"children": []any{
			map[string]any{"op": "attr", "index": 0},
			map[string]any{"op": "attr", "index": 2},
		},
	}
	resolved, err := system.PreResolve(policy)
	if err != nil {
		log.Fatal(err)
	}
	defer resolved.Close()

	authorized, err := system.KeyGen([]uint8{1, 0, 1, 0})
	if err != nil {
		log.Fatal(err)
	}
	defer authorized.Close()
	unauthorized, err := system.KeyGen([]uint8{1, 1, 0, 0})
	if err != nil {
		log.Fatal(err)
	}
	defer unauthorized.Close()

	seed := make([]byte, 16)
	if _, err := rand.Read(seed); err != nil {
		log.Fatal(err)
	}
	aad := []byte("cid:test")
	key, err := polylock.DeriveDataKey(seed, aad)
	if err != nil {
		log.Fatal(err)
	}
	data, err := encryptData(key, []byte("controlled geospatial object"), aad)
	if err != nil {
		log.Fatal(err)
	}
	lock, err := system.Encaps(resolved, hex.EncodeToString(seed))
	if err != nil {
		log.Fatal(err)
	}
	defer lock.Close()

	recovered, ok, err := system.Decaps(authorized, lock, data)
	if err != nil {
		log.Fatal(err)
	}
	if !ok || recovered != hex.EncodeToString(key) {
		log.Fatal("authorized user failed to recover the session key")
	}
	_, unauthorizedOK, err := system.Decaps(unauthorized, lock, data)
	if err != nil {
		log.Fatal(err)
	}
	if unauthorizedOK {
		log.Fatal("unauthorized user unexpectedly recovered the session key")
	}

	metadata, _ := system.Metadata()
	resolvedMetadata, _ := resolved.Metadata()
	fmt.Println("================ POLYLOCK_LWE_DEMO_BEGIN ================")
	fmt.Println("SYSTEM=" + mustPrettyJSON(metadata))
	fmt.Println("POLICY=" + mustPrettyJSON(resolvedMetadata))
	fmt.Println("AUTHORIZED_RECOVERY=true")
	fmt.Println("UNAUTHORIZED_REJECTION=true")
	fmt.Println("C_ABI_GO_BRIDGE=true")
	fmt.Println("================= POLYLOCK_LWE_DEMO_END =================")
}
