package integration

import (
	"bytes"
	"encoding/hex"
	"testing"

	"polylock-thesis/go-bridge/polylock"
)

func TestSetupReuseIsIndependentOfConstraintOrder(t *testing.T) {
	dir := t.TempDir()
	profiles := [][]int{{0, 0, 0, 0}, {1, 0, 0, 0}, {1, 1, 0, 0}}
	config := SetupConfig{
		UniverseSize: 4, DMax: 2, MaxCardinality: 2,
		Dependencies: [][2]int{{0, 1}, {2, 3}},
		Exclusions:   [][2]int{{1, 2}}, LegalProfiles: profiles,
		SecurityProfile: SecurityProfile, DecompositionBase: 32, ErrorEta: 4,
	}
	first, err := SetupAndSave(config, dir)
	if err != nil {
		t.Fatal(err)
	}
	key, err := first.KeyGenVersioned([]uint8{1, 1, 0, 0}, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	first.Close()

	config.Dependencies[0], config.Dependencies[1] = config.Dependencies[1], config.Dependencies[0]
	second, err := SetupAndSave(config, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	resolved, err := second.PreResolveVersionedProfiles([]polylock.VersionedProfile{{Attributes: []uint8{1, 1, 0, 0}, Version: 3}})
	if err != nil {
		t.Fatal(err)
	}
	defer resolved.Close()
	seed := bytes.Repeat([]byte{7}, 16)
	lock, err := second.Encaps(resolved, hex.EncodeToString(seed))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	data, payload, err := EncryptData(seed, []byte("reuse"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	_ = payload
	keyHex, ok, err := second.Decaps(key, lock, CoreDataCiphertext(data))
	if err != nil || !ok {
		t.Fatalf("reused system rejected the first user's key: ok=%v err=%v", ok, err)
	}
	plain, err := DecryptData(keyHex, data)
	if err != nil || string(plain) != "reuse" {
		t.Fatalf("decrypt after system reuse: plaintext=%q err=%v", plain, err)
	}
}
