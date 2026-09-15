package polylock

import (
	"strings"
	"testing"
)

func TestInvalidAttributeProfileIsRejected(t *testing.T) {
	config := map[string]any{
		"universe_size":      3,
		"d_max":              2,
		"max_cardinality":    2,
		"dependencies":       [][2]int{{0, 1}},
		"exclusions":         [][2]int{},
		"security_profile":   "ring128",
		"decomposition_base": 32,
		"error_eta":          4,
	}
	system, err := Setup(config)
	if err != nil {
		t.Fatal(err)
	}
	defer system.Close()
	if _, err := system.KeyGen([]uint8{0, 1, 0}); err == nil {
		t.Fatal("expected dependency-violating profile to be rejected")
	}
}

func TestCompactCiphertextSerializationAcrossCABI(t *testing.T) {
	config := map[string]any{
		"universe_size":      4,
		"d_max":              4,
		"max_cardinality":    4,
		"dependencies":       [][2]int{},
		"exclusions":         [][2]int{},
		"security_profile":   "ring100",
		"decomposition_base": 32,
		"error_eta":          4,
	}
	system, err := Setup(config)
	if err != nil {
		t.Fatal(err)
	}
	defer system.Close()
	resolved, err := system.PreResolve(map[string]any{"op": "attr", "index": 0})
	if err != nil {
		t.Fatal(err)
	}
	defer resolved.Close()
	lock, err := system.Encaps(resolved, strings.Repeat("00", 16))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	encoded, err := lock.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(encoded)) != lock.SerializedSize() {
		t.Fatalf("serialized-size mismatch: got %d, expected %d", len(encoded), lock.SerializedSize())
	}
	restored, err := DeserializeCiphertext(encoded)
	if err != nil {
		t.Fatal(err)
	}
	restored.Close()
}
