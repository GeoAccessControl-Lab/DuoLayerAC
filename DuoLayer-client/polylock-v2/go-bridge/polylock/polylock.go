package polylock

/*
#cgo CFLAGS: -I${SRCDIR}/../../crypto-rust/include
#cgo LDFLAGS: -L${SRCDIR}/../../crypto-rust/target/release -lpolylock_core -ldl -lpthread -lm
#include <stdlib.h>
#include "polylock.h"
*/
import "C"

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

type System struct{ ptr *C.PolyLockSystem }
type UserKey struct{ ptr *C.PolyLockUserKey }
type ResolvedPolicy struct{ ptr *C.PolyLockResolvedPolicy }
type Ciphertext struct{ ptr *C.PolyLockCiphertext }
type DecapsulationContext struct {
	ptr *C.PolyLockDecapsulationContext
}

type DataCiphertext struct {
	NonceHex      string `json:"nonce_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
	AADHex        string `json:"aad_hex,omitempty"`
}

type VersionedProfile struct {
	Attributes []uint8 `json:"attributes"`
	Version    uint64  `json:"version"`
}

func rustError(value *C.char) error {
	if value == nil {
		return errors.New("Rust core returned an unspecified error")
	}
	defer C.polylock_string_free(value)
	return errors.New(C.GoString(value))
}

func Setup(config any) (*System, error) {
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("encode setup configuration: %w", err)
	}
	input := C.CString(string(encoded))
	defer C.free(unsafe.Pointer(input))
	var rustErr *C.char
	ptr := C.polylock_setup(input, &rustErr)
	if ptr == nil {
		return nil, rustError(rustErr)
	}
	system := &System{ptr: ptr}
	runtime.SetFinalizer(system, (*System).Close)
	return system, nil
}

func LoadPublicSystem(encoded []byte) (*System, error) {
	if len(encoded) == 0 {
		return nil, errors.New("public system is empty")
	}
	var rustErr *C.char
	ptr := C.polylock_system_deserialize_public(
		(*C.uint8_t)(unsafe.Pointer(&encoded[0])),
		C.size_t(len(encoded)),
		&rustErr,
	)
	runtime.KeepAlive(encoded)
	if ptr == nil {
		return nil, rustError(rustErr)
	}
	system := &System{ptr: ptr}
	runtime.SetFinalizer(system, (*System).Close)
	return system, nil
}

func LoadAuthoritySystem(public, master []byte) (*System, error) {
	if len(public) == 0 || len(master) == 0 {
		return nil, errors.New("public system or master secret is empty")
	}
	var rustErr *C.char
	ptr := C.polylock_system_deserialize_authority(
		(*C.uint8_t)(unsafe.Pointer(&public[0])),
		C.size_t(len(public)),
		(*C.uint8_t)(unsafe.Pointer(&master[0])),
		C.size_t(len(master)),
		&rustErr,
	)
	runtime.KeepAlive(public)
	runtime.KeepAlive(master)
	if ptr == nil {
		return nil, rustError(rustErr)
	}
	system := &System{ptr: ptr}
	runtime.SetFinalizer(system, (*System).Close)
	return system, nil
}

func copyRustBytes(value *C.uint8_t, length C.size_t, rustErr *C.char) ([]byte, error) {
	if value == nil {
		return nil, rustError(rustErr)
	}
	defer C.polylock_bytes_free(value, length)
	return C.GoBytes(unsafe.Pointer(value), C.int(length)), nil
}

func (s *System) SerializePublic() ([]byte, error) {
	var length C.size_t
	var rustErr *C.char
	value := C.polylock_system_public_serialize(s.ptr, &length, &rustErr)
	return copyRustBytes(value, length, rustErr)
}

func (s *System) SerializeMasterSecret() ([]byte, error) {
	var length C.size_t
	var rustErr *C.char
	value := C.polylock_system_master_serialize(s.ptr, &length, &rustErr)
	return copyRustBytes(value, length, rustErr)
}

func (s *System) KeyGen(attributes []uint8) (*UserKey, error) {
	// encoding/json treats []byte as Base64 text. The Rust ABI accepts an
	// explicit binary-attribute vector, so marshal integer entries instead.
	values := make([]int, len(attributes))
	for index, value := range attributes {
		values[index] = int(value)
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return nil, fmt.Errorf("encode attributes: %w", err)
	}
	input := C.CString(string(encoded))
	defer C.free(unsafe.Pointer(input))
	var rustErr *C.char
	ptr := C.polylock_keygen(s.ptr, input, &rustErr)
	if ptr == nil {
		return nil, rustError(rustErr)
	}
	key := &UserKey{ptr: ptr}
	runtime.SetFinalizer(key, (*UserKey).Close)
	return key, nil
}

func (s *System) KeyGenVersioned(attributes []uint8, version uint64) (*UserKey, error) {
	values := make([]int, len(attributes))
	for index, value := range attributes {
		values[index] = int(value)
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return nil, fmt.Errorf("encode attributes: %w", err)
	}
	input := C.CString(string(encoded))
	defer C.free(unsafe.Pointer(input))
	var rustErr *C.char
	ptr := C.polylock_keygen_versioned(s.ptr, input, C.uint64_t(version), &rustErr)
	if ptr == nil {
		return nil, rustError(rustErr)
	}
	key := &UserKey{ptr: ptr}
	runtime.SetFinalizer(key, (*UserKey).Close)
	return key, nil
}

func (s *System) PreResolve(policy any) (*ResolvedPolicy, error) {
	encoded, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("encode policy: %w", err)
	}
	input := C.CString(string(encoded))
	defer C.free(unsafe.Pointer(input))
	var rustErr *C.char
	ptr := C.polylock_preresolve(s.ptr, input, &rustErr)
	if ptr == nil {
		return nil, rustError(rustErr)
	}
	resolved := &ResolvedPolicy{ptr: ptr}
	runtime.SetFinalizer(resolved, (*ResolvedPolicy).Close)
	return resolved, nil
}

func (s *System) PreResolveVersionedProfiles(profiles []VersionedProfile) (*ResolvedPolicy, error) {
	type wireProfile struct {
		Attributes []int  `json:"attributes"`
		Version    uint64 `json:"version"`
	}
	wire := make([]wireProfile, len(profiles))
	for index, profile := range profiles {
		attributes := make([]int, len(profile.Attributes))
		for attributeIndex, value := range profile.Attributes {
			attributes[attributeIndex] = int(value)
		}
		wire[index] = wireProfile{Attributes: attributes, Version: profile.Version}
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encode versioned profiles: %w", err)
	}
	input := C.CString(string(encoded))
	defer C.free(unsafe.Pointer(input))
	var rustErr *C.char
	ptr := C.polylock_preresolve_versioned_profiles(s.ptr, input, &rustErr)
	if ptr == nil {
		return nil, rustError(rustErr)
	}
	resolved := &ResolvedPolicy{ptr: ptr}
	runtime.SetFinalizer(resolved, (*ResolvedPolicy).Close)
	return resolved, nil
}

func (s *System) Encaps(resolved *ResolvedPolicy, keyHex string) (*Ciphertext, error) {
	key := C.CString(keyHex)
	defer C.free(unsafe.Pointer(key))
	var rustErr *C.char
	ptr := C.polylock_encaps(s.ptr, resolved.ptr, key, &rustErr)
	if ptr == nil {
		return nil, rustError(rustErr)
	}
	ciphertext := &Ciphertext{ptr: ptr}
	runtime.SetFinalizer(ciphertext, (*Ciphertext).Close)
	return ciphertext, nil
}

func (s *System) ReEncaps(
	oldResolved, newResolved *ResolvedPolicy,
	oldCiphertext *Ciphertext,
	keyHex string,
) (*Ciphertext, int, int, error) {
	key := C.CString(keyHex)
	defer C.free(unsafe.Pointer(key))
	var refreshed C.size_t
	var reused C.size_t
	var rustErr *C.char
	ptr := C.polylock_reencaps(
		s.ptr,
		oldResolved.ptr,
		newResolved.ptr,
		oldCiphertext.ptr,
		key,
		&refreshed,
		&reused,
		&rustErr,
	)
	if ptr == nil {
		return nil, 0, 0, rustError(rustErr)
	}
	ciphertext := &Ciphertext{ptr: ptr}
	runtime.SetFinalizer(ciphertext, (*Ciphertext).Close)
	return ciphertext, int(refreshed), int(reused), nil
}

// DeriveDataKey expands a 128-bit KEM seed into the 256-bit AES key bound to
// the object's authenticated metadata. The same HKDF is used by Rust after
// decapsulation.
func DeriveDataKey(seed, aad []byte) ([]byte, error) {
	seedHex := C.CString(hex.EncodeToString(seed))
	aadHex := C.CString(hex.EncodeToString(aad))
	defer C.free(unsafe.Pointer(seedHex))
	defer C.free(unsafe.Pointer(aadHex))
	var rustErr *C.char
	value := C.polylock_derive_data_key(seedHex, aadHex, &rustErr)
	if value == nil {
		return nil, rustError(rustErr)
	}
	defer C.polylock_string_free(value)
	decoded, err := hex.DecodeString(C.GoString(value))
	if err != nil {
		return nil, fmt.Errorf("decode derived key: %w", err)
	}
	return decoded, nil
}

func (s *System) Decaps(
	userKey *UserKey,
	ciphertext *Ciphertext,
	dataCiphertext DataCiphertext,
) (string, bool, error) {
	encoded, err := json.Marshal(dataCiphertext)
	if err != nil {
		return "", false, fmt.Errorf("encode data ciphertext: %w", err)
	}
	input := C.CString(string(encoded))
	defer C.free(unsafe.Pointer(input))
	var rustErr *C.char
	value := C.polylock_decaps(s.ptr, userKey.ptr, ciphertext.ptr, input, &rustErr)
	if value == nil {
		if rustErr != nil {
			return "", false, rustError(rustErr)
		}
		return "", false, nil
	}
	defer C.polylock_string_free(value)
	return C.GoString(value), true, nil
}

func NewDecapsulationContext(securityProfile string) (*DecapsulationContext, error) {
	profile := C.CString(securityProfile)
	defer C.free(unsafe.Pointer(profile))
	var rustErr *C.char
	ptr := C.polylock_decapsulation_context_new(profile, &rustErr)
	if ptr == nil {
		return nil, rustError(rustErr)
	}
	context := &DecapsulationContext{ptr: ptr}
	runtime.SetFinalizer(context, (*DecapsulationContext).Close)
	return context, nil
}

func (context *DecapsulationContext) Decaps(
	userKey *UserKey,
	ciphertext *Ciphertext,
	dataCiphertext DataCiphertext,
) (string, bool, error) {
	encoded, err := json.Marshal(dataCiphertext)
	if err != nil {
		return "", false, fmt.Errorf("encode data ciphertext: %w", err)
	}
	input := C.CString(string(encoded))
	defer C.free(unsafe.Pointer(input))
	var rustErr *C.char
	value := C.polylock_decaps_with_context(
		context.ptr,
		userKey.ptr,
		ciphertext.ptr,
		input,
		&rustErr,
	)
	if value == nil {
		if rustErr != nil {
			return "", false, rustError(rustErr)
		}
		return "", false, nil
	}
	defer C.polylock_string_free(value)
	return C.GoString(value), true, nil
}

// DecapsSerialized validates and evaluates the compact lock directly from its
// wire representation. The Rust core expands only the buckets being tested,
// so a resource-constrained terminal does not retain both a packed lock and a
// complete in-memory Vec<u32> expansion.
func (context *DecapsulationContext) DecapsSerialized(
	userKey *UserKey,
	ciphertext []byte,
	dataCiphertext DataCiphertext,
) (string, bool, error) {
	if len(ciphertext) == 0 {
		return "", false, errors.New("serialized ciphertext is empty")
	}
	encoded, err := json.Marshal(dataCiphertext)
	if err != nil {
		return "", false, fmt.Errorf("encode data ciphertext: %w", err)
	}
	input := C.CString(string(encoded))
	defer C.free(unsafe.Pointer(input))
	var rustErr *C.char
	value := C.polylock_decaps_serialized_with_context(
		context.ptr,
		userKey.ptr,
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		C.size_t(len(ciphertext)),
		input,
		&rustErr,
	)
	runtime.KeepAlive(ciphertext)
	if value == nil {
		if rustErr != nil {
			return "", false, rustError(rustErr)
		}
		return "", false, nil
	}
	defer C.polylock_string_free(value)
	return C.GoString(value), true, nil
}

func (s *System) Metadata() (string, error) {
	value := C.polylock_system_metadata(s.ptr)
	if value == nil {
		return "", errors.New("system metadata is unavailable")
	}
	defer C.polylock_string_free(value)
	return C.GoString(value), nil
}

func (r *ResolvedPolicy) Metadata() (string, error) {
	value := C.polylock_resolved_metadata(r.ptr)
	if value == nil {
		return "", errors.New("resolved-policy metadata is unavailable")
	}
	defer C.polylock_string_free(value)
	return C.GoString(value), nil
}

func (c *Ciphertext) SerializedSize() int64 {
	if c == nil || c.ptr == nil {
		return 0
	}
	return int64(C.polylock_ciphertext_serialized_size(c.ptr))
}

func (c *Ciphertext) Serialize() ([]byte, error) {
	if c == nil || c.ptr == nil {
		return nil, errors.New("ciphertext is closed")
	}
	var length C.size_t
	var rustErr *C.char
	value := C.polylock_ciphertext_serialize(c.ptr, &length, &rustErr)
	if value == nil {
		return nil, rustError(rustErr)
	}
	defer C.polylock_bytes_free(value, length)
	return C.GoBytes(unsafe.Pointer(value), C.int(length)), nil
}

func DeserializeCiphertext(encoded []byte) (*Ciphertext, error) {
	if len(encoded) == 0 {
		return nil, errors.New("serialized ciphertext is empty")
	}
	var rustErr *C.char
	ptr := C.polylock_ciphertext_deserialize(
		(*C.uint8_t)(unsafe.Pointer(&encoded[0])),
		C.size_t(len(encoded)),
		&rustErr,
	)
	if ptr == nil {
		return nil, rustError(rustErr)
	}
	ciphertext := &Ciphertext{ptr: ptr}
	runtime.SetFinalizer(ciphertext, (*Ciphertext).Close)
	return ciphertext, nil
}

func (k *UserKey) SerializedSize() int64 {
	if k == nil || k.ptr == nil {
		return 0
	}
	return int64(C.polylock_user_key_serialized_size(k.ptr))
}

func (k *UserKey) Serialize() ([]byte, error) {
	if k == nil || k.ptr == nil {
		return nil, errors.New("user key is closed")
	}
	var length C.size_t
	var rustErr *C.char
	value := C.polylock_user_key_serialize(k.ptr, &length, &rustErr)
	if value == nil {
		return nil, rustError(rustErr)
	}
	defer C.polylock_bytes_free(value, length)
	return C.GoBytes(unsafe.Pointer(value), C.int(length)), nil
}

func DeserializeUserKey(encoded []byte) (*UserKey, error) {
	if len(encoded) == 0 {
		return nil, errors.New("serialized user key is empty")
	}
	var rustErr *C.char
	ptr := C.polylock_user_key_deserialize(
		(*C.uint8_t)(unsafe.Pointer(&encoded[0])),
		C.size_t(len(encoded)),
		&rustErr,
	)
	if ptr == nil {
		return nil, rustError(rustErr)
	}
	key := &UserKey{ptr: ptr}
	runtime.SetFinalizer(key, (*UserKey).Close)
	return key, nil
}

func (s *System) Close() {
	if s != nil && s.ptr != nil {
		C.polylock_system_free(s.ptr)
		s.ptr = nil
	}
}
func (context *DecapsulationContext) Close() {
	if context != nil && context.ptr != nil {
		C.polylock_decapsulation_context_free(context.ptr)
		context.ptr = nil
	}
}
func (k *UserKey) Close() {
	if k != nil && k.ptr != nil {
		C.polylock_user_key_free(k.ptr)
		k.ptr = nil
	}
}
func (r *ResolvedPolicy) Close() {
	if r != nil && r.ptr != nil {
		C.polylock_resolved_free(r.ptr)
		r.ptr = nil
	}
}
func (c *Ciphertext) Close() {
	if c != nil && c.ptr != nil {
		C.polylock_ciphertext_free(c.ptr)
		c.ptr = nil
	}
}
