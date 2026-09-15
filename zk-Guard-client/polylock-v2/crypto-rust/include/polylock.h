#ifndef POLYLOCK_H
#define POLYLOCK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct PolyLockSystem PolyLockSystem;
typedef struct PolyLockUserKey PolyLockUserKey;
typedef struct PolyLockResolvedPolicy PolyLockResolvedPolicy;
typedef struct PolyLockCiphertext PolyLockCiphertext;
typedef struct PolyLockDecapsulationContext PolyLockDecapsulationContext;

PolyLockSystem *polylock_setup(const char *config_json, char **error_out);
uint8_t *polylock_system_public_serialize(
    const PolyLockSystem *system,
    size_t *length_out,
    char **error_out);
uint8_t *polylock_system_master_serialize(
    const PolyLockSystem *system,
    size_t *length_out,
    char **error_out);
PolyLockSystem *polylock_system_deserialize_public(
    const uint8_t *input,
    size_t length,
    char **error_out);
PolyLockSystem *polylock_system_deserialize_authority(
    const uint8_t *public_input,
    size_t public_length,
    const uint8_t *master_input,
    size_t master_length,
    char **error_out);
PolyLockUserKey *polylock_keygen(
    const PolyLockSystem *system,
    const char *attributes_json,
    char **error_out);
PolyLockUserKey *polylock_keygen_versioned(
    const PolyLockSystem *system,
    const char *attributes_json,
    uint64_t version,
    char **error_out);
PolyLockResolvedPolicy *polylock_preresolve(
    const PolyLockSystem *system,
    const char *policy_json,
    char **error_out);
PolyLockResolvedPolicy *polylock_preresolve_versioned_profiles(
    const PolyLockSystem *system,
    const char *profiles_json,
    char **error_out);
PolyLockCiphertext *polylock_encaps(
    const PolyLockSystem *system,
    const PolyLockResolvedPolicy *resolved,
    const char *seed_hex,
    char **error_out);
PolyLockCiphertext *polylock_reencaps(
    const PolyLockSystem *system,
    const PolyLockResolvedPolicy *old_resolved,
    const PolyLockResolvedPolicy *new_resolved,
    const PolyLockCiphertext *old_ciphertext,
    const char *seed_hex,
    size_t *refreshed_out,
    size_t *reused_out,
    char **error_out);
char *polylock_decaps(
    const PolyLockSystem *system,
    const PolyLockUserKey *user_key,
    const PolyLockCiphertext *ciphertext,
    const char *data_cipher_json,
    char **error_out);
PolyLockDecapsulationContext *polylock_decapsulation_context_new(
    const char *security_profile,
    char **error_out);
char *polylock_decaps_with_context(
    const PolyLockDecapsulationContext *context,
    const PolyLockUserKey *user_key,
    const PolyLockCiphertext *ciphertext,
    const char *data_cipher_json,
    char **error_out);
char *polylock_decaps_serialized_with_context(
    const PolyLockDecapsulationContext *context,
    const PolyLockUserKey *user_key,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    const char *data_cipher_json,
    char **error_out);
char *polylock_derive_data_key(
    const char *seed_hex,
    const char *aad_hex,
    char **error_out);

char *polylock_system_metadata(const PolyLockSystem *system);
char *polylock_resolved_metadata(const PolyLockResolvedPolicy *resolved);
size_t polylock_ciphertext_serialized_size(const PolyLockCiphertext *ciphertext);
uint8_t *polylock_ciphertext_serialize(
    const PolyLockCiphertext *ciphertext,
    size_t *length_out,
    char **error_out);
PolyLockCiphertext *polylock_ciphertext_deserialize(
    const uint8_t *input,
    size_t length,
    char **error_out);
size_t polylock_user_key_serialized_size(const PolyLockUserKey *user_key);
uint8_t *polylock_user_key_serialize(
    const PolyLockUserKey *user_key,
    size_t *length_out,
    char **error_out);
PolyLockUserKey *polylock_user_key_deserialize(
    const uint8_t *input,
    size_t length,
    char **error_out);

void polylock_system_free(PolyLockSystem *system);
void polylock_decapsulation_context_free(PolyLockDecapsulationContext *context);
void polylock_user_key_free(PolyLockUserKey *user_key);
void polylock_resolved_free(PolyLockResolvedPolicy *resolved);
void polylock_ciphertext_free(PolyLockCiphertext *ciphertext);
void polylock_string_free(char *value);
void polylock_bytes_free(uint8_t *value, size_t length);

#ifdef __cplusplus
}
#endif

#endif
