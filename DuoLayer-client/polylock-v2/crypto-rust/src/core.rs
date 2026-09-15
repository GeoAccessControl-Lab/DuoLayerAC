use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use concrete_ntt::prime32::Plan;
use falcon::{
    codec::{modq_decode, trim_i8_decode, MAX_FG_BITS, MAX_FG_BITS_UPPER},
    safe_api::FnDsaKeyPair,
    shake::{i_shake256_flip, i_shake256_init, i_shake256_inject, InnerShake256Context},
    sign::sign_dyn,
    vrfy::complete_private,
};
use hmac::{Hmac, Mac};
use rand::{thread_rng, Rng, RngCore};
use rayon::prelude::*;
use reed_solomon::{Decoder as ReedSolomonDecoder, Encoder as ReedSolomonEncoder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

pub const Q: u32 = 12_289;
const LOG_N_RING100: u32 = 9;
const LOG_N_RING128: u32 = 10;
const KDF_SALT: &[u8] = b"PolyLock-Ring-KEM-v2/HKDF-SHA256";
const KDF_INFO: &[u8] = b"PolyLock/data-key";
pub const SEED_BYTES: usize = 16;
const COEFFICIENT_BITS: usize = 14;
const LOCK_MAGIC: &[u8; 4] = b"PLK3";
const LOCK_VERSION: u8 = 1;
const LOCK_HEADER_BYTES: usize = 25;
const USER_KEY_MAGIC: &[u8; 4] = b"PLK4";
const USER_KEY_VERSION: u8 = 1;
const USER_KEY_HEADER_BYTES: usize = 17;
const PUBLIC_PARAMETER_HEADER_BYTES: usize = 25;
const MASTER_SECRET_HEADER_BYTES: usize = 17;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SetupConfig {
    pub universe_size: usize,
    pub d_max: usize,
    pub max_cardinality: usize,
    #[serde(default)]
    pub dependencies: Vec<[usize; 2]>,
    #[serde(default)]
    pub exclusions: Vec<[usize; 2]>,
    #[serde(default)]
    pub legal_profiles: Vec<Vec<u8>>,
    #[serde(default = "default_security_profile")]
    pub security_profile: String,
    #[serde(default = "default_decomposition_base")]
    pub decomposition_base: u32,
    #[serde(default = "default_error_eta")]
    pub error_eta: u32,
}
fn default_security_profile() -> String {
    "ring128".into()
}
fn default_decomposition_base() -> u32 {
    32
}
fn default_error_eta() -> u32 {
    4
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Policy {
    Attr { index: usize },
    And { children: Vec<Policy> },
    Or { children: Vec<Policy> },
    Threshold { k: usize, children: Vec<Policy> },
}
impl Policy {
    fn evaluate(&self, a: &[u8]) -> bool {
        match self {
            Self::Attr { index } => a.get(*index).copied() == Some(1),
            Self::And { children } => children.iter().all(|p| p.evaluate(a)),
            Self::Or { children } => children.iter().any(|p| p.evaluate(a)),
            Self::Threshold { k, children } => {
                children.iter().filter(|p| p.evaluate(a)).count() >= *k
            }
        }
    }
    fn validate(&self, size: usize) -> bool {
        match self {
            Self::Attr { index } => *index < size,
            Self::And { children } | Self::Or { children } => {
                !children.is_empty() && children.iter().all(|p| p.validate(size))
            }
            Self::Threshold { k, children } => {
                *k > 0 && *k <= children.len() && children.iter().all(|p| p.validate(size))
            }
        }
    }
}

#[derive(Clone)]
struct Constraints {
    universe_size: usize,
    max_cardinality: usize,
    dependencies: Vec<[usize; 2]>,
    exclusions: Vec<[usize; 2]>,
}
impl Constraints {
    fn validate(&self, a: &[u8]) -> bool {
        a.len() == self.universe_size
            && a.iter().all(|x| *x <= 1)
            && a.iter().map(|x| *x as usize).sum::<usize>() <= self.max_cardinality
            && !self
                .dependencies
                .iter()
                .any(|[p, c]| a[*c] == 1 && a[*p] == 0)
            && !self
                .exclusions
                .iter()
                .any(|[l, r]| a[*l] == 1 && a[*r] == 1)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Poly {
    coeffs: Vec<u32>,
}
impl Poly {
    fn zero(n: usize) -> Self {
        Self { coeffs: vec![0; n] }
    }
    fn constant(n: usize, x: u32) -> Self {
        let mut p = Self::zero(n);
        p.coeffs[0] = x % Q;
        p
    }
    fn add_assign(&mut self, r: &Self) {
        for (a, b) in self.coeffs.iter_mut().zip(&r.coeffs) {
            *a = add_q(*a, *b);
        }
    }
    fn sub_assign(&mut self, r: &Self) {
        for (a, b) in self.coeffs.iter_mut().zip(&r.coeffs) {
            *a = sub_q(*a, *b);
        }
    }
    fn scalar_mul(&self, s: u32) -> Self {
        Self {
            coeffs: self.coeffs.iter().map(|x| mul_q(*x, s)).collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct RingRoot {
    constant: u32,
    linear: u32,
}
impl RingRoot {
    fn as_small_poly(self) -> SmallPoly {
        SmallPoly {
            coeffs: vec![self.constant, self.linear],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SmallPoly {
    coeffs: Vec<u32>,
}
impl SmallPoly {
    fn zero() -> Self {
        Self { coeffs: vec![0] }
    }
    fn one() -> Self {
        Self { coeffs: vec![1] }
    }
    fn normalize(&mut self) {
        while self.coeffs.len() > 1 && self.coeffs.last() == Some(&0) {
            self.coeffs.pop();
        }
    }
    fn add_assign(&mut self, other: &Self) {
        self.coeffs
            .resize(self.coeffs.len().max(other.coeffs.len()), 0);
        for (index, value) in other.coeffs.iter().enumerate() {
            self.coeffs[index] = add_q(self.coeffs[index], *value);
        }
        self.normalize();
    }
    fn sub_assign(&mut self, other: &Self) {
        self.coeffs
            .resize(self.coeffs.len().max(other.coeffs.len()), 0);
        for (index, value) in other.coeffs.iter().enumerate() {
            self.coeffs[index] = sub_q(self.coeffs[index], *value);
        }
        self.normalize();
    }
    fn mul(&self, other: &Self) -> Self {
        let mut output = vec![0; self.coeffs.len() + other.coeffs.len() - 1];
        for (left_index, left) in self.coeffs.iter().enumerate() {
            for (right_index, right) in other.coeffs.iter().enumerate() {
                let index = left_index + right_index;
                output[index] = add_q(output[index], mul_q(*left, *right));
            }
        }
        let mut output = Self { coeffs: output };
        output.normalize();
        output
    }
    fn scalar_mul(&self, scalar: u32) -> Self {
        Self {
            coeffs: self
                .coeffs
                .iter()
                .map(|coefficient| mul_q(*coefficient, scalar))
                .collect(),
        }
    }
    fn to_ring_poly(&self, ring_degree: usize) -> Result<Poly, String> {
        if self.coeffs.len() > ring_degree {
            return Err("low-degree predicate polynomial exceeds the ring degree".into());
        }
        let mut output = Poly::zero(ring_degree);
        output.coeffs[..self.coeffs.len()].copy_from_slice(&self.coeffs);
        Ok(output)
    }
}

struct Ring {
    n: usize,
    plan: Plan,
}
impl Ring {
    fn new(n: usize) -> Result<Self, String> {
        Ok(Self {
            n,
            plan: Plan::try_new(n, Q)
                .ok_or_else(|| format!("q={Q} has no {n}-point negacyclic NTT"))?,
        })
    }
    fn mul(&self, a: &Poly, b: &Poly) -> Poly {
        let mut x = a.coeffs.clone();
        let mut y = b.coeffs.clone();
        self.plan.fwd(&mut x);
        self.plan.fwd(&mut y);
        self.plan.mul_assign_normalize(&mut x, &y);
        self.plan.inv(&mut x);
        Poly { coeffs: x }
    }
    fn uniform(&self, rng: &mut impl Rng) -> Poly {
        Poly {
            coeffs: (0..self.n).map(|_| rng.gen_range(0..Q)).collect(),
        }
    }
    fn error(&self, rng: &mut impl Rng, eta: u32) -> Poly {
        // A fixed-low-weight ternary error is used by this NTRU/Ring-LWE
        // profile.  It keeps the convolution with a Falcon short preimage
        // inside the 1-bit decoding radius while retaining nonzero masking.
        let mut out = vec![0u32; self.n];
        let weight = 8 * eta as usize;
        let mut used = HashSet::new();
        while used.len() < weight {
            let i = rng.gen_range(0..self.n);
            if used.insert(i) {
                out[i] = if rng.gen::<bool>() { 1 } else { Q - 1 }
            }
        }
        Poly { coeffs: out }
    }
    fn ternary(&self, rng: &mut impl Rng) -> Vec<i16> {
        (0..self.n).map(|_| rng.gen_range(-1i16..=1)).collect()
    }
    fn from_signed(&self, x: &[i16]) -> Poly {
        Poly {
            coeffs: x.iter().map(|v| signed_to_q(*v as i32)).collect(),
        }
    }
}

struct NtruTrapdoor {
    logn: u32,
    f: Vec<i8>,
    g: Vec<i8>,
    big_f: Vec<i8>,
    big_g: Vec<i8>,
    h: Poly,
}
impl NtruTrapdoor {
    fn generate(logn: u32) -> Result<Self, String> {
        let kp = FnDsaKeyPair::generate(logn)
            .map_err(|e| format!("NTRU trapdoor generation failed: {e:?}"))?;
        let n = 1usize << logn;
        let sk = kp.private_key();
        let pk = kp.public_key();
        let mut off = 1;
        let mut f = vec![0i8; n];
        let mut g = vec![0i8; n];
        let mut big_f = vec![0i8; n];
        for (dst, bits) in [
            (&mut f, MAX_FG_BITS[logn as usize]),
            (&mut g, MAX_FG_BITS[logn as usize]),
            (&mut big_f, MAX_FG_BITS_UPPER[logn as usize]),
        ] {
            let used = trim_i8_decode(dst, logn, bits as u32, &sk[off..]);
            if used == 0 {
                return Err("cannot decode NTRU trapdoor".into());
            }
            off += used;
        }
        let mut big_g = vec![0i8; n];
        let mut tmp = vec![0u8; 8 * n + 16];
        if !complete_private(&mut big_g, &f, &g, &big_f, logn, &mut tmp) {
            return Err("cannot complete NTRU basis".into());
        }
        let mut h = vec![0u16; n];
        if modq_decode(&mut h, logn, &pk[1..]) == 0 {
            return Err("cannot decode NTRU public key".into());
        }
        Ok(Self {
            logn,
            f,
            g,
            big_f,
            big_g,
            h: Poly {
                coeffs: h.into_iter().map(u32::from).collect(),
            },
        })
    }
    fn sample_preimage(&self, target: &Poly, ring: &Ring) -> Result<(Vec<i16>, Vec<i16>), String> {
        let hm: Vec<u16> = target.coeffs.iter().map(|x| *x as u16).collect();
        let mut s2 = vec![0i16; ring.n];
        let need = falcon::falcon::falcon_tmpsize_signdyn(self.logn);
        let mut aligned = vec![0u64; need.div_ceil(8)];
        let tmp = unsafe {
            std::slice::from_raw_parts_mut(aligned.as_mut_ptr() as *mut u8, aligned.len() * 8)
        };
        let mut seed = [0u8; 48];
        thread_rng().fill_bytes(&mut seed);
        let mut rng = InnerShake256Context::new();
        i_shake256_init(&mut rng);
        i_shake256_inject(&mut rng, &seed);
        i_shake256_flip(&mut rng);
        sign_dyn(
            &mut s2,
            &mut rng,
            &self.f,
            &self.g,
            &self.big_f,
            &self.big_g,
            &hm,
            self.logn,
            tmp,
        );
        let s1 = unsafe { std::slice::from_raw_parts(tmp.as_ptr() as *const i16, ring.n) }.to_vec();
        let mut check = ring.from_signed(&s1);
        check.add_assign(&ring.mul(&self.h, &ring.from_signed(&s2)));
        if check != *target {
            return Err("NTRU short-preimage syndrome invariant failed".into());
        }
        Ok((s1, s2))
    }
}

pub struct System {
    config: SetupConfig,
    constraints: Constraints,
    legal_profiles: Vec<Vec<u8>>,
    images: HashMap<Vec<u8>, RingRoot>,
    profile_indices: HashMap<Vec<u8>, usize>,
    ring: Ring,
    trapdoor: Option<NtruTrapdoor>,
    public_h: Poly,
    digits: usize,
    predicate_dimension: usize,
    public_b: Vec<Poly>,
    target_u: Poly,
}
pub struct DecapsulationContext {
    ring: Ring,
}
pub struct UserKey {
    predicate_digits: Vec<Poly>,
    short_preimage: [Vec<i16>; 3],
}
pub struct ResolvedPolicy {
    coefficients: Vec<Vec<SmallPoly>>,
    pub buckets: Vec<Vec<Vec<u8>>>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VersionedProfile {
    pub attributes: Vec<u8>,
    #[serde(default)]
    pub version: u64,
}
#[derive(Clone)]
pub struct BucketCiphertext {
    c0: [Poly; 2],
    c1: Vec<Poly>,
    c2: Poly,
}
enum LockStorage {
    Expanded(Vec<BucketCiphertext>),
    Packed {
        bytes: Vec<u8>,
        ring_degree: usize,
        bucket_count: usize,
        c1_len: usize,
    },
}
#[derive(Clone, Copy)]
struct PackedLockLayout {
    ring_degree: usize,
    bucket_count: usize,
    c1_len: usize,
    bytes_per_bucket: usize,
}
pub struct LockCiphertext {
    storage: LockStorage,
}

impl LockCiphertext {
    pub fn serialized_size(&self) -> usize {
        const HEADER_BYTES: usize = 25;
        match &self.storage {
            LockStorage::Expanded(buckets) => {
                let coefficient_count: usize = buckets
                    .iter()
                    .map(|bucket| (bucket.c0.len() + bucket.c1.len() + 1) * bucket.c2.coeffs.len())
                    .sum();
                HEADER_BYTES + (coefficient_count * COEFFICIENT_BITS).div_ceil(8)
            }
            LockStorage::Packed { bytes, .. } => bytes.len(),
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        let buckets = match &self.storage {
            LockStorage::Expanded(buckets) => buckets,
            LockStorage::Packed { bytes, .. } => return Ok(bytes.clone()),
        };
        let first = buckets.first().ok_or("cannot serialize an empty lock")?;
        let ring_degree = first.c2.coeffs.len();
        let c1_len = first.c1.len();
        if buckets.iter().any(|bucket| {
            bucket.c1.len() != c1_len
                || bucket
                    .c0
                    .iter()
                    .any(|poly| poly.coeffs.len() != ring_degree)
                || bucket
                    .c1
                    .iter()
                    .any(|poly| poly.coeffs.len() != ring_degree)
                || bucket.c2.coeffs.len() != ring_degree
        }) {
            return Err("lock ciphertext has inconsistent polynomial dimensions".into());
        }
        let mut output = Vec::with_capacity(self.serialized_size());
        output.extend_from_slice(LOCK_MAGIC);
        output.push(LOCK_VERSION);
        output.extend_from_slice(&Q.to_le_bytes());
        output.extend_from_slice(&(ring_degree as u32).to_le_bytes());
        output.extend_from_slice(&(buckets.len() as u64).to_le_bytes());
        output.extend_from_slice(&(c1_len as u32).to_le_bytes());
        pack_coefficients(
            buckets.iter().flat_map(|bucket| {
                bucket
                    .c0
                    .iter()
                    .chain(bucket.c1.iter())
                    .chain(std::iter::once(&bucket.c2))
                    .flat_map(|poly| poly.coeffs.iter().copied())
            }),
            &mut output,
        );
        debug_assert_eq!(output.len(), self.serialized_size());
        Ok(output)
    }

    pub fn deserialize(input: &[u8]) -> Result<Self, String> {
        let layout = parse_packed_lock(input)?;
        Ok(Self {
            storage: LockStorage::Packed {
                bytes: input.to_vec(),
                ring_degree: layout.ring_degree,
                bucket_count: layout.bucket_count,
                c1_len: layout.c1_len,
            },
        })
    }

    fn expanded_buckets(&self) -> Result<Vec<BucketCiphertext>, String> {
        match &self.storage {
            LockStorage::Expanded(buckets) => Ok(buckets.clone()),
            LockStorage::Packed {
                bytes,
                ring_degree,
                bucket_count,
                c1_len,
            } => {
                let layout = parse_packed_lock(bytes)?;
                if layout.ring_degree != *ring_degree
                    || layout.bucket_count != *bucket_count
                    || layout.c1_len != *c1_len
                {
                    return Err("packed lock metadata is inconsistent".into());
                }
                let polynomial_count = 3 + layout.c1_len;
                let coefficient_count = polynomial_count * layout.ring_degree;
                let mut buckets = Vec::with_capacity(layout.bucket_count);
                for packed in bytes[LOCK_HEADER_BYTES..].chunks_exact(layout.bytes_per_bucket) {
                    let coefficients = unpack_coefficients(packed, coefficient_count)?;
                    let polynomials = coefficients
                        .chunks_exact(layout.ring_degree)
                        .map(|coeffs| Poly {
                            coeffs: coeffs.to_vec(),
                        })
                        .collect::<Vec<_>>();
                    buckets.push(BucketCiphertext {
                        c0: [polynomials[0].clone(), polynomials[1].clone()],
                        c1: polynomials[2..2 + layout.c1_len].to_vec(),
                        c2: polynomials[2 + layout.c1_len].clone(),
                    });
                }
                Ok(buckets)
            }
        }
    }
}

fn parse_packed_lock(input: &[u8]) -> Result<PackedLockLayout, String> {
    if input.len() < LOCK_HEADER_BYTES || &input[..4] != LOCK_MAGIC {
        return Err("invalid compact-lock header".into());
    }
    if input[4] != LOCK_VERSION {
        return Err("unsupported compact-lock version".into());
    }
    let modulus = u32::from_le_bytes(input[5..9].try_into().unwrap());
    let ring_degree = u32::from_le_bytes(input[9..13].try_into().unwrap()) as usize;
    let bucket_count = u64::from_le_bytes(input[13..21].try_into().unwrap()) as usize;
    let c1_len = u32::from_le_bytes(input[21..25].try_into().unwrap()) as usize;
    if modulus != Q || ring_degree == 0 || bucket_count == 0 || c1_len == 0 {
        return Err("compact-lock parameters are invalid".into());
    }
    let coefficients_per_bucket = (3 + c1_len)
        .checked_mul(ring_degree)
        .ok_or("compact-lock bucket coefficient count overflow")?;
    let bits_per_bucket = coefficients_per_bucket
        .checked_mul(COEFFICIENT_BITS)
        .ok_or("compact-lock bucket bit length overflow")?;
    if bits_per_bucket % 8 != 0 {
        return Err("compact-lock bucket is not byte aligned".into());
    }
    let bytes_per_bucket = bits_per_bucket / 8;
    let expected = LOCK_HEADER_BYTES
        + bucket_count
            .checked_mul(bytes_per_bucket)
            .ok_or("compact-lock byte length overflow")?;
    if input.len() != expected {
        return Err("compact-lock byte length does not match its header".into());
    }
    for packed_bucket in input[LOCK_HEADER_BYTES..].chunks_exact(bytes_per_bucket) {
        // Validate canonical coefficients without retaining an expanded copy
        // of the complete lock.
        let _ = unpack_coefficients(packed_bucket, coefficients_per_bucket)?;
    }
    Ok(PackedLockLayout {
        ring_degree,
        bucket_count,
        c1_len,
        bytes_per_bucket,
    })
}

impl UserKey {
    pub fn serialized_size(&self) -> usize {
        let ring_degree = self
            .short_preimage
            .first()
            .map(Vec::len)
            .unwrap_or_default();
        let predicate_coefficients = self.predicate_digits.len() * ring_degree;
        let short_coefficients: usize = self.short_preimage.iter().map(Vec::len).sum();
        USER_KEY_HEADER_BYTES
            + (predicate_coefficients * COEFFICIENT_BITS).div_ceil(8)
            + short_coefficients * std::mem::size_of::<i16>()
    }

    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        let ring_degree = self
            .short_preimage
            .first()
            .map(Vec::len)
            .ok_or("user key has no short preimage")?;
        if ring_degree == 0
            || self.predicate_digits.is_empty()
            || self
                .predicate_digits
                .iter()
                .any(|poly| poly.coeffs.len() != ring_degree)
            || self
                .short_preimage
                .iter()
                .any(|poly| poly.len() != ring_degree)
        {
            return Err("user key has inconsistent polynomial dimensions".into());
        }
        let mut output = Vec::with_capacity(self.serialized_size());
        output.extend_from_slice(USER_KEY_MAGIC);
        output.push(USER_KEY_VERSION);
        output.extend_from_slice(&(ring_degree as u32).to_le_bytes());
        output.extend_from_slice(&(self.predicate_digits.len() as u32).to_le_bytes());
        output.extend_from_slice(&(self.short_preimage.len() as u32).to_le_bytes());
        pack_coefficients(
            self.predicate_digits
                .iter()
                .flat_map(|poly| poly.coeffs.iter().copied()),
            &mut output,
        );
        for polynomial in &self.short_preimage {
            for coefficient in polynomial {
                output.extend_from_slice(&coefficient.to_le_bytes());
            }
        }
        debug_assert_eq!(output.len(), self.serialized_size());
        Ok(output)
    }

    pub fn deserialize(input: &[u8]) -> Result<Self, String> {
        if input.len() < USER_KEY_HEADER_BYTES || &input[..4] != USER_KEY_MAGIC {
            return Err("invalid user-key header".into());
        }
        if input[4] != USER_KEY_VERSION {
            return Err("unsupported user-key version".into());
        }
        let ring_degree = u32::from_le_bytes(input[5..9].try_into().unwrap()) as usize;
        let predicate_count = u32::from_le_bytes(input[9..13].try_into().unwrap()) as usize;
        let short_count = u32::from_le_bytes(input[13..17].try_into().unwrap()) as usize;
        if ring_degree == 0 || predicate_count == 0 || short_count != 3 {
            return Err("user-key parameters are invalid".into());
        }
        let predicate_coefficients = predicate_count
            .checked_mul(ring_degree)
            .ok_or("user-key predicate coefficient count overflow")?;
        let packed_predicate_bytes = predicate_coefficients
            .checked_mul(COEFFICIENT_BITS)
            .ok_or("user-key predicate bit length overflow")?
            .div_ceil(8);
        let short_bytes = short_count
            .checked_mul(ring_degree)
            .and_then(|count| count.checked_mul(std::mem::size_of::<i16>()))
            .ok_or("user-key short-preimage length overflow")?;
        let expected = USER_KEY_HEADER_BYTES
            .checked_add(packed_predicate_bytes)
            .and_then(|length| length.checked_add(short_bytes))
            .ok_or("user-key byte length overflow")?;
        if input.len() != expected {
            return Err("user-key byte length does not match its header".into());
        }
        let packed_end = USER_KEY_HEADER_BYTES + packed_predicate_bytes;
        let coefficients = unpack_coefficients(
            &input[USER_KEY_HEADER_BYTES..packed_end],
            predicate_coefficients,
        )?;
        let predicate_digits = coefficients
            .chunks_exact(ring_degree)
            .map(|coeffs| Poly {
                coeffs: coeffs.to_vec(),
            })
            .collect();
        let mut cursor = packed_end;
        let mut read_short = || -> Result<Vec<i16>, String> {
            let mut polynomial = Vec::with_capacity(ring_degree);
            for _ in 0..ring_degree {
                let bytes: [u8; 2] = input
                    .get(cursor..cursor + 2)
                    .ok_or("user-key short-preimage stream ended early")?
                    .try_into()
                    .unwrap();
                cursor += 2;
                polynomial.push(i16::from_le_bytes(bytes));
            }
            Ok(polynomial)
        };
        let short_preimage = [read_short()?, read_short()?, read_short()?];
        Ok(Self {
            predicate_digits,
            short_preimage,
        })
    }

    fn ring_degree(&self) -> usize {
        self.short_preimage[0].len()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DataCiphertext {
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    #[serde(default)]
    pub aad_hex: String,
}

#[derive(Serialize)]
pub struct SystemMetadata {
    construction: &'static str,
    security_profile: String,
    security_target_bits: usize,
    universe_size: usize,
    legal_space_size: usize,
    ring_degree: usize,
    ring_modulus: u32,
    root_embedding: &'static str,
    root_capacity: u64,
    exact_low_degree_bound: bool,
    ntt: bool,
    decomposition_base: u32,
    decomposition_digits: usize,
    d_max: usize,
    predicate_dimension: usize,
    kem_seed_bits: usize,
    kem_ecc: String,
    error_distribution: &'static str,
    error_hamming_weight: usize,
    short_preimages_per_user: usize,
    ciphertext_polynomials_per_bucket: usize,
    coefficient_bits: usize,
    public_parameter_bytes: usize,
    master_secret_bytes: usize,
}
#[derive(Serialize)]
pub struct ResolvedMetadata {
    bucket_count: usize,
    bucket_sizes: Vec<usize>,
    coefficient_dimension: usize,
}

#[derive(Serialize, Deserialize)]
struct PublicSystemSnapshot {
    format: String,
    config: SetupConfig,
    legal_profiles: Vec<Vec<u8>>,
    ring_degree: usize,
    public_h: Poly,
    public_b: Vec<Poly>,
    target_u: Poly,
}

#[derive(Serialize, Deserialize)]
struct MasterSecretSnapshot {
    format: String,
    logn: u32,
    f: Vec<i8>,
    g: Vec<i8>,
    big_f: Vec<i8>,
    big_g: Vec<i8>,
}

pub struct ReEncapsulationResult {
    pub ciphertext: LockCiphertext,
    pub refreshed_buckets: usize,
    pub reused_buckets: usize,
}

impl System {
    pub fn setup(config: SetupConfig) -> Result<Self, String> {
        validate_config(&config)?;
        let constraints = Constraints {
            universe_size: config.universe_size,
            max_cardinality: config.max_cardinality,
            dependencies: config.dependencies.clone(),
            exclusions: config.exclusions.clone(),
        };
        let legal_profiles = if config.legal_profiles.is_empty() {
            enumerate(&constraints)?
        } else {
            let mut p = config.legal_profiles.clone();
            if p.iter().any(|x| !constraints.validate(x)) {
                return Err("legal_profiles violates Sigma".into());
            }
            p.sort();
            p.dedup();
            p
        };
        if legal_profiles.is_empty() {
            return Err("Sigma induces an empty legal space".into());
        }
        if legal_profiles.len() as u64 >= Q as u64 * Q as u64 {
            return Err("legal space exceeds the injective a+bX root domain".into());
        }
        let logn = match config.security_profile.as_str() {
            "ring100" => LOG_N_RING100,
            "ring128" => LOG_N_RING128,
            x => return Err(format!("unsupported security profile: {x}")),
        };
        let ring = Ring::new(1usize << logn)?;
        let trapdoor = NtruTrapdoor::generate(logn)?;
        if config.d_max >= ring.n {
            return Err("d_max must be smaller than the ring degree".into());
        }
        let images = build_profile_map(&legal_profiles, ring.n);
        let profile_indices = legal_profiles
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, profile)| (profile, index))
            .collect();
        let predicate_dimension = config.d_max + 1;
        let digits = radix_digits(config.decomposition_base);
        let mut rng = thread_rng();
        let len = predicate_dimension * digits;
        let public_b = (0..len).map(|_| ring.uniform(&mut rng)).collect();
        let target_u = ring.uniform(&mut rng);
        let public_h = trapdoor.h.clone();
        Ok(Self {
            config,
            constraints,
            legal_profiles,
            images,
            profile_indices,
            ring,
            trapdoor: Some(trapdoor),
            public_h,
            digits,
            predicate_dimension,
            public_b,
            target_u,
        })
    }
    pub fn keygen(&self, a: Vec<u8>) -> Result<UserKey, String> {
        if !self.constraints.validate(&a) {
            return Err("attribute profile violates Sigma".into());
        }
        let image = *self
            .images
            .get(&a)
            .ok_or("profile absent from legal space")?;
        self.keygen_for_root(image)
    }

    pub fn keygen_versioned(&self, a: Vec<u8>, version: u64) -> Result<UserKey, String> {
        if !self.constraints.validate(&a) {
            return Err("attribute profile violates Sigma".into());
        }
        let image = self.versioned_root(&a, version)?;
        self.keygen_for_root(image)
    }

    fn keygen_for_root(&self, image: RingRoot) -> Result<UserKey, String> {
        let trapdoor = self
            .trapdoor
            .as_ref()
            .ok_or("master secret is unavailable for KeyGen")?;
        let powers = vandermonde_root(image, self.config.d_max + 1, self.ring.n)?;
        let pd = decompose_polys(
            &powers,
            self.config.decomposition_base,
            self.digits,
            self.ring.n,
        );
        let bv = self.combine_b(&pd);
        let mut rng = thread_rng();
        let r2 = self.ring.ternary(&mut rng);
        let mut target = self.target_u.clone();
        target.sub_assign(&self.ring.mul(&bv, &self.ring.from_signed(&r2)));
        let (r0, r1) = trapdoor.sample_preimage(&target, &self.ring)?;
        let key = UserKey {
            predicate_digits: pd,
            short_preimage: [r0, r1, r2],
        };
        if !self.verify_key(&key) {
            return Err("SampleLeft syndrome invariant failed".into());
        }
        Ok(key)
    }

    fn versioned_root(&self, attributes: &[u8], version: u64) -> Result<RingRoot, String> {
        let index = *self
            .profile_indices
            .get(attributes)
            .ok_or("profile absent from legal space")? as u64;
        let space_size = self.legal_profiles.len() as u64;
        let encoded = version
            .checked_mul(space_size)
            .and_then(|value| value.checked_add(index + 1))
            .ok_or("versioned profile root overflow")?;
        let domain = Q as u64 * Q as u64;
        if encoded >= domain {
            return Err(format!(
                "versioned profile root exceeds R_q linear-root domain: version={version}, space={space_size}"
            ));
        }
        Ok(RingRoot {
            constant: (encoded % Q as u64) as u32,
            linear: (encoded / Q as u64) as u32,
        })
    }
    pub fn preresolve(&self, p: &Policy) -> Result<ResolvedPolicy, String> {
        if !p.validate(self.config.universe_size) {
            return Err("malformed policy".into());
        }
        let mut roots: Vec<(RingRoot, Vec<u8>)> = self
            .legal_profiles
            .iter()
            .filter(|a| p.evaluate(a))
            .map(|a| (self.images[a], a.clone()))
            .collect();
        if roots.is_empty() {
            return Err("policy authorizes no legal profile".into());
        }
        roots.sort_by_key(|(r, a)| (r.constant, r.linear, a.clone()));
        let mut coefficients = Vec::new();
        let mut buckets = Vec::new();
        for chunk in roots.chunks(self.config.d_max) {
            coefficients.push(vanishing_small(
                &chunk.iter().map(|x| x.0).collect::<Vec<_>>(),
                self.config.d_max + 1,
            ));
            buckets.push(chunk.iter().map(|x| x.1.clone()).collect())
        }
        Ok(ResolvedPolicy {
            coefficients,
            buckets,
        })
    }

    pub fn preresolve_versioned_profiles(
        &self,
        profiles: &[VersionedProfile],
    ) -> Result<ResolvedPolicy, String> {
        if profiles.is_empty() {
            return Err("versioned policy authorizes no legal profile".into());
        }
        let mut seen = HashSet::new();
        let mut roots = Vec::with_capacity(profiles.len());
        for profile in profiles {
            if !self.constraints.validate(&profile.attributes)
                || !self.profile_indices.contains_key(&profile.attributes)
            {
                return Err("versioned policy contains a profile outside S_Sigma".into());
            }
            if !seen.insert(profile.attributes.clone()) {
                return Err("versioned policy contains a duplicate profile".into());
            }
            roots.push((
                self.versioned_root(&profile.attributes, profile.version)?,
                profile.attributes.clone(),
            ));
        }
        roots.sort_by_key(|(root, attributes)| (root.constant, root.linear, attributes.clone()));
        let mut coefficients = Vec::new();
        let mut buckets = Vec::new();
        for chunk in roots.chunks(self.config.d_max) {
            coefficients.push(vanishing_small(
                &chunk.iter().map(|entry| entry.0).collect::<Vec<_>>(),
                self.config.d_max + 1,
            ));
            buckets.push(chunk.iter().map(|entry| entry.1.clone()).collect());
        }
        Ok(ResolvedPolicy {
            coefficients,
            buckets,
        })
    }
    pub fn encaps(
        &self,
        r: &ResolvedPolicy,
        seed: &[u8; SEED_BYTES],
    ) -> Result<LockCiphertext, String> {
        let encoded = encode_seed(seed, self.ring.n);
        let buckets = r
            .coefficients
            .par_iter()
            .map(|c| self.encaps_bucket(c, &encoded))
            .collect::<Vec<_>>();
        Ok(LockCiphertext {
            storage: LockStorage::Expanded(buckets.into_iter().collect::<Result<Vec<_>, _>>()?),
        })
    }
    fn encaps_bucket(&self, c: &[SmallPoly], encoded: &Poly) -> Result<BucketCiphertext, String> {
        let mut rng = thread_rng();
        let blind = rng.gen_range(1..Q);
        let w: Vec<_> = c
            .iter()
            .map(|x| x.scalar_mul(blind).to_ring_poly(self.ring.n))
            .collect::<Result<_, _>>()?;
        let s = self.ring.uniform(&mut rng);
        let mut c00 = s.clone();
        c00.add_assign(&self.ring.error(&mut rng, self.config.error_eta));
        let mut c01 = self.ring.mul(&s, &self.public_h);
        c01.add_assign(&self.ring.error(&mut rng, self.config.error_eta));
        let mut c1 = Vec::with_capacity(self.public_b.len());
        for (coord, value) in w.iter().enumerate() {
            let mut power = 1;
            for d in 0..self.digits {
                let i = coord * self.digits + d;
                let mut aug = self.public_b[i].clone();
                aug.add_assign(&value.scalar_mul(power));
                let mut x = self.ring.mul(&s, &aug);
                x.add_assign(&self.ring.error(&mut rng, self.config.error_eta));
                c1.push(x);
                power = mul_q(power, self.config.decomposition_base)
            }
        }
        let mut c2 = self.ring.mul(&s, &self.target_u);
        c2.add_assign(&self.ring.error(&mut rng, self.config.error_eta));
        c2.add_assign(encoded);
        Ok(BucketCiphertext {
            c0: [c00, c01],
            c1,
            c2,
        })
    }
    pub fn decaps(
        &self,
        k: &UserKey,
        ct: &LockCiphertext,
        data: &DataCiphertext,
    ) -> Result<Option<[u8; 32]>, String> {
        decaps_with_ring(&self.ring, k, ct, data)
    }
    fn combine_b(&self, digits: &[Poly]) -> Poly {
        aggregate_ring(&self.public_b, digits, &self.ring)
    }
    fn verify_key(&self, k: &UserKey) -> bool {
        let public = [
            Poly::constant(self.ring.n, 1),
            self.public_h.clone(),
            self.combine_b(&k.predicate_digits),
        ];
        let mut s = Poly::zero(self.ring.n);
        for (a, b) in public.iter().zip(&k.short_preimage) {
            s.add_assign(&self.ring.mul(a, &self.ring.from_signed(b)))
        }
        s == self.target_u
    }
    pub fn metadata(&self) -> SystemMetadata {
        let public_polynomials = 2 + self.public_b.len();
        let public_parameter_bytes = PUBLIC_PARAMETER_HEADER_BYTES
            + (public_polynomials * self.ring.n * COEFFICIENT_BITS).div_ceil(8);
        let master_secret_bytes =
            MASTER_SECRET_HEADER_BYTES + 4 * self.ring.n * std::mem::size_of::<i8>();
        SystemMetadata {
            construction: "compact NTT NTRU/Ring-LWE polynomial-inner-product lock over R_q",
            security_profile: self.config.security_profile.clone(),
            security_target_bits: match self.config.security_profile.as_str() {
                "ring100" => 100,
                "ring128" => 128,
                _ => unreachable!(),
            },
            universe_size: self.config.universe_size,
            legal_space_size: self.legal_profiles.len(),
            ring_degree: self.ring.n,
            ring_modulus: Q,
            root_embedding: "injective a+bX in R_q",
            root_capacity: Q as u64 * Q as u64 - 1,
            exact_low_degree_bound: self.config.d_max < self.ring.n,
            ntt: true,
            decomposition_base: self.config.decomposition_base,
            decomposition_digits: self.digits,
            d_max: self.config.d_max,
            predicate_dimension: self.predicate_dimension,
            kem_seed_bits: 128,
            kem_ecc: format!("RS({},{})", self.ring.n / 8, SEED_BYTES),
            error_distribution: "fixed-weight ternary",
            error_hamming_weight: 8 * self.config.error_eta as usize,
            short_preimages_per_user: 1,
            ciphertext_polynomials_per_bucket: 3 + self.predicate_dimension * self.digits,
            coefficient_bits: COEFFICIENT_BITS,
            public_parameter_bytes,
            master_secret_bytes,
        }
    }

    pub fn serialize_public(&self) -> Result<Vec<u8>, String> {
        let mut config = self.config.clone();
        // The canonical, sorted legal space is stored once below.
        config.legal_profiles.clear();
        serde_json::to_vec(&PublicSystemSnapshot {
            format: "polylock-public-system-v1".into(),
            config,
            legal_profiles: self.legal_profiles.clone(),
            ring_degree: self.ring.n,
            public_h: self.public_h.clone(),
            public_b: self.public_b.clone(),
            target_u: self.target_u.clone(),
        })
        .map_err(|error| format!("serialize public system: {error}"))
    }

    pub fn serialize_master_secret(&self) -> Result<Vec<u8>, String> {
        let trapdoor = self
            .trapdoor
            .as_ref()
            .ok_or("master secret is unavailable")?;
        serde_json::to_vec(&MasterSecretSnapshot {
            format: "polylock-master-secret-v1".into(),
            logn: trapdoor.logn,
            f: trapdoor.f.clone(),
            g: trapdoor.g.clone(),
            big_f: trapdoor.big_f.clone(),
            big_g: trapdoor.big_g.clone(),
        })
        .map_err(|error| format!("serialize master secret: {error}"))
    }

    pub fn deserialize_public(input: &[u8]) -> Result<Self, String> {
        let snapshot: PublicSystemSnapshot = serde_json::from_slice(input)
            .map_err(|error| format!("deserialize public system: {error}"))?;
        if snapshot.format != "polylock-public-system-v1" {
            return Err("unsupported public-system format".into());
        }
        let mut config = snapshot.config;
        config.legal_profiles = snapshot.legal_profiles.clone();
        validate_config(&config)?;
        let constraints = Constraints {
            universe_size: config.universe_size,
            max_cardinality: config.max_cardinality,
            dependencies: config.dependencies.clone(),
            exclusions: config.exclusions.clone(),
        };
        if snapshot.legal_profiles.is_empty()
            || snapshot
                .legal_profiles
                .iter()
                .any(|profile| !constraints.validate(profile))
        {
            return Err("public snapshot contains an invalid legal space".into());
        }
        let expected_degree = match config.security_profile.as_str() {
            "ring100" => 1usize << LOG_N_RING100,
            "ring128" => 1usize << LOG_N_RING128,
            value => return Err(format!("unsupported security profile: {value}")),
        };
        if snapshot.ring_degree != expected_degree
            || snapshot.public_h.coeffs.len() != expected_degree
            || snapshot.target_u.coeffs.len() != expected_degree
            || snapshot
                .public_b
                .iter()
                .any(|poly| poly.coeffs.len() != expected_degree)
        {
            return Err("public snapshot has inconsistent ring dimensions".into());
        }
        let digits = radix_digits(config.decomposition_base);
        let predicate_dimension = config.d_max + 1;
        if snapshot.public_b.len() != digits * predicate_dimension {
            return Err("public snapshot has an inconsistent gadget matrix".into());
        }
        let legal_profiles = snapshot.legal_profiles;
        let images = build_profile_map(&legal_profiles, expected_degree);
        let profile_indices = legal_profiles
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, profile)| (profile, index))
            .collect();
        Ok(Self {
            config,
            constraints,
            legal_profiles,
            images,
            profile_indices,
            ring: Ring::new(expected_degree)?,
            trapdoor: None,
            public_h: snapshot.public_h,
            digits,
            predicate_dimension,
            public_b: snapshot.public_b,
            target_u: snapshot.target_u,
        })
    }

    pub fn deserialize_authority(public: &[u8], master: &[u8]) -> Result<Self, String> {
        let mut system = Self::deserialize_public(public)?;
        let secret: MasterSecretSnapshot = serde_json::from_slice(master)
            .map_err(|error| format!("deserialize master secret: {error}"))?;
        if secret.format != "polylock-master-secret-v1" {
            return Err("unsupported master-secret format".into());
        }
        let expected_logn = system.ring.n.trailing_zeros();
        if secret.logn != expected_logn
            || [&secret.f, &secret.g, &secret.big_f, &secret.big_g]
                .iter()
                .any(|polynomial| polynomial.len() != system.ring.n)
        {
            return Err("master secret has inconsistent ring dimensions".into());
        }
        system.trapdoor = Some(NtruTrapdoor {
            logn: secret.logn,
            f: secret.f,
            g: secret.g,
            big_f: secret.big_f,
            big_g: secret.big_g,
            h: system.public_h.clone(),
        });
        Ok(system)
    }

    pub fn reencaps(
        &self,
        old_resolved: &ResolvedPolicy,
        new_resolved: &ResolvedPolicy,
        old_ciphertext: &LockCiphertext,
        seed: &[u8; SEED_BYTES],
    ) -> Result<ReEncapsulationResult, String> {
        let old_buckets = old_ciphertext.expanded_buckets()?;
        if old_buckets.len() != old_resolved.coefficients.len() {
            return Err("old lock and old resolved policy have different bucket counts".into());
        }
        let mut reusable: HashMap<Vec<Vec<u32>>, Vec<usize>> = HashMap::new();
        for (index, coefficients) in old_resolved.coefficients.iter().enumerate() {
            reusable
                .entry(coefficient_key(coefficients))
                .or_default()
                .push(index);
        }
        let encoded = encode_seed(seed, self.ring.n);
        let mut output = Vec::with_capacity(new_resolved.coefficients.len());
        let mut reused_buckets = 0usize;
        for coefficients in &new_resolved.coefficients {
            let key = coefficient_key(coefficients);
            let reused = reusable.get_mut(&key).and_then(Vec::pop);
            if let Some(index) = reused {
                output.push(old_buckets[index].clone());
                reused_buckets += 1;
            } else {
                output.push(self.encaps_bucket(coefficients, &encoded)?);
            }
        }
        let refreshed_buckets = output.len() - reused_buckets;
        Ok(ReEncapsulationResult {
            ciphertext: LockCiphertext {
                storage: LockStorage::Expanded(output),
            },
            refreshed_buckets,
            reused_buckets,
        })
    }
}

fn coefficient_key(coefficients: &[SmallPoly]) -> Vec<Vec<u32>> {
    coefficients
        .iter()
        .map(|coefficient| coefficient.coeffs.clone())
        .collect()
}

impl DecapsulationContext {
    pub fn new(security_profile: &str) -> Result<Self, String> {
        let ring_degree = match security_profile {
            "ring100" => 1usize << LOG_N_RING100,
            "ring128" => 1usize << LOG_N_RING128,
            value => return Err(format!("unsupported security profile: {value}")),
        };
        Ok(Self {
            ring: Ring::new(ring_degree)?,
        })
    }

    pub fn decaps(
        &self,
        key: &UserKey,
        ciphertext: &LockCiphertext,
        data: &DataCiphertext,
    ) -> Result<Option<[u8; 32]>, String> {
        decaps_with_ring(&self.ring, key, ciphertext, data)
    }

    pub fn decaps_serialized(
        &self,
        key: &UserKey,
        ciphertext: &[u8],
        data: &DataCiphertext,
    ) -> Result<Option<[u8; 32]>, String> {
        decaps_serialized_with_ring(&self.ring, key, ciphertext, data)
    }
}
impl ResolvedPolicy {
    pub fn metadata(&self) -> ResolvedMetadata {
        ResolvedMetadata {
            bucket_count: self.buckets.len(),
            bucket_sizes: self.buckets.iter().map(Vec::len).collect(),
            coefficient_dimension: self.coefficients.first().map(Vec::len).unwrap_or(0),
        }
    }
}

fn validate_config(c: &SetupConfig) -> Result<(), String> {
    if c.universe_size == 0 || c.d_max == 0 {
        return Err("universe_size and d_max must be positive".into());
    }
    if c.max_cardinality > c.universe_size {
        return Err("max_cardinality exceeds universe".into());
    }
    if c.decomposition_base < 2
        || !c.decomposition_base.is_power_of_two()
        || c.decomposition_base > 32
    {
        return Err("decomposition_base must be 2..32 and a power of two".into());
    }
    if c.error_eta == 0 || c.error_eta > 4 {
        return Err("error_eta must be in 1..=4".into());
    }
    for x in c.dependencies.iter().chain(&c.exclusions) {
        if x[0] >= c.universe_size || x[1] >= c.universe_size {
            return Err("constraint index exceeds universe".into());
        }
    }
    Ok(())
}
fn enumerate(c: &Constraints) -> Result<Vec<Vec<u8>>, String> {
    if c.universe_size > 24 {
        return Err("provide legal_profiles when universe_size > 24".into());
    }
    Ok((0u64..1u64 << c.universe_size)
        .map(|m| {
            (0..c.universe_size)
                .map(|i| ((m >> i) & 1) as u8)
                .collect::<Vec<_>>()
        })
        .filter(|a| c.validate(a))
        .collect())
}
fn build_profile_map(p: &[Vec<u8>], _ring_degree: usize) -> HashMap<Vec<u8>, RingRoot> {
    let domain = Q as u64 * Q as u64;
    let mut used = HashSet::new();
    let mut out = HashMap::new();
    for a in p {
        let mut h = Sha256::new();
        h.update(b"PolyLock-H_Fq2-v2");
        h.update((a.len() as u64).to_be_bytes());
        h.update(a);
        let d = h.finalize();
        let mut x = u64::from_be_bytes(d[..8].try_into().unwrap()) % domain;
        while !used.insert(x) {
            x = (x + 1) % domain
        }
        out.insert(
            a.clone(),
            RingRoot {
                constant: (x % Q as u64) as u32,
                linear: (x / Q as u64) as u32,
            },
        );
    }
    out
}
fn vandermonde_root(r: RingRoot, n: usize, ring_degree: usize) -> Result<Vec<Poly>, String> {
    let mut out = Vec::with_capacity(n);
    let root = r.as_small_poly();
    let mut x = SmallPoly::one();
    for _ in 0..n {
        out.push(x.to_ring_poly(ring_degree)?);
        x = x.mul(&root)
    }
    Ok(out)
}
fn vanishing_small(roots: &[RingRoot], n: usize) -> Vec<SmallPoly> {
    let mut c = vec![SmallPoly::one()];
    for r in roots {
        let root = r.as_small_poly();
        let mut d = vec![SmallPoly::zero(); c.len() + 1];
        for (i, x) in c.iter().enumerate() {
            d[i].sub_assign(&x.mul(&root));
            d[i + 1].add_assign(x)
        }
        c = d
    }
    c.resize_with(n, SmallPoly::zero);
    c
}
fn radix_digits(base: u32) -> usize {
    let (mut v, mut d) = (1u64, 0);
    while v < Q as u64 {
        v *= base as u64;
        d += 1
    }
    d
}
fn decompose(v: &[u32], base: u32, digits: usize) -> Vec<u32> {
    let mut o = Vec::with_capacity(v.len() * digits);
    for x in v {
        let mut r = *x;
        for _ in 0..digits {
            o.push(r % base);
            r /= base
        }
    }
    o
}
fn decompose_polys(v: &[Poly], base: u32, digits: usize, n: usize) -> Vec<Poly> {
    let mut out = Vec::with_capacity(v.len() * digits);
    for x in v {
        let mut limbs = vec![Poly::zero(n); digits];
        for (i, coefficient) in x.coeffs.iter().enumerate() {
            let ds = decompose(&[*coefficient], base, digits);
            for (digit, value) in ds.into_iter().enumerate() {
                limbs[digit].coeffs[i] = value;
            }
        }
        out.extend(limbs);
    }
    out
}
fn aggregate_ring(c: &[Poly], d: &[Poly], ring: &Ring) -> Poly {
    let mut out = Poly::zero(ring.n);
    for (cipher, digit) in c.iter().zip(d) {
        out.add_assign(&ring.mul(cipher, digit));
    }
    out
}
fn decaps_with_ring(
    ring: &Ring,
    key: &UserKey,
    ciphertext: &LockCiphertext,
    data: &DataCiphertext,
) -> Result<Option<[u8; 32]>, String> {
    if key.ring_degree() != ring.n
        || key
            .short_preimage
            .iter()
            .any(|polynomial| polynomial.len() != ring.n)
    {
        return Err("user key, ciphertext and ring dimensions are inconsistent".into());
    }
    let (nonce, encrypted_data, aad) = decode_data_fields(data)?;
    match &ciphertext.storage {
        LockStorage::Expanded(buckets) => {
            if buckets.iter().any(|bucket| {
                bucket.c1.len() != key.predicate_digits.len()
                    || bucket.c0.iter().any(|poly| poly.coeffs.len() != ring.n)
                    || bucket.c1.iter().any(|poly| poly.coeffs.len() != ring.n)
                    || bucket.c2.coeffs.len() != ring.n
            }) {
                return Err("user key, ciphertext and ring dimensions are inconsistent".into());
            }
            Ok(buckets.par_iter().find_map_any(|bucket| {
                decaps_bucket(ring, key, bucket, &nonce, &encrypted_data, &aad)
            }))
        }
        LockStorage::Packed {
            bytes,
            ring_degree,
            bucket_count,
            c1_len,
        } => {
            let bytes_per_bucket = (3 + *c1_len) * *ring_degree * COEFFICIENT_BITS / 8;
            decaps_packed_buckets(
                ring,
                key,
                bytes,
                PackedLockLayout {
                    ring_degree: *ring_degree,
                    bucket_count: *bucket_count,
                    c1_len: *c1_len,
                    bytes_per_bucket,
                },
                &nonce,
                &encrypted_data,
                &aad,
            )
        }
    }
}

fn decaps_serialized_with_ring(
    ring: &Ring,
    key: &UserKey,
    ciphertext: &[u8],
    data: &DataCiphertext,
) -> Result<Option<[u8; 32]>, String> {
    if key.ring_degree() != ring.n
        || key
            .short_preimage
            .iter()
            .any(|polynomial| polynomial.len() != ring.n)
    {
        return Err("user key, ciphertext and ring dimensions are inconsistent".into());
    }
    let layout = parse_packed_lock(ciphertext)?;
    let (nonce, encrypted_data, aad) = decode_data_fields(data)?;
    decaps_packed_buckets(ring, key, ciphertext, layout, &nonce, &encrypted_data, &aad)
}

fn decode_data_fields(data: &DataCiphertext) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let nonce = hex::decode(&data.nonce_hex).map_err(|error| error.to_string())?;
    if nonce.len() != 12 {
        return Err("AES-GCM nonce must be 12 bytes".into());
    }
    let encrypted_data = hex::decode(&data.ciphertext_hex).map_err(|error| error.to_string())?;
    let aad = hex::decode(&data.aad_hex).map_err(|error| error.to_string())?;
    Ok((nonce, encrypted_data, aad))
}

fn decaps_packed_buckets(
    ring: &Ring,
    key: &UserKey,
    bytes: &[u8],
    layout: PackedLockLayout,
    nonce: &[u8],
    encrypted_data: &[u8],
    aad: &[u8],
) -> Result<Option<[u8; 32]>, String> {
    if layout.ring_degree != ring.n || layout.c1_len != key.predicate_digits.len() {
        return Err("user key, ciphertext and ring dimensions are inconsistent".into());
    }
    Ok((0..layout.bucket_count)
        .into_par_iter()
        .find_map_any(|index| {
            let start = LOCK_HEADER_BYTES + index * layout.bytes_per_bucket;
            let end = start + layout.bytes_per_bucket;
            let bucket =
                decode_packed_bucket(bytes.get(start..end)?, layout.ring_degree, layout.c1_len)
                    .ok()?;
            decaps_bucket(ring, key, &bucket, nonce, encrypted_data, aad)
        }))
}

fn decode_packed_bucket(
    input: &[u8],
    ring_degree: usize,
    c1_len: usize,
) -> Result<BucketCiphertext, String> {
    let coefficient_count = (3 + c1_len)
        .checked_mul(ring_degree)
        .ok_or("compact-lock bucket coefficient count overflow")?;
    let coefficients = unpack_coefficients(input, coefficient_count)?;
    let mut chunks = coefficients.chunks_exact(ring_degree);
    let mut next_poly = || -> Result<Poly, String> {
        Ok(Poly {
            coeffs: chunks
                .next()
                .ok_or("compact-lock bucket ended early")?
                .to_vec(),
        })
    };
    let c0 = [next_poly()?, next_poly()?];
    let mut c1 = Vec::with_capacity(c1_len);
    for _ in 0..c1_len {
        c1.push(next_poly()?);
    }
    let c2 = next_poly()?;
    if !chunks.remainder().is_empty() {
        return Err("compact-lock bucket has trailing coefficients".into());
    }
    Ok(BucketCiphertext { c0, c1, c2 })
}

fn decaps_bucket(
    ring: &Ring,
    key: &UserKey,
    bucket: &BucketCiphertext,
    nonce: &[u8],
    encrypted_data: &[u8],
    aad: &[u8],
) -> Option<[u8; 32]> {
    let cv = aggregate_ring(&bucket.c1, &key.predicate_digits, ring);
    let terms = [&bucket.c0[0], &bucket.c0[1], &cv];
    let mut main = Poly::zero(ring.n);
    for (value, preimage) in terms.into_iter().zip(&key.short_preimage) {
        main.add_assign(&ring.mul(value, &ring.from_signed(preimage)))
    }
    let mut residual = bucket.c2.clone();
    residual.sub_assign(&main);
    if !looks_rs_decodable(&residual) {
        return None;
    }
    let seed = decode_seed(&residual)?;
    let data_key = derive_data_key(&seed, aad);
    let cipher = Aes256Gcm::new_from_slice(&data_key).ok()?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: encrypted_data,
                aad,
            },
        )
        .ok()
        .map(|_| data_key)
}
fn pack_coefficients(values: impl Iterator<Item = u32>, output: &mut Vec<u8>) {
    let mut accumulator = 0u64;
    let mut available = 0usize;
    for value in values {
        debug_assert!(value < Q && value < (1 << COEFFICIENT_BITS));
        accumulator |= (value as u64) << available;
        available += COEFFICIENT_BITS;
        while available >= 8 {
            output.push(accumulator as u8);
            accumulator >>= 8;
            available -= 8;
        }
    }
    if available != 0 {
        output.push(accumulator as u8);
    }
}
fn unpack_coefficients(input: &[u8], count: usize) -> Result<Vec<u32>, String> {
    let mut output = Vec::with_capacity(count);
    let mut accumulator = 0u64;
    let mut available = 0usize;
    let mut cursor = 0usize;
    while output.len() < count {
        while available < COEFFICIENT_BITS {
            let byte = *input
                .get(cursor)
                .ok_or("compact-lock coefficient stream ended early")?;
            accumulator |= (byte as u64) << available;
            available += 8;
            cursor += 1;
        }
        let value = (accumulator & ((1u64 << COEFFICIENT_BITS) - 1)) as u32;
        if value >= Q {
            return Err("compact-lock contains a non-canonical coefficient".into());
        }
        output.push(value);
        accumulator >>= COEFFICIENT_BITS;
        available -= COEFFICIENT_BITS;
    }
    if available != 0 && accumulator != 0 {
        return Err("compact-lock has nonzero padding bits".into());
    }
    if input[cursor..].iter().any(|byte| *byte != 0) {
        return Err("compact-lock has trailing nonzero bytes".into());
    }
    Ok(output)
}
fn encode_seed(seed: &[u8; SEED_BYTES], n: usize) -> Poly {
    let codeword_bytes = n / 8;
    debug_assert!(n % 8 == 0 && codeword_bytes > SEED_BYTES && codeword_bytes < 256);
    let encoder = ReedSolomonEncoder::new(codeword_bytes - SEED_BYTES);
    let codeword = encoder.encode(seed);
    let mut p = Poly::zero(n);
    for i in 0..n {
        let v = if (codeword[i / 8] >> (i % 8)) & 1 == 1 {
            Q / 2
        } else {
            0
        };
        p.coeffs[i] = v;
    }
    p
}
fn decode_seed(p: &Poly) -> Option<[u8; SEED_BYTES]> {
    if p.coeffs.len() % 8 != 0 {
        return None;
    }
    let codeword_bytes = p.coeffs.len() / 8;
    if codeword_bytes <= SEED_BYTES || codeword_bytes >= 256 {
        return None;
    }
    let mut codeword = vec![0u8; codeword_bytes];
    for i in 0..p.coeffs.len() {
        if circular_distance(p.coeffs[i], Q / 2) < circular_distance(p.coeffs[i], 0) {
            codeword[i / 8] |= 1 << (i % 8);
        }
    }
    let decoder = ReedSolomonDecoder::new(codeword_bytes - SEED_BYTES);
    let recovered = decoder.correct(&mut codeword, None).ok()?;
    recovered.data().try_into().ok()
}

fn looks_rs_decodable(p: &Poly) -> bool {
    // A valid residual is concentrated around the two message cosets 0 and
    // floor(q/2). A non-orthogonal bucket is statistically spread over R_q.
    // The prefilter only avoids expensive RS decoding; AEAD authentication
    // remains the final acceptance condition.
    let radius = Q / 8;
    let close = p
        .coeffs
        .iter()
        .filter(|value| {
            circular_distance(**value, 0) <= radius || circular_distance(**value, Q / 2) <= radius
        })
        .count();
    close * 5 >= p.coeffs.len() * 3
}
pub fn derive_data_key(seed: &[u8; SEED_BYTES], aad: &[u8]) -> [u8; 32] {
    let mut e = <HmacSha256 as Mac>::new_from_slice(KDF_SALT).unwrap();
    e.update(seed);
    let prk = e.finalize().into_bytes();
    let mut x = <HmacSha256 as Mac>::new_from_slice(&prk).unwrap();
    x.update(KDF_INFO);
    x.update(&(aad.len() as u64).to_be_bytes());
    x.update(aad);
    x.update(&[1]);
    x.finalize().into_bytes().into()
}
fn add_q(a: u32, b: u32) -> u32 {
    ((a as u64 + b as u64) % Q as u64) as u32
}
fn sub_q(a: u32, b: u32) -> u32 {
    ((a as u64 + Q as u64 - b as u64) % Q as u64) as u32
}
fn mul_q(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % Q as u64) as u32
}
fn signed_to_q(x: i32) -> u32 {
    x.rem_euclid(Q as i32) as u32
}
fn circular_distance(a: u32, b: u32) -> u32 {
    let d = a.abs_diff(b);
    d.min(Q - d)
}

#[cfg(test)]
pub fn encrypt_for_test(seed: &[u8; SEED_BYTES], plaintext: &[u8], aad: &[u8]) -> DataCiphertext {
    let key = derive_data_key(seed, aad);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce: [u8; 12] = thread_rng().gen();
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .unwrap();
    DataCiphertext {
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ct),
        aad_hex: hex::encode(aad),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn system_with_profile(error_eta: u32, security_profile: &str) -> System {
        System::setup(SetupConfig {
            universe_size: 4,
            d_max: 2,
            max_cardinality: 3,
            dependencies: vec![[0, 1]],
            exclusions: vec![[2, 3]],
            legal_profiles: vec![],
            security_profile: security_profile.into(),
            decomposition_base: 32,
            error_eta,
        })
        .unwrap()
    }
    fn system_with_error(error_eta: u32) -> System {
        system_with_profile(error_eta, "ring100")
    }
    fn system() -> System {
        system_with_error(4)
    }
    #[test]
    fn ntt_mul() {
        let r = Ring::new(512).unwrap();
        let mut a = Poly::zero(512);
        let mut b = Poly::zero(512);
        a.coeffs[0] = 3;
        a.coeffs[511] = 2;
        b.coeffs[0] = 5;
        b.coeffs[1] = 7;
        let c = r.mul(&a, &b);
        assert_eq!(c.coeffs[0], sub_q(15, 14));
        assert_eq!(c.coeffs[1], 21);
        assert_eq!(c.coeffs[511], 10)
    }
    #[test]
    fn ring_polynomial_roots() {
        let ring = Ring::new(512).unwrap();
        let roots = [
            RingRoot {
                constant: 17,
                linear: 9,
            },
            RingRoot {
                constant: 41,
                linear: 3,
            },
        ];
        let c = vanishing_small(&roots, 3);
        for r in roots {
            let powers = vandermonde_root(r, 3, ring.n).unwrap();
            let mut value = Poly::zero(ring.n);
            for (coefficient, power) in c.iter().zip(powers) {
                value.add_assign(&ring.mul(&coefficient.to_ring_poly(ring.n).unwrap(), &power));
            }
            assert_eq!(value, Poly::zero(ring.n))
        }
    }
    #[test]
    fn short_preimage() {
        let s = system();
        let k = s.keygen(vec![1, 0, 1, 0]).unwrap();
        assert!(s.verify_key(&k))
    }
    #[test]
    fn end_to_end() {
        let s = system();
        let p = Policy::And {
            children: vec![Policy::Attr { index: 0 }, Policy::Attr { index: 2 }],
        };
        let r = s.preresolve(&p).unwrap();
        let ka = s.keygen(vec![1, 0, 1, 0]).unwrap();
        let ku = s.keygen(vec![1, 1, 0, 0]).unwrap();
        let seed: [u8; SEED_BYTES] = thread_rng().gen();
        let aad = b"cid:test";
        let data = encrypt_for_test(&seed, b"object", aad);
        let ct = s.encaps(&r, &seed).unwrap();
        assert_eq!(
            s.decaps(&ka, &ct, &data).unwrap(),
            Some(derive_data_key(&seed, aad))
        );
        assert_eq!(s.decaps(&ku, &ct, &data).unwrap(), None)
    }
    #[test]
    fn ring128_end_to_end() {
        let s = system_with_profile(4, "ring128");
        let p = Policy::And {
            children: vec![Policy::Attr { index: 0 }, Policy::Attr { index: 2 }],
        };
        let r = s.preresolve(&p).unwrap();
        let k = s.keygen(vec![1, 0, 1, 0]).unwrap();
        let seed: [u8; SEED_BYTES] = thread_rng().gen();
        let aad = b"cid:ring128";
        let data = encrypt_for_test(&seed, b"object", aad);
        let ct = s.encaps(&r, &seed).unwrap();
        assert_eq!(
            s.decaps(&k, &ct, &data).unwrap(),
            Some(derive_data_key(&seed, aad))
        )
    }
    #[test]
    fn compact_lock_serialization_roundtrip() {
        let s = system();
        let p = Policy::And {
            children: vec![Policy::Attr { index: 0 }, Policy::Attr { index: 2 }],
        };
        let resolved = s.preresolve(&p).unwrap();
        let key = s.keygen(vec![1, 0, 1, 0]).unwrap();
        let seed: [u8; SEED_BYTES] = thread_rng().gen();
        let aad = b"cid:packed-lock";
        let data = encrypt_for_test(&seed, b"object", aad);
        let lock = s.encaps(&resolved, &seed).unwrap();
        let bytes = lock.serialize().unwrap();
        assert_eq!(bytes.len(), lock.serialized_size());
        let recovered_lock = LockCiphertext::deserialize(&bytes).unwrap();
        assert_eq!(
            s.decaps(&key, &recovered_lock, &data).unwrap(),
            Some(derive_data_key(&seed, aad))
        );
        let context = DecapsulationContext::new("ring100").unwrap();
        assert_eq!(
            context.decaps_serialized(&key, &bytes, &data).unwrap(),
            Some(derive_data_key(&seed, aad))
        );
    }

    #[test]
    fn user_key_serialization_roundtrip() {
        let s = system();
        let p = Policy::And {
            children: vec![Policy::Attr { index: 0 }, Policy::Attr { index: 2 }],
        };
        let resolved = s.preresolve(&p).unwrap();
        let key = s.keygen(vec![1, 0, 1, 0]).unwrap();
        let encoded_key = key.serialize().unwrap();
        assert_eq!(encoded_key.len(), key.serialized_size());
        let recovered_key = UserKey::deserialize(&encoded_key).unwrap();
        let seed: [u8; SEED_BYTES] = thread_rng().gen();
        let aad = b"cid:packed-user-key";
        let data = encrypt_for_test(&seed, b"object", aad);
        let lock = s.encaps(&resolved, &seed).unwrap();
        assert_eq!(
            s.decaps(&recovered_key, &lock, &data).unwrap(),
            Some(derive_data_key(&seed, aad))
        );
        let context = DecapsulationContext::new("ring100").unwrap();
        assert_eq!(
            context.decaps(&recovered_key, &lock, &data).unwrap(),
            Some(derive_data_key(&seed, aad))
        );
    }
    #[test]
    fn versioned_profiles_and_persistent_system_roundtrip() {
        let authority = system();
        let attributes = vec![1, 0, 1, 0];
        let public_bytes = authority.serialize_public().unwrap();
        let master_bytes = authority.serialize_master_secret().unwrap();
        let public = System::deserialize_public(&public_bytes).unwrap();
        let authority = System::deserialize_authority(&public_bytes, &master_bytes).unwrap();
        let resolved = public
            .preresolve_versioned_profiles(&[VersionedProfile {
                attributes: attributes.clone(),
                version: 3,
            }])
            .unwrap();
        let current_key = authority.keygen_versioned(attributes.clone(), 3).unwrap();
        let stale_key = authority.keygen_versioned(attributes, 2).unwrap();
        let seed: [u8; SEED_BYTES] = thread_rng().gen();
        let aad = b"cid:versioned";
        let data = encrypt_for_test(&seed, b"object", aad);
        let ciphertext = public.encaps(&resolved, &seed).unwrap();
        assert_eq!(
            public.decaps(&current_key, &ciphertext, &data).unwrap(),
            Some(derive_data_key(&seed, aad))
        );
        assert_eq!(public.decaps(&stale_key, &ciphertext, &data).unwrap(), None);
    }

    #[test]
    fn local_reencapsulation_reuses_unchanged_buckets() {
        let system = system();
        let profiles = system
            .legal_profiles
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>();
        let old_profiles = profiles[..4]
            .iter()
            .cloned()
            .map(|attributes| VersionedProfile {
                attributes,
                version: 0,
            })
            .collect::<Vec<_>>();
        let new_profiles = [
            profiles[0].clone(),
            profiles[1].clone(),
            profiles[2].clone(),
            profiles[4].clone(),
        ]
        .into_iter()
        .map(|attributes| VersionedProfile {
            attributes,
            version: 0,
        })
        .collect::<Vec<_>>();
        let old_resolved = system.preresolve_versioned_profiles(&old_profiles).unwrap();
        let new_resolved = system.preresolve_versioned_profiles(&new_profiles).unwrap();
        let seed: [u8; SEED_BYTES] = thread_rng().gen();
        let aad = b"cid:local-reencaps";
        let data = encrypt_for_test(&seed, b"object", aad);
        let old_ciphertext = system.encaps(&old_resolved, &seed).unwrap();
        let updated = system
            .reencaps(&old_resolved, &new_resolved, &old_ciphertext, &seed)
            .unwrap();
        assert!(updated.reused_buckets > 0);
        assert!(updated.refreshed_buckets > 0);
        let retained_key = system.keygen_versioned(profiles[0].clone(), 0).unwrap();
        let added_key = system.keygen_versioned(profiles[4].clone(), 0).unwrap();
        let removed_key = system.keygen_versioned(profiles[3].clone(), 0).unwrap();
        let expected = Some(derive_data_key(&seed, aad));
        assert_eq!(
            system
                .decaps(&retained_key, &updated.ciphertext, &data)
                .unwrap(),
            expected
        );
        assert_eq!(
            system
                .decaps(&added_key, &updated.ciphertext, &data)
                .unwrap(),
            expected
        );
        assert_eq!(
            system
                .decaps(&removed_key, &updated.ciphertext, &data)
                .unwrap(),
            None
        );
    }
    #[test]
    fn all_profiles() {
        let s = system();
        let p = Policy::Or {
            children: vec![
                Policy::And {
                    children: vec![Policy::Attr { index: 0 }, Policy::Attr { index: 2 }],
                },
                Policy::And {
                    children: vec![Policy::Attr { index: 1 }, Policy::Attr { index: 3 }],
                },
            ],
        };
        let r = s.preresolve(&p).unwrap();
        let seed: [u8; SEED_BYTES] = thread_rng().gen();
        let aad = b"cid:all";
        let data = encrypt_for_test(&seed, b"object", aad);
        let ct = s.encaps(&r, &seed).unwrap();
        let expected = derive_data_key(&seed, aad);
        for a in &s.legal_profiles {
            let k = s.keygen(a.clone()).unwrap();
            assert_eq!(
                p.evaluate(a),
                s.decaps(&k, &ct, &data).unwrap() == Some(expected),
                "{a:?}"
            )
        }
    }
    #[test]
    fn all_profiles_compact_dmax4() {
        let s = System::setup(SetupConfig {
            universe_size: 6,
            d_max: 4,
            max_cardinality: 6,
            dependencies: vec![],
            exclusions: vec![],
            legal_profiles: vec![],
            security_profile: "ring100".into(),
            decomposition_base: 32,
            error_eta: 4,
        })
        .unwrap();
        let policy = Policy::Attr { index: 0 };
        let resolved = s.preresolve(&policy).unwrap();
        let seed: [u8; SEED_BYTES] = thread_rng().gen();
        let aad = b"cid:dmax4-all-profiles";
        let data = encrypt_for_test(&seed, b"object", aad);
        let ciphertext = s.encaps(&resolved, &seed).unwrap();
        let expected = derive_data_key(&seed, aad);
        for attributes in &s.legal_profiles {
            let key = s.keygen(attributes.clone()).unwrap();
            assert_eq!(
                policy.evaluate(attributes),
                s.decaps(&key, &ciphertext, &data).unwrap() == Some(expected),
                "{attributes:?}"
            );
        }
    }
    #[test]
    fn stronger_sparse_error_repeated() {
        for error_eta in 2..=4 {
            for _ in 0..100 {
                let s = system_with_error(error_eta);
                let p = Policy::And {
                    children: vec![Policy::Attr { index: 0 }, Policy::Attr { index: 2 }],
                };
                let r = s.preresolve(&p).unwrap();
                let k = s.keygen(vec![1, 0, 1, 0]).unwrap();
                let seed: [u8; SEED_BYTES] = thread_rng().gen();
                let aad = b"cid:stronger-error";
                let data = encrypt_for_test(&seed, b"object", aad);
                let ct = s.encaps(&r, &seed).unwrap();
                assert_eq!(
                    s.decaps(&k, &ct, &data).unwrap(),
                    Some(derive_data_key(&seed, aad)),
                    "error_eta={error_eta}"
                )
            }
        }
    }
}
