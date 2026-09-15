// attributeUpdate.go —— 从 IPFS config 读取 PeerID & 私钥，pid=PeerID 进行注册；公私钥写 PEM 并带用户名后缀
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/hash"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
	plintegration "polylock-thesis/go-bridge/integration"
	polylockv2 "polylock-thesis/go-bridge/polylock"
)

/* ---------------- 与链码保持一致的常量 ---------------- */
const (
	AttrNum                = 100
	IntNum                 = AttrNum - 1
	GroupSz                = 253
	TotalNode              = 2*AttrNum - 1 // 满二叉堆大小
	mspID                  = "Org1MSP"
	cryptoPath             = "../../../organizations/peerOrganizations/org1.example.com"
	certPath               = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem"
	keyPath                = cryptoPath + "/users/User1@org1.example.com/msp/keystore/"
	tlsCertPath            = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint           = "peer0.org1.example.com:7051"
	gatewayPeer            = "peer0.org1.example.com"
	chaincodeName          = "acmc"
	channelName            = "mychannel"
	attrPath               = "./zk-guard_attrs.json"
	credentialPathTemplate = "./zk-guard_credential_%s.json"

	// PolyLock prototype parameters. Must be consistent with systemInit/dataStorage/dataRetrieve.
	polyLockLogN            = 10
	polyLockLogQ            = 27
	polyLockMaxActiveAttrs  = 20
	polyLockUSKDir          = "./polylock_state"
	polyLockSystemDir       = "./polylock_state/system"
	systemConfigPath        = polyLockSystemDir + "/system_config.json"
	defaultProfileSpacePath = polyLockSystemDir + "/profile_space.json"
	mp12SimulatedDelay      = 6 * time.Millisecond
)

/* ---------------- 本地 MiMC 承诺（保持一致） ---------------- */
func hashCalc(bits []int) string {
	const LimbBits = 253
	var seg []*big.Int
	for i := 0; i < len(bits); i += LimbBits {
		end := i + LimbBits
		if end > len(bits) {
			end = len(bits)
		}
		val := big.NewInt(0)
		for j := i; j < end; j++ {
			if bits[j] == 1 {
				val.SetBit(val, j-i, 1)
			}
		}
		h := hash.MIMC_BN254.New()
		h.Write(val.Bytes())
		seg = append(seg, new(big.Int).SetBytes(h.Sum(nil)))
	}
	hf := hash.MIMC_BN254.New()
	for _, s := range seg {
		hf.Write(s.Bytes())
	}
	return new(big.Int).SetBytes(hf.Sum(nil)).String()
}

// randomFieldElement generates the user-side randomness r used only by
// zk-Guard's randomized identity binding Reg[pid] = H(w || r).  PolyLock
// roots and profile versions still use the deterministic profile hash H(w).
func randomFieldElement() (*big.Int, error) {
	modulus := ecc.BN254.ScalarField()
	for {
		r, err := crand.Int(crand.Reader, modulus)
		if err != nil {
			return nil, err
		}
		if r.Sign() != 0 {
			return r, nil
		}
	}
}

func fieldElementFixedBytes(x *big.Int) []byte {
	out := make([]byte, 32)
	if x == nil {
		return out
	}
	b := x.Bytes()
	if len(b) > len(out) {
		b = b[len(b)-len(out):]
	}
	copy(out[len(out)-len(b):], b)
	return out
}

type mimcByteWriter interface {
	Write([]byte) (int, error)
}

func writeMiMCFieldElement(h mimcByteWriter, x *big.Int) {
	var e fr.Element
	if x != nil {
		e.SetBigInt(x)
	}
	b := e.Bytes()
	_, _ = h.Write(b[:])
}

// hashCalcUserCommit computes the randomized zk-Guard user-binding commitment
// C_u = H(w || r).  The original hashCalc(w) is intentionally kept unchanged
// for PolyLock profile/root/version semantics.
func hashCalcUserCommit(bits []int, randBI *big.Int) string {
	const LimbBits = 253
	var seg []*big.Int

	for i := 0; i < len(bits); i += LimbBits {
		end := i + LimbBits
		if end > len(bits) {
			end = len(bits)
		}

		val := big.NewInt(0)
		for j := i; j < end; j++ {
			if bits[j] == 1 {
				val.SetBit(val, j-i, 1)
			}
		}

		h := hash.MIMC_BN254.New()
		writeMiMCFieldElement(h, val)
		seg = append(seg, new(big.Int).SetBytes(h.Sum(nil)))
	}

	hf := hash.MIMC_BN254.New()
	for _, ss := range seg {
		writeMiMCFieldElement(hf, ss)
	}
	if randBI == nil {
		randBI = big.NewInt(0)
	}
	writeMiMCFieldElement(hf, randBI)
	return new(big.Int).SetBytes(hf.Sum(nil)).String()
}

func parseCredentialRand(randDec, randB64, source string) (*big.Int, error) {
	if strings.TrimSpace(randDec) != "" {
		r := new(big.Int)
		if _, ok := r.SetString(strings.TrimSpace(randDec), 10); ok && r.Sign() > 0 {
			return r, nil
		}
		return nil, fmt.Errorf("invalid attr_rand in %s", source)
	}
	if strings.TrimSpace(randB64) != "" {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(randB64))
		if err != nil {
			return nil, fmt.Errorf("decode attr_rand_base64 in %s failed: %v", source, err)
		}
		r := new(big.Int).SetBytes(raw)
		if r.Sign() > 0 {
			return r, nil
		}
		return nil, fmt.Errorf("zero attr_rand_base64 in %s", source)
	}
	return nil, fmt.Errorf("missing randomized binding secret r in %s", source)
}

func makeDefaultValidAttrVector() []int {
	bits := make([]int, AttrNum)
	limit := polyLockMaxActiveAttrs
	if limit > AttrNum {
		limit = AttrNum
	}
	for i := 0; i < limit; i++ {
		bits[i] = 1
	}
	return bits
}

func validatePolyLockAttrVector(bits []int) bool {
	if len(bits) != AttrNum {
		return false
	}
	active := 0
	for _, v := range bits {
		if v == 1 {
			active++
		}
	}
	if active > polyLockMaxActiveAttrs {
		return false
	}
	depLimit := 50
	if depLimit > AttrNum {
		depLimit = AttrNum
	}
	for child := 1; child < depLimit; child++ {
		parent := child - 1
		if bits[child] == 1 && bits[parent] == 0 {
			return false
		}
	}
	startIdx := 50
	if startIdx+10 >= AttrNum {
		startIdx = AttrNum / 2
	}
	if startIdx < 0 {
		startIdx = 0
	}
	for i := 0; i < 5; i++ {
		left := startIdx + i*2
		right := startIdx + i*2 + 1
		if right < AttrNum && bits[left] == 1 && bits[right] == 1 {
			return false
		}
	}
	return true
}

func loadCurrentAttrVector() []int {
	raw, err := os.ReadFile(attrPath)
	if err != nil {
		return makeDefaultValidAttrVector()
	}
	var bits []int
	if err := json.Unmarshal(raw, &bits); err != nil || !validatePolyLockAttrVector(bits) {
		return makeDefaultValidAttrVector()
	}
	return bits
}

func makeUpdatedVector(oldVec []int) ([]int, bool) {
	oldHash := hashCalc(oldVec)
	for i := len(oldVec) - 1; i >= 0; i-- {
		candidate := append([]int(nil), oldVec...)
		if candidate[i] == 0 {
			candidate[i] = 1
		} else {
			candidate[i] = 0
		}
		if validatePolyLockAttrVector(candidate) && hashCalc(candidate) != oldHash {
			return candidate, true
		}
	}
	return nil, false
}

/* ---------------- PolyLock local USK refresh ----------------
最小原型说明：
1) zk-Guard 的 Reg[pid] 使用随机化用户承诺 H(w || r) 更新。
2) PolyLock 的版本绑定仍然使用 profileHash=H(w)，而不是 userCommit=H(w||r)。
3) 属性更新时需要同时更新 Reg[pid]，并推进 oldProfileHash 的 profile-level 版本。
4) 后续 dataRetrieve/dataDecrypt 只加载本地 USK，不再执行 KeyGen。
*/

type ZKGuardCredentialDisk struct {
	Format         string `json:"format"`
	Username       string `json:"username"`
	PID            string `json:"pid"`
	AttrNum        int    `json:"attr_num"`
	ProfileHash    string `json:"profile_hash"`
	UserCommit     string `json:"user_commit"`
	AttrRand       string `json:"attr_rand"`
	AttrRandBase64 string `json:"attr_rand_base64"`
	AttrVector     []int  `json:"attr_vector"`
	CreatedAt      string `json:"created_at"`
}

type LocalCredential struct {
	Bits        []int
	Rand        *big.Int
	ProfileHash string
	UserCommit  string
	Source      string
}

func saveZKGuardCredential(username, pid string, bits []int, randBI *big.Int, profileHash, userCommit string) (string, error) {
	cred := ZKGuardCredentialDisk{
		Format:         "zkguard-randomized-credential-v1",
		Username:       username,
		PID:            pid,
		AttrNum:        AttrNum,
		ProfileHash:    profileHash,
		UserCommit:     userCommit,
		AttrRand:       randBI.String(),
		AttrRandBase64: base64.StdEncoding.EncodeToString(fieldElementFixedBytes(randBI)),
		AttrVector:     cloneIntVector(bits),
		CreatedAt:      time.Now().Format(time.RFC3339),
	}
	b, _ := json.MarshalIndent(cred, "", "  ")
	path := fmt.Sprintf(credentialPathTemplate, username)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

type PolyLockUSKDisk struct {
	Format           string `json:"format"`
	Username         string `json:"username"`
	PID              string `json:"pid"`
	AttrNum          int    `json:"attr_num"`
	AttrHash         string `json:"attr_hash"` // profile hash H(w), kept for PolyLock
	UserCommit       string `json:"user_commit"`
	AttrRand         string `json:"attr_rand"`
	AttrRandBase64   string `json:"attr_rand_base64"`
	Version          uint64 `json:"version"`
	VersionedHash    string `json:"versioned_hash"`
	RingLogN         int    `json:"ring_log_n"`
	RingLogQ         int    `json:"ring_log_q"`
	SignatureSBase64 string `json:"signature_s_base64"`
	Encoding         string `json:"encoding"`
	AttrVector       []int  `json:"attr_vector"`
	CreatedAt        string `json:"created_at"`
}

type PolyLockParamsDisk struct {
	Format             string  `json:"format"`
	RingLogN           int     `json:"ring_log_n"`
	RingLogQ           int     `json:"ring_log_q"`
	AttrNum            int     `json:"attr_num"`
	ProfileTotal       int     `json:"profile_total"`
	TargetSigma        float64 `json:"target_sigma"`
	ProfileSpacePath   string  `json:"profile_space_path"`
	ProfileSpaceDigest string  `json:"profile_space_digest"`
	HashMethod         string  `json:"hash_method"`
	KeyGenModel        string  `json:"keygen_model"`
	MP12SimulatedDelay string  `json:"mp12_simulated_delay"`
	UpdatedAt          string  `json:"updated_at"`
}

type SystemConfigDisk struct {
	Format             string  `json:"format"`
	AttrNum            int     `json:"attr_num"`
	U                  int     `json:"U"`
	ProfileTotal       int     `json:"profile_total"`
	SpaceSize          int     `json:"space_size"`
	TargetSigma        float64 `json:"target_sigma"`
	Sigma              float64 `json:"sigma"`
	ProfileSpacePath   string  `json:"profile_space_path"`
	ProfileSpaceDigest string  `json:"profile_space_digest"`
	SpaceDigest        string  `json:"space_digest"`
	CreatedAt          string  `json:"created_at"`
}

func hashCalcVersionedBytes(bits []int, ver uint64) []byte {
	const LimbBits = 253
	var seg []*big.Int
	for i := 0; i < len(bits); i += LimbBits {
		end := i + LimbBits
		if end > len(bits) {
			end = len(bits)
		}
		val := big.NewInt(0)
		for j := i; j < end; j++ {
			if bits[j] == 1 {
				val.SetBit(val, j-i, 1)
			}
		}
		h := hash.MIMC_BN254.New()
		h.Write(val.Bytes())
		seg = append(seg, new(big.Int).SetBytes(h.Sum(nil)))
	}
	hf := hash.MIMC_BN254.New()
	for _, ss := range seg {
		hf.Write(ss.Bytes())
	}
	verBI := new(big.Int).SetUint64(ver)
	hf.Write(verBI.Bytes())
	return hf.Sum(nil)
}

func hashCalcVersioned(bits []int, ver uint64) string {
	return new(big.Int).SetBytes(hashCalcVersionedBytes(bits, ver)).String()
}

func serializePolyCoeffs(p ring.Poly) []byte {
	if len(p.Coeffs) == 0 {
		return nil
	}
	buf := make([]byte, len(p.Coeffs[0])*8)
	for i, c := range p.Coeffs[0] {
		binary.LittleEndian.PutUint64(buf[i*8:(i+1)*8], c)
	}
	return buf
}

func polyLockSimulatedMP12KeyGen(bits []int, ver uint64) (versionedHash string, sigB64 string, elapsed time.Duration, err error) {
	start := time.Now()
	params, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{LogN: polyLockLogN, LogQ: []int{polyLockLogQ}, NTTFlag: true})
	if err != nil {
		return "", "", 0, fmt.Errorf("PolyLock parameter init failed: %v", err)
	}
	r := params.RingQ()
	seed := hashCalcVersionedBytes(bits, ver)
	prng, err := sampling.NewKeyedPRNG(seed)
	if err != nil {
		return "", "", 0, fmt.Errorf("PolyLock PRNG init failed: %v", err)
	}
	tSampler, err := ring.NewTernarySampler(prng, r, ring.Ternary{P: 0.5}, false)
	if err != nil {
		return "", "", 0, fmt.Errorf("PolyLock ternary sampler init failed: %v", err)
	}

	// 与 PolyLock 实验代码保持一致：生成代表性短向量，并转入 NTT/Montgomery 域。
	sigS := tSampler.ReadNew()
	r.MForm(sigS, sigS)
	r.NTT(sigS, sigS)

	// 计入 MP12 SamplePre 的模拟采样成本。
	time.Sleep(mp12SimulatedDelay)

	versionedHash = hashCalcVersioned(bits, ver)
	sigB64 = base64.StdEncoding.EncodeToString(serializePolyCoeffs(sigS))
	return versionedHash, sigB64, time.Since(start), nil
}

func savePolyLockParams(cfg *SystemConfigDisk, profileTotal int) error {
	if err := os.MkdirAll(polyLockUSKDir, 0o755); err != nil {
		return err
	}
	params := map[string]any{
		"format": "zkguard-polylock-params-v2-ring", "security_profile": plintegration.SecurityProfile,
		"ring_degree": 512, "ring_modulus": 12289, "d_max": 4, "decomposition_base": 32, "error_eta": 4,
		"attr_num": AttrNum, "profile_total": profileTotal, "target_sigma": effectiveSigma(cfg),
		"profile_space_path": effectiveProfileSpacePath(cfg), "profile_space_digest": effectiveSpaceDigest(cfg),
		"construction": "audited NTRU trapdoor and compact NTT Ring-LWE polynomial-inner-product lock",
		"updated_at":   time.Now().Format(time.RFC3339),
	}
	b, _ := json.MarshalIndent(params, "", "  ")
	return os.WriteFile(filepath.Join(polyLockUSKDir, "polylock_params.json"), b, 0o644)
}

func savePolyLockUSK(username, pid string, bits []int, profileHash, userCommit string, randBI *big.Int, ver uint64) (string, time.Duration, error) {
	if err := os.MkdirAll(polyLockUSKDir, 0o755); err != nil {
		return "", 0, err
	}
	versionedHash, sigB64, keyTime, err := polyLockSimulatedMP12KeyGen(bits, ver)
	if err != nil {
		return "", 0, err
	}
	usk := PolyLockUSKDisk{
		Format:           "zkguard-polylock-usk-v1",
		Username:         username,
		PID:              pid,
		AttrNum:          AttrNum,
		AttrHash:         profileHash,
		UserCommit:       userCommit,
		AttrRand:         randBI.String(),
		AttrRandBase64:   base64.StdEncoding.EncodeToString(fieldElementFixedBytes(randBI)),
		Version:          ver,
		VersionedHash:    versionedHash,
		RingLogN:         polyLockLogN,
		RingLogQ:         polyLockLogQ,
		SignatureSBase64: sigB64,
		Encoding:         "ring.Poly Coeffs[0], uint64 little-endian, NTT+Montgomery domain",
		AttrVector:       bits,
		CreatedAt:        time.Now().Format(time.RFC3339),
	}
	b, _ := json.MarshalIndent(usk, "", "  ")
	path := filepath.Join(polyLockUSKDir, fmt.Sprintf("polylock_usk_%s.json", username))
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", 0, err
	}
	return path, keyTime, nil
}

func savePolyLockUSKV2(system *polylockv2.System, username, pid string, bits []int, profileHash, userCommit string, randBI *big.Int, ver uint64) (string, time.Duration, error) {
	start := time.Now()
	attributes, err := plintegration.IntBits(bits)
	if err != nil {
		return "", 0, err
	}
	key, err := system.KeyGenVersioned(attributes, ver)
	if err != nil {
		return "", 0, err
	}
	defer key.Close()
	path := filepath.Join(polyLockUSKDir, fmt.Sprintf("polylock_usk_%s.json", username))
	err = plintegration.SaveUserKey(path, plintegration.UserKeyDisk{
		Username: username, PID: pid, AttrNum: AttrNum, AttrHash: profileHash,
		UserCommit: userCommit, AttrRand: randBI.String(),
		AttrRandBase64: base64.StdEncoding.EncodeToString(fieldElementFixedBytes(randBI)),
		Version:        ver, AttrVector: cloneIntVector(bits), CreatedAt: time.Now().Format(time.RFC3339),
	}, key)
	return path, time.Since(start), err
}

func parseVersionBytes(b []byte) uint64 {
	v, ok := new(big.Int).SetString(strings.TrimSpace(string(b)), 10)
	if !ok || v.Sign() < 0 {
		return 0
	}
	return v.Uint64()
}

func effectiveProfileSpacePath(cfg *SystemConfigDisk) string {
	if cfg != nil && strings.TrimSpace(cfg.ProfileSpacePath) != "" {
		return strings.TrimSpace(cfg.ProfileSpacePath)
	}
	return defaultProfileSpacePath
}

func effectiveSpaceDigest(cfg *SystemConfigDisk) string {
	if cfg == nil {
		return ""
	}
	if strings.TrimSpace(cfg.ProfileSpaceDigest) != "" {
		return strings.TrimSpace(cfg.ProfileSpaceDigest)
	}
	return strings.TrimSpace(cfg.SpaceDigest)
}

func effectiveSigma(cfg *SystemConfigDisk) float64 {
	if cfg == nil {
		return 0
	}
	if cfg.TargetSigma > 0 {
		return cfg.TargetSigma
	}
	return cfg.Sigma
}

func effectiveAttrNum(cfg *SystemConfigDisk) int {
	if cfg == nil {
		return AttrNum
	}
	if cfg.AttrNum > 0 {
		return cfg.AttrNum
	}
	if cfg.U > 0 {
		return cfg.U
	}
	return AttrNum
}

func decodeProfileSpace(raw []byte, path string) ([][]int, error) {
	// Backward-compatible format: profile_space.json is directly [][]int.
	var direct [][]int
	if err := json.Unmarshal(raw, &direct); err == nil && len(direct) > 0 {
		return direct, nil
	}

	// Current systemInit format: profile_space.json is a metadata object whose
	// actual vectors are under the "profiles" field. Keep a few alternative
	// field names to tolerate older generated files in this prototype.
	var wrapped struct {
		Profiles     [][]int `json:"profiles"`
		ProfileSpace [][]int `json:"profile_space"`
		Space        [][]int `json:"space"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, fmt.Errorf("parse profile space %s failed: %v", path, err)
	}
	switch {
	case len(wrapped.Profiles) > 0:
		return wrapped.Profiles, nil
	case len(wrapped.ProfileSpace) > 0:
		return wrapped.ProfileSpace, nil
	case len(wrapped.Space) > 0:
		return wrapped.Space, nil
	default:
		return nil, fmt.Errorf("profile space %s contains no attribute vectors", path)
	}
}

func loadSystemProfileSpace() (*SystemConfigDisk, [][]int, error) {
	rawCfg, err := os.ReadFile(systemConfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read system config %s failed: %v; please run systemInit first", systemConfigPath, err)
	}
	var cfg SystemConfigDisk
	if err := json.Unmarshal(rawCfg, &cfg); err != nil {
		return nil, nil, fmt.Errorf("parse system config: %v", err)
	}
	spacePath := effectiveProfileSpacePath(&cfg)
	rawSpace, err := os.ReadFile(spacePath)
	if err != nil {
		return nil, nil, fmt.Errorf("read profile space %s failed: %v", spacePath, err)
	}
	space, err := decodeProfileSpace(rawSpace, spacePath)
	if err != nil {
		return nil, nil, err
	}
	if len(space) == 0 {
		return nil, nil, fmt.Errorf("profile space is empty")
	}
	for i, bits := range space {
		if len(bits) != AttrNum {
			return nil, nil, fmt.Errorf("profile_space[%d] length=%d, expect AttrNum=%d", i, len(bits), AttrNum)
		}
	}
	if n := effectiveAttrNum(&cfg); n != AttrNum {
		return nil, nil, fmt.Errorf("system attr_num=%d but binary AttrNum=%d; rebuild all clients with the same U", n, AttrNum)
	}
	return &cfg, space, nil
}

func cloneIntVector(v []int) []int {
	out := make([]int, len(v))
	copy(out, v)
	return out
}

func attrVectorKey(bits []int) string {
	var b strings.Builder
	b.Grow(len(bits))
	for _, v := range bits {
		if v == 0 {
			b.WriteByte('0')
		} else {
			b.WriteByte('1')
		}
	}
	return b.String()
}

func profileIndexByHash(space [][]int, attrHash string) int {
	for i, bits := range space {
		if hashCalc(bits) == attrHash {
			return i
		}
	}
	return -1
}

func chooseUpdatedVectorFromSpace(space [][]int, oldHash string) ([]int, int, error) {
	oldIdx := profileIndexByHash(space, oldHash)
	if oldIdx < 0 {
		return nil, -1, fmt.Errorf("current attribute hash is not in system profile space S*")
	}
	for off := 1; off < len(space); off++ {
		idx := (oldIdx + off) % len(space)
		candidate := space[idx]
		if hashCalc(candidate) != oldHash {
			return cloneIntVector(candidate), idx, nil
		}
	}
	return nil, -1, fmt.Errorf("cannot find a different legal attribute vector in S*")
}

// chooseRandomUpdatedVectorFromSpace is the experiment path for attribute-update
// benchmarking. It samples one legal profile from S* and only checks that its
// profile hash differs from the current one. This avoids scanning the entire
// admissible profile space during LocalCommitRefresh.
func chooseRandomUpdatedVectorFromSpace(space [][]int, oldHash string) ([]int, string, error) {
	if len(space) == 0 {
		return nil, "", fmt.Errorf("profile space is empty")
	}
	if len(space) == 1 {
		candidate := cloneIntVector(space[0])
		h := hashCalc(candidate)
		if h == oldHash {
			return nil, "", fmt.Errorf("profile space has only the current attribute vector")
		}
		return candidate, h, nil
	}

	max := big.NewInt(int64(len(space)))
	for retry := 0; retry < 32; retry++ {
		n, err := crand.Int(crand.Reader, max)
		if err != nil {
			return nil, "", err
		}
		candidate := cloneIntVector(space[int(n.Int64())])
		h := hashCalc(candidate)
		if h != oldHash {
			return candidate, h, nil
		}
	}

	return nil, "", fmt.Errorf("failed to sample a different legal attribute vector from S* after 32 retries")
}

func loadLocalAttrVector(username string) ([]int, string, error) {
	uskPath := filepath.Join(polyLockUSKDir, fmt.Sprintf("polylock_usk_%s.json", username))
	if raw, err := os.ReadFile(uskPath); err == nil {
		var usk PolyLockUSKDisk
		if err := json.Unmarshal(raw, &usk); err != nil {
			return nil, "", fmt.Errorf("parse %s: %v", uskPath, err)
		}
		if len(usk.AttrVector) != AttrNum {
			return nil, "", fmt.Errorf("USK attr_vector length=%d, expect %d", len(usk.AttrVector), AttrNum)
		}
		if usk.AttrHash != "" && hashCalc(usk.AttrVector) != usk.AttrHash {
			return nil, "", fmt.Errorf("USK attr_hash mismatch: stored=%s computed=%s", usk.AttrHash, hashCalc(usk.AttrVector))
		}
		return cloneIntVector(usk.AttrVector), uskPath, nil
	}

	raw, err := os.ReadFile(attrPath)
	if err != nil {
		return nil, "", fmt.Errorf("read local attribute vector failed: neither USK nor %s exists", attrPath)
	}
	var bits []int
	if err := json.Unmarshal(raw, &bits); err != nil {
		return nil, "", fmt.Errorf("parse %s: %v", attrPath, err)
	}
	if len(bits) != AttrNum {
		return nil, "", fmt.Errorf("local attr vector length=%d, expect %d", len(bits), AttrNum)
	}
	return cloneIntVector(bits), attrPath, nil
}

func loadLocalCredential(username, pid string) (*LocalCredential, error) {
	credPath := fmt.Sprintf(credentialPathTemplate, username)
	if raw, err := os.ReadFile(credPath); err == nil {
		var cred ZKGuardCredentialDisk
		if err := json.Unmarshal(raw, &cred); err != nil {
			return nil, fmt.Errorf("parse %s: %v", credPath, err)
		}
		if cred.PID != "" && cred.PID != pid {
			return nil, fmt.Errorf("%s pid mismatch: file=%s current=%s", credPath, cred.PID, pid)
		}
		if len(cred.AttrVector) != AttrNum {
			return nil, fmt.Errorf("%s attr_vector length=%d, expect %d", credPath, len(cred.AttrVector), AttrNum)
		}
		randBI, err := parseCredentialRand(cred.AttrRand, cred.AttrRandBase64, credPath)
		if err != nil {
			return nil, err
		}
		profileHash := hashCalc(cred.AttrVector)
		if cred.ProfileHash != "" && cred.ProfileHash != profileHash {
			return nil, fmt.Errorf("%s profile_hash mismatch: stored=%s computed=%s", credPath, cred.ProfileHash, profileHash)
		}
		userCommit := hashCalcUserCommit(cred.AttrVector, randBI)
		if cred.UserCommit != "" && cred.UserCommit != userCommit {
			return nil, fmt.Errorf("%s user_commit mismatch: stored=%s computed=%s", credPath, cred.UserCommit, userCommit)
		}
		return &LocalCredential{
			Bits:        cloneIntVector(cred.AttrVector),
			Rand:        randBI,
			ProfileHash: profileHash,
			UserCommit:  userCommit,
			Source:      credPath,
		}, nil
	}

	// Compatibility fallback: the updated systemInit also stores the same
	// randomized zk-Guard fields inside the PolyLock USK file.  Old USK files
	// without attr_rand cannot support Reg[pid]=H(w||r), so fail explicitly.
	uskPath := filepath.Join(polyLockUSKDir, fmt.Sprintf("polylock_usk_%s.json", username))
	if raw, err := os.ReadFile(uskPath); err == nil {
		var usk PolyLockUSKDisk
		if err := json.Unmarshal(raw, &usk); err != nil {
			return nil, fmt.Errorf("parse %s: %v", uskPath, err)
		}
		if len(usk.AttrVector) != AttrNum {
			return nil, fmt.Errorf("USK attr_vector length=%d, expect %d", len(usk.AttrVector), AttrNum)
		}
		randBI, err := parseCredentialRand(usk.AttrRand, usk.AttrRandBase64, uskPath)
		if err != nil {
			return nil, err
		}
		profileHash := hashCalc(usk.AttrVector)
		if usk.AttrHash != "" && usk.AttrHash != profileHash {
			return nil, fmt.Errorf("USK attr_hash mismatch: stored=%s computed=%s", usk.AttrHash, profileHash)
		}
		userCommit := hashCalcUserCommit(usk.AttrVector, randBI)
		if usk.UserCommit != "" && usk.UserCommit != userCommit {
			return nil, fmt.Errorf("USK user_commit mismatch: stored=%s computed=%s", usk.UserCommit, userCommit)
		}
		return &LocalCredential{
			Bits:        cloneIntVector(usk.AttrVector),
			Rand:        randBI,
			ProfileHash: profileHash,
			UserCommit:  userCommit,
			Source:      uskPath,
		}, nil
	}

	return nil, fmt.Errorf("randomized zk-Guard credential not found for %s; please rerun systemInit with Reg[pid]=H(w||r)", username)
}

func queryHashAttr(contract *client.Contract, pid string) (string, error) {
	b, err := contract.EvaluateTransaction("QueryHashAttr", pid)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func queryConfigVersionByHash(contract *client.Contract, attrHash string) (uint64, error) {
	b, err := contract.EvaluateTransaction("QueryConfigVersion", attrHash)
	if err != nil {
		return 0, err
	}
	return parseVersionBytes(b), nil
}

func submitProfileVersionUpdate(contract *client.Contract, oldProfileHash, newProfileHash string) error {
	// PolyLock 前向撤销要求推进 profile-level 版本 VerMap[H(w)]，
	// 不能推进 zk-Guard 的随机化用户承诺 VerMap[H(w||r)]。
	// 该交易不携带 pid，因此不会在同一合约调用中公开 pid -> profileHash 绑定。
	if _, err := contract.SubmitTransaction("ProfileVersionUpdate", oldProfileHash, newProfileHash); err != nil {
		return fmt.Errorf("ProfileVersionUpdate(oldProfileHash=%s, newProfileHash=%s) failed: %v", oldProfileHash, newProfileHash, err)
	}
	fmt.Printf("✓ PolyLock profile version updated: oldProfileHash=%s newProfileHash=%s\n", oldProfileHash, newProfileHash)
	return nil
}

func simulateReKeyUsers(bits []int, ver uint64, n int) (time.Duration, error) {
	if n <= 0 {
		return 0, nil
	}
	start := time.Now()
	for i := 0; i < n; i++ {
		if _, _, _, err := polyLockSimulatedMP12KeyGen(bits, ver); err != nil {
			return time.Since(start), err
		}
	}
	return time.Since(start), nil
}

func reKeyUsersV2(system *polylockv2.System, bits []int, ver uint64, n int) (time.Duration, error) {
	if n <= 0 {
		return 0, nil
	}
	attributes, err := plintegration.IntBits(bits)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	for i := 0; i < n; i++ {
		key, err := system.KeyGenVersioned(attributes, ver)
		if err != nil {
			return time.Since(start), err
		}
		key.Close()
	}
	return time.Since(start), nil
}

/* ---------------- IPFS config 读取与密钥导出 ---------------- */
type ipfsConfig struct {
	Identity struct {
		PeerID  string `json:"PeerID"`
		PrivKey string `json:"PrivKey"` // base64 (protobuf)
	} `json:"Identity"`
}

// 生成 Ed25519 身份并返回 PeerID、libp2p 私钥/公钥、base64 编码的 PrivKey
func genLibp2pIdentity() (peerID string, privB64 string, lpPriv libp2pcrypto.PrivKey, lpPub libp2pcrypto.PubKey, err error) {
	lpPriv, lpPub, err = libp2pcrypto.GenerateEd25519Key(nil)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("GenerateEd25519Key: %v", err)
	}
	id, err := peer.IDFromPublicKey(lpPub)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("IDFromPublicKey: %v", err)
	}
	raw, err := libp2pcrypto.MarshalPrivateKey(lpPriv)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("MarshalPrivateKey: %v", err)
	}
	return id.String(), base64.StdEncoding.EncodeToString(raw), lpPriv, lpPub, nil
}

// 将 Identity 写入 config 路径（仅包含 Identity 段）；必要时创建目录；如果已存在则做 .bak 备份
func writeIPFSIdentityConfig(configPath, peerID, privB64 string) error {
	// 备份已有文件
	if st, err := os.Stat(configPath); err == nil && !st.IsDir() {
		bak := configPath + ".bak." + time.Now().Format("20060102-150405")
		if err := os.Rename(configPath, bak); err != nil {
			return fmt.Errorf("backup existing config: %v", err)
		}
	}

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return fmt.Errorf("mkdir: %v", err)
	}

	var cfg ipfsConfig
	cfg.Identity.PeerID = peerID
	cfg.Identity.PrivKey = privB64
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, b, 0o600); err != nil {
		return fmt.Errorf("write config: %v", err)
	}
	return nil
}

// 读取 IPFS config 并返回 pid(字符串)、libp2p 私钥、公钥（Ed25519）
func loadIPFSIdentity(cfgPath string) (pid string, lpPriv libp2pcrypto.PrivKey, lpPub libp2pcrypto.PubKey, err error) {
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return "", nil, nil, fmt.Errorf("read ipfs config: %v", err)
	}
	var cfg ipfsConfig
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return "", nil, nil, fmt.Errorf("parse ipfs config: %v", err)
	}
	pid = cfg.Identity.PeerID

	// 解码私钥（protobuf-base64）
	privBytes, err := base64.StdEncoding.DecodeString(cfg.Identity.PrivKey)
	if err != nil {
		return "", nil, nil, fmt.Errorf("decode Identity.PrivKey: %v", err)
	}
	lpPriv, err = libp2pcrypto.UnmarshalPrivateKey(privBytes)
	if err != nil {
		return "", nil, nil, fmt.Errorf("unmarshal libp2p private key: %v", err)
	}
	lpPub = lpPriv.GetPublic()

	// 使用 libp2p 公式验证 PeerID
	pidFromPub, err := peer.IDFromPublicKey(lpPub)
	if err != nil {
		return "", nil, nil, fmt.Errorf("peer.IDFromPublicKey: %v", err)
	}
	if pidFromPub.String() != pid {
		// 与你的自测代码保持一致：只输出警告，不中断
		fmt.Printf("[WARN] PeerID mismatch: config=%s, derived=%s\n", pid, pidFromPub.String())
	}
	return pid, lpPriv, lpPub, nil
}

// 将 libp2p Ed25519 公私钥写为 PEM（PKCS#8 / PKIX），文件名带 username
func writePEMKeys(username string, lpPriv libp2pcrypto.PrivKey, lpPub libp2pcrypto.PubKey) (privPath, pubPath string, err error) {
	// 原始 key bytes（Ed25519: priv 64B, pub 32B）
	privRaw, err := lpPriv.Raw()
	if err != nil {
		return "", "", fmt.Errorf("priv.Raw: %v", err)
	}
	pubRaw, err := lpPub.Raw()
	if err != nil {
		return "", "", fmt.Errorf("pub.Raw: %v", err)
	}

	// 转成 Go 标准库类型（与自测程序一致）
	stdPriv := ed25519.PrivateKey(privRaw)
	stdPub := ed25519.PublicKey(pubRaw)

	// 私钥：PKCS#8
	pkcs8, err := x509.MarshalPKCS8PrivateKey(stdPriv)
	if err != nil {
		return "", "", fmt.Errorf("MarshalPKCS8PrivateKey: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	privPath = fmt.Sprintf("./zk-guard_priv_%s.pem", username)
	if err = os.WriteFile(privPath, privPEM, 0600); err != nil {
		return "", "", fmt.Errorf("write %s: %v", privPath, err)
	}

	// 公钥：PKIX (SubjectPublicKeyInfo)
	spki, err := x509.MarshalPKIXPublicKey(stdPub)
	if err != nil {
		return "", "", fmt.Errorf("MarshalPKIXPublicKey: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
	pubPath = fmt.Sprintf("./zk-guard_pub_%s.pem", username)
	if err = os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		return "", "", fmt.Errorf("write %s: %v", pubPath, err)
	}

	return privPath, pubPath, nil
}

/* ---------------------------- main ---------------------------- */

func main() {
	startTotal := time.Now()

	var tLocalCommitRefresh time.Duration
	var tChainUpdate time.Duration
	var tPolyLockKeyGen time.Duration
	var tProfileSpaceLoad time.Duration

	// ============================================================
	// One-time state preparation: load the globally initialized admissible
	// profile space. In a long-running deployment this state is loaded once and
	// retained by the CA, so it is excluded from the online attribute-update
	// stages and reported only as a diagnostic cold-start cost.
	// ============================================================

	// === 1. 参数解析 ===
	// 用法：./attributeUpdate <ipfsConfig> [username] [affectedUserCount]
	// affectedUserCount 表示本次属性更新需要重新 KeyGen 的用户数量，包含被更新用户本人。
	ipfsCfg := "./config_user"
	if len(os.Args) > 1 && os.Args[1] != "" {
		ipfsCfg = os.Args[1]
	}
	username := "ipfs-Alice"
	if len(os.Args) > 2 && os.Args[2] != "" {
		username = os.Args[2]
	}
	affectedUserCount := 10
	if len(os.Args) > 3 && os.Args[3] != "" {
		n, err := strconv.Atoi(os.Args[3])
		if err != nil || n < 1 {
			log.Fatalf("invalid affectedUserCount=%q, expect positive integer", os.Args[3])
		}
		affectedUserCount = n
	}

	// === 2. 加载 systemInit 生成的全局合法属性空间 S* ===
	startProfileSpaceLoad := time.Now()
	cfg, profileSpace, err := loadSystemProfileSpace()
	if err != nil {
		log.Fatalf("load system profile space failed: %v", err)
	}
	tProfileSpaceLoad = time.Since(startProfileSpaceLoad)

	// ============================================================
	// Local phase A: load the current online identity and randomized credential.
	// The one-time profile-space materialization above is deliberately excluded.
	// ============================================================
	startLocal := time.Now()

	// === 3. 从 IPFS config 中读取 pid ===
	pid, _, _, err := loadIPFSIdentity(ipfsCfg)
	if err != nil {
		log.Fatalf("load IPFS identity failed: %v", err)
	}

	// === 4. 加载当前本地随机化凭证 ===
	oldCred, err := loadLocalCredential(username, pid)
	if err != nil {
		log.Fatalf("load local randomized credential failed: %v", err)
	}
	oldBits := oldCred.Bits

	tLocalCommitRefresh += time.Since(startLocal)

	fmt.Printf("System profile space loaded: U=%d |S*|=%d sigma=%.4f digest=%s\n",
		AttrNum, len(profileSpace), effectiveSigma(cfg), effectiveSpaceDigest(cfg))

	// ============================================================
	// Chain phase A: Fabric connection and pre-update chain-state checks.
	// Fabric gateway construction, ledger queries, transaction submission,
	// and post-update ledger verification are counted into ChainAttributeUpdate.
	// ============================================================
	startChain := time.Now()

	// === 5. Fabric 连接 ===
	conn := newGrpcConnection(tlsCertPath, gatewayPeer, peerEndpoint)
	defer conn.Close()
	gw, err := client.Connect(
		newIdentity(certPath, mspID),
		client.WithSign(newSign(keyPath)),
		client.WithClientConnection(conn),
		client.WithEvaluateTimeout(5*time.Second),
	)
	if err != nil {
		log.Fatalf("Gateway 连接失败: %v", err)
	}
	defer gw.Close()
	contract := gw.GetNetwork(channelName).GetContract(chaincodeName)

	// === 6. 与链上 Reg[pid] 和 VerMap[H(w)] 对齐 ===
	chainOldCommit, err := queryHashAttr(contract, pid)
	if err != nil {
		log.Fatalf("QueryHashAttr before update failed: %v", err)
	}
	if chainOldCommit != oldCred.UserCommit {
		log.Fatalf("old userCommit mismatch: local(%s)=%s, chain Reg[%s]=%s", oldCred.Source, oldCred.UserCommit, pid, chainOldCommit)
	}
	oldVersionBefore, err := queryConfigVersionByHash(contract, oldCred.ProfileHash)
	if err != nil {
		log.Fatalf("QueryConfigVersion(oldProfileHash before update) failed: %v", err)
	}

	tChainUpdate += time.Since(startChain)

	// ============================================================
	// Local phase B: select a new legal attribute vector and compute the new
	// profile/user commitments. This is the core local commitment refresh.
	// The experiment path samples from S* and does not scan the whole space.
	// ============================================================
	startLocal = time.Now()

	// === 7. 随机选择新的合法属性向量，并生成新的随机化绑定 r' ===
	newBits, newProfileHash, err := chooseRandomUpdatedVectorFromSpace(profileSpace, oldCred.ProfileHash)
	if err != nil {
		log.Fatalf("choose random updated vector from S* failed: %v", err)
	}
	newRand, err := randomFieldElement()
	if err != nil {
		log.Fatalf("generate new randomized binding secret failed: %v", err)
	}
	newUserCommit := hashCalcUserCommit(newBits, newRand)

	tLocalCommitRefresh += time.Since(startLocal)

	fmt.Println("============== Attribute Update Plan ==============")
	fmt.Printf("PID              : %s\n", pid)
	fmt.Printf("Username         : %s\n", username)
	fmt.Printf("Old profileHash  : %s\n", oldCred.ProfileHash)
	fmt.Printf("Old userCommit   : %s\n", chainOldCommit)
	fmt.Printf("New profileHash  : %s\n", newProfileHash)
	fmt.Printf("New userCommit   : %s\n", newUserCommit)
	fmt.Printf("Old profile version(before): %d\n", oldVersionBefore)
	fmt.Printf("Affected users   : %d\n", affectedUserCount)

	// ============================================================
	// Chain phase B: submit the attribute-update transactions and verify the
	// committed chain state after update.
	// ============================================================
	startChain = time.Now()

	// === 8. 链上属性更新：
	// 8.1 Reg[pid] 更新为随机化承诺 H(new_w || new_r)，用于 zk-Guard 身份绑定隐私；
	// 8.2 ProfileVersionUpdate(oldProfileHash, newProfileHash) 更新 VerMap[H(w)]，用于 PolyLock 前向撤销。
	if _, err = contract.SubmitTransaction("AttributeUpdate", pid, newUserCommit); err != nil {
		log.Fatalf("AttributeUpdate chain transaction failed: %v", err)
	}
	if err = submitProfileVersionUpdate(contract, oldCred.ProfileHash, newProfileHash); err != nil {
		log.Fatalf("PolyLock profile version update failed: %v", err)
	}

	chainNewCommit, err := queryHashAttr(contract, pid)
	if err != nil {
		log.Fatalf("QueryHashAttr after update failed: %v", err)
	}
	if chainNewCommit != newUserCommit {
		log.Fatalf("Reg[pid] not updated correctly: expect %s, got %s", newUserCommit, chainNewCommit)
	}
	oldVersionAfter, err := queryConfigVersionByHash(contract, oldCred.ProfileHash)
	if err != nil {
		log.Fatalf("QueryConfigVersion(oldProfileHash after update) failed: %v", err)
	}
	newVersion, err := queryConfigVersionByHash(contract, newProfileHash)
	if err != nil {
		log.Fatalf("QueryConfigVersion(newProfileHash after update) failed: %v", err)
	}
	if oldCred.ProfileHash != newProfileHash && oldVersionAfter <= oldVersionBefore {
		log.Fatalf("VerMap[oldProfileHash] was not advanced: before=%d after=%d", oldVersionBefore, oldVersionAfter)
	}

	tChainUpdate += time.Since(startChain)

	fmt.Printf("Reg[pid] after        : %s\n", chainNewCommit)
	fmt.Printf("VerMap[oldProfileHash]: %d -> %d\n", oldVersionBefore, oldVersionAfter)
	fmt.Printf("VerMap[newProfileHash]: %d\n", newVersion)

	// ============================================================
	// Local phase C: persist the updated zk-Guard local attribute state and
	// randomized credential after the chain update succeeds.
	// ============================================================
	startLocal = time.Now()

	// === 9. 更新本地 zk-Guard 属性文件 ===
	attrJSON, _ := json.Marshal(newBits)
	if err := os.WriteFile(attrPath, attrJSON, 0o644); err != nil {
		log.Fatalf("write updated zk-guard attribute vector failed: %v", err)
	}
	credPath, err := saveZKGuardCredential(username, pid, newBits, newRand, newProfileHash, newUserCommit)
	if err != nil {
		log.Fatalf("write updated zk-Guard randomized credential failed: %v", err)
	}

	tLocalCommitRefresh += time.Since(startLocal)

	// ============================================================
	// PolyLock phase: refresh data-layer key material. The total phase time is
	// reported as PolyLockKeyGenTotal so that the three stacked metrics cover
	// the whole measured attribute-update path.
	// ============================================================
	startPolyLock := time.Now()
	polySystem, err := plintegration.LoadAuthority(polyLockSystemDir)
	if err != nil {
		log.Fatalf("load PolyLock authority state failed: %v", err)
	}
	defer polySystem.Close()

	// === 10. PolyLock KeyGen：当前用户切换到新属性；其余受影响用户留在 oldHash 下重发新版本 key ===
	if err := savePolyLockParams(cfg, len(profileSpace)); err != nil {
		log.Printf("保存 PolyLock 参数失败: %v", err)
	}

	uskPath, tCurrentKeyGen, err := savePolyLockUSKV2(polySystem, username, pid, newBits, newProfileHash, newUserCommit, newRand, newVersion)
	if err != nil {
		log.Fatalf("PolyLock current-user KeyGen/USK refresh failed: %v", err)
	}

	remainingUsers := affectedUserCount - 1
	tRemainingKeyGen, err := reKeyUsersV2(polySystem, oldBits, oldVersionAfter, remainingUsers)
	if err != nil {
		log.Fatalf("PolyLock remaining-user batch re-key failed: %v", err)
	}

	tPolyLockKeyGen = time.Since(startPolyLock)

	fmt.Printf("✓ zk-Guard randomized credential refreshed: %s\n", credPath)
	fmt.Printf("✓ PolyLock USK refreshed: %s\n", uskPath)
	fmt.Printf("  current user key: profileHash=%s userCommit=%s version=%d\n", newProfileHash, newUserCommit, newVersion)
	if remainingUsers > 0 {
		fmt.Printf("  batch re-key: %d users under old profileHash version=%d\n", remainingUsers, oldVersionAfter)
	}

	tWall := time.Since(startTotal)
	tAttributeUpdate := tLocalCommitRefresh + tChainUpdate + tPolyLockKeyGen
	tWallExcludingProfileSpace := tWall - tProfileSpaceLoad
	if tWallExcludingProfileSpace < 0 {
		tWallExcludingProfileSpace = 0
	}
	fmt.Println("✓ AttributeUpdate 完成")

	fmt.Println("==== ⏱️ 计时 (毫秒) ====")
	fmt.Printf("LocalCommitRefresh   : %.3f ms\n", float64(tLocalCommitRefresh.Microseconds())/1000)
	fmt.Printf("ChainAttributeUpdate : %.3f ms\n", float64(tChainUpdate.Microseconds())/1000)
	fmt.Printf("CurrentUserKeyGen    : %.3f ms\n", float64(tCurrentKeyGen.Microseconds())/1000)
	fmt.Printf("RemainingReKeyUsers  : %d\n", remainingUsers)
	fmt.Printf("RemainingReKeyGen    : %.3f ms\n", float64(tRemainingKeyGen.Microseconds())/1000)
	fmt.Printf("PolyLockKeyGenTotal  : %.3f ms\n", float64(tPolyLockKeyGen.Microseconds())/1000)
	fmt.Printf("AttributeUpdate      : %.3f ms\n", float64(tAttributeUpdate.Microseconds())/1000)
	fmt.Printf("ProfileSpaceLoad(diag): %.3f ms\n", float64(tProfileSpaceLoad.Microseconds())/1000)
	fmt.Printf("AttributeUpdateWallExclProfileSpace: %.3f ms\n", float64(tWallExcludingProfileSpace.Microseconds())/1000)
	fmt.Printf("AttributeUpdateWall  : %.3f ms (diagnostic cold-start wall)\n", float64(tWall.Microseconds())/1000)
	fmt.Printf("ATTRIBUTE_UPDATE_USERS=%d\n", affectedUserCount)
	fmt.Printf("LOCAL_COMMIT_REFRESH_MS=%.3f\n", float64(tLocalCommitRefresh.Microseconds())/1000)
	fmt.Printf("CHAIN_ATTRIBUTE_UPDATE_MS=%.3f\n", float64(tChainUpdate.Microseconds())/1000)
	fmt.Printf("POLYLOCK_KEYGEN_TOTAL_MS=%.3f\n", float64(tPolyLockKeyGen.Microseconds())/1000)
	fmt.Printf("ATTRIBUTE_UPDATE_TOTAL_MS=%.3f\n", float64(tAttributeUpdate.Microseconds())/1000)
	fmt.Printf("PROFILE_SPACE_LOAD_DIAG_MS=%.3f\n", float64(tProfileSpaceLoad.Microseconds())/1000)
	fmt.Printf("ATTRIBUTE_UPDATE_WALL_EXCL_PROFILE_SPACE_MS=%.3f\n", float64(tWallExcludingProfileSpace.Microseconds())/1000)
	fmt.Printf("ATTRIBUTE_UPDATE_WALL_MS=%.3f\n", float64(tWall.Microseconds())/1000)
}

/* ---------------- Fabric helpers（保持原实现） ---------------- */

func newGrpcConnection(_ string, gatewayPeer, peerEndpoint string) *grpc.ClientConn {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	creds := credentials.NewTLS(tlsConfig)
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(120*1024*1024),
			grpc.MaxCallRecvMsgSize(120*1024*1024),
		),
	}
	connection, err := grpc.Dial(peerEndpoint, dialOpts...)
	if err != nil {
		log.Printf("无法创建 gRPC 连接: %v", err)
	}
	return connection
}

func newIdentity(certPath, mspID string) *identity.X509Identity {
	certificate, err := loadCertificate(certPath)
	if err != nil {
		panic(err)
	}
	id, err := identity.NewX509Identity(mspID, certificate)
	if err != nil {
		panic(err)
	}
	return id
}

func newSign(keyPath string) identity.Sign {
	files, err := os.ReadDir(keyPath)
	if err != nil {
		panic(fmt.Errorf("无法读取私钥目录: %w", err))
	}
	if len(files) == 0 {
		panic("未找到私钥文件")
	}
	privateKeyPEM, err := os.ReadFile(filepath.Join(keyPath, files[0].Name()))
	if err != nil {
		panic(fmt.Errorf("无法读取私钥文件: %w", err))
	}
	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		panic(err)
	}
	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		panic(err)
	}
	return sign
}

func loadCertificate(filename string) (*x509.Certificate, error) {
	certificatePEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("无法读取证书文件: %w", err)
	}
	return identity.CertificateFromPEM(certificatePEM)
}

// 压缩为 []byte
func gzipBytes(raw []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return buf.Bytes()
}
