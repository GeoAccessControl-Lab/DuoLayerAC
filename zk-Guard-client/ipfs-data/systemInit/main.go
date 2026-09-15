// register_pid.go —— 从 IPFS config 读取 PeerID & 私钥，pid=PeerID 进行注册；公私钥写 PEM 并带用户名后缀
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	mrand "math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	plintegration "polylock-thesis/go-bridge/integration"
	polylockv2 "polylock-thesis/go-bridge/polylock"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

/* ---------------- 与链码保持一致的常量 ---------------- */
const (
	AttrNum                = 100
	IntNum                 = AttrNum - 1
	GroupSz                = 253
	TotalNode              = 2*AttrNum - 1 // 满二叉堆大小
	mspID                  = "Org2MSP"
	cryptoPath             = "../../../organizations/peerOrganizations/org2.example.com"
	certPath               = cryptoPath + "/users/User1@org2.example.com/msp/signcerts/User1@org2.example.com-cert.pem"
	keyPath                = cryptoPath + "/users/User1@org2.example.com/msp/keystore/"
	tlsCertPath            = cryptoPath + "/peers/peer0.org2.example.com/tls/ca.crt"
	peerEndpoint           = "peer0.org2.example.com:9051"
	gatewayPeer            = "peer0.org2.example.com"
	chaincodeName          = "acmc"
	channelName            = "mychannel"
	attrPath               = "./zk-guard_attrs.json"
	credentialPathTemplate = "./zk-guard_credential_%s.json"

	// PolyLock prototype parameters. These must be kept consistent with the
	// PolyLock data encryption/decryption code used by dataStorage/dataDecrypt.
	polyLockLogN           = 10
	polyLockLogQ           = 27
	polyLockMaxActiveAttrs = 20
	polyLockProfileTotal   = 1000
	polyLockTargetSigma    = 0.90
	polyLockProfileSeed    = int64(2024051701)
	polyLockUSKDir         = "./polylock_state"
	polyLockSystemDir      = "./polylock_state/system"
	mp12SimulatedDelay     = 6 * time.Millisecond
)

/* ---------------- 子电路：仅用于计算单次 MiMC 约束计数（包括一次断言） ---------------- */

type MiMCCore struct {
	In frontend.Variable `gnark:",secret"`
	//Out frontend.Variable `gnark:",public"`
}

func (c *MiMCCore) Define(api frontend.API) error {
	h, _ := mimc.NewMiMC(api)
	h.Write(c.In)
	_ = h.Sum()
	return nil
}

func compileMiMCCore() (constraint.ConstraintSystem, error) {
	var sub MiMCCore
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &sub)
}

/* ---------------- 主电路 ---------------- */
type Circuit struct {
	X      [AttrNum]frontend.Variable `gnark:",secret"`
	Rand   frontend.Variable          `gnark:",secret"`
	Hash   frontend.Variable          `gnark:",public"`
	Flag   [AttrNum]frontend.Variable `gnark:",public"`
	SelAnd [IntNum]frontend.Variable  `gnark:",public"`
	SelOr  [IntNum]frontend.Variable  `gnark:",public"`
	SelNop [IntNum]frontend.Variable  `gnark:",public"`
}

func (c *Circuit) Define(api frontend.API) error {
	for i := 0; i < AttrNum; i++ {
		api.AssertIsBoolean(c.Flag[i])
		api.AssertIsBoolean(c.X[i])
	}
	for i := 0; i < IntNum; i++ {
		a, o, n := c.SelAnd[i], c.SelOr[i], c.SelNop[i]
		api.AssertIsBoolean(a)
		api.AssertIsBoolean(o)
		api.AssertIsBoolean(n)
		api.AssertIsEqual(api.Add(api.Add(a, o), n), 1)
	}

	const LimbBits = 253
	pow2 := make([]*big.Int, LimbBits)
	for k := 0; k < LimbBits; k++ {
		pow2[k] = new(big.Int).Lsh(big.NewInt(1), uint(k))
	}

	var grp []frontend.Variable
	for i := 0; i < AttrNum; i += LimbBits {
		end := i + LimbBits
		if end > AttrNum {
			end = AttrNum
		}
		acc := frontend.Variable(0)
		for j := i; j < end; j++ {
			term := api.Mul(c.X[j], pow2[j-i])
			acc = api.Add(acc, term)
		}
		h, _ := mimc.NewMiMC(api)
		h.Write(acc)
		grp = append(grp, h.Sum())
	}
	hf, _ := mimc.NewMiMC(api)
	for _, g := range grp {
		hf.Write(g)
	}
	// Randomized user binding commitment: Reg[pid] = H(w || r).
	// The attribute vector w is still used by the policy predicate, while r
	// prevents dictionary matching over the public admissible space S*.
	hf.Write(c.Rand)
	api.AssertIsEqual(c.Hash, hf.Sum())

	node := make([]frontend.Variable, TotalNode)
	for i := 0; i < AttrNum; i++ {
		node[IntNum+i] = api.Mul(c.Flag[i], c.X[i])
	}
	for i := IntNum - 1; i >= 0; i-- {
		l, r := node[2*i+1], node[2*i+2]
		andV := api.Mul(l, r)
		orV := api.Sub(api.Add(l, r), andV)
		nopV := l
		a, o, n := c.SelAnd[i], c.SelOr[i], c.SelNop[i]
		node[i] = api.Add(api.Add(api.Mul(a, andV), api.Mul(o, orV)), api.Mul(n, nopV))
	}
	api.AssertIsEqual(node[0], 1)
	return nil
}

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

// randomFieldElement returns a high-entropy field element used as the user-side
// binding randomness r in Reg[pid] = H(w || r). It is not used by PolyLock.
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
// C_u = H(w || r).  This value replaces the old deterministic Reg[pid]=H(w)
// registration value.  The original hashCalc(w) is intentionally kept for
// PolyLock profile/version semantics.
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

/* ---------------- PolyLock/zk-Guard 统一系统空间 S* ---------------- */

// SystemConstraints defines the admissible profile space S* used by the
// prototype. In the dissertation model, CA only registers vectors satisfying
// these constraints; therefore zk-Guard users are implicitly restricted to S*.
type SystemConstraints struct {
	DependencyMap map[int]int `json:"dependency_map"`
	SoDPairs      [][2]int    `json:"sod_pairs"`
	MaxCard       int         `json:"max_card"`
}

type SystemProfileSpaceDisk struct {
	Format       string            `json:"format"`
	AttrNum      int               `json:"attr_num"`
	ProfileTotal int               `json:"profile_total"`
	TargetSigma  float64           `json:"target_sigma"`
	Seed         int64             `json:"seed"`
	Constraints  SystemConstraints `json:"constraints"`
	Profiles     [][]int           `json:"profiles"`
	SpaceDigest  string            `json:"space_digest"`
	CreatedAt    string            `json:"created_at"`
}

type SystemConfigDisk struct {
	Format           string            `json:"format"`
	AttrNum          int               `json:"attr_num"`
	ProfileTotal     int               `json:"profile_total"`
	TargetSigma      float64           `json:"target_sigma"`
	Seed             int64             `json:"seed"`
	Constraints      SystemConstraints `json:"constraints"`
	ProfileSpacePath string            `json:"profile_space_path"`
	SpaceDigest      string            `json:"space_digest"`
	CreatedAt        string            `json:"created_at"`
}

func buildSystemConstraints() SystemConstraints {
	constraints := SystemConstraints{
		DependencyMap: make(map[int]int),
		SoDPairs:      make([][2]int, 0),
		MaxCard:       polyLockMaxActiveAttrs,
	}

	depLimit := 50
	if depLimit > AttrNum {
		depLimit = AttrNum
	}
	for child := 1; child < depLimit; child++ {
		constraints.DependencyMap[child] = child - 1
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
		if right < AttrNum {
			constraints.SoDPairs = append(constraints.SoDPairs, [2]int{left, right})
		}
	}
	return constraints
}

func validateAttributesInternal(bits []int, constraints SystemConstraints) bool {
	if len(bits) != AttrNum {
		return false
	}
	active := 0
	for _, v := range bits {
		if v == 1 {
			active++
		}
	}
	if active > constraints.MaxCard {
		return false
	}
	for child, parent := range constraints.DependencyMap {
		if child >= 0 && child < AttrNum && parent >= 0 && parent < AttrNum && bits[child] == 1 && bits[parent] == 0 {
			return false
		}
	}
	for _, pair := range constraints.SoDPairs {
		left, right := pair[0], pair[1]
		if left >= 0 && left < AttrNum && right >= 0 && right < AttrNum && bits[left] == 1 && bits[right] == 1 {
			return false
		}
	}
	return true
}

func attrVectorKey(bits []int) string {
	buf := make([]byte, len(bits))
	for i, v := range bits {
		if v == 0 {
			buf[i] = '0'
		} else {
			buf[i] = '1'
		}
	}
	return string(buf)
}

func addProfile(space *[][]int, seen map[string]bool, bits []int, constraints SystemConstraints) {
	if !validateAttributesInternal(bits, constraints) {
		return
	}
	key := attrVectorKey(bits)
	if seen[key] {
		return
	}
	cp := append([]int(nil), bits...)
	seen[key] = true
	*space = append(*space, cp)
}

func generateAdmissibleProfileSpace(constraints SystemConstraints, target int, seed int64) ([][]int, error) {
	if target <= 0 {
		return nil, fmt.Errorf("profile target must be positive")
	}
	space := make([][]int, 0, target)
	seen := make(map[string]bool)
	addProfile(&space, seen, makeDefaultValidAttrVector(), constraints)

	rnd := mrand.New(mrand.NewSource(seed))
	maxAttempts := target * 1000
	for attempts := 0; len(space) < target && attempts < maxAttempts; attempts++ {
		bits := make([]int, AttrNum)
		initialCount := rnd.Intn(constraints.MaxCard) + 1
		for k := 0; k < initialCount; k++ {
			bits[rnd.Intn(AttrNum)] = 1
		}

		changed := true
		for changed {
			changed = false
			for child, parent := range constraints.DependencyMap {
				if bits[child] == 1 && bits[parent] == 0 {
					bits[parent] = 1
					changed = true
				}
			}
		}

		for _, pair := range constraints.SoDPairs {
			left, right := pair[0], pair[1]
			if bits[left] == 1 && bits[right] == 1 {
				if rnd.Intn(2) == 0 {
					bits[left] = 0
				} else {
					bits[right] = 0
				}
			}
		}

		addProfile(&space, seen, bits, constraints)
	}
	if len(space) < target {
		return nil, fmt.Errorf("only generated %d admissible profiles, target=%d", len(space), target)
	}
	return space, nil
}

func digestProfileSpace(space [][]int) string {
	b, _ := json.Marshal(space)
	d := sha256.Sum256(b)
	return fmt.Sprintf("%x", d[:])
}

func saveSystemProfileSpace(space [][]int, constraints SystemConstraints) (string, string, error) {
	if err := os.MkdirAll(polyLockSystemDir, 0o755); err != nil {
		return "", "", err
	}
	digest := digestProfileSpace(space)
	profilePath := filepath.Join(polyLockSystemDir, "profile_space.json")
	profileDisk := SystemProfileSpaceDisk{
		Format:       "zkguard-polylock-profile-space-v1",
		AttrNum:      AttrNum,
		ProfileTotal: len(space),
		TargetSigma:  polyLockTargetSigma,
		Seed:         polyLockProfileSeed,
		Constraints:  constraints,
		Profiles:     space,
		SpaceDigest:  digest,
		CreatedAt:    time.Now().Format(time.RFC3339),
	}
	b, _ := json.MarshalIndent(profileDisk, "", "  ")
	if err := os.WriteFile(profilePath, b, 0o644); err != nil {
		return "", "", err
	}

	configPath := filepath.Join(polyLockSystemDir, "system_config.json")
	configDisk := SystemConfigDisk{
		Format:           "zkguard-polylock-system-config-v1",
		AttrNum:          AttrNum,
		ProfileTotal:     len(space),
		TargetSigma:      polyLockTargetSigma,
		Seed:             polyLockProfileSeed,
		Constraints:      constraints,
		ProfileSpacePath: profilePath,
		SpaceDigest:      digest,
		CreatedAt:        time.Now().Format(time.RFC3339),
	}
	b, _ = json.MarshalIndent(configDisk, "", "  ")
	if err := os.WriteFile(configPath, b, 0o644); err != nil {
		return "", "", err
	}
	return profilePath, digest, nil
}

/* ---------------- zk-Guard 本地随机化属性凭证 ---------------- */

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
		AttrVector:     append([]int(nil), bits...),
		CreatedAt:      time.Now().Format(time.RFC3339),
	}
	b, _ := json.MarshalIndent(cred, "", "  ")
	path := fmt.Sprintf(credentialPathTemplate, username)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

/* ---------------- PolyLock 用户密钥生成（systemInit 阶段） ----------------

最小原型说明：
1) zk-Guard 与 PolyLock 使用同一个属性向量 bits 和同一个 hashCalc(w)。
2) 版本号来自链上 VerMap[hashCalc(w)]，保证与链码版本绑定逻辑一致。
3) 当前系统原型采用与 PolyLock 实验代码一致的 MP12 SamplePre 模拟方式：
   由 H(w, ver) 的版本绑定种子确定一个代表性短向量，并计入 MP12 采样延迟。
4) 生成的 USK 保存到本地，后续 dataDecrypt 只加载本地 USK，不再执行 KeyGen。
*/

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
	for _, s := range seg {
		hf.Write(s.Bytes())
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
	params, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN:    polyLockLogN,
		LogQ:    []int{polyLockLogQ},
		NTTFlag: true,
	})
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
	s := tSampler.ReadNew()
	r.MForm(s, s)
	r.NTT(s, s)

	// 计入 MP12 SamplePre 的模拟采样成本。
	time.Sleep(mp12SimulatedDelay)

	versionedHash = hashCalcVersioned(bits, ver)
	sigB64 = base64.StdEncoding.EncodeToString(serializePolyCoeffs(s))
	return versionedHash, sigB64, time.Since(start), nil
}

func savePolyLockParams(profilePath, profileDigest string) error {
	if err := os.MkdirAll(polyLockUSKDir, 0o755); err != nil {
		return err
	}
	params := map[string]any{
		"format": "zkguard-polylock-params-v2-ring", "security_profile": plintegration.SecurityProfile,
		"ring_degree": 512, "ring_modulus": 12289, "d_max": 4, "decomposition_base": 32, "error_eta": 4,
		"attr_num": AttrNum, "profile_total": polyLockProfileTotal, "target_sigma": polyLockTargetSigma,
		"profile_space_path": profilePath, "profile_space_digest": profileDigest,
		"construction": "audited NTRU trapdoor and compact NTT Ring-LWE polynomial-inner-product lock",
		"created_at":   time.Now().Format(time.RFC3339),
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
		Username:       username,
		PID:            pid,
		AttrNum:        AttrNum,
		AttrHash:       profileHash,
		UserCommit:     userCommit,
		AttrRand:       randBI.String(),
		AttrRandBase64: base64.StdEncoding.EncodeToString(fieldElementFixedBytes(randBI)),
		Version:        ver,
		AttrVector:     append([]int(nil), bits...),
		CreatedAt:      time.Now().Format(time.RFC3339),
	}, key)
	return path, time.Since(start), err
}

/* ---------------- 基础打印（v0.14 公开 API） ---------------- */

func printConstraintBasics(cs constraint.ConstraintSystem) {
	fmt.Printf("\n============== Constraint Basics (gnark v0.14) ==============\n")
	fmt.Printf("Total Constraints : %d\n", cs.GetNbConstraints())
	// 注：以下三个方法在 v0.14 的 R1CS 上是公开的；若你本地小版本没有，可注释掉。
	fmt.Printf("Public Vars       : %d\n", cs.GetNbPublicVariables())
	fmt.Printf("Secret Vars       : %d\n", cs.GetNbSecretVariables())
	fmt.Printf("Internal Vars     : %d\n", cs.GetNbInternalVariables())
	fmt.Printf("================================================================\n")
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
	// === 0. 先编译一次“MiMCOnly 子电路”，得到单次 MiMC 的约束数 ===
	coreCS, err := compileMiMCCore()
	if err != nil {
		log.Fatalf("MiMC-core Compile 失败: %v", err)
	}
	mimcCore := coreCS.GetNbConstraints()

	startTotal := time.Now()
	// === 1. 编译主电路（保留你的统计/演示逻辑） ===
	var uni Circuit
	startCircuitGen := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &uni)
	if err != nil {
		log.Fatalf("主电路 Compile 失败: %v", err)
	}
	tCircuitGen := time.Since(startCircuitGen)
	//printConstraintBasics(ccs)
	// === 1.1 粗分 MiMC 与非 MiMC（同一实现/版本口径） ===
	total := ccs.GetNbConstraints()

	// 你的电路里 MiMC 调用了两次
	G := (AttrNum + GroupSz - 1) / GroupSz
	mimcTotal := (G+1)*mimcCore + 1
	nonMiMC := total - mimcTotal
	fmt.Printf("MiMC constraints        : %d\n", mimcTotal)
	//fmt.Printf("MiMC (2 calls)     : %d\n", mimcTotal)
	fmt.Printf("Non-MiMC constraints    : %d\n", nonMiMC)
	fmt.Printf("===============================================================\n")

	// === 2. Setup ===
	startUniSetup := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalf("Setup 失败: %v", err)
	}
	tUniSetup := time.Since(startUniSetup)

	var ccsBuf, pkBuf, vkBuf bytes.Buffer
	_, _ = ccs.WriteTo(&ccsBuf)
	_, _ = pk.WriteRawTo(&pkBuf)
	_, _ = vk.WriteRawTo(&vkBuf)

	pkC := gzipBytes(pkBuf.Bytes())
	vkC := gzipBytes(vkBuf.Bytes())
	ccsC := gzipBytes(ccsBuf.Bytes())

	// === 3. Fabric 连接 ===
	conn := newGrpcConnection(tlsCertPath, gatewayPeer, peerEndpoint)
	defer conn.Close()
	gw, err := client.Connect(
		newIdentity(certPath, mspID),
		client.WithSign(newSign(keyPath)),
		client.WithClientConnection(conn),
		client.WithEvaluateTimeout(5*time.Second),
	)
	if err != nil {
		log.Printf("Gateway 连接失败: %v", err)
	}
	defer gw.Close()
	contract := gw.GetNetwork(channelName).GetContract(chaincodeName)

	// === 4. UniSetup ===
	if _, err = contract.SubmitTransaction(
		"UniSetup",
		string(pkC),
		string(vkC),
		string(ccsC),
	); err != nil {
		log.Printf("UniversalSetup 失败: %v", err)
	}
	tUniversalSetup := time.Since(startTotal)
	fmt.Println("✓ UniversalSetup 完成")

	// === 4.1 PolyLock Setup: 生成统一合法属性空间 S* ===
	// 这是后续 dataStorage / policyUpdate 的共同实验空间。CA 只从该空间中
	// 注册用户属性向量，因此 zk-Guard 与 PolyLock 共享同一组合法属性承诺。
	startProfileSpace := time.Now()
	constraints := buildSystemConstraints()
	profileSpace, err := generateAdmissibleProfileSpace(constraints, polyLockProfileTotal, polyLockProfileSeed)
	if err != nil {
		log.Fatalf("生成合法属性空间失败: %v", err)
	}
	profilePath, profileDigest, err := saveSystemProfileSpace(profileSpace, constraints)
	if err != nil {
		log.Fatalf("保存合法属性空间失败: %v", err)
	}
	legalProfiles := make([][]int, len(profileSpace))
	for i := range profileSpace {
		legalProfiles[i] = append([]int(nil), profileSpace[i]...)
	}
	dependencies := make([][2]int, 0, len(constraints.DependencyMap))
	for child, parent := range constraints.DependencyMap {
		dependencies = append(dependencies, [2]int{parent, child})
	}
	polySystem, err := plintegration.SetupAndSave(plintegration.SetupConfig{
		UniverseSize:      AttrNum,
		DMax:              4,
		MaxCardinality:    constraints.MaxCard,
		Dependencies:      dependencies,
		Exclusions:        append([][2]int(nil), constraints.SoDPairs...),
		LegalProfiles:     legalProfiles,
		SecurityProfile:   plintegration.SecurityProfile,
		DecompositionBase: 32,
		ErrorEta:          4,
	}, polyLockSystemDir)
	if err != nil {
		log.Fatalf("PolyLock Setup failed: %v", err)
	}
	defer polySystem.Close()
	tProfileSpace := time.Since(startProfileSpace)
	fmt.Printf("✓ PolyLock admissible profile space S* generated\n")
	fmt.Printf("  U=%d |S|=%d targetSigma=%.2f\n", AttrNum, len(profileSpace), polyLockTargetSigma)
	fmt.Printf("  Constraints: Dep=%d SoD=%d MaxCard=%d\n", len(constraints.DependencyMap), len(constraints.SoDPairs), constraints.MaxCard)
	fmt.Printf("  ProfileSpacePath: %s\n", profilePath)
	fmt.Printf("  ProfileSpaceDigest: %s\n", profileDigest)

	// === 5. 用户生成peerID（公钥）和私钥或者从config文件中读取 ===
	// 参数：
	//   argv[1] = username （例如 Alice）
	//   argv[2] = ipfs config 路径（可选；若省略或空，则自动生成 Identity 并写入默认 ~/.ipfs/config）
	username := "user"
	if len(os.Args) > 1 && os.Args[1] != "" {
		username = os.Args[1]
	}
	ipfsCfg := fmt.Sprintf("./config_%s", username)
	var cfgProvided bool
	if len(os.Args) > 2 && os.Args[2] != "" {
		ipfsCfg = os.Args[2]
		cfgProvided = true
	}

	var (
		pid    string
		lpPriv libp2pcrypto.PrivKey
		lpPub  libp2pcrypto.PubKey
		//gerr    error
	)
	if !cfgProvided {
		// 生成
		genPID, genPrivB64, genPriv, genPub, gerr := genLibp2pIdentity()
		if gerr != nil {
			log.Fatalf("generate identity failed: %v", gerr)
		}
		// 写入 ~/.ipfs/config（仅 Identity 段，字段名与 IPFS 一致）
		if err := writeIPFSIdentityConfig(ipfsCfg, genPID, genPrivB64); err != nil {
			log.Fatalf("write ipfs config failed: %v", err)
		}
		fmt.Printf("✓ Generated new IPFS Identity and wrote to %s\n", ipfsCfg)

		// 直接使用刚生成的身份继续后续流程
		pid, lpPriv, lpPub = genPID, genPriv, genPub
	} else {
		// 读取指定 config
		var lerr error
		pid, lpPriv, lpPub, lerr = loadIPFSIdentity(ipfsCfg)
		if lerr != nil {
			log.Fatalf("load IPFS identity failed: %v", lerr)
		}
	}

	// pid 现在就是 PeerID（字符串），用于注册
	//fmt.Printf("Using PeerID as pid: %s\n", pid)

	// 将 libp2p（Ed25519）密钥导出为 PEM，并带上用户名后缀（与自测代码一致）
	privPath, pubPath, err := writePEMKeys(username, lpPriv, lpPub)
	if err != nil {
		log.Fatalf("write PEM keys failed: %v", err)
	}
	fmt.Printf("PEM keys saved:\n  %s\n  %s\n", privPath, pubPath)

	// === 6. 计算 hashAttr（从统一合法空间 S* 中选择注册属性向量） ===
	t_userRegister := time.Now()
	bits := append([]int(nil), profileSpace[0]...)
	if !validateAttributesInternal(bits, constraints) {
		log.Fatalf("selected registration profile is not admissible")
	}
	profileHash := hashCalc(bits)
	attrRand, err := randomFieldElement()
	if err != nil {
		log.Fatalf("generate zk-Guard attribute randomness failed: %v", err)
	}
	userCommit := hashCalcUserCommit(bits, attrRand)

	// Keep the legacy attribute-vector file for compatibility with older tools,
	// and additionally store the randomized zk-Guard credential for proof generation.
	attrJSON, _ := json.Marshal(bits)
	if err := os.WriteFile(attrPath, attrJSON, 0644); err != nil {
		log.Printf("写属性向量失败: %v", err)
	}
	credPath, err := saveZKGuardCredential(username, pid, bits, attrRand, profileHash, userCommit)
	if err != nil {
		log.Printf("保存 zk-Guard 随机化属性凭证失败: %v", err)
	}
	fmt.Printf("✓ CA selected profile[0] from S* for %s\n", username)
	fmt.Printf("  profileHash=H(w)      : %s\n", profileHash)
	fmt.Printf("  userCommit=H(w||r)   : %s\n", userCommit)
	if credPath != "" {
		fmt.Printf("  credential path      : %s\n", credPath)
	}

	// === 6. UserRegister（pid = PeerID） ===
	// 为避免将 pid 与确定性 profileHash=H(w) 绑定在同一笔交易中，
	// 注册拆成两个合约调用：
	//   1) UserRegister(pid, userCommit) 只更新 Reg[pid]=H(w||r)；
	//   2) ProfileVersionRegister(profileHash) 只确保 VerMap[H(w)] 存在。
	registerOK := false
	if _, err = contract.SubmitTransaction(
		"UserRegister",
		pid,        // 直接用 PeerID
		userCommit, // 随机化属性承诺 H(w||r)，用于 zk-Guard 身份绑定
	); err != nil {
		log.Printf("UserRegister 失败: %v", err)
		if _, updErr := contract.SubmitTransaction("AttributeUpdate", pid, userCommit); updErr != nil {
			log.Fatalf("AttributeUpdate fallback 失败: %v", updErr)
		} else {
			registerOK = true
			fmt.Printf("✓ 已用 AttributeUpdate 同步链上随机化属性承诺: %s\n", userCommit)
		}
	} else {
		registerOK = true
	}
	if registerOK {
		if _, err = contract.SubmitTransaction("ProfileVersionRegister", profileHash); err != nil {
			log.Fatalf("ProfileVersionRegister 失败: %v", err)
		}
		fmt.Printf("✓ ProfileVersionRegister 完成: profileHash=%s\n", profileHash)
	}
	tUserRegister := time.Since(t_userRegister)
	fmt.Println("✓ UserRegister 完成")

	var configVersion uint64 = 0
	verBytes, err := contract.EvaluateTransaction("QueryConfigVersion", profileHash)
	if err != nil {
		log.Printf("QueryConfigVersion 失败: %v", err)
	} else {
		fmt.Printf("VerMap[profileHash=%s] = %s\n", profileHash, string(verBytes))
		verBI := new(big.Int)
		if _, ok := verBI.SetString(string(verBytes), 10); ok {
			configVersion = verBI.Uint64()
		}
	}

	// === 6.1 PolyLock KeyGen：与 zk-Guard UserRegister 绑定在同一个 systemInit 阶段 ===
	startPolyLockKeyGen := time.Now()
	if err := savePolyLockParams(profilePath, profileDigest); err != nil {
		log.Printf("保存 PolyLock 参数失败: %v", err)
	}
	uskPath, tPolyLockKeyGen, err := savePolyLockUSKV2(polySystem, username, pid, bits, profileHash, userCommit, attrRand, configVersion)
	if err != nil {
		log.Printf("PolyLock KeyGen 失败: %v", err)
	} else {
		fmt.Printf("✓ PolyLock KeyGen 完成，USK 保存至: %s\n", uskPath)
	}
	_ = startPolyLockKeyGen

	// === 7. 总时间 ===
	tTotal := time.Since(startTotal)

	// === 8. 输出三项时间 ===
	fmt.Println("\n==== ⏱️ 计时 (毫秒) ====")
	fmt.Printf("CircuitGen   : %.3f ms\n", float64(tCircuitGen.Microseconds())/1000)
	fmt.Printf("UniSetup     : %.3f ms\n", float64(tUniSetup.Microseconds())/1000)
	fmt.Printf("UniversalSetup     : %.3f ms\n", float64(tUniversalSetup.Microseconds())/1000)
	fmt.Printf("ProfileSpace : %.3f ms\n", float64(tProfileSpace.Microseconds())/1000)
	fmt.Printf("UserRegister : %.3f ms\n", float64(tUserRegister.Microseconds())/1000)
	fmt.Printf("PolyLockKeyGen: %.3f ms\n", float64(tPolyLockKeyGen.Microseconds())/1000)
	fmt.Printf("SystemInit   : %.3f ms\n", float64(tTotal.Microseconds())/1000)

	// === 9. 打印体积 ===
	toMB := func(n int) float64 { return float64(n) / (1024.0 * 1024.0) }
	/*fmt.Println("\n==== 原始对象大小 (Raw, 未压缩/未B64) ====")
	fmt.Printf("ccs_raw : %d bytes (%.3f MB)\n", ccsBuf.Len(), toMB(ccsBuf.Len()))
	fmt.Printf("pk_raw  : %d bytes (%.3f MB)\n", pkBuf.Len(), toMB(pkBuf.Len()))
	fmt.Printf("vk_raw  : %d bytes (%.3f MB)\n", vkBuf.Len(), toMB(vkBuf.Len()))*/

	fmt.Printf("\n==== 压缩后体积 ====\n")
	fmt.Printf("pk  : %d bytes (%.3f MB)\n", len(pkC), toMB(len(pkC)))
	fmt.Printf("vk  : %d bytes (%.3f MB)\n", len(vkC), toMB(len(vkC)))
	fmt.Printf("ccs : %d bytes (%.3f MB)\n", len(ccsC), toMB(len(ccsC)))
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
