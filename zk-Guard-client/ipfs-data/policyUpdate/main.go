// policyUpdate.go — DU端：刷新 PolyLock 锁密文，复用 DataCID 并构造新的 two-link RootCID，并注册新 rootCID 的策略矩阵
//
// 用法：./policyUpdate <oldRootCID> <pid> [username]
//
// 说明：
//   - 读取 dataStorage 阶段保存的 owner state：./polylock_state/objects/state_<username>_<oldRootCID>.json
//   - 复用原 data.ct 的 DataCID，不重新加密数据、不重新上传数据密文
//   - 重新生成 lock.ct = CT_lock_serialized || footer_json || footer_len_fixed_8bytes
//   - 通过 old DataCID + new LockCID 构造新的 two-link RootCID
//   - 当前链码尚无 oldCID->newCID 的 PolicyUpdateCID 接口，因此最小原型中将 newRootCID 作为新资源调用 DataStorage 注册
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	mrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/hash"
	lpcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	plintegration "polylock-thesis/go-bridge/integration"
	polylockv2 "polylock-thesis/go-bridge/polylock"
)

/* ---------------- Fabric 连接常量 & 系统参数 ---------------- */
const (
	AttrNum       = 100
	IntNum        = AttrNum - 1
	GroupSz       = 253
	TotalNode     = 2*AttrNum - 1
	mspID         = "Org1MSP"
	cryptoPath    = "../../../organizations/peerOrganizations/org1.example.com"
	certPath      = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem"
	keyPath       = cryptoPath + "/users/User1@org1.example.com/msp/keystore/"
	tlsCertPath   = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint  = "peer0.org1.example.com:7051"
	gatewayPeer   = "peer0.org1.example.com"
	chaincodeName = "acmc"
	channelName   = "mychannel"

	mconfPathTemplate = "./mconf_%s.b64"
	sigPathTemplate   = "./sig_%s.b64"

	// PolyLock minimal prototype parameters. Must be consistent with systemInit/dataStorage/dataRetrieve.
	polyLockLogN           = 10
	polyLockLogQ           = 27
	polyLockKeySize        = 32
	polyLockCompress       = 11
	polyLockBucketDegree   = 2
	polyLockPolicyAttrNum  = AttrNum / 2
	polyLockLegalSpaceSize = 1000
	polyLockMaxActiveAttrs = 20
	polyLockTargetSigma    = 0.90
	ipfsChunkSize          = 256 * 1024
	polyLockObjectsDir     = "./polylock_state/objects"
	polyLockSystemDir      = "./polylock_state/system"
)

var (
	polyLockDependencies  = buildPolyLockDependencies()
	polyLockMutexes       = buildPolyLockMutexes()
	excludedPolicyGenTime time.Duration
)

/* ---------- 策略树结构 & 编码 ---------- */
type PNode struct {
	Op, Attr string
	L, R     *PNode
}

func buildThresholdPolicy(attrs []string, probAND float64) *PNode {
	if len(attrs) == 0 {
		return nil
	}
	if len(attrs) == 1 {
		return &PNode{Op: "ATTR", Attr: attrs[0]}
	}
	mid := len(attrs) / 2
	op := "OR"
	if mrand.Float64() < probAND {
		op = "AND"
	}
	return &PNode{
		Op: op,
		L:  buildThresholdPolicy(attrs[:mid], probAND),
		R:  buildThresholdPolicy(attrs[mid:], probAND),
	}
}

func makePolicyAttributes(num int) []string {
	if num > AttrNum {
		num = AttrNum
	}
	attrs := make([]string, num)
	for i := range attrs {
		attrs[i] = fmt.Sprintf("attr%d", i)
	}
	return attrs
}

func evalPolicy(n *PNode, bits []int) bool {
	if n == nil {
		return false
	}
	if n.Op == "ATTR" {
		var id int
		if _, err := fmt.Sscanf(n.Attr, "attr%d", &id); err != nil {
			return false
		}
		return id >= 0 && id < len(bits) && bits[id] == 1
	}
	left := evalPolicy(n.L, bits)
	right := evalPolicy(n.R, bits)
	if n.Op == "OR" {
		return left || right
	}
	return left && right
}

func countPolicyMatches(policy *PNode, space [][]int) int {
	matched := 0
	for _, profile := range space {
		if evalPolicy(policy, profile) {
			matched++
		}
	}
	return matched
}

// localPolicySatisfied evaluates the exact mconf semantics used by dataRetrieve.go and zk-Guard.
func localPolicySatisfied(bits, f, aS, oS, nS []int) bool {
	if len(bits) != AttrNum || len(f) != AttrNum || len(aS) != IntNum || len(oS) != IntNum || len(nS) != IntNum {
		return false
	}
	node := make([]int, TotalNode)
	for i := 0; i < AttrNum; i++ {
		node[IntNum+i] = f[i] * bits[i]
	}
	for i := IntNum - 1; i >= 0; i-- {
		l, r := node[2*i+1], node[2*i+2]
		andV := l * r
		orV := l + r - andV
		nopV := l
		node[i] = aS[i]*andV + oS[i]*orV + nS[i]*nopV
	}
	return node[0] == 1
}

func countMConfMatches(space [][]int, flag, selA, selO, selN []int) int {
	matched := 0
	for _, profile := range space {
		if localPolicySatisfied(profile, flag, selA, selO, selN) {
			matched++
		}
	}
	return matched
}

func generatePolyLockPolicy(targetSigma float64, required []int) (*PNode, int, int) {
	space := makeLegalAttributeSpace()
	targetCount := int(float64(len(space)) * targetSigma)
	if targetCount < 1 {
		targetCount = 1
	}

	attrs := makePolicyAttributes(polyLockPolicyAttrNum)
	currentProbAND := 0.5
	step := 0.1
	maxRetries := 200
	minDiff := len(space) + 1
	var bestPolicy *PNode
	bestMatched := 0

	for i := 0; i < maxRetries; i++ {
		mrand.Shuffle(len(attrs), func(i, j int) { attrs[i], attrs[j] = attrs[j], attrs[i] })
		policy := buildThresholdPolicy(attrs, currentProbAND)
		matched := countPolicyMatches(policy, space)
		requiredOK := required == nil || evalPolicy(policy, required)
		diff := int(math.Abs(float64(matched - targetCount)))
		if matched > 0 && requiredOK && diff < minDiff {
			minDiff = diff
			bestPolicy = policy
			bestMatched = matched
		}

		tolerance := int(float64(targetCount) * 0.05)
		if tolerance < 5 {
			tolerance = 5
		}
		if matched > 0 && requiredOK && diff <= tolerance {
			break
		}
		if matched < targetCount {
			if matched == 0 {
				currentProbAND -= 0.15
			} else {
				currentProbAND -= step
			}
		} else {
			currentProbAND += step
		}
		if currentProbAND < 0.01 {
			currentProbAND = 0.01
		}
		if currentProbAND > 0.99 {
			currentProbAND = 0.99
		}
	}

	if bestPolicy == nil {
		bestPolicy = &PNode{Op: "ATTR", Attr: "attr0"}
		bestMatched = countPolicyMatches(bestPolicy, space)
	}
	return bestPolicy, len(space), bestMatched
}

func encodePolicy(root *PNode) (flag []int, andS, orS, nopS []int) {
	flag = make([]int, AttrNum)
	andS, orS, nopS = make([]int, IntNum), make([]int, IntNum), make([]int, IntNum)
	for i := range nopS {
		nopS[i] = 1
	}
	var dfs func(*PNode, int) bool
	dfs = func(n *PNode, idx int) bool {
		if n == nil {
			return false
		}
		if n.Op == "ATTR" {
			var id int
			fmt.Sscanf(n.Attr, "attr%d", &id)
			if id < AttrNum {
				flag[id] = 1
			}
			return true
		}
		if idx >= IntNum {
			var markLeaves func(*PNode)
			markLeaves = func(t *PNode) {
				if t == nil {
					return
				}
				if t.Op == "ATTR" {
					var id int
					fmt.Sscanf(t.Attr, "attr%d", &id)
					if id < AttrNum {
						flag[id] = 1
					}
					return
				}
				markLeaves(t.L)
				markLeaves(t.R)
			}
			markLeaves(n)
			return true
		}
		left := dfs(n.L, 2*idx+1)
		right := dfs(n.R, 2*idx+2)
		nopS[idx] = 0
		if n.Op == "AND" {
			andS[idx] = 1
		} else {
			orS[idx] = 1
		}
		if n.Op == "AND" && (!left || !right) {
			andS[idx] = 0
			nopS[idx] = 1
			return left || right
		}
		return left || right
	}
	dfs(root, 0)
	return
}

/* ---------- gzip & base64 ---------- */
func gzipB64(raw []byte) string {
	encoded, _ := gzipB64WithSize(raw)
	return encoded
}

// gzipB64WithSize returns the transport representation together with the
// actual gzip byte length stored by the chaincode after Base64 decoding.
func gzipB64WithSize(raw []byte) (string, int) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	gz := buf.Bytes()
	return base64.StdEncoding.EncodeToString(gz), len(gz)
}

/* ---------- 签名（兼容 Ed25519 + ECDSA） ---------- */
func signPID(privAny interface{}, msg string) (sigB64 string, err error) {
	d := sha256.Sum256([]byte(msg))
	switch k := privAny.(type) {
	case ed25519.PrivateKey:
		sig := ed25519.Sign(k, d[:])
		return base64.StdEncoding.EncodeToString(sig), nil
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, d[:])
		if err != nil {
			return "", fmt.Errorf("ecdsa.Sign: %v", err)
		}
		der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		if err != nil {
			return "", fmt.Errorf("asn1 marshal: %v", err)
		}
		return base64.StdEncoding.EncodeToString(der), nil
	default:
		return "", fmt.Errorf("unsupported private key type: %T", privAny)
	}
}

func derivePeerIDFromSavedPEM(pubPath string) (string, error) {
	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		return "", fmt.Errorf("read pub PEM: %v", err)
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return "", fmt.Errorf("invalid PUBLIC KEY PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("ParsePKIXPublicKey: %v", err)
	}
	stdPub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return "", nil
	}
	lpPub, err := lpcrypto.UnmarshalEd25519PublicKey([]byte(stdPub))
	if err != nil {
		return "", fmt.Errorf("UnmarshalEd25519PublicKey: %v", err)
	}
	idFromPEM, err := peer.IDFromPublicKey(lpPub)
	if err != nil {
		return "", fmt.Errorf("IDFromPublicKey: %v", err)
	}
	return idFromPEM.String(), nil
}

/* ---------------- PolyLock minimal prototype ---------------- */
type PolyPublicParams struct {
	RingQ   *ring.Ring
	MatrixA ring.Poly
}

type PolyLockOnlyCT struct {
	SubLocks [][][]byte `json:"sub_locks"`
}

// marshalPolyLockCTBinary serializes PolyLockOnlyCT as raw binary instead of
// JSON. This avoids Go's encoding/json behavior that base64-encodes []byte and
// inflates lock.ct before it is uploaded to IPFS.
//
// Format:
//
//	magic        : 4 bytes, "PLK1"
//	bucket_count : uint32
//	for each bucket:
//	    sample_count : uint16
//	    for each sample:
//	        sample_len : uint32
//	        sample     : raw bytes
func marshalPolyLockCTBinary(ct *PolyLockOnlyCT) ([]byte, error) {
	if ct == nil {
		return nil, fmt.Errorf("nil PolyLock CT")
	}

	var buf bytes.Buffer
	if _, err := buf.Write([]byte("PLK1")); err != nil {
		return nil, err
	}
	if len(ct.SubLocks) > 0xffffffff {
		return nil, fmt.Errorf("too many lock buckets: %d", len(ct.SubLocks))
	}
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(ct.SubLocks))); err != nil {
		return nil, err
	}

	for bi, bucket := range ct.SubLocks {
		if len(bucket) > 0xffff {
			return nil, fmt.Errorf("too many lock samples in bucket %d: %d", bi, len(bucket))
		}
		if err := binary.Write(&buf, binary.BigEndian, uint16(len(bucket))); err != nil {
			return nil, err
		}
		for si, sample := range bucket {
			if len(sample) > 0xffffffff {
				return nil, fmt.Errorf("lock sample too large at bucket=%d sample=%d: %d", bi, si, len(sample))
			}
			if err := binary.Write(&buf, binary.BigEndian, uint32(len(sample))); err != nil {
				return nil, err
			}
			if _, err := buf.Write(sample); err != nil {
				return nil, err
			}
		}
	}

	return buf.Bytes(), nil
}

// unmarshalPolyLockCT reads the new binary lock format. For backward
// compatibility, it falls back to the previous JSON format when the magic header
// is absent, so policyUpdate can still consume old JSON/base64 lock.ct files.
func unmarshalPolyLockCT(data []byte) (*PolyLockOnlyCT, error) {
	if !bytes.HasPrefix(data, []byte("PLK1")) {
		var ct PolyLockOnlyCT
		if err := json.Unmarshal(data, &ct); err != nil {
			return nil, err
		}
		return &ct, nil
	}

	r := bytes.NewReader(data[4:])
	var bucketCount uint32
	if err := binary.Read(r, binary.BigEndian, &bucketCount); err != nil {
		return nil, fmt.Errorf("read lock bucket count: %v", err)
	}

	ct := &PolyLockOnlyCT{SubLocks: make([][][]byte, int(bucketCount))}
	for bi := 0; bi < int(bucketCount); bi++ {
		var sampleCount uint16
		if err := binary.Read(r, binary.BigEndian, &sampleCount); err != nil {
			return nil, fmt.Errorf("read sample count for bucket %d: %v", bi, err)
		}
		ct.SubLocks[bi] = make([][]byte, int(sampleCount))
		for si := 0; si < int(sampleCount); si++ {
			var sampleLen uint32
			if err := binary.Read(r, binary.BigEndian, &sampleLen); err != nil {
				return nil, fmt.Errorf("read sample length for bucket %d sample %d: %v", bi, si, err)
			}
			sample := make([]byte, int(sampleLen))
			if _, err := io.ReadFull(r, sample); err != nil {
				return nil, fmt.Errorf("read sample bytes for bucket %d sample %d: %v", bi, si, err)
			}
			ct.SubLocks[bi][si] = sample
		}
	}
	if r.Len() != 0 {
		return nil, fmt.Errorf("trailing bytes in binary PolyLock CT: %d", r.Len())
	}
	return ct, nil
}

type ProtectedObjectFooter struct {
	Format          string `json:"format"`
	ChunkSize       int    `json:"chunk_size"`
	DataLen         int    `json:"data_len"`
	PadLen          int    `json:"pad_len"`
	LockOff         int    `json:"lock_offset"`
	LockLen         int    `json:"lock_len"`
	Version         uint64 `json:"version"`
	AttrHash        string `json:"attr_hash"`
	EffectiveRoots  int    `json:"effective_roots"`
	BucketCount     int    `json:"bucket_count"`
	BucketDegree    int    `json:"bucket_degree"`
	SecurityProfile string `json:"security_profile,omitempty"`
	AADBase64       string `json:"aad_base64,omitempty"`
	CreatedAt       string `json:"created_at"`
}

type OwnerObjectState struct {
	Format          string `json:"format"`
	Username        string `json:"username"`
	PID             string `json:"pid"`
	RootCID         string `json:"root_cid"`
	DataCID         string `json:"data_cid,omitempty"`
	LockCID         string `json:"lock_cid,omitempty"`
	ObjectPath      string `json:"object_path"`
	DataPartPath    string `json:"data_part_path"`
	LockPartPath    string `json:"lock_part_path,omitempty"`
	PlainPath       string `json:"plain_path"`
	KeyBase64       string `json:"key_base64"`
	AttrHash        string `json:"attr_hash"`
	Version         uint64 `json:"version"`
	DataLen         int    `json:"data_len"`
	PadLen          int    `json:"pad_len"`
	LockLen         int    `json:"lock_len"`
	ChunkSize       int    `json:"chunk_size"`
	EffectiveRoots  int    `json:"effective_roots"`
	BucketCount     int    `json:"bucket_count"`
	BucketDegree    int    `json:"bucket_degree"`
	CreatedAt       string `json:"created_at"`
	PolicyMConfPath string `json:"policy_mconf_path"`
	LockStatePath   string `json:"lock_state_path"`
}

type BucketStateDisk struct {
	Index    int      `json:"index"`
	Roots    [][]int  `json:"roots"`
	RootKeys []string `json:"root_keys"`
}

type LockStateDisk struct {
	Format            string                        `json:"format"`
	AttrNum           int                           `json:"attr_num"`
	BucketDegree      int                           `json:"bucket_degree"`
	LegalConfigs      int                           `json:"legal_configs"`
	EffectiveRoots    int                           `json:"effective_roots"`
	BucketCount       int                           `json:"bucket_count"`
	Flag              []int                         `json:"flag"`
	SelAnd            []int                         `json:"selAnd"`
	SelOr             []int                         `json:"selOr"`
	SelNop            []int                         `json:"selNop"`
	Buckets           []BucketStateDisk             `json:"buckets"`
	RootToBucket      map[string]int                `json:"root_to_bucket"`
	VersionedProfiles []polylockv2.VersionedProfile `json:"versioned_profiles,omitempty"`
	CreatedAt         string                        `json:"created_at"`
}

type RootProfile struct {
	Bits     []int
	AttrHash string
	Version  uint64
	RootKey  string
}

type SystemConstraints struct {
	DependencyMap map[int]int `json:"dependency_map"`
	SoDPairs      [][2]int    `json:"sod_pairs"`
	MaxCard       int         `json:"max_card"`
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

type PolyLockUSKDisk struct {
	Format     string `json:"format"`
	Username   string `json:"username"`
	PID        string `json:"pid"`
	AttrNum    int    `json:"attr_num"`
	AttrHash   string `json:"attr_hash"`
	Version    uint64 `json:"version"`
	AttrVector []int  `json:"attr_vector"`
}

type PolicyGenStats struct {
	LegalConfigs int
	TargetCount  int
	Matched      int
	Attempts     int
	TargetSigma  float64
	ActualSigma  float64
	BestDiff     int
}

// SchemePhaseTimings contains only the six protocol-level operations reported
// in the dissertation. Engineering diagnostics such as local state loading and
// experiment-artifact persistence are deliberately kept outside this sum.
type SchemePhaseTimings struct {
	MConfGenerate       time.Duration
	ResolveRootVersions time.Duration
	LockRefresh         time.Duration
	ObjectBuild         time.Duration
	IPFSAddLockRoot     time.Duration
	BlockchainRegister  time.Duration
}

func (t SchemePhaseTimings) Sum() time.Duration {
	return t.MConfGenerate +
		t.ResolveRootVersions +
		t.LockRefresh +
		t.ObjectBuild +
		t.IPFSAddLockRoot +
		t.BlockchainRegister
}

// UnifiedPolicyUpdateMetrics is populated by the unified policy-update path.
// The program is a single-shot CLI, so a process-local record keeps the return
// signature compact while main() emits the machine-readable experiment report.
type UnifiedPolicyUpdateMetrics struct {
	Timings      SchemePhaseTimings
	CoreWallTime time.Duration

	// Diagnostics excluded from the dissertation six-stage total.
	PolicyGenTime    time.Duration
	StatePrepareTime time.Duration
	LocalPersistTime time.Duration
	PostProcessTime  time.Duration

	AttrNum             int
	LegalSpaceSize      int
	TargetSigma         float64
	OldEffectiveRoots   int
	NewEffectiveRoots   int
	OldBucketCount      int
	NewBucketCount      int
	AffectedBuckets     int
	DeltaAdd            int
	DeltaRm             int
	ObservedBucketRatio float64

	MConfB64       string
	SignatureB64   string
	MConfGzipBytes int
	LockCTBytes    int
	DataCIDReused  bool
	DataCID        string
	OldRootCID     string
	NewRootCID     string
	NewLockCID     string

	VerMapExplicit      int
	VersionMatched      int
	VersionDefaultZero  int
	VersionSkippedAfter int
}

var lastUnifiedPolicyUpdateMetrics UnifiedPolicyUpdateMetrics

type PolicyStateDisk struct {
	Format              string  `json:"format"`
	RootCID             string  `json:"root_cid"`
	Username            string  `json:"username"`
	TargetSigma         float64 `json:"target_sigma"`
	ActualSigma         float64 `json:"actual_sigma"`
	LegalConfigs        int     `json:"legal_configs"`
	TargetCount         int     `json:"target_count"`
	Matched             int     `json:"matched"`
	ObservedBucketRatio float64 `json:"observed_bucket_ratio"`
	AffectedBuckets     int     `json:"affected_buckets"`
	OldBucketCount      int     `json:"old_bucket_count"`
	Flag                []int   `json:"flag"`
	SelAnd              []int   `json:"selAnd"`
	SelOr               []int   `json:"selOr"`
	SelNop              []int   `json:"selNop"`
	SystemSpaceDigest   string  `json:"system_space_digest"`
	CreatedAt           string  `json:"created_at"`
}

type PartialUpdateStats struct {
	AffectedBuckets int
	DeltaAdd        int
	DeltaRm         int
	LocateTime      time.Duration
	RecompileTime   time.Duration
	ReEncapsTime    time.Duration
	TotalTime       time.Duration
}

func cloneIntVector(v []int) []int {
	out := make([]int, len(v))
	copy(out, v)
	return out
}

func cloneIntVectors(vs [][]int) [][]int {
	out := make([][]int, len(vs))
	for i := range vs {
		out[i] = cloneIntVector(vs[i])
	}
	return out
}

func rootKeyHash(rootKey string) string {
	if idx := strings.Index(rootKey, ":"); idx >= 0 {
		return rootKey[:idx]
	}
	return rootKey
}

type PolyLockCompileStats struct {
	LegalConfigs   int
	EffectiveRoots int
	BucketCount    int
	BucketDegree   int
}

func polySetup() (*PolyPublicParams, error) {
	params, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{LogN: polyLockLogN, LogQ: []int{polyLockLogQ}, NTTFlag: true})
	if err != nil {
		return nil, err
	}
	r := params.RingQ()
	prng, _ := sampling.NewKeyedPRNG([]byte("System_Global_Matrix_A_Seed"))
	uSampler := ring.NewUniformSampler(prng, r)
	A := uSampler.ReadNew()
	r.MForm(A, A)
	r.NTT(A, A)
	return &PolyPublicParams{RingQ: r, MatrixA: A}, nil
}

func hashCalc(bits []int) string {
	return new(big.Int).SetBytes(hashCalcBytes(bits)).String()
}

func hashCalcBytes(bits []int) []byte {
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
	return hf.Sum(nil)
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

func hashToPointVersioned(pp *PolyPublicParams, w []int, ver uint64) ring.Poly {
	seed := hashCalcVersionedBytes(w, ver)
	prng, _ := sampling.NewKeyedPRNG(seed)
	tSampler, _ := ring.NewTernarySampler(prng, pp.RingQ, ring.Ternary{P: 0.5}, false)
	s := tSampler.ReadNew()
	pp.RingQ.MForm(s, s)
	pp.RingQ.NTT(s, s)
	H := pp.RingQ.NewPoly()
	pp.RingQ.MulCoeffsMontgomery(pp.MatrixA, s, H)
	return *H.CopyNew()
}

func mapCoefStringToPoly(r *ring.Ring, coefStr string) ring.Poly {
	val := new(big.Int)
	val.SetString(coefStr, 10)
	val.Mod(val, new(big.Int).SetUint64(r.SubRings[0].Modulus))
	p := r.NewPoly()
	p.Coeffs[0][0] = val.Uint64()
	r.MForm(p, p)
	r.NTT(p, p)
	return p
}

func buildPolyLockDependencies() [][2]int {
	depLimit := 50
	if depLimit > AttrNum {
		depLimit = AttrNum
	}
	deps := make([][2]int, 0, depLimit)
	for child := 1; child < depLimit; child++ {
		deps = append(deps, [2]int{child - 1, child})
	}
	return deps
}

func buildPolyLockMutexes() [][2]int {
	startIdx := 50
	if startIdx+10 >= AttrNum {
		startIdx = AttrNum / 2
	}
	if startIdx < 0 {
		startIdx = 0
	}
	pairs := make([][2]int, 0, 5)
	for i := 0; i < 5; i++ {
		left := startIdx + i*2
		right := startIdx + i*2 + 1
		if right < AttrNum {
			pairs = append(pairs, [2]int{left, right})
		}
	}
	return pairs
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

func satisfiesGlobalConstraints(bits []int) bool {
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
	for _, dep := range polyLockDependencies {
		parent, child := dep[0], dep[1]
		if parent >= 0 && parent < AttrNum && child >= 0 && child < AttrNum && bits[child] == 1 && bits[parent] == 0 {
			return false
		}
	}
	for _, pair := range polyLockMutexes {
		left, right := pair[0], pair[1]
		if left >= 0 && left < AttrNum && right >= 0 && right < AttrNum && bits[left] == 1 && bits[right] == 1 {
			return false
		}
	}
	return true
}

func addLegalAttrVector(space *[][]int, seen map[string]bool, bits []int) {
	if !satisfiesGlobalConstraints(bits) {
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

func makeLegalAttributeSpace() [][]int {
	space := make([][]int, 0, polyLockLegalSpaceSize)
	seen := make(map[string]bool)
	addLegalAttrVector(&space, seen, makeDefaultValidAttrVector())

	rnd := mrand.New(mrand.NewSource(2024051701))
	for attempts := 0; len(space) < polyLockLegalSpaceSize && attempts < polyLockLegalSpaceSize*1000; attempts++ {
		bits := make([]int, AttrNum)
		initialCount := rnd.Intn(polyLockMaxActiveAttrs) + 1
		for k := 0; k < initialCount; k++ {
			bits[rnd.Intn(AttrNum)] = 1
		}

		changed := true
		for changed {
			changed = false
			for _, dep := range polyLockDependencies {
				parent, child := dep[0], dep[1]
				if parent >= 0 && parent < AttrNum && child >= 0 && child < AttrNum && bits[child] == 1 && bits[parent] == 0 {
					bits[parent] = 1
					changed = true
				}
			}
		}

		for _, pair := range polyLockMutexes {
			left, right := pair[0], pair[1]
			if left >= 0 && left < AttrNum && right >= 0 && right < AttrNum && bits[left] == 1 && bits[right] == 1 {
				if rnd.Intn(2) == 0 {
					bits[left] = 0
				} else {
					bits[right] = 0
				}
			}
		}

		addLegalAttrVector(&space, seen, bits)
	}
	return space
}

func queryConfigVersion(contract *client.Contract, bits []int) (string, uint64, error) {
	attrHash := hashCalc(bits)
	verBytes, err := contract.EvaluateTransaction("QueryConfigVersion", attrHash)
	if err != nil {
		return attrHash, 0, err
	}
	return attrHash, parseVersion(verBytes, 0), nil
}

func queryAllConfigVersions(contract *client.Contract) (map[string]uint64, error) {
	raw, err := contract.EvaluateTransaction("QueryAllConfigVersions")
	if err != nil {
		return nil, err
	}

	out := make(map[string]uint64)
	body := strings.TrimSpace(string(raw))
	if body == "" || body == "null" {
		return out, nil
	}

	if err := json.Unmarshal(raw, &out); err == nil {
		return out, nil
	}

	// Compatibility fallback: tolerate a chaincode implementation that returns
	// {"profileHash":"version"} instead of {"profileHash":version}.
	var strMap map[string]string
	if err := json.Unmarshal(raw, &strMap); err != nil {
		return nil, fmt.Errorf("decode QueryAllConfigVersions response failed: %v; body=%s", err, body)
	}
	for k, v := range strMap {
		out[strings.TrimSpace(k)] = parseVersion([]byte(v), 0)
	}
	return out, nil
}

type VersionResolver struct {
	VerMap       map[string]uint64
	Seen         map[string]bool
	SeenVersion  map[string]uint64
	Found        int
	DefaultZero  int
	SkippedAfter int
	Exhausted    bool
}

func NewVersionResolver(verMap map[string]uint64) *VersionResolver {
	if verMap == nil {
		verMap = make(map[string]uint64)
	}
	return &VersionResolver{
		VerMap:      verMap,
		Seen:        make(map[string]bool),
		SeenVersion: make(map[string]uint64),
	}
}

func (r *VersionResolver) Resolve(attrHash string) uint64 {
	if r == nil {
		return 0
	}
	attrHash = strings.TrimSpace(attrHash)
	if attrHash == "" {
		r.DefaultZero++
		return 0
	}
	if len(r.VerMap) == 0 {
		r.DefaultZero++
		return 0
	}

	if r.Exhausted {
		// All explicit VerMap entries have already been observed. A repeated
		// explicit profile hash is still resolved correctly; all unseen profiles
		// are necessarily default version 0.
		if v, ok := r.SeenVersion[attrHash]; ok {
			return v
		}
		r.DefaultZero++
		r.SkippedAfter++
		return 0
	}

	if v, ok := r.VerMap[attrHash]; ok {
		if !r.Seen[attrHash] {
			r.Seen[attrHash] = true
			r.SeenVersion[attrHash] = v
			r.Found++
			if r.Found >= len(r.VerMap) {
				r.Exhausted = true
			}
		}
		return v
	}

	r.DefaultZero++
	return 0
}

func compileRootBucket(pp *PolyPublicParams, roots []ring.Poly) []ring.Poly {
	r := pp.RingQ
	coeffs := []ring.Poly{mapCoefStringToPoly(r, "1")}
	for _, root := range roots {
		next := make([]ring.Poly, len(coeffs)+1)
		for i := range next {
			next[i] = r.NewPoly()
		}
		for i, coeff := range coeffs {
			term := r.NewPoly()
			r.MulCoeffsMontgomery(coeff, root, term)
			r.Sub(next[i], term, next[i])
			r.Add(next[i+1], coeff, next[i+1])
		}
		coeffs = next
	}
	return coeffs
}

type polyLockRootJob struct {
	Bits     []int
	RootKey  string
	AttrHash string
	Version  uint64
}

func polyLockWorkerCount(total int) int {
	if total <= 1 {
		return 1
	}
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	if workers > total {
		workers = total
	}
	return workers
}

func resolveRootJobsParallel(pp *PolyPublicParams, jobs []polyLockRootJob) []ring.Poly {
	roots := make([]ring.Poly, len(jobs))
	if len(jobs) == 0 {
		return roots
	}
	workers := polyLockWorkerCount(len(jobs))
	idxCh := make(chan int, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range idxCh {
				roots[i] = hashToPointVersioned(pp, jobs[i].Bits, jobs[i].Version)
			}
		}()
	}
	for i := range jobs {
		idxCh <- i
	}
	close(idxCh)
	wg.Wait()
	return roots
}

func compileRootBucketsParallel(pp *PolyPublicParams, bucketRoots [][]ring.Poly) [][]ring.Poly {
	out := make([][]ring.Poly, len(bucketRoots))
	if len(bucketRoots) == 0 {
		return out
	}
	workers := polyLockWorkerCount(len(bucketRoots))
	idxCh := make(chan int, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range idxCh {
				out[i] = compileRootBucket(pp, bucketRoots[i])
			}
		}()
	}
	for i := range bucketRoots {
		idxCh <- i
	}
	close(idxCh)
	wg.Wait()
	return out
}

func compileBucketDisksParallel(pp *PolyPublicParams, buckets []BucketStateDisk) [][]ring.Poly {
	out := make([][]ring.Poly, len(buckets))
	if len(buckets) == 0 {
		return out
	}
	workers := polyLockWorkerCount(len(buckets))
	idxCh := make(chan int, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range idxCh {
				out[i] = compileBucketFromDisk(pp, buckets[i])
			}
		}()
	}
	for i := range buckets {
		idxCh <- i
	}
	close(idxCh)
	wg.Wait()
	return out
}

func precomputePowersOfA(pp *PolyPublicParams, maxDegree int) []ring.Poly {
	if maxDegree < 1 {
		maxDegree = 1
	}
	r := pp.RingQ
	powers := make([]ring.Poly, maxDegree)
	powers[0] = mapCoefStringToPoly(r, "1")
	for k := 1; k < maxDegree; k++ {
		powers[k] = r.NewPoly()
		r.MulCoeffsMontgomery(powers[k-1], pp.MatrixA, powers[k])
	}
	return powers
}

func encapsCompiledBucketsParallel(pp *PolyPublicParams, K []byte, compiled [][]ring.Poly) [][][]byte {
	out := make([][][]byte, len(compiled))
	if len(compiled) == 0 {
		return out
	}
	maxDegree := 1
	for _, coeffs := range compiled {
		if len(coeffs) > maxDegree {
			maxDegree = len(coeffs)
		}
	}
	polyKey := encodeKey(pp.RingQ, K)
	powersOfA := precomputePowersOfA(pp, maxDegree)
	workers := polyLockWorkerCount(len(compiled))
	idxCh := make(chan int, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range idxCh {
				out[i] = encapsBucketWithPrecomp(pp, compiled[i], polyKey, powersOfA)
			}
		}()
	}
	for i := range compiled {
		idxCh <- i
	}
	close(idxCh)
	wg.Wait()
	return out
}

func preResolvePolicyBucketsFromMConf(pp *PolyPublicParams, flag, selA, selO, selN []int, resolver *VersionResolver) ([][]ring.Poly, *LockStateDisk, PolyLockCompileStats, error) {
	space := makeLegalAttributeSpace()
	stats := PolyLockCompileStats{LegalConfigs: len(space), BucketDegree: polyLockBucketDegree}
	lockState := &LockStateDisk{
		Format:       "zkguard-polylock-lock-state-v1",
		AttrNum:      AttrNum,
		BucketDegree: polyLockBucketDegree,
		LegalConfigs: len(space),
		Flag:         cloneIntVector(flag),
		SelAnd:       cloneIntVector(selA),
		SelOr:        cloneIntVector(selO),
		SelNop:       cloneIntVector(selN),
		Buckets:      make([]BucketStateDisk, 0),
		RootToBucket: make(map[string]int),
		CreatedAt:    time.Now().Format(time.RFC3339),
	}

	jobs := make([]polyLockRootJob, 0)
	seenRoots := make(map[string]bool)
	for _, bits := range space {
		if !localPolicySatisfied(bits, flag, selA, selO, selN) {
			continue
		}
		attrHash := hashCalc(bits)
		ver := resolver.Resolve(attrHash)
		rootKey := fmt.Sprintf("%s:%d", attrHash, ver)
		if seenRoots[rootKey] {
			continue
		}
		seenRoots[rootKey] = true
		jobs = append(jobs, polyLockRootJob{Bits: cloneIntVector(bits), AttrHash: attrHash, Version: ver, RootKey: rootKey})
	}
	if len(jobs) == 0 {
		return nil, nil, stats, fmt.Errorf("mconf policy has no effective roots in legal attribute space")
	}

	roots := resolveRootJobsParallel(pp, jobs)
	bucketRootGroups := make([][]ring.Poly, 0, (len(jobs)+polyLockBucketDegree-1)/polyLockBucketDegree)
	bucketRoots := make([]ring.Poly, 0, polyLockBucketDegree)
	bucketBits := make([][]int, 0, polyLockBucketDegree)
	bucketKeys := make([]string, 0, polyLockBucketDegree)
	flushBucket := func() {
		if len(bucketRoots) == 0 {
			return
		}
		bid := len(bucketRootGroups)
		bucketRootGroups = append(bucketRootGroups, append([]ring.Poly(nil), bucketRoots...))
		lockState.Buckets = append(lockState.Buckets, BucketStateDisk{Index: bid, Roots: cloneIntVectors(bucketBits), RootKeys: append([]string(nil), bucketKeys...)})
		bucketRoots = bucketRoots[:0]
		bucketBits = bucketBits[:0]
		bucketKeys = bucketKeys[:0]
	}
	for i, job := range jobs {
		lockState.RootToBucket[job.RootKey] = len(bucketRootGroups)
		bucketRoots = append(bucketRoots, roots[i])
		bucketBits = append(bucketBits, cloneIntVector(job.Bits))
		bucketKeys = append(bucketKeys, job.RootKey)
		stats.EffectiveRoots++
		if len(bucketRoots) == polyLockBucketDegree {
			flushBucket()
		}
	}
	flushBucket()
	buckets := compileRootBucketsParallel(pp, bucketRootGroups)
	stats.BucketCount = len(buckets)
	lockState.EffectiveRoots = stats.EffectiveRoots
	lockState.BucketCount = stats.BucketCount
	return buckets, lockState, stats, nil
}

func getScaleShift(r *ring.Ring) uint64 {
	q := r.SubRings[0].Modulus
	logQ := math.Log2(float64(q))
	return uint64(logQ) - 2
}

func encodeKey(r *ring.Ring, key []byte) ring.Poly {
	p := r.NewPoly()
	shift := getScaleShift(r)
	for i := 0; i < polyLockKeySize; i++ {
		for j := 0; j < 8; j++ {
			bit := (key[i] >> j) & 1
			p.Coeffs[0][i*8+j] = uint64(bit) << shift
		}
	}
	r.MForm(p, p)
	r.NTT(p, p)
	return p
}

func compressPoly(r *ring.Ring, p ring.Poly) []byte {
	tmp := r.NewPoly()
	r.INTT(p, tmp)
	r.IMForm(tmp, tmp)
	N := r.N()
	q := r.SubRings[0].Modulus
	activeBits := math.Log2(float64(q)) - float64(polyLockCompress)
	bytesPerCoeff := 4
	if activeBits <= 16 {
		bytesPerCoeff = 2
	}
	compressed := make([]byte, N*bytesPerCoeff)
	for i := 0; i < N; i++ {
		val := tmp.Coeffs[0][i]
		shifted := (val + (1 << (polyLockCompress - 1))) >> polyLockCompress
		if bytesPerCoeff == 2 {
			compressed[i*2] = byte(shifted)
			compressed[i*2+1] = byte(shifted >> 8)
		} else {
			compressed[i*4] = byte(shifted)
			compressed[i*4+1] = byte(shifted >> 8)
			compressed[i*4+2] = byte(shifted >> 16)
			compressed[i*4+3] = byte(shifted >> 24)
		}
	}
	return compressed
}

func newEphemeralRingComponents(r *ring.Ring) (*ring.Ring, *ring.GaussianSampler, *ring.TernarySampler) {
	seed := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, seed)
	prng, _ := sampling.NewKeyedPRNG(seed)
	gSampler := ring.NewGaussianSampler(prng, r, ring.DiscreteGaussian{Sigma: 3.2, Bound: 19}, false)
	tSampler, _ := ring.NewTernarySampler(prng, r, ring.Ternary{P: 0.5}, false)
	return r, gSampler, tSampler
}

func encapsBucketWithPrecomp(pp *PolyPublicParams, coeffs []ring.Poly, polyKey ring.Poly, powersOfA []ring.Poly) [][]byte {
	r, gSampler, tSampler := newEphemeralRingComponents(pp.RingQ)
	ephemeralR := tSampler.ReadNew()
	r.MForm(ephemeralR, ephemeralR)
	r.NTT(ephemeralR, ephemeralR)
	degree := len(coeffs)
	lockSamples := make([][]byte, degree)
	if len(powersOfA) < degree {
		powersOfA = precomputePowersOfA(pp, degree)
	}
	for k := 0; k < degree; k++ {
		M_i := r.NewPoly()
		r.MulCoeffsMontgomery(coeffs[k], powersOfA[k], M_i)
		L_i := r.NewPoly()
		r.MulCoeffsMontgomery(M_i, ephemeralR, L_i)
		e := gSampler.ReadNew()
		r.MForm(e, e)
		r.NTT(e, e)
		r.Add(L_i, e, L_i)
		if k == 0 {
			r.Add(L_i, polyKey, L_i)
		}
		lockSamples[k] = compressPoly(r, L_i)
	}
	return lockSamples
}

func encapsBucket(pp *PolyPublicParams, coeffs []ring.Poly, K []byte) [][]byte {
	polyKey := encodeKey(pp.RingQ, K)
	powersOfA := precomputePowersOfA(pp, len(coeffs))
	return encapsBucketWithPrecomp(pp, coeffs, polyKey, powersOfA)
}

func encapsLockForExistingKey(pp *PolyPublicParams, K []byte, bucketCoeffs [][]ring.Poly) ([]byte, error) {
	lockCT := PolyLockOnlyCT{SubLocks: encapsCompiledBucketsParallel(pp, K, bucketCoeffs)}
	return marshalPolyLockCTBinary(&lockCT)
}

func newProtectedObjectFooter(paddedDataLen int, dataLen int, padLen int, lockLen int, attrHash string, ver uint64) ProtectedObjectFooter {
	return ProtectedObjectFooter{
		Format:    "zkguard-polylock-object-v1",
		ChunkSize: ipfsChunkSize,
		DataLen:   dataLen,
		PadLen:    padLen,
		LockOff:   paddedDataLen,
		LockLen:   lockLen,
		Version:   ver,
		AttrHash:  attrHash,
		CreatedAt: time.Now().Format(time.RFC3339),
	}
}

func buildProtectedObjectFromPadded(paddedData []byte, dataLen int, padLen int, lockBytes []byte, attrHash string, ver uint64) ([]byte, ProtectedObjectFooter, error) {
	footer := newProtectedObjectFooter(len(paddedData), dataLen, padLen, len(lockBytes), attrHash, ver)
	footerBytes, err := json.Marshal(footer)
	if err != nil {
		return nil, footer, err
	}
	obj := make([]byte, 0, len(paddedData)+len(lockBytes)+len(footerBytes)+8)
	obj = append(obj, paddedData...)
	obj = append(obj, lockBytes...)
	obj = append(obj, footerBytes...)
	lenBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBuf, uint64(len(footerBytes)))
	obj = append(obj, lenBuf...)
	return obj, footer, nil
}

func ipfsAddObject(path string) (string, time.Duration, error) {
	start := time.Now()

	cmd := exec.Command("ipfs", "add", "--chunker=size-262144", "-q", path)
	out, err := cmd.CombinedOutput()

	elapsed := time.Since(start)

	if err != nil {
		return "", elapsed, fmt.Errorf("ipfs add failed: %v\n%s", err, string(out))
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[len(lines)-1]) == "" {
		return "", elapsed, fmt.Errorf("ipfs add returned empty output")
	}

	return strings.TrimSpace(lines[len(lines)-1]), elapsed, nil
}

func buildLockComponent(lockBytes []byte, footer ProtectedObjectFooter) ([]byte, error) {
	footerBytes, err := json.Marshal(footer)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(lockBytes)+len(footerBytes)+8)
	out = append(out, lockBytes...)
	out = append(out, footerBytes...)
	lenBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBuf, uint64(len(footerBytes)))
	out = append(out, lenBuf...)
	return out, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func linkOrCopyFile(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	return copyFile(src, dst)
}

func ipfsRun(args ...string) (string, error) {
	cmd := exec.Command("ipfs", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ipfs %s failed: %v\n%s", strings.Join(args, " "), err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

// buildTwoLinkRootFromCIDs constructs a new access-control root by linking
// existing DataCID and newly generated LockCID. It does not re-add data.ct.
func buildTwoLinkRootFromCIDs(dataCID, lockCID string) (string, time.Duration, error) {
	start := time.Now()
	dataCID = strings.TrimSpace(dataCID)
	lockCID = strings.TrimSpace(lockCID)
	if dataCID == "" {
		return "", time.Since(start), fmt.Errorf("empty DataCID")
	}
	if lockCID == "" {
		return "", time.Since(start), fmt.Errorf("empty LockCID")
	}

	mfsDir := fmt.Sprintf("/zkguard-polylock-twolink-update-%d-%d", os.Getpid(), time.Now().UnixNano())
	_ = exec.Command("ipfs", "files", "rm", "-r", mfsDir).Run()

	if _, err := ipfsRun("files", "mkdir", "-p", mfsDir); err != nil {
		return "", time.Since(start), err
	}
	if _, err := ipfsRun("files", "cp", "/ipfs/"+dataCID, mfsDir+"/data.ct"); err != nil {
		return "", time.Since(start), fmt.Errorf("link reused data.ct -> %s failed: %v", dataCID, err)
	}
	if _, err := ipfsRun("files", "cp", "/ipfs/"+lockCID, mfsDir+"/lock.ct"); err != nil {
		return "", time.Since(start), fmt.Errorf("link new lock.ct -> %s failed: %v", lockCID, err)
	}

	rootCID, err := ipfsRun("files", "stat", "--hash", mfsDir)
	if err != nil {
		return "", time.Since(start), err
	}
	if rootCID == "" {
		return "", time.Since(start), fmt.Errorf("ipfs files stat --hash returned empty RootCID")
	}

	// Keep the MFS path so the tiny root node remains reachable locally. This
	// avoids a recursive pin over the reused data DAG during policy updates.
	return rootCID, time.Since(start), nil
}

func publishTwoLinkObjectWithDataCID(dataPath, dataCID, lockPath string) (rootCID, lockCID string, elapsed time.Duration, err error) {
	start := time.Now()

	lockCID, _, err = ipfsAddObject(lockPath)
	if err != nil {
		return "", "", time.Since(start), fmt.Errorf("ipfs add lock.ct failed: %v", err)
	}

	rootCID, _, err = buildTwoLinkRootFromCIDs(dataCID, lockCID)
	if err != nil {
		return "", "", time.Since(start), err
	}

	// dataPath is intentionally not re-added here. It is kept in the signature
	// for minimal compatibility with the previous implementation and local
	// owner-state bookkeeping.
	_ = dataPath
	return rootCID, lockCID, time.Since(start), nil
}

func readOwnerState(user, rcid string) (*OwnerObjectState, string, error) {
	statePath := filepath.Join(polyLockObjectsDir, fmt.Sprintf("state_%s_%s.json", user, rcid))
	b, err := os.ReadFile(statePath)
	if err != nil {
		return nil, "", fmt.Errorf("read owner state %s: %v", statePath, err)
	}
	var st OwnerObjectState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, "", fmt.Errorf("parse owner state: %v", err)
	}
	return &st, statePath, nil
}

func writeOwnerState(user, pid, cid, objectPath, dataPartPath, lockPartPath, plainPath, dataCID, lockCID string, K []byte, footer ProtectedObjectFooter, mconfPath, lockStatePath string) error {
	state := OwnerObjectState{
		Format:          "zkguard-polylock-owner-state-v2-two-link",
		Username:        user,
		PID:             pid,
		RootCID:         cid,
		DataCID:         dataCID,
		LockCID:         lockCID,
		ObjectPath:      objectPath,
		DataPartPath:    dataPartPath,
		LockPartPath:    lockPartPath,
		PlainPath:       plainPath,
		KeyBase64:       base64.StdEncoding.EncodeToString(K),
		AttrHash:        footer.AttrHash,
		Version:         footer.Version,
		DataLen:         footer.DataLen,
		PadLen:          footer.PadLen,
		LockLen:         footer.LockLen,
		ChunkSize:       footer.ChunkSize,
		EffectiveRoots:  footer.EffectiveRoots,
		BucketCount:     footer.BucketCount,
		BucketDegree:    footer.BucketDegree,
		CreatedAt:       time.Now().Format(time.RFC3339),
		PolicyMConfPath: mconfPath,
		LockStatePath:   lockStatePath,
	}
	if err := os.MkdirAll(polyLockObjectsDir, 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(state, "", "  ")
	return os.WriteFile(filepath.Join(polyLockObjectsDir, fmt.Sprintf("state_%s_%s.json", user, cid)), b, 0o600)
}

func readLockState(path string) (*LockStateDisk, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("owner state has empty lock_state_path; rerun dataStorage with the partial-update version first")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read lock state %s: %v", path, err)
	}
	var st LockStateDisk
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("parse lock state: %v", err)
	}
	if st.RootToBucket == nil {
		st.RootToBucket = make(map[string]int)
		for _, b := range st.Buckets {
			for _, rk := range b.RootKeys {
				st.RootToBucket[rk] = b.Index
			}
		}
	}
	return &st, nil
}

func writeLockState(user, cid string, state *LockStateDisk) (string, error) {
	if state == nil {
		return "", fmt.Errorf("nil lock state")
	}
	if err := os.MkdirAll(polyLockObjectsDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(polyLockObjectsDir, fmt.Sprintf("lockstate_%s_%s.json", user, cid))
	b, _ := json.MarshalIndent(state, "", "  ")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func parseLockComponent(component []byte) ([]byte, ProtectedObjectFooter, error) {
	var footer ProtectedObjectFooter
	if len(component) < 8 {
		return nil, footer, fmt.Errorf("lock component too small")
	}
	footerLen := int(binary.BigEndian.Uint64(component[len(component)-8:]))
	if footerLen <= 0 || footerLen > len(component)-8 {
		return nil, footer, fmt.Errorf("invalid footer length %d", footerLen)
	}
	footerStart := len(component) - 8 - footerLen
	if err := json.Unmarshal(component[footerStart:len(component)-8], &footer); err != nil {
		return nil, footer, err
	}
	return component[:footerStart], footer, nil
}

func acceptedHashSetFromMConf(space [][]int, flag, selA, selO, selN []int) map[string][]int {
	out := make(map[string][]int)
	for _, bits := range space {
		if localPolicySatisfied(bits, flag, selA, selO, selN) {
			out[hashCalc(bits)] = cloneIntVector(bits)
		}
	}
	return out
}

func estimateAffectedBuckets(oldState *LockStateDisk, newHashes map[string][]int) int {
	affected := make(map[int]bool)
	oldHashes := make(map[string]bool)
	remaining := make([]int, len(oldState.Buckets))
	for i, b := range oldState.Buckets {
		remaining[i] = len(b.RootKeys)
		for _, rk := range b.RootKeys {
			h := rootKeyHash(rk)
			oldHashes[h] = true
			if _, ok := newHashes[h]; !ok {
				affected[b.Index] = true
				if b.Index >= 0 && b.Index < len(remaining) {
					remaining[b.Index]--
				}
			}
		}
	}
	additions := 0
	for h := range newHashes {
		if !oldHashes[h] {
			additions++
		}
	}
	if additions == 0 {
		return len(affected)
	}
	free := 0
	for bid := range affected {
		if bid >= 0 && bid < len(remaining) && remaining[bid] < polyLockBucketDegree {
			free += polyLockBucketDegree - remaining[bid]
		}
	}
	need := additions - free
	if need <= 0 {
		return len(affected)
	}
	for _, b := range oldState.Buckets {
		if affected[b.Index] {
			continue
		}
		if len(b.RootKeys) < polyLockBucketDegree {
			affected[b.Index] = true
			need -= polyLockBucketDegree - len(b.RootKeys)
			if need <= 0 {
				return len(affected)
			}
		}
	}
	newBuckets := int(math.Ceil(float64(need) / float64(polyLockBucketDegree)))
	return len(affected) + newBuckets
}

func mutateMConfByAffectedRatio(oldState *LockStateDisk, ratio float64, required []int) ([]int, []int, []int, []int, int, int, int) {
	if ratio <= 0 {
		ratio = 0.05
	}
	if ratio > 1 {
		ratio = 1
	}
	space := makeLegalAttributeSpace()
	targetAffected := int(math.Round(ratio * float64(len(oldState.Buckets))))
	if targetAffected < 1 {
		targetAffected = 1
	}

	active := make([]int, 0)
	for i := 0; i < IntNum; i++ {
		if oldState.SelNop[i] == 0 && (oldState.SelAnd[i] == 1 || oldState.SelOr[i] == 1) {
			active = append(active, i)
		}
	}
	if len(active) == 0 {
		active = []int{0}
	}

	bestFlag := cloneIntVector(oldState.Flag)
	bestA := cloneIntVector(oldState.SelAnd)
	bestO := cloneIntVector(oldState.SelOr)
	bestN := cloneIntVector(oldState.SelNop)
	bestMatched := countMConfMatches(space, bestFlag, bestA, bestO, bestN)
	bestAffected := estimateAffectedBuckets(oldState, acceptedHashSetFromMConf(space, bestFlag, bestA, bestO, bestN))
	bestDiff := int(^uint(0) >> 1)

	maxMut := int(math.Ceil(ratio * float64(len(active))))
	if maxMut < 1 {
		maxMut = 1
	}
	if maxMut > len(active) {
		maxMut = len(active)
	}

	for try := 0; try < 500; try++ {
		flag := cloneIntVector(oldState.Flag)
		a := cloneIntVector(oldState.SelAnd)
		o := cloneIntVector(oldState.SelOr)
		n := cloneIntVector(oldState.SelNop)
		mutCnt := 1 + mrand.Intn(maxMut)
		mrand.Shuffle(len(active), func(i, j int) { active[i], active[j] = active[j], active[i] })
		for i := 0; i < mutCnt; i++ {
			idx := active[i]
			if a[idx] == 1 {
				a[idx] = 0
				o[idx] = 1
				n[idx] = 0
			} else if o[idx] == 1 {
				o[idx] = 0
				a[idx] = 1
				n[idx] = 0
			}
		}
		if required != nil && !localPolicySatisfied(required, flag, a, o, n) {
			continue
		}
		newHashes := acceptedHashSetFromMConf(space, flag, a, o, n)
		matched := len(newHashes)
		if matched == 0 {
			continue
		}
		affected := estimateAffectedBuckets(oldState, newHashes)
		diff := int(math.Abs(float64(affected - targetAffected)))
		if diff < bestDiff || (diff == bestDiff && affected > 0) {
			bestDiff = diff
			bestFlag = flag
			bestA = a
			bestO = o
			bestN = n
			bestMatched = matched
			bestAffected = affected
			if diff == 0 {
				break
			}
		}
	}
	return bestFlag, bestA, bestO, bestN, len(space), bestMatched, bestAffected
}

func buildAcceptedProfilesFromMConf(resolver *VersionResolver, flag, selA, selO, selN []int) ([]RootProfile, error) {
	space := makeLegalAttributeSpace()
	out := make([]RootProfile, 0)
	seen := make(map[string]bool)
	for _, bits := range space {
		if !localPolicySatisfied(bits, flag, selA, selO, selN) {
			continue
		}
		attrHash := hashCalc(bits)
		ver := resolver.Resolve(attrHash)
		key := fmt.Sprintf("%s:%d", attrHash, ver)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, RootProfile{Bits: cloneIntVector(bits), AttrHash: attrHash, Version: ver, RootKey: key})
	}
	return out, nil
}

func cloneLockCT(ct *PolyLockOnlyCT) *PolyLockOnlyCT {
	out := &PolyLockOnlyCT{SubLocks: make([][][]byte, len(ct.SubLocks))}
	for i := range ct.SubLocks {
		out.SubLocks[i] = make([][]byte, len(ct.SubLocks[i]))
		for j := range ct.SubLocks[i] {
			out.SubLocks[i][j] = append([]byte(nil), ct.SubLocks[i][j]...)
		}
	}
	return out
}

func partialRefreshLock(pp *PolyPublicParams, oldState *LockStateDisk, oldCT *PolyLockOnlyCT, profiles []RootProfile, K []byte) (*PolyLockOnlyCT, *LockStateDisk, *PartialUpdateStats, error) {
	startTotal := time.Now()
	startLocate := time.Now()

	newCT := cloneLockCT(oldCT)
	newState := &LockStateDisk{
		Format:       "zkguard-polylock-lock-state-v1",
		AttrNum:      AttrNum,
		BucketDegree: polyLockBucketDegree,
		LegalConfigs: oldState.LegalConfigs,
		Flag:         cloneIntVector(oldState.Flag),
		SelAnd:       cloneIntVector(oldState.SelAnd),
		SelOr:        cloneIntVector(oldState.SelOr),
		SelNop:       cloneIntVector(oldState.SelNop),
		Buckets:      make([]BucketStateDisk, len(oldState.Buckets)),
		RootToBucket: make(map[string]int),
		CreatedAt:    time.Now().Format(time.RFC3339),
	}
	for i := range oldState.Buckets {
		newState.Buckets[i] = BucketStateDisk{Index: oldState.Buckets[i].Index, Roots: cloneIntVectors(oldState.Buckets[i].Roots), RootKeys: append([]string(nil), oldState.Buckets[i].RootKeys...)}
	}

	newMap := make(map[string]RootProfile)
	for _, rp := range profiles {
		newMap[rp.RootKey] = rp
	}
	oldMap := make(map[string]int)
	for _, b := range oldState.Buckets {
		for _, rk := range b.RootKeys {
			oldMap[rk] = b.Index
		}
	}

	affected := make(map[int]bool)
	deltaRm := 0
	for bi := range newState.Buckets {
		b := &newState.Buckets[bi]
		keptRoots := make([][]int, 0, len(b.Roots))
		keptKeys := make([]string, 0, len(b.RootKeys))
		for i, rk := range b.RootKeys {
			if _, ok := newMap[rk]; ok {
				keptRoots = append(keptRoots, b.Roots[i])
				keptKeys = append(keptKeys, rk)
			} else {
				affected[b.Index] = true
				deltaRm++
			}
		}
		b.Roots = keptRoots
		b.RootKeys = keptKeys
	}

	deltaAdd := 0
	placeProfile := func(rp RootProfile, preferAffected bool) bool {
		for bi := range newState.Buckets {
			b := &newState.Buckets[bi]
			if preferAffected && !affected[b.Index] {
				continue
			}
			if len(b.RootKeys) < polyLockBucketDegree {
				b.Roots = append(b.Roots, cloneIntVector(rp.Bits))
				b.RootKeys = append(b.RootKeys, rp.RootKey)
				affected[b.Index] = true
				return true
			}
		}
		return false
	}
	for _, rp := range profiles {
		if _, ok := oldMap[rp.RootKey]; ok {
			continue
		}
		if !placeProfile(rp, true) && !placeProfile(rp, false) {
			bid := len(newState.Buckets)
			newState.Buckets = append(newState.Buckets, BucketStateDisk{Index: bid, Roots: [][]int{cloneIntVector(rp.Bits)}, RootKeys: []string{rp.RootKey}})
			newCT.SubLocks = append(newCT.SubLocks, nil)
			affected[bid] = true
		}
		deltaAdd++
	}
	for _, b := range newState.Buckets {
		for _, rk := range b.RootKeys {
			newState.RootToBucket[rk] = b.Index
		}
	}
	newState.EffectiveRoots = len(profiles)
	newState.BucketCount = len(newState.Buckets)
	locateTime := time.Since(startLocate)

	affectedIDs := make([]int, 0, len(affected))
	for bid := range affected {
		affectedIDs = append(affectedIDs, bid)
	}
	sort.Ints(affectedIDs)

	startRecompile := time.Now()
	affectedBuckets := make([]BucketStateDisk, 0, len(affectedIDs))
	for _, bid := range affectedIDs {
		if bid < 0 || bid >= len(newState.Buckets) {
			continue
		}
		affectedBuckets = append(affectedBuckets, newState.Buckets[bid])
	}
	compiledList := compileBucketDisksParallel(pp, affectedBuckets)
	recompileTime := time.Since(startRecompile)

	startReEncaps := time.Now()
	newSubLocks := encapsCompiledBucketsParallel(pp, K, compiledList)
	for i, bid := range affectedIDs {
		if bid < 0 {
			continue
		}
		for bid >= len(newCT.SubLocks) {
			newCT.SubLocks = append(newCT.SubLocks, nil)
		}
		newCT.SubLocks[bid] = newSubLocks[i]
	}
	reEncapsTime := time.Since(startReEncaps)
	return newCT, newState, &PartialUpdateStats{AffectedBuckets: len(affectedIDs), DeltaAdd: deltaAdd, DeltaRm: deltaRm, LocateTime: locateTime, RecompileTime: recompileTime, ReEncapsTime: reEncapsTime, TotalTime: time.Since(startTotal)}, nil
}

func rootKeyVersion(rootKey string) uint64 {
	idx := strings.LastIndex(rootKey, ":")
	if idx < 0 || idx+1 >= len(rootKey) {
		return 0
	}
	var ver uint64
	_, _ = fmt.Sscanf(rootKey[idx+1:], "%d", &ver)
	return ver
}

func countRootsInLockState(state *LockStateDisk) int {
	cnt := 0
	for _, b := range state.Buckets {
		cnt += len(b.RootKeys)
	}
	return cnt
}

func cloneLockStateForUpdate(oldState *LockStateDisk) *LockStateDisk {
	newState := &LockStateDisk{
		Format:         "zkguard-polylock-lock-state-v1",
		AttrNum:        AttrNum,
		BucketDegree:   polyLockBucketDegree,
		LegalConfigs:   oldState.LegalConfigs,
		EffectiveRoots: oldState.EffectiveRoots,
		BucketCount:    oldState.BucketCount,
		Flag:           cloneIntVector(oldState.Flag),
		SelAnd:         cloneIntVector(oldState.SelAnd),
		SelOr:          cloneIntVector(oldState.SelOr),
		SelNop:         cloneIntVector(oldState.SelNop),
		Buckets:        make([]BucketStateDisk, len(oldState.Buckets)),
		RootToBucket:   make(map[string]int),
		CreatedAt:      time.Now().Format(time.RFC3339),
	}
	for i := range oldState.Buckets {
		newState.Buckets[i] = BucketStateDisk{
			Index:    oldState.Buckets[i].Index,
			Roots:    cloneIntVectors(oldState.Buckets[i].Roots),
			RootKeys: append([]string(nil), oldState.Buckets[i].RootKeys...),
		}
	}
	for _, b := range newState.Buckets {
		for _, rk := range b.RootKeys {
			newState.RootToBucket[rk] = b.Index
		}
	}
	return newState
}

func rebuildRootToBucket(state *LockStateDisk) {
	state.RootToBucket = make(map[string]int)
	for _, b := range state.Buckets {
		for _, rk := range b.RootKeys {
			state.RootToBucket[rk] = b.Index
		}
	}
	state.EffectiveRoots = countRootsInLockState(state)
	state.BucketCount = len(state.Buckets)
	state.CreatedAt = time.Now().Format(time.RFC3339)
}

func firstRemovableRootIndex(b BucketStateDisk, protected map[string]bool) int {
	for i, rk := range b.RootKeys {
		if !protected[rk] {
			return i
		}
	}
	return -1
}

func compileBucketFromDisk(pp *PolyPublicParams, b BucketStateDisk) []ring.Poly {
	roots := make([]ring.Poly, 0, len(b.Roots))
	for i, bits := range b.Roots {
		ver := uint64(0)
		if i < len(b.RootKeys) {
			ver = rootKeyVersion(b.RootKeys[i])
		}
		roots = append(roots, hashToPointVersioned(pp, bits, ver))
	}
	return compileRootBucket(pp, roots)
}

func buildReplacementProfiles(resolver *VersionResolver, oldState *LockStateDisk, protected map[string]bool, need int) ([]RootProfile, int, error) {
	space := makeLegalAttributeSpace()
	used := make(map[string]bool)
	for _, b := range oldState.Buckets {
		for _, rk := range b.RootKeys {
			used[rk] = true
		}
	}
	out := make([]RootProfile, 0, need)
	for _, bits := range space {
		attrHash := hashCalc(bits)
		ver := resolver.Resolve(attrHash)
		rootKey := fmt.Sprintf("%s:%d", attrHash, ver)
		if used[rootKey] || protected[rootKey] {
			continue
		}
		used[rootKey] = true
		out = append(out, RootProfile{Bits: cloneIntVector(bits), AttrHash: attrHash, Version: ver, RootKey: rootKey})
		if len(out) >= need {
			break
		}
	}
	if len(out) < need {
		return nil, len(space), fmt.Errorf("not enough replacement profiles: need=%d got=%d", need, len(out))
	}
	return out, len(space), nil
}

func partialRefreshLockByBucketRatio(pp *PolyPublicParams, oldState *LockStateDisk, oldCT *PolyLockOnlyCT, K []byte, affectedRatio float64, resolver *VersionResolver, protected map[string]bool) (*PolyLockOnlyCT, *LockStateDisk, *PartialUpdateStats, int, int, error) {
	if affectedRatio <= 0 {
		affectedRatio = 0.05
	}
	if affectedRatio > 1 {
		affectedRatio = 1
	}
	bucketCount := len(oldState.Buckets)
	if bucketCount == 0 {
		return nil, nil, nil, 0, 0, fmt.Errorf("empty lock state")
	}
	targetAffected := int(math.Round(affectedRatio * float64(bucketCount)))
	if targetAffected < 1 {
		targetAffected = 1
	}
	if targetAffected > bucketCount {
		targetAffected = bucketCount
	}

	selected := make([]int, 0, targetAffected)
	for _, b := range oldState.Buckets {
		if len(selected) >= targetAffected {
			break
		}
		if len(b.RootKeys) == 0 {
			continue
		}
		if firstRemovableRootIndex(b, protected) >= 0 {
			selected = append(selected, b.Index)
		}
	}
	if len(selected) == 0 {
		return nil, nil, nil, targetAffected, 0, fmt.Errorf("no removable bucket found; protected roots may occupy all buckets")
	}

	replacements, legalConfigs, err := buildReplacementProfiles(resolver, oldState, protected, len(selected))
	if err != nil {
		return nil, nil, nil, targetAffected, 0, err
	}

	startTotal := time.Now()
	startLocate := time.Now()
	newCT := cloneLockCT(oldCT)
	newState := cloneLockStateForUpdate(oldState)

	posByIndex := make(map[int]int)
	for pos, b := range newState.Buckets {
		posByIndex[b.Index] = pos
	}
	deltaRm := 0
	deltaAdd := 0
	for i, bid := range selected {
		pos, ok := posByIndex[bid]
		if !ok {
			return nil, nil, nil, targetAffected, legalConfigs, fmt.Errorf("selected bucket %d not found", bid)
		}
		b := &newState.Buckets[pos]
		removeIdx := firstRemovableRootIndex(*b, protected)
		if removeIdx < 0 {
			continue
		}
		b.Roots = append(append([][]int(nil), b.Roots[:removeIdx]...), b.Roots[removeIdx+1:]...)
		b.RootKeys = append(append([]string(nil), b.RootKeys[:removeIdx]...), b.RootKeys[removeIdx+1:]...)
		deltaRm++

		rp := replacements[i]
		b.Roots = append(b.Roots, cloneIntVector(rp.Bits))
		b.RootKeys = append(b.RootKeys, rp.RootKey)
		deltaAdd++
	}
	rebuildRootToBucket(newState)
	locateTime := time.Since(startLocate)

	affectedIDs := append([]int(nil), selected...)
	sort.Ints(affectedIDs)

	startRecompile := time.Now()
	affectedBuckets := make([]BucketStateDisk, 0, len(affectedIDs))
	for _, bid := range affectedIDs {
		pos, ok := posByIndex[bid]
		if !ok {
			continue
		}
		affectedBuckets = append(affectedBuckets, newState.Buckets[pos])
	}
	compiledList := compileBucketDisksParallel(pp, affectedBuckets)
	recompileTime := time.Since(startRecompile)

	startReEncaps := time.Now()
	newSubLocks := encapsCompiledBucketsParallel(pp, K, compiledList)
	for i, bid := range affectedIDs {
		if bid < 0 || bid >= len(newCT.SubLocks) {
			return nil, nil, nil, targetAffected, legalConfigs, fmt.Errorf("SubLocks index out of range: %d", bid)
		}
		newCT.SubLocks[bid] = newSubLocks[i]
	}
	reEncapsTime := time.Since(startReEncaps)

	stats := &PartialUpdateStats{
		AffectedBuckets: len(affectedIDs),
		DeltaAdd:        deltaAdd,
		DeltaRm:         deltaRm,
		LocateTime:      locateTime,
		RecompileTime:   recompileTime,
		ReEncapsTime:    reEncapsTime,
		TotalTime:       time.Since(startTotal),
	}
	return newCT, newState, stats, targetAffected, legalConfigs, nil
}

func fullRefreshLockAllBuckets(pp *PolyPublicParams, state *LockStateDisk, oldCT *PolyLockOnlyCT, K []byte) (*PolyLockOnlyCT, *PartialUpdateStats, error) {
	startTotal := time.Now()
	newCT := cloneLockCT(oldCT)

	startRecompile := time.Now()
	buckets := append([]BucketStateDisk(nil), state.Buckets...)
	compiledList := compileBucketDisksParallel(pp, buckets)
	recompileTime := time.Since(startRecompile)

	startReEncaps := time.Now()
	newSubLocks := encapsCompiledBucketsParallel(pp, K, compiledList)
	for i, b := range buckets {
		if b.Index < 0 || b.Index >= len(newCT.SubLocks) {
			return nil, nil, fmt.Errorf("SubLocks index out of range in full refresh: %d", b.Index)
		}
		newCT.SubLocks[b.Index] = newSubLocks[i]
	}
	reEncapsTime := time.Since(startReEncaps)

	stats := &PartialUpdateStats{
		AffectedBuckets: len(state.Buckets),
		LocateTime:      0,
		RecompileTime:   recompileTime,
		ReEncapsTime:    reEncapsTime,
		TotalTime:       time.Since(startTotal),
	}
	return newCT, stats, nil
}

func parseVersion(verBytes []byte, fallback uint64) uint64 {
	verBI, ok := new(big.Int).SetString(strings.TrimSpace(string(verBytes)), 10)
	if !ok {
		return fallback
	}
	return verBI.Uint64()
}

func loadSystemProfileSpace() (*SystemConfigDisk, [][]int, error) {
	configPath := filepath.Join(polyLockSystemDir, "system_config.json")
	cfgBytes, err := os.ReadFile(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read system config %s: %v; run systemInit first", configPath, err)
	}
	var cfg SystemConfigDisk
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		return nil, nil, fmt.Errorf("parse system config: %v", err)
	}
	if cfg.AttrNum != AttrNum {
		return nil, nil, fmt.Errorf("system AttrNum mismatch: config=%d binary=%d", cfg.AttrNum, AttrNum)
	}
	profilePath := strings.TrimSpace(cfg.ProfileSpacePath)
	if profilePath == "" {
		profilePath = filepath.Join(polyLockSystemDir, "profile_space.json")
	}
	profileBytes, err := os.ReadFile(profilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("read profile space %s: %v", profilePath, err)
	}
	var disk SystemProfileSpaceDisk
	if err := json.Unmarshal(profileBytes, &disk); err != nil {
		return nil, nil, fmt.Errorf("parse profile space: %v", err)
	}
	if disk.AttrNum != AttrNum {
		return nil, nil, fmt.Errorf("profile space AttrNum mismatch: file=%d binary=%d", disk.AttrNum, AttrNum)
	}
	if len(disk.Profiles) == 0 {
		return nil, nil, fmt.Errorf("empty profile space")
	}
	for i, bits := range disk.Profiles {
		if len(bits) != AttrNum {
			return nil, nil, fmt.Errorf("profile_space[%d] length=%d expect=%d", i, len(bits), AttrNum)
		}
	}
	if cfg.ProfileTotal != 0 && cfg.ProfileTotal != len(disk.Profiles) {
		fmt.Printf("[WARN] profile_total mismatch: config=%d actual=%d\n", cfg.ProfileTotal, len(disk.Profiles))
	}
	return &cfg, disk.Profiles, nil
}

func loadRequesterProfile(user string, profileSpace [][]int) ([]int, string, error) {
	uskPath := filepath.Join("./polylock_state", fmt.Sprintf("polylock_usk_%s.json", user))
	b, err := os.ReadFile(uskPath)
	if err == nil {
		var usk PolyLockUSKDisk
		if err := json.Unmarshal(b, &usk); err != nil {
			return nil, "", fmt.Errorf("parse PolyLock USK %s: %v", uskPath, err)
		}
		if len(usk.AttrVector) != AttrNum {
			return nil, "", fmt.Errorf("USK attr vector length=%d expect=%d", len(usk.AttrVector), AttrNum)
		}
		computed := hashCalc(usk.AttrVector)
		if strings.TrimSpace(usk.AttrHash) != "" && strings.TrimSpace(usk.AttrHash) != computed {
			return nil, "", fmt.Errorf("USK attr_hash mismatch: file=%s computed=%s", usk.AttrHash, computed)
		}
		return cloneIntVector(usk.AttrVector), computed, nil
	}
	if len(profileSpace) == 0 {
		return nil, "", fmt.Errorf("empty profile space and cannot read %s", uskPath)
	}
	bits := cloneIntVector(profileSpace[0])
	return bits, hashCalc(bits), nil
}

func buildRandomMConfCandidate(selected []bool, probAND float64) ([]int, []int, []int, []int) {
	flag := make([]int, AttrNum)
	andS := make([]int, IntNum)
	orS := make([]int, IntNum)
	nopS := make([]int, IntNum)
	has := make([]bool, TotalNode)
	for i := 0; i < AttrNum; i++ {
		if selected[i] {
			flag[i] = 1
			has[IntNum+i] = true
		}
	}
	for i := IntNum - 1; i >= 0; i-- {
		left := has[2*i+1]
		right := has[2*i+2]
		has[i] = left || right
		switch {
		case !left && !right:
			nopS[i] = 1
		case left && !right:
			nopS[i] = 1
		case !left && right:
			orS[i] = 1
		default:
			if mrand.Float64() < probAND {
				andS[i] = 1
			} else {
				orS[i] = 1
			}
		}
	}
	return flag, andS, orS, nopS
}

func acceptedProfilesFromMConf(space [][]int, flag, selA, selO, selN []int) [][]int {
	out := make([][]int, 0)
	for _, bits := range space {
		if localPolicySatisfied(bits, flag, selA, selO, selN) {
			out = append(out, cloneIntVector(bits))
		}
	}
	return out
}

func addCandidateIfBetter(space [][]int, required []int, targetCount int, flag, selA, selO, selN []int, best *struct {
	flag, a, o, n []int
	accepted      [][]int
	diff          int
	attempts      int
}) {
	if required != nil && !localPolicySatisfied(required, flag, selA, selO, selN) {
		return
	}
	accepted := acceptedProfilesFromMConf(space, flag, selA, selO, selN)
	if len(accepted) == 0 {
		return
	}
	diff := int(math.Abs(float64(len(accepted) - targetCount)))
	if best.accepted == nil || diff < best.diff || (diff == best.diff && mrand.Intn(5) == 0) {
		best.diff = diff
		best.flag = cloneIntVector(flag)
		best.a = cloneIntVector(selA)
		best.o = cloneIntVector(selO)
		best.n = cloneIntVector(selN)
		best.accepted = accepted
	}
}

func attributeFrequencies(space [][]int) []int {
	freq := make([]int, AttrNum)
	for _, bits := range space {
		for i, b := range bits {
			if b == 1 {
				freq[i]++
			}
		}
	}
	return freq
}

func generateUnifiedMConfPolicyFromSpace(space [][]int, targetSigma float64, required []int) ([]int, []int, []int, []int, [][]int, PolicyGenStats, error) {
	if len(space) == 0 {
		return nil, nil, nil, nil, nil, PolicyGenStats{}, fmt.Errorf("empty profile space")
	}
	if targetSigma <= 0 {
		targetSigma = 0.1
	}
	if targetSigma > 1 {
		targetSigma = 1
	}
	targetCount := int(math.Round(float64(len(space)) * targetSigma))
	if targetCount < 1 {
		targetCount = 1
	}
	best := &struct {
		flag, a, o, n []int
		accepted      [][]int
		diff          int
		attempts      int
	}{diff: int(^uint(0) >> 1)}

	freq := attributeFrequencies(space)
	idxDesc := make([]int, AttrNum)
	idxAsc := make([]int, AttrNum)
	for i := 0; i < AttrNum; i++ {
		idxDesc[i] = i
		idxAsc[i] = i
	}
	sort.Slice(idxDesc, func(i, j int) bool { return freq[idxDesc[i]] > freq[idxDesc[j]] })
	sort.Slice(idxAsc, func(i, j int) bool { return freq[idxAsc[i]] < freq[idxAsc[j]] })

	trySelected := func(indices []int, k int, probAND float64) {
		if k < 1 {
			k = 1
		}
		if k > len(indices) {
			k = len(indices)
		}
		selected := make([]bool, AttrNum)
		for i := 0; i < k; i++ {
			selected[indices[i]] = true
		}
		if required != nil {
			// Keep the requester authorized whenever possible. For OR-like candidates,
			// it is enough to include one active requester attribute.
			any := false
			for i, v := range required {
				if v == 1 && selected[i] {
					any = true
					break
				}
			}
			if !any {
				for i, v := range required {
					if v == 1 {
						selected[i] = true
						break
					}
				}
			}
		}
		flag, a, o, n := buildRandomMConfCandidate(selected, probAND)
		best.attempts++
		addCandidateIfBetter(space, required, targetCount, flag, a, o, n, best)
	}

	// Deterministic OR candidates over frequent and rare attributes give a stable
	// sigma control similar to the standalone PolyLock experiment.
	for k := 1; k <= AttrNum; k++ {
		trySelected(idxDesc, k, 0.0)
		trySelected(idxAsc, k, 0.0)
		if best.diff == 0 {
			break
		}
	}

	// AND candidates over requester-active attributes help low-sigma cases while
	// preserving requester authorization.
	if required != nil {
		active := make([]int, 0)
		for i, v := range required {
			if v == 1 {
				active = append(active, i)
			}
		}
		sort.Slice(active, func(i, j int) bool { return freq[active[i]] > freq[active[j]] })
		for k := 1; k <= len(active); k++ {
			trySelected(active, k, 1.0)
			if best.diff == 0 {
				break
			}
		}
	}

	// Random mconf-compatible formulas provide additional candidates beyond pure
	// OR/AND forms. PolicyGen time is treated as an offline policy-design cost.
	maxRetries := 2500
	currentProbAND := 0.5
	for t := 0; t < maxRetries; t++ {
		selected := make([]bool, AttrNum)
		k := 1 + mrand.Intn(AttrNum)
		perm := mrand.Perm(AttrNum)
		for i := 0; i < k; i++ {
			selected[perm[i]] = true
		}
		if required != nil && mrand.Float64() < 0.7 {
			for i, v := range required {
				if v == 1 && mrand.Float64() < 0.25 {
					selected[i] = true
				}
			}
		}
		flag, a, o, n := buildRandomMConfCandidate(selected, currentProbAND)
		best.attempts++
		beforeDiff := best.diff
		addCandidateIfBetter(space, required, targetCount, flag, a, o, n, best)
		if len(best.accepted) > 0 {
			if len(best.accepted) < targetCount {
				currentProbAND -= 0.05
			} else if beforeDiff == best.diff {
				currentProbAND += 0.05
			}
		}
		if currentProbAND < 0.0 {
			currentProbAND = 0.0
		}
		if currentProbAND > 1.0 {
			currentProbAND = 1.0
		}
	}

	if best.accepted == nil {
		return nil, nil, nil, nil, nil, PolicyGenStats{}, fmt.Errorf("PolicyGen failed: no satisfiable mconf candidate")
	}
	stats := PolicyGenStats{
		LegalConfigs: len(space),
		TargetCount:  targetCount,
		Matched:      len(best.accepted),
		Attempts:     best.attempts,
		TargetSigma:  targetSigma,
		ActualSigma:  float64(len(best.accepted)) / float64(len(space)),
		BestDiff:     best.diff,
	}
	return best.flag, best.a, best.o, best.n, best.accepted, stats, nil
}

func buildRootProfilesFromAccepted(resolver *VersionResolver, accepted [][]int) ([]RootProfile, error) {
	out := make([]RootProfile, 0, len(accepted))
	seen := make(map[string]bool)
	for _, bits := range accepted {
		attrHash := hashCalc(bits)
		ver := resolver.Resolve(attrHash)
		rootKey := fmt.Sprintf("%s:%d", attrHash, ver)
		if seen[rootKey] {
			continue
		}
		seen[rootKey] = true
		out = append(out, RootProfile{Bits: cloneIntVector(bits), AttrHash: attrHash, Version: ver, RootKey: rootKey})
	}
	return out, nil
}

func writeObjectMConf(user, cid string, mjson []byte) (string, error) {
	if err := os.MkdirAll(polyLockObjectsDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(polyLockObjectsDir, fmt.Sprintf("mconf_%s_%s.b64", user, cid))
	if err := os.WriteFile(path, []byte(gzipB64(mjson)), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func writePolicyState(user, cid string, cfg *SystemConfigDisk, flag, selA, selO, selN []int, pg PolicyGenStats, affected int, oldBucketCount int, observedRatio float64) (string, error) {
	if err := os.MkdirAll(polyLockObjectsDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(polyLockObjectsDir, fmt.Sprintf("policy_%s_%s.json", user, cid))
	ps := PolicyStateDisk{
		Format:              "zkguard-polylock-policy-state-v1",
		RootCID:             cid,
		Username:            user,
		TargetSigma:         pg.TargetSigma,
		ActualSigma:         pg.ActualSigma,
		LegalConfigs:        pg.LegalConfigs,
		TargetCount:         pg.TargetCount,
		Matched:             pg.Matched,
		ObservedBucketRatio: observedRatio,
		AffectedBuckets:     affected,
		OldBucketCount:      oldBucketCount,
		Flag:                cloneIntVector(flag),
		SelAnd:              cloneIntVector(selA),
		SelOr:               cloneIntVector(selO),
		SelNop:              cloneIntVector(selN),
		CreatedAt:           time.Now().Format(time.RFC3339),
	}
	if cfg != nil {
		ps.SystemSpaceDigest = cfg.SpaceDigest
	}
	b, _ := json.MarshalIndent(ps, "", "  ")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func rebuildPolyLockObjectForFullPolicyUpdate(oldCID, pid, user string, contract *client.Contract) (newCID string, newMJSON []byte, t time.Duration, err error) {
	start := time.Now()
	state, statePath, err := readOwnerState(user, oldCID)
	if err != nil {
		return "", nil, 0, err
	}
	if state.PID != "" && state.PID != pid {
		return "", nil, 0, fmt.Errorf("owner state pid mismatch: state=%s input=%s", state.PID, pid)
	}

	paddedData, err := os.ReadFile(state.DataPartPath)
	if err != nil {
		return "", nil, 0, fmt.Errorf("read padded data part: %v", err)
	}
	if len(paddedData)%ipfsChunkSize != 0 {
		return "", nil, 0, fmt.Errorf("padded data is not 256KB-aligned: len=%d", len(paddedData))
	}
	K, err := base64.StdEncoding.DecodeString(state.KeyBase64)
	if err != nil {
		return "", nil, 0, fmt.Errorf("decode stored data key: %v", err)
	}
	if len(K) != polyLockKeySize {
		return "", nil, 0, fmt.Errorf("invalid stored key size: %d", len(K))
	}

	verMap, err := queryAllConfigVersions(contract)
	if err != nil {
		return "", nil, 0, fmt.Errorf("QueryAllConfigVersions failed: %v", err)
	}
	resolver := NewVersionResolver(verMap)

	ownerAttr := makeDefaultValidAttrVector()
	attrHash := hashCalc(ownerAttr)
	ver := resolver.Resolve(attrHash)

	pp, err := polySetup()
	if err != nil {
		return "", nil, 0, err
	}

	startPolicy := time.Now()
	var policy *PNode
	var flag, selA, selO, selN []int
	legalConfigs := 0
	pnodeMatches := 0
	mconfOK := false
	for retry := 0; retry < 50; retry++ {
		policy, legalConfigs, pnodeMatches = generatePolyLockPolicy(polyLockTargetSigma, ownerAttr)
		flag, selA, selO, selN = encodePolicy(policy)
		if localPolicySatisfied(ownerAttr, flag, selA, selO, selN) {
			mconfOK = true
			break
		}
	}
	if !mconfOK {
		return "", nil, 0, fmt.Errorf("generated full-update mconf does not authorize owner/default profile")
	}
	mjson, _ := json.Marshal(struct{ Flag, SelAnd, SelOr, SelNop []int }{flag, selA, selO, selN})
	policyTime := time.Since(startPolicy)

	startPre := time.Now()
	bucketCoeffs, newLockState, stats, err := preResolvePolicyBucketsFromMConf(pp, flag, selA, selO, selN, resolver)
	if err != nil {
		return "", nil, 0, err
	}
	preResolveTime := time.Since(startPre)

	startEnc := time.Now()
	lockBytes, err := encapsLockForExistingKey(pp, K, bucketCoeffs)
	if err != nil {
		return "", nil, 0, err
	}
	fullEncapsTime := time.Since(startEnc)

	_, footer, err := buildProtectedObjectFromPadded(paddedData, state.DataLen, state.PadLen, lockBytes, attrHash, ver)
	if err != nil {
		return "", nil, 0, err
	}
	footer.EffectiveRoots = stats.EffectiveRoots
	footer.BucketCount = stats.BucketCount
	footer.BucketDegree = polyLockBucketDegree
	lockComponent, err := buildLockComponent(lockBytes, footer)
	if err != nil {
		return "", nil, 0, err
	}

	dataCID := strings.TrimSpace(state.DataCID)
	var tDataAdd time.Duration
	if dataCID == "" {
		fmt.Printf("[WARN] owner state has no DataCID; fallback to ipfs add existing data.ct\n")
		dataCID, tDataAdd, err = ipfsAddObject(state.DataPartPath)
		if err != nil {
			return "", nil, 0, fmt.Errorf("fallback ipfs add data.ct failed: %v", err)
		}
	}

	tag := fmt.Sprintf("%s_fullpolicy_%d", user, time.Now().UnixNano())
	rootDirPath := filepath.Join(polyLockObjectsDir, "root_"+tag)
	lockPartPath := filepath.Join(rootDirPath, "lock.ct")
	if err := os.MkdirAll(rootDirPath, 0o755); err != nil {
		return "", nil, 0, err
	}
	if err := os.WriteFile(lockPartPath, lockComponent, 0o600); err != nil {
		return "", nil, 0, err
	}
	cid, lockCID, tIPFSAdd, err := publishTwoLinkObjectWithDataCID(state.DataPartPath, dataCID, lockPartPath)
	if err != nil {
		return "", nil, 0, err
	}
	tIPFSAdd += tDataAdd

	lockStatePath, err := writeLockState(user, cid, newLockState)
	if err != nil {
		return "", nil, 0, err
	}
	if err := writeOwnerState(user, pid, cid, rootDirPath, state.DataPartPath, lockPartPath, state.PlainPath, dataCID, lockCID, K, footer, "", lockStatePath); err != nil {
		return "", nil, 0, err
	}

	excludedPolicyGenTime += policyTime
	fullObjectTime := time.Since(start) - policyTime
	fmt.Printf("✓ PolyLock full policy object refreshed\n")
	fmt.Printf("  Old owner state : %s\n", statePath)
	fmt.Printf("  New lock state  : %s\n", lockStatePath)
	fmt.Printf("  Old RootCID     : %s\n", oldCID)
	fmt.Printf("  New RootCID     : %s\n", cid)
	fmt.Printf("  DataCID reused  : %s\n", dataCID)
	fmt.Printf("  New LockCID     : %s\n", lockCID)
	fmt.Printf("  Policy target   : %.3f\n", polyLockTargetSigma)
	fmt.Printf("  Legal configs   : %d\n", legalConfigs)
	fmt.Printf("  PNode matches   : %d\n", pnodeMatches)
	fmt.Printf("  Effective roots : %d\n", stats.EffectiveRoots)
	fmt.Printf("  Lock buckets    : %d x degree<=%d\n", stats.BucketCount, polyLockBucketDegree)
	fmt.Printf("  IPFSAddTime     : %.3f ms\n", float64(tIPFSAdd.Microseconds())/1000)
	fmt.Printf("  New CT_lock     : %.3f KB\n", float64(len(lockComponent))/1024.0)
	fmt.Printf("  FullPreResolve  : %.3f ms\n", float64(preResolveTime.Microseconds())/1000)
	fmt.Printf("  FullReEncaps    : %.3f ms\n", float64(fullEncapsTime.Microseconds())/1000)
	fmt.Printf("  FullObjectTotal : %.3f ms\n", float64(fullObjectTime.Microseconds())/1000)
	fmt.Printf("  Version         : %d\n", ver)
	return cid, mjson, fullObjectTime, nil
}

func rebuildPolyLockObjectForPolicyUpdate(oldCID, pid, user string, affectedRatio float64, contract *client.Contract) (newCID string, newMJSON []byte, t time.Duration, err error) {
	start := time.Now()
	state, statePath, err := readOwnerState(user, oldCID)
	if err != nil {
		return "", nil, 0, err
	}
	if state.PID != "" && state.PID != pid {
		return "", nil, 0, fmt.Errorf("owner state pid mismatch: state=%s input=%s", state.PID, pid)
	}
	lockState, err := readLockState(state.LockStatePath)
	if err != nil {
		return "", nil, 0, err
	}

	paddedData, err := os.ReadFile(state.DataPartPath)
	if err != nil {
		return "", nil, 0, fmt.Errorf("read padded data part: %v", err)
	}
	if len(paddedData)%ipfsChunkSize != 0 {
		return "", nil, 0, fmt.Errorf("padded data is not 256KB-aligned: len=%d", len(paddedData))
	}
	K, err := base64.StdEncoding.DecodeString(state.KeyBase64)
	if err != nil {
		return "", nil, 0, fmt.Errorf("decode stored data key: %v", err)
	}
	if len(K) != polyLockKeySize {
		return "", nil, 0, fmt.Errorf("invalid stored key size: %d", len(K))
	}

	oldLockComponent, err := os.ReadFile(state.LockPartPath)
	if err != nil {
		return "", nil, 0, fmt.Errorf("read old lock.ct: %v", err)
	}
	oldLockBytes, _, err := parseLockComponent(oldLockComponent)
	if err != nil {
		return "", nil, 0, fmt.Errorf("parse old lock.ct: %v", err)
	}
	oldLockCT, err := unmarshalPolyLockCT(oldLockBytes)
	if err != nil {
		return "", nil, 0, fmt.Errorf("parse old PolyLock CT: %v", err)
	}
	if len(oldLockCT.SubLocks) != len(lockState.Buckets) {
		return "", nil, 0, fmt.Errorf("lock state / ciphertext bucket mismatch: state=%d ct=%d", len(lockState.Buckets), len(oldLockCT.SubLocks))
	}

	verMap, err := queryAllConfigVersions(contract)
	if err != nil {
		return "", nil, 0, fmt.Errorf("QueryAllConfigVersions failed: %v", err)
	}
	resolver := NewVersionResolver(verMap)

	ownerAttr := makeDefaultValidAttrVector()
	attrHash := hashCalc(ownerAttr)
	ver := resolver.Resolve(attrHash)
	ownerKey := fmt.Sprintf("%s:%d", attrHash, ver)
	if !localPolicySatisfied(ownerAttr, lockState.Flag, lockState.SelAnd, lockState.SelOr, lockState.SelNop) {
		return "", nil, 0, fmt.Errorf("owner/default profile does not satisfy stored mconf; cannot keep requester authorized")
	}

	// 最小系统原型：这里采用受控的 bucket-level 策略差分来表示策略修改幅度。
	// mconf 保持旧语义，保证 zk-Guard 侧仍能授权默认测试用户；
	// PolyLock 锁集合按 affectedRatio 替换指定比例 bucket 中的 roots，并在同一新锁集合上测量 partial/full 两种刷新方式。
	mjson, _ := json.Marshal(struct{ Flag, SelAnd, SelOr, SelNop []int }{lockState.Flag, lockState.SelAnd, lockState.SelOr, lockState.SelNop})

	pp, err := polySetup()
	if err != nil {
		return "", nil, 0, err
	}

	protected := map[string]bool{ownerKey: true}
	newLockCT, newLockState, partialStats, targetAffected, legalConfigs, err := partialRefreshLockByBucketRatio(pp, lockState, oldLockCT, K, affectedRatio, resolver, protected)
	if err != nil {
		return "", nil, 0, err
	}
	_, fullStats, err := fullRefreshLockAllBuckets(pp, newLockState, oldLockCT, K)
	if err != nil {
		return "", nil, 0, err
	}

	lockBytes, err := marshalPolyLockCTBinary(newLockCT)
	if err != nil {
		return "", nil, 0, err
	}
	_, footer, err := buildProtectedObjectFromPadded(paddedData, state.DataLen, state.PadLen, lockBytes, attrHash, ver)
	if err != nil {
		return "", nil, 0, err
	}
	footer.EffectiveRoots = newLockState.EffectiveRoots
	footer.BucketCount = len(newLockState.Buckets)
	footer.BucketDegree = polyLockBucketDegree
	lockComponent, err := buildLockComponent(lockBytes, footer)
	if err != nil {
		return "", nil, 0, err
	}

	dataCID := strings.TrimSpace(state.DataCID)
	var tDataAdd time.Duration
	if dataCID == "" {
		fmt.Printf("[WARN] owner state has no DataCID; fallback to ipfs add existing data.ct\n")
		dataCID, tDataAdd, err = ipfsAddObject(state.DataPartPath)
		if err != nil {
			return "", nil, 0, fmt.Errorf("fallback ipfs add data.ct failed: %v", err)
		}
	}

	tag := fmt.Sprintf("%s_policy_%d", user, time.Now().UnixNano())
	rootDirPath := filepath.Join(polyLockObjectsDir, "root_"+tag)
	lockPartPath := filepath.Join(rootDirPath, "lock.ct")
	if err := os.MkdirAll(rootDirPath, 0o755); err != nil {
		return "", nil, 0, err
	}
	if err := os.WriteFile(lockPartPath, lockComponent, 0o600); err != nil {
		return "", nil, 0, err
	}
	cid, lockCID, tIPFSAdd, err := publishTwoLinkObjectWithDataCID(state.DataPartPath, dataCID, lockPartPath)
	if err != nil {
		return "", nil, 0, err
	}
	tIPFSAdd += tDataAdd

	lockStatePath, err := writeLockState(user, cid, newLockState)
	if err != nil {
		return "", nil, 0, err
	}
	if err := writeOwnerState(user, pid, cid, rootDirPath, state.DataPartPath, lockPartPath, state.PlainPath, dataCID, lockCID, K, footer, "", lockStatePath); err != nil {
		return "", nil, 0, err
	}

	actualRatio := 0.0
	if len(lockState.Buckets) > 0 {
		actualRatio = float64(partialStats.AffectedBuckets) / float64(len(lockState.Buckets))
	}
	speedup := 0.0
	if partialStats.TotalTime > 0 {
		speedup = float64(fullStats.TotalTime) / float64(partialStats.TotalTime)
	}

	partialObjectTime := time.Since(start)
	fmt.Printf("✓ PolyLock controlled partial policy object refreshed\n")
	fmt.Printf("  Old owner state : %s\n", statePath)
	fmt.Printf("  Old lock state  : %s\n", state.LockStatePath)
	fmt.Printf("  New lock state  : %s\n", lockStatePath)
	fmt.Printf("  Old RootCID     : %s\n", oldCID)
	fmt.Printf("  New RootCID     : %s\n", cid)
	fmt.Printf("  DataCID reused  : %s\n", dataCID)
	fmt.Printf("  New LockCID     : %s\n", lockCID)
	fmt.Printf("  Target ratio    : %.3f\n", affectedRatio)
	fmt.Printf("  Affected buckets: %d/%d (actual %.3f, target %d)\n", partialStats.AffectedBuckets, len(lockState.Buckets), actualRatio, targetAffected)
	fmt.Printf("  DeltaAdd/DeltaRm: %d/%d\n", partialStats.DeltaAdd, partialStats.DeltaRm)
	fmt.Printf("  Legal configs   : %d\n", legalConfigs)
	fmt.Printf("  Effective roots : %d\n", newLockState.EffectiveRoots)
	fmt.Printf("  Lock buckets    : %d x degree<=%d\n", len(newLockState.Buckets), polyLockBucketDegree)
	fmt.Printf("  IPFSAddTime     : %.3f ms\n", float64(tIPFSAdd.Microseconds())/1000)
	fmt.Printf("  New CT_lock     : %.3f KB\n", float64(len(lockComponent))/1024.0)
	fmt.Printf("  Locate          : %.3f ms\n", float64(partialStats.LocateTime.Microseconds())/1000)
	fmt.Printf("  Recompile       : %.3f ms\n", float64(partialStats.RecompileTime.Microseconds())/1000)
	fmt.Printf("  ReEncaps        : %.3f ms\n", float64(partialStats.ReEncapsTime.Microseconds())/1000)
	fmt.Printf("  PartialTotal    : %.3f ms\n", float64(partialStats.TotalTime.Microseconds())/1000)
	fmt.Printf("  FullRecompile   : %.3f ms\n", float64(fullStats.RecompileTime.Microseconds())/1000)
	fmt.Printf("  FullReEncaps    : %.3f ms\n", float64(fullStats.ReEncapsTime.Microseconds())/1000)
	fmt.Printf("  FullTotal       : %.3f ms\n", float64(fullStats.TotalTime.Microseconds())/1000)
	fmt.Printf("  LocalSpeedup    : %.3f x\n", speedup)
	fmt.Printf("  Version         : %d\n", ver)
	return cid, mjson, partialObjectTime, nil
}

func rebuildPolyLockObjectForUnifiedPolicyUpdate(oldCID, pid, user string, contract *client.Contract, privAny interface{}, pubPEM []byte) (newCID string, newMJSON []byte, t time.Duration, err error) {
	lastUnifiedPolicyUpdateMetrics = UnifiedPolicyUpdateMetrics{}
	startStatePrepare := time.Now()

	state, statePath, err := readOwnerState(user, oldCID)
	if err != nil {
		return "", nil, 0, err
	}
	if state.PID != "" && state.PID != pid {
		return "", nil, 0, fmt.Errorf("owner state pid mismatch: state=%s input=%s", state.PID, pid)
	}
	oldState, err := readLockState(state.LockStatePath)
	if err != nil {
		return "", nil, 0, err
	}
	cfg, profileSpace, err := loadSystemProfileSpace()
	if err != nil {
		return "", nil, 0, err
	}
	requesterBits, requesterHash, err := loadRequesterProfile(user, profileSpace)
	if err != nil {
		return "", nil, 0, err
	}

	dataPartInfo, err := os.Stat(state.DataPartPath)
	if err != nil {
		return "", nil, 0, fmt.Errorf("stat padded data part: %v", err)
	}
	paddedDataLen := dataPartInfo.Size()
	if paddedDataLen%int64(ipfsChunkSize) != 0 {
		return "", nil, 0, fmt.Errorf("padded data is not 256KB-aligned: len=%d", paddedDataLen)
	}
	K, err := base64.StdEncoding.DecodeString(state.KeyBase64)
	if err != nil {
		return "", nil, 0, fmt.Errorf("decode stored data key: %v", err)
	}
	if len(K) != 16 {
		return "", nil, 0, fmt.Errorf("invalid stored KEM seed size: %d", len(K))
	}
	oldLockComponent, err := os.ReadFile(state.LockPartPath)
	if err != nil {
		return "", nil, 0, fmt.Errorf("read old lock.ct: %v", err)
	}
	oldLockBytes, oldFooter, err := parseLockComponent(oldLockComponent)
	if err != nil {
		return "", nil, 0, fmt.Errorf("parse old lock.ct: %v", err)
	}
	oldLockCT, err := polylockv2.DeserializeCiphertext(oldLockBytes)
	if err != nil {
		return "", nil, 0, fmt.Errorf("parse old PolyLock CT: %v", err)
	}
	defer oldLockCT.Close()
	if len(oldState.VersionedProfiles) == 0 {
		return "", nil, 0, fmt.Errorf("old lock state is not a versioned PolyLock v2 state; recreate the object with dataStorage")
	}

	polySystem, err := plintegration.LoadPublic(polyLockSystemDir)
	if err != nil {
		return "", nil, 0, err
	}
	defer polySystem.Close()
	statePrepareTime := time.Since(startStatePrepare)

	// PolicyGen is the offline policy design step. It is intentionally excluded
	// from the online policy-update runtime, but the time is printed for audit.
	startPolicy := time.Now()
	candidateFlag, candidateSelA, candidateSelO, candidateSelN, accepted, pgStats, err := generateUnifiedMConfPolicyFromSpace(profileSpace, cfg.TargetSigma, requesterBits)
	policyTime := time.Since(startPolicy)
	if err != nil {
		return "", nil, 0, err
	}
	if !localPolicySatisfied(requesterBits, candidateFlag, candidateSelA, candidateSelO, candidateSelN) {
		return "", nil, 0, fmt.Errorf("generated policy does not authorize requester profile")
	}

	// The six dissertation phases form one continuous wall-time window. State
	// preparation and random PolicyGen finish before this point; local state
	// persistence and reporting start only after BlockchainRegister completes.
	coreWallStart := time.Now()

	// Phase 1: independently materialize the finalized zk-Guard configuration
	// from the selected PolicyGen candidate, then serialize and compress it.
	startMConf := time.Now()
	startMatrixBuild := time.Now()
	flag := cloneIntVector(candidateFlag)
	selA := cloneIntVector(candidateSelA)
	selO := cloneIntVector(candidateSelO)
	selN := cloneIntVector(candidateSelN)
	mconfMatrixBuildTime := time.Since(startMatrixBuild)
	startMConfFinalize := time.Now()
	mjson, err := json.Marshal(struct {
		Flag   []int `json:"flag"`
		SelAnd []int `json:"selAnd"`
		SelOr  []int `json:"selOr"`
		SelNop []int `json:"selNop"`
	}{flag, selA, selO, selN})
	if err != nil {
		return "", nil, 0, fmt.Errorf("marshal finalized mconf: %v", err)
	}
	mconfB64, mconfGzipBytes := gzipB64WithSize(mjson)
	mconfFinalizeTime := time.Since(startMConfFinalize)
	mconfGenerateTime := time.Since(startMConf)

	// Phase 2: obtain the ledger VerMap snapshot and bind each newly authorized
	// profile to its current version. The previous implementation timed only the
	// local loop and omitted QueryAllConfigVersions.
	startProfiles := time.Now()
	verMap, err := queryAllConfigVersions(contract)
	if err != nil {
		return "", nil, 0, fmt.Errorf("QueryAllConfigVersions failed: %v", err)
	}
	resolver := NewVersionResolver(verMap)
	attrHash := requesterHash
	ver := resolver.Resolve(attrHash)
	newVersions := make([]uint64, len(accepted))
	for i := range accepted {
		newVersions[i] = resolver.Resolve(hashCalc(accepted[i]))
	}
	newProfiles, err := plintegration.VersionedProfiles(accepted, newVersions)
	if err != nil {
		return "", nil, 0, err
	}
	profileResolveTime := time.Since(startProfiles)

	// Phase 3: locate the policy difference and refresh only affected lock
	// buckets. Fine-grained timings remain available for the delta experiment.
	startPartial := time.Now()
	startLocate := time.Now()
	oldSet := make(map[string]struct{}, len(oldState.VersionedProfiles))
	for _, profile := range oldState.VersionedProfiles {
		raw, _ := json.Marshal(profile)
		oldSet[string(raw)] = struct{}{}
	}
	newSet := make(map[string]struct{}, len(newProfiles))
	for _, profile := range newProfiles {
		raw, _ := json.Marshal(profile)
		newSet[string(raw)] = struct{}{}
	}
	deltaAdd, deltaRm := 0, 0
	for key := range newSet {
		if _, ok := oldSet[key]; !ok {
			deltaAdd++
		}
	}
	for key := range oldSet {
		if _, ok := newSet[key]; !ok {
			deltaRm++
		}
	}
	locateTime := time.Since(startLocate)

	startRecompile := time.Now()
	oldResolved, err := polySystem.PreResolveVersionedProfiles(oldState.VersionedProfiles)
	if err != nil {
		return "", nil, 0, err
	}
	defer oldResolved.Close()
	newResolved, err := polySystem.PreResolveVersionedProfiles(newProfiles)
	if err != nil {
		return "", nil, 0, err
	}
	defer newResolved.Close()
	newMetadata, err := plintegration.Metadata(newResolved)
	if err != nil {
		return "", nil, 0, err
	}
	recompileTime := time.Since(startRecompile)

	startReEncaps := time.Now()
	newLockCT, refreshed, reused, err := polySystem.ReEncaps(oldResolved, newResolved, oldLockCT, fmt.Sprintf("%x", K))
	if err != nil {
		return "", nil, 0, err
	}
	defer newLockCT.Close()
	reEncapsTime := time.Since(startReEncaps)
	partialStats := &PartialUpdateStats{
		AffectedBuckets: refreshed, DeltaAdd: deltaAdd, DeltaRm: deltaRm,
		LocateTime: locateTime, RecompileTime: recompileTime, ReEncapsTime: reEncapsTime,
	}
	partialStats.TotalTime = partialStats.LocateTime + partialStats.RecompileTime + partialStats.ReEncapsTime
	newLockState := &LockStateDisk{
		Format: "zkguard-polylock-lockstate-v3-ring", AttrNum: AttrNum,
		BucketDegree: newMetadata.BucketDegree, LegalConfigs: len(profileSpace),
		EffectiveRoots: newMetadata.EffectiveRoots, BucketCount: newMetadata.BucketCount,
		Flag: cloneIntVector(flag), SelAnd: cloneIntVector(selA),
		SelOr: cloneIntVector(selO), SelNop: cloneIntVector(selN),
		VersionedProfiles: newProfiles, CreatedAt: time.Now().Format(time.RFC3339),
	}
	_ = reused
	lockRefreshTime := time.Since(startPartial)

	// Phase 4: serialize the refreshed lock and materialize the new lock.ct
	// object. This phase deliberately stops before any IPFS command is invoked.
	startObjectBuild := time.Now()
	lockBytes, err := newLockCT.Serialize()
	if err != nil {
		return "", nil, 0, err
	}
	footer := newProtectedObjectFooter(int(paddedDataLen), state.DataLen, state.PadLen, len(lockBytes), attrHash, ver)
	footer.EffectiveRoots = newLockState.EffectiveRoots
	footer.BucketCount = newLockState.BucketCount
	footer.BucketDegree = newLockState.BucketDegree
	footer.Format = "zkguard-polylock-object-v2-ring"
	footer.SecurityProfile = oldFooter.SecurityProfile
	footer.AADBase64 = oldFooter.AADBase64
	lockComponent, err := buildLockComponent(lockBytes, footer)
	if err != nil {
		return "", nil, 0, err
	}

	dataCID := strings.TrimSpace(state.DataCID)

	tag := fmt.Sprintf("%s_policy_%d", user, time.Now().UnixNano())
	rootDirPath := filepath.Join(polyLockObjectsDir, "root_"+tag)
	lockPartPath := filepath.Join(rootDirPath, "lock.ct")
	if err := os.MkdirAll(rootDirPath, 0o755); err != nil {
		return "", nil, 0, err
	}
	if err := os.WriteFile(lockPartPath, lockComponent, 0o600); err != nil {
		return "", nil, 0, err
	}
	objectBuildTime := time.Since(startObjectBuild)

	// Phase 5: publish the new lock and construct a new two-link RootCID while
	// reusing the old DataCID. The rare legacy fallback is included here because
	// it is an IPFS operation.
	dataCIDReused := dataCID != ""
	startIPFS := time.Now()
	if dataCID == "" {
		fmt.Printf("[WARN] owner state has no DataCID; fallback to ipfs add existing data.ct\n")
		dataCID, _, err = ipfsAddObject(state.DataPartPath)
		if err != nil {
			return "", nil, 0, fmt.Errorf("fallback ipfs add data.ct failed: %v", err)
		}
	}
	cid, lockCID, _, err := publishTwoLinkObjectWithDataCID(state.DataPartPath, dataCID, lockPartPath)
	if err != nil {
		return "", nil, 0, err
	}
	ipfsAddTime := time.Since(startIPFS)

	// Phase 6: sign the finalized Mconf and register the new RootCID on Fabric.
	// No local bookkeeping or report output is allowed before this phase ends.
	startBlockchain := time.Now()
	sigB64, err := signPID(privAny, mconfB64)
	if err != nil {
		return "", nil, 0, fmt.Errorf("sign finalized mconf: %v", err)
	}
	_, err = contract.SubmitTransaction("DataStorage", cid, pid, sigB64, string(pubPEM), mconfB64)
	if err != nil {
		return "", nil, 0, fmt.Errorf("register updated rootCID: %v", err)
	}
	blockchainRegisterTime := time.Since(startBlockchain)
	coreWallTime := time.Since(coreWallStart)

	// Prototype-only local persistence starts after all six protocol phases.
	stateWriteStart := time.Now()
	lockStatePath, err := writeLockState(user, cid, newLockState)
	if err != nil {
		return "", nil, 0, err
	}
	mconfPath, err := writeObjectMConf(user, cid, mjson)
	if err != nil {
		return "", nil, 0, err
	}
	oldBucketCount := oldState.BucketCount
	newBucketCount := newLockState.BucketCount
	deltaDenominator := oldBucketCount
	if newBucketCount > deltaDenominator {
		deltaDenominator = newBucketCount
	}
	observedRatio := 0.0
	if deltaDenominator > 0 {
		observedRatio = float64(partialStats.AffectedBuckets) / float64(deltaDenominator)
	}
	policyStatePath, err := writePolicyState(user, cid, cfg, flag, selA, selO, selN, pgStats, partialStats.AffectedBuckets, oldBucketCount, observedRatio)
	if err != nil {
		return "", nil, 0, err
	}
	if err := writeOwnerState(user, pid, cid, rootDirPath, state.DataPartPath, lockPartPath, state.PlainPath, dataCID, lockCID, K, footer, mconfPath, lockStatePath); err != nil {
		return "", nil, 0, err
	}
	stateArtifactsTime := time.Since(stateWriteStart)
	postProcessStart := time.Now()

	oldRootCount := oldState.EffectiveRoots
	newRootCount := newLockState.EffectiveRoots

	lastUnifiedPolicyUpdateMetrics = UnifiedPolicyUpdateMetrics{
		Timings: SchemePhaseTimings{
			MConfGenerate:       mconfGenerateTime,
			ResolveRootVersions: profileResolveTime,
			LockRefresh:         lockRefreshTime,
			ObjectBuild:         objectBuildTime,
			IPFSAddLockRoot:     ipfsAddTime,
			BlockchainRegister:  blockchainRegisterTime,
		},
		CoreWallTime:        coreWallTime,
		PolicyGenTime:       policyTime,
		StatePrepareTime:    statePrepareTime,
		LocalPersistTime:    stateArtifactsTime,
		AttrNum:             AttrNum,
		LegalSpaceSize:      len(profileSpace),
		TargetSigma:         cfg.TargetSigma,
		OldEffectiveRoots:   oldRootCount,
		NewEffectiveRoots:   newRootCount,
		OldBucketCount:      oldBucketCount,
		NewBucketCount:      newBucketCount,
		AffectedBuckets:     partialStats.AffectedBuckets,
		DeltaAdd:            partialStats.DeltaAdd,
		DeltaRm:             partialStats.DeltaRm,
		ObservedBucketRatio: observedRatio,
		MConfB64:            mconfB64,
		SignatureB64:        sigB64,
		MConfGzipBytes:      mconfGzipBytes,
		LockCTBytes:         len(lockComponent),
		DataCIDReused:       dataCIDReused,
		DataCID:             dataCID,
		OldRootCID:          oldCID,
		NewRootCID:          cid,
		NewLockCID:          lockCID,
		VerMapExplicit:      len(verMap),
		VersionMatched:      resolver.Found,
		VersionDefaultZero:  resolver.DefaultZero,
		VersionSkippedAfter: resolver.SkippedAfter,
	}

	excludedPolicyGenTime += policyTime
	sixStageTime := lastUnifiedPolicyUpdateMetrics.Timings.Sum()
	fmt.Printf("✓ Unified two-layer policy update completed\n")
	fmt.Printf("  Old owner state      : %s\n", statePath)
	fmt.Printf("  Old lock state       : %s\n", state.LockStatePath)
	fmt.Printf("  New lock state       : %s\n", lockStatePath)
	fmt.Printf("  New mconf path       : %s\n", mconfPath)
	fmt.Printf("  New policy state     : %s\n", policyStatePath)
	fmt.Printf("  Old RootCID          : %s\n", oldCID)
	fmt.Printf("  New RootCID          : %s\n", cid)
	fmt.Printf("  DataCID reused       : %s\n", dataCID)
	fmt.Printf("  New LockCID          : %s\n", lockCID)
	fmt.Printf("  System |S*|          : %d\n", len(profileSpace))
	fmt.Printf("  Target sigma         : %.3f\n", cfg.TargetSigma)
	fmt.Printf("  Target roots         : %d\n", pgStats.TargetCount)
	fmt.Printf("  Effective roots      : %d -> %d (new actual sigma %.4f)\n", oldRootCount, newRootCount, pgStats.ActualSigma)
	fmt.Printf("  PolicyGen excluded   : %.3f ms\n", float64(policyTime.Microseconds())/1000)
	fmt.Printf("  Final Mconf material.: %.3f ms\n", float64(mconfMatrixBuildTime.Microseconds())/1000)
	fmt.Printf("  Mconf finalize       : %.3f ms\n", float64(mconfFinalizeTime.Microseconds())/1000)
	fmt.Printf("  MconfGenerate        : %.3f ms\n", float64(mconfGenerateTime.Microseconds())/1000)
	fmt.Printf("  ResolveRootVersions  : %.3f ms\n", float64(profileResolveTime.Microseconds())/1000)
	fmt.Printf("  VerMap snapshot      : %d explicit versions\n", len(verMap))
	fmt.Printf("  Version resolves     : matched=%d defaultZero=%d skippedAfterAll=%d\n", resolver.Found, resolver.DefaultZero, resolver.SkippedAfter)
	fmt.Printf("  Affected buckets     : %d/%d (observed ratio %.4f)\n", partialStats.AffectedBuckets, oldBucketCount, observedRatio)
	fmt.Printf("  DeltaAdd/DeltaRm     : %d/%d\n", partialStats.DeltaAdd, partialStats.DeltaRm)
	fmt.Printf("  Locate               : %.3f ms\n", float64(partialStats.LocateTime.Microseconds())/1000)
	fmt.Printf("  Recompile            : %.3f ms\n", float64(partialStats.RecompileTime.Microseconds())/1000)
	fmt.Printf("  ReEncaps             : %.3f ms\n", float64(partialStats.ReEncapsTime.Microseconds())/1000)
	fmt.Printf("  PartialRefreshTotal  : %.3f ms\n", float64(partialStats.TotalTime.Microseconds())/1000)
	fmt.Printf("  LockRefresh          : %.3f ms\n", float64(lockRefreshTime.Microseconds())/1000)
	fmt.Printf("  ObjectBuild          : %.3f ms\n", float64(objectBuildTime.Microseconds())/1000)
	fmt.Printf("  IPFSAddLockRoot      : %.3f ms\n", float64(ipfsAddTime.Microseconds())/1000)
	fmt.Printf("  StatePrepare(diag)   : %.3f ms\n", float64(statePrepareTime.Microseconds())/1000)
	fmt.Printf("  LocalPersist(diag)   : %.3f ms\n", float64(stateArtifactsTime.Microseconds())/1000)
	fmt.Printf("  Mconf gzip size      : %.3f KB\n", float64(mconfGzipBytes)/1024.0)
	fmt.Printf("  New lock.ct          : %.3f KB\n", float64(len(lockComponent))/1024.0)
	fmt.Printf("  Version              : %d\n", ver)
	fmt.Printf("  UPDATE_OBSERVED_RATIO=%.6f\n", observedRatio)
	lastUnifiedPolicyUpdateMetrics.PostProcessTime = time.Since(postProcessStart)
	return cid, mjson, sixStageTime, nil
}

/* -------------------- main -------------------- */

func main() {
	programStart := time.Now()
	seed := time.Now()
	mrand.Seed(seed.UnixNano())

	if len(os.Args) < 3 {
		log.Fatalf("用法: %s <oldRootCID> <pid> [username]", os.Args[0])
	}
	oldCID := os.Args[1]
	pid := os.Args[2]
	user := "ipfs-Alice"
	if len(os.Args) > 3 && os.Args[3] != "" {
		user = os.Args[3]
	}
	if len(os.Args) > 4 {
		fmt.Printf("[WARN] policyUpdate now performs true end-to-end policy update; extra ratio/mode arguments are ignored.\n")
	}

	privPath := fmt.Sprintf("./zk-guard_priv_%s.pem", user)
	pubPath := fmt.Sprintf("./zk-guard_pub_%s.pem", user)
	privPEM, err := os.ReadFile(privPath)
	if err != nil {
		log.Fatalf("读取私钥失败: %v", err)
	}
	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		log.Fatalf("读取公钥失败: %v", err)
	}
	privBlock, _ := pem.Decode(privPEM)
	if privBlock == nil || privBlock.Type != "PRIVATE KEY" {
		log.Fatalf("私钥PEM无效: %s", privPath)
	}
	privAny, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		log.Fatalf("ParsePKCS8 私钥失败: %v", err)
	}

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
	bootstrapTime := time.Since(programStart)
	updateWallStart := time.Now()

	newCID, mjson, _, err := rebuildPolyLockObjectForUnifiedPolicyUpdate(oldCID, pid, user, contract, privAny, pubPEM)
	if err != nil {
		log.Fatalf("Unified PolicyUpdate failed: %v", err)
	}
	metrics := &lastUnifiedPolicyUpdateMetrics

	mconf := metrics.MConfB64
	if mconf == "" {
		mconf, metrics.MConfGzipBytes = gzipB64WithSize(mjson)
	}
	sigB64 := metrics.SignatureB64
	if sigB64 == "" {
		log.Fatalf("Unified PolicyUpdate returned an empty Mconf signature")
	}

	// This diagnostic E2E window includes StatePrepare, the continuous six-stage
	// core, LocalPersist and function reporting, but excludes random PolicyGen.
	updateE2EExcludingPolicyGen := time.Since(updateWallStart) - metrics.PolicyGenTime

	startArtifactWrite := time.Now()
	mconfPath := fmt.Sprintf(mconfPathTemplate, user)
	if err := os.WriteFile(mconfPath, []byte(mconf), 0o644); err != nil {
		log.Fatalf("写入 %s 失败: %v", mconfPath, err)
	}
	sigPath := fmt.Sprintf(sigPathTemplate, user)
	if err := os.WriteFile(sigPath, []byte(sigB64), 0o644); err != nil {
		log.Fatalf("写入 %s 失败: %v", sigPath, err)
	}
	clientArtifactWriteTime := time.Since(startArtifactWrite)
	programWallTime := time.Since(programStart)

	stageSum := metrics.Timings.Sum()
	coreWallTime := metrics.CoreWallTime
	wallStageGap := coreWallTime - stageSum
	programWallStageGap := programWallTime - stageSum
	unattributedGap := wallStageGap
	gapPct := 0.0
	if coreWallTime > 0 {
		gapPct = float64(wallStageGap) / float64(coreWallTime) * 100.0
	}
	programGapPct := 0.0
	if programWallTime > 0 {
		programGapPct = float64(programWallStageGap) / float64(programWallTime) * 100.0
	}
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

	fmt.Printf("----- PolicyUpdate six-stage timing (ms) -----\n")
	fmt.Printf("MconfGenerate        : %.3f ms\n", ms(metrics.Timings.MConfGenerate))
	fmt.Printf("ResolveRootVersions  : %.3f ms\n", ms(metrics.Timings.ResolveRootVersions))
	fmt.Printf("LockRefresh          : %.3f ms\n", ms(metrics.Timings.LockRefresh))
	fmt.Printf("ObjectBuild          : %.3f ms\n", ms(metrics.Timings.ObjectBuild))
	fmt.Printf("IPFSAddLockRoot      : %.3f ms\n", ms(metrics.Timings.IPFSAddLockRoot))
	fmt.Printf("BlockchainRegister   : %.3f ms\n", ms(metrics.Timings.BlockchainRegister))
	fmt.Printf("SixStageSum          : %.3f ms\n", ms(stageSum))
	fmt.Printf("CoreSixStageWall     : %.3f ms\n", ms(coreWallTime))
	fmt.Printf("WallMinusSixStages   : %.3f ms (%.2f%%)\n", ms(wallStageGap), gapPct)
	fmt.Printf("ProgramWallMinusSix  : %.3f ms (%.2f%%)\n", ms(programWallStageGap), programGapPct)
	fmt.Printf("----- Non-paper timing diagnostics (ms) -----\n")
	fmt.Printf("PolicyGen excluded   : %.3f ms\n", ms(metrics.PolicyGenTime))
	fmt.Printf("ProgramBootstrap     : %.3f ms\n", ms(bootstrapTime))
	fmt.Printf("StatePrepare         : %.3f ms\n", ms(metrics.StatePrepareTime))
	fmt.Printf("LocalPersist         : %.3f ms\n", ms(metrics.LocalPersistTime))
	fmt.Printf("PostProcess/Report   : %.3f ms\n", ms(metrics.PostProcessTime))
	fmt.Printf("ClientArtifactWrite  : %.3f ms\n", ms(clientArtifactWriteTime))
	fmt.Printf("OnlineE2EExclPolicy  : %.3f ms\n", ms(updateE2EExcludingPolicyGen))
	fmt.Printf("UnattributedGap      : %.3f ms\n", ms(unattributedGap))
	fmt.Printf("ProgramWall          : %.3f ms\n", ms(programWallTime))
	fmt.Printf("Mconf chain size     : %.3f KB\n", float64(metrics.MConfGzipBytes)/1024.0)
	fmt.Printf("New lock.ct size     : %.3f KB\n", float64(metrics.LockCTBytes)/1024.0)
	fmt.Printf("✓ PolicyUpdate six-stage total %.3f ms\n", ms(stageSum))

	// Machine-readable fields consumed by test_ipfs_cluster.sh and the
	// dissertation experiment data pipeline.
	fmt.Printf("UPDATE_MODE=unified-policy\n")
	fmt.Printf("ATTR_NUM=%d\n", metrics.AttrNum)
	fmt.Printf("LEGAL_SPACE_SIZE=%d\n", metrics.LegalSpaceSize)
	fmt.Printf("TARGET_SIGMA=%.6f\n", metrics.TargetSigma)
	fmt.Printf("OLD_EFFECTIVE_ROOTS=%d\n", metrics.OldEffectiveRoots)
	fmt.Printf("NEW_EFFECTIVE_ROOTS=%d\n", metrics.NewEffectiveRoots)
	fmt.Printf("DELTA_ADD=%d\n", metrics.DeltaAdd)
	fmt.Printf("DELTA_RM=%d\n", metrics.DeltaRm)
	fmt.Printf("AFFECTED_BUCKETS=%d\n", metrics.AffectedBuckets)
	fmt.Printf("OLD_BUCKET_COUNT=%d\n", metrics.OldBucketCount)
	fmt.Printf("NEW_BUCKET_COUNT=%d\n", metrics.NewBucketCount)
	fmt.Printf("OBSERVED_DELTA=%.6f\n", metrics.ObservedBucketRatio)
	fmt.Printf("MCONF_GZIP_BYTES=%d\n", metrics.MConfGzipBytes)
	fmt.Printf("LOCK_CT_BYTES=%d\n", metrics.LockCTBytes)
	fmt.Printf("MCONF_GENERATE_MS=%.3f\n", ms(metrics.Timings.MConfGenerate))
	fmt.Printf("RESOLVE_ROOT_VERSIONS_MS=%.3f\n", ms(metrics.Timings.ResolveRootVersions))
	fmt.Printf("LOCK_REFRESH_MS=%.3f\n", ms(metrics.Timings.LockRefresh))
	fmt.Printf("OBJECT_BUILD_MS=%.3f\n", ms(metrics.Timings.ObjectBuild))
	fmt.Printf("IPFS_ADD_LOCK_ROOT_MS=%.3f\n", ms(metrics.Timings.IPFSAddLockRoot))
	fmt.Printf("BLOCKCHAIN_REGISTER_MS=%.3f\n", ms(metrics.Timings.BlockchainRegister))
	fmt.Printf("POLICY_UPDATE_SIX_STAGE_SUM_MS=%.3f\n", ms(stageSum))
	fmt.Printf("POLICY_UPDATE_TOTAL_MS=%.3f\n", ms(stageSum))
	fmt.Printf("POLICY_UPDATE_CORE_WALL_MS=%.3f\n", ms(coreWallTime))
	fmt.Printf("POLICY_UPDATE_WALL_EXCL_POLICY_GEN_MS=%.3f\n", ms(coreWallTime))
	fmt.Printf("POLICY_UPDATE_WALL_GAP_MS=%.3f\n", ms(wallStageGap))
	fmt.Printf("POLICY_UPDATE_WALL_GAP_PCT=%.3f\n", gapPct)
	fmt.Printf("POLICY_UPDATE_E2E_EXCL_POLICY_GEN_MS=%.3f\n", ms(updateE2EExcludingPolicyGen))
	fmt.Printf("PROGRAM_WALL_MS=%.3f\n", ms(programWallTime))
	fmt.Printf("PROGRAM_WALL_MINUS_SIX_STAGES_MS=%.3f\n", ms(programWallStageGap))
	fmt.Printf("PROGRAM_WALL_MINUS_SIX_STAGES_PCT=%.3f\n", programGapPct)
	fmt.Printf("POLICY_GEN_EXCLUDED_MS=%.3f\n", ms(metrics.PolicyGenTime))
	fmt.Printf("PROGRAM_BOOTSTRAP_MS=%.3f\n", ms(bootstrapTime))
	fmt.Printf("STATE_PREPARE_DIAG_MS=%.3f\n", ms(metrics.StatePrepareTime))
	fmt.Printf("LOCAL_PERSIST_DIAG_MS=%.3f\n", ms(metrics.LocalPersistTime))
	fmt.Printf("POST_PROCESS_DIAG_MS=%.3f\n", ms(metrics.PostProcessTime))
	fmt.Printf("CLIENT_ARTIFACT_WRITE_DIAG_MS=%.3f\n", ms(clientArtifactWriteTime))
	fmt.Printf("UNATTRIBUTED_GAP_MS=%.3f\n", ms(unattributedGap))
	fmt.Printf("VERMAP_EXPLICIT=%d\n", metrics.VerMapExplicit)
	fmt.Printf("VERSION_MATCHED=%d\n", metrics.VersionMatched)
	fmt.Printf("VERSION_DEFAULT_ZERO=%d\n", metrics.VersionDefaultZero)
	fmt.Printf("VERSION_SKIPPED_AFTER=%d\n", metrics.VersionSkippedAfter)
	fmt.Printf("DATA_CID_REUSED=%t\n", metrics.DataCIDReused)
	fmt.Printf("OLD_ROOT_CID=%s\n", oldCID)
	fmt.Printf("NEW_ROOT_CID=%s\n", newCID)
}

/* -------------------- Fabric 辅助 -------------------- */
func newGrpcConnection(_ string, gatewayPeer, peerEndpoint string) *grpc.ClientConn {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	creds := credentials.NewTLS(tlsConfig)
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(32*1024*1024),
			grpc.MaxCallRecvMsgSize(32*1024*1024),
		),
	}
	connection, err := grpc.Dial(peerEndpoint, dialOpts...)
	if err != nil {
		log.Fatalf("无法创建 gRPC 连接: %v", err)
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
