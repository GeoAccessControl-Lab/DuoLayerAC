// dataStorage.go — DU端：PolyLock加密数据并上传IPFS，然后生成策略矩阵 & 签名后调用 DataStorage
//
// 用法：./dataStorage <plainFileOrRcid> <pid> <username>
//
//	plainFileOrRcid : 若是本地文件路径，则先执行 PolyLock 数据加密，分别发布 data.ct/lock.ct，并用 MFS link 构造 two-link RootCID；
//	                  若不是本地文件路径，则兼容旧逻辑，直接把它当作已有 rcid 注册。
//	pid             : 作为链上身份的字符串（例如 IPFS PeerID 12D3Koo...）
//	username        : 定位密钥文件（./zk-guard_priv_<username>.pem / ./zk-guard_pub_<username>.pem）
//
// 密文对象格式（two-link RootCID）：
//
//	RootCID
//	├── data.ct = CT_data_payload || padding_to_256KB_boundary
//	└── lock.ct = CT_lock_serialized || footer_json || footer_len_fixed_8bytes
//
// 注意：链上只注册 RootCID；DataCID/LockCID 只作为 RootCID 内部链接。
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
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

	// 输出文件（可按需修改路径）
	mconfPathTemplate = "./mconf_%s.b64"
	sigPathTemplate   = "./sig_%s.b64"
	attrPath          = "./zk-guard_attrs.json"

	// PolyLock minimal prototype parameters. Must be consistent with systemInit.
	polyLockLogN           = 10
	polyLockLogQ           = 27
	polyLockKeySize        = 32
	polyLockCompress       = 11
	polyLockBucketDegree   = 2
	polyLockPolicyAttrNum  = AttrNum / 2
	polyLockLegalSpaceSize = 1000
	polyLockMaxActiveAttrs = 20
	polyLockTargetSigma    = 0.90 // fallback; systemInit writes the effective sigma to system_config.json
	ipfsChunkSize          = 256 * 1024
	polyLockStateDir       = "./polylock_state"
	polyLockSystemDir      = "./polylock_state/system"
	polyLockObjectsDir     = "./polylock_state/objects"
)

var (
	polyLockDependencies = buildPolyLockDependencies()
	polyLockMutexes      = buildPolyLockMutexes()
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

// localPolicySatisfied evaluates exactly the same public mconf semantics used by
// dataRetrieve.go and the zk-Guard circuit. This must be the single source of
// truth for both the control layer and the PolyLock accepted set.
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

// generateUnifiedPolicyMConf generates a random PNode and immediately encodes it
// into the mconf representation used by zk-Guard. Candidate policies are judged
// by the encoded mconf semantics, not by the raw PNode semantics. This avoids the
// previous mismatch:
//
//	evalPolicy(PNode, w) == true, but localPolicySatisfied(w, mconf) == false.
func generateUnifiedPolicyMConf(targetSigma float64, required []int) (*PNode, []int, []int, []int, []int, int, int) {
	space := makeLegalAttributeSpace()
	targetCount := int(float64(len(space)) * targetSigma)
	if targetCount < 1 {
		targetCount = 1
	}

	attrs := makePolicyAttributes(polyLockPolicyAttrNum)
	currentProbAND := 0.5
	step := 0.1
	maxRetries := 500
	minDiff := len(space) + 1

	var bestPolicy *PNode
	var bestFlag, bestSelA, bestSelO, bestSelN []int
	bestMatched := 0

	for i := 0; i < maxRetries; i++ {
		mrand.Shuffle(len(attrs), func(i, j int) { attrs[i], attrs[j] = attrs[j], attrs[i] })
		policy := buildThresholdPolicy(attrs, currentProbAND)
		flag, selA, selO, selN := encodePolicy(policy)

		matched := countMConfMatches(space, flag, selA, selO, selN)
		requiredOK := required == nil || localPolicySatisfied(required, flag, selA, selO, selN)
		diff := int(math.Abs(float64(matched - targetCount)))
		if matched > 0 && requiredOK && diff < minDiff {
			minDiff = diff
			bestPolicy = policy
			bestFlag = append([]int(nil), flag...)
			bestSelA = append([]int(nil), selA...)
			bestSelO = append([]int(nil), selO...)
			bestSelN = append([]int(nil), selN...)
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
		// Deterministic fallback that definitely accepts makeDefaultValidAttrVector().
		bestPolicy = &PNode{Op: "ATTR", Attr: "attr0"}
		bestFlag, bestSelA, bestSelO, bestSelN = encodePolicy(bestPolicy)
		bestMatched = countMConfMatches(space, bestFlag, bestSelA, bestSelO, bestSelN)
	}

	return bestPolicy, bestFlag, bestSelA, bestSelO, bestSelN, len(space), bestMatched
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
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
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
	PolicyPath      string `json:"policy_path,omitempty"`
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

func encryptDataAndLockV2(system *polylockv2.System, plain []byte, resolved *polylockv2.ResolvedPolicy, aad []byte) ([]byte, []byte, []byte, error) {
	seed, err := plintegration.NewSeed()
	if err != nil {
		return nil, nil, nil, err
	}
	_, dataPayload, err := plintegration.EncryptData(seed, plain, aad)
	if err != nil {
		return nil, nil, nil, err
	}
	lock, err := system.Encaps(resolved, fmt.Sprintf("%x", seed))
	if err != nil {
		return nil, nil, nil, err
	}
	defer lock.Close()
	lockBytes, err := lock.Serialize()
	if err != nil {
		return nil, nil, nil, err
	}
	return seed, dataPayload, lockBytes, nil
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

type PolyLockCompileStats struct {
	LegalConfigs   int
	EffectiveRoots int
	BucketCount    int
	BucketDegree   int
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

type UnifiedPolicyDisk struct {
	Format           string   `json:"format"`
	AttrNum          int      `json:"attr_num"`
	ProfileTotal     int      `json:"profile_total"`
	TargetSigma      float64  `json:"target_sigma"`
	TargetCount      int      `json:"target_count"`
	Matched          int      `json:"matched"`
	ActualSigma      float64  `json:"actual_sigma"`
	PolicyModel      string   `json:"policy_model"`
	ProfileSpacePath string   `json:"profile_space_path"`
	SpaceDigest      string   `json:"space_digest"`
	Flag             []int    `json:"flag"`
	SelAnd           []int    `json:"selAnd"`
	SelOr            []int    `json:"selOr"`
	SelNop           []int    `json:"selNop"`
	AcceptedHashes   []string `json:"accepted_hashes,omitempty"`
	CreatedAt        string   `json:"created_at"`
}

type PolicyGenResult struct {
	Flag             []int
	SelAnd           []int
	SelOr            []int
	SelNop           []int
	AcceptedProfiles [][]int
	AcceptedHashes   []string
	TargetCount      int
	Matched          int
	ActualSigma      float64
	TargetSigma      float64
	ProfileTotal     int
	SpaceDigest      string
	ProfileSpacePath string
}

func digestProfileSpace(space [][]int) string {
	b, _ := json.Marshal(space)
	d := sha256.Sum256(b)
	return fmt.Sprintf("%x", d[:])
}

func loadSystemProfileSpace() (*SystemConfigDisk, [][]int, error) {
	configPath := filepath.Join(polyLockSystemDir, "system_config.json")
	cb, err := os.ReadFile(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read system config %s failed: %v; run systemInit first", configPath, err)
	}
	var cfg SystemConfigDisk
	if err := json.Unmarshal(cb, &cfg); err != nil {
		return nil, nil, fmt.Errorf("parse system config: %v", err)
	}
	if cfg.AttrNum != AttrNum {
		return nil, nil, fmt.Errorf("system AttrNum mismatch: config=%d binary=%d", cfg.AttrNum, AttrNum)
	}
	profilePath := strings.TrimSpace(cfg.ProfileSpacePath)
	if profilePath == "" {
		profilePath = filepath.Join(polyLockSystemDir, "profile_space.json")
	}
	pb, err := os.ReadFile(profilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("read profile space %s failed: %v", profilePath, err)
	}
	var disk SystemProfileSpaceDisk
	if err := json.Unmarshal(pb, &disk); err != nil {
		return nil, nil, fmt.Errorf("parse profile space: %v", err)
	}
	if disk.AttrNum != AttrNum {
		return nil, nil, fmt.Errorf("profile space AttrNum mismatch: profile=%d binary=%d", disk.AttrNum, AttrNum)
	}
	if len(disk.Profiles) == 0 {
		return nil, nil, fmt.Errorf("profile space is empty")
	}
	actualDigest := digestProfileSpace(disk.Profiles)
	if cfg.SpaceDigest != "" && cfg.SpaceDigest != actualDigest {
		return nil, nil, fmt.Errorf("profile space digest mismatch: config=%s actual=%s", cfg.SpaceDigest, actualDigest)
	}
	cfg.ProfileSpacePath = profilePath
	cfg.ProfileTotal = len(disk.Profiles)
	cfg.SpaceDigest = actualDigest
	return &cfg, disk.Profiles, nil
}

func profileInSpace(bits []int, space [][]int) bool {
	key := attrVectorKey(bits)
	for _, w := range space {
		if attrVectorKey(w) == key {
			return true
		}
	}
	return false
}

func loadRequiredProfile(profileSpace [][]int) []int {
	if b, err := os.ReadFile(attrPath); err == nil {
		var bits []int
		if err := json.Unmarshal(b, &bits); err == nil && len(bits) == AttrNum && profileInSpace(bits, profileSpace) {
			return cloneIntVector(bits)
		}
	}
	return cloneIntVector(profileSpace[0])
}

func cloneMConf(flag, selA, selO, selN []int) ([]int, []int, []int, []int) {
	return cloneIntVector(flag), cloneIntVector(selA), cloneIntVector(selO), cloneIntVector(selN)
}

func buildRandomMConfCandidate(probAND float64) (flag, selA, selO, selN []int) {
	flag = make([]int, AttrNum)
	selA = make([]int, IntNum)
	selO = make([]int, IntNum)
	selN = make([]int, IntNum)

	attrs := make([]int, AttrNum)
	for i := range attrs {
		attrs[i] = i
	}
	mrand.Shuffle(len(attrs), func(i, j int) { attrs[i], attrs[j] = attrs[j], attrs[i] })
	selected := polyLockPolicyAttrNum
	if selected <= 0 || selected > AttrNum {
		selected = AttrNum
	}
	for _, id := range attrs[:selected] {
		flag[id] = 1
	}

	for i := 0; i < IntNum; i++ {
		if mrand.Float64() < probAND {
			selA[i] = 1
		} else {
			selO[i] = 1
		}
	}
	return
}

func acceptedProfilesFromMConf(space [][]int, flag, selA, selO, selN []int) ([][]int, []string) {
	profiles := make([][]int, 0)
	hashes := make([]string, 0)
	for _, w := range space {
		if localPolicySatisfied(w, flag, selA, selO, selN) {
			profiles = append(profiles, cloneIntVector(w))
			hashes = append(hashes, hashCalc(w))
		}
	}
	return profiles, hashes
}

// generateUnifiedPolicyFromSpace is the system-prototype PolicyGen used in the
// integrated zk-Guard + PolyLock experiment. It follows the PolyLock paper
// logic: given the globally initialized admissible space S* and target sigma,
// search a policy whose accepted roots are close to |S*|*sigma. The policy is
// generated directly in the mconf-compatible form, so zk-Guard and PolyLock use
// the same predicate without post-hoc semantic repair.
func generateUnifiedPolicyFromSpace(space [][]int, targetSigma float64, required []int, cfg *SystemConfigDisk) (*PolicyGenResult, error) {
	if len(space) == 0 {
		return nil, fmt.Errorf("empty profile space")
	}
	if targetSigma <= 0 {
		targetSigma = polyLockTargetSigma
	}
	if targetSigma > 1 {
		targetSigma = 1
	}
	targetCount := int(float64(len(space)) * targetSigma)
	if targetCount < 1 {
		targetCount = 1
	}

	currentProbAND := 0.5
	step := 0.1
	maxRetries := 500
	minDiff := len(space) + 1
	bestMatched := 0
	var bestFlag, bestA, bestO, bestN []int
	var bestProfiles [][]int
	var bestHashes []string

	for i := 0; i < maxRetries; i++ {
		flag, a, o, n := buildRandomMConfCandidate(currentProbAND)
		profiles, hashes := acceptedProfilesFromMConf(space, flag, a, o, n)
		matched := len(profiles)
		requiredOK := required == nil || localPolicySatisfied(required, flag, a, o, n)
		diff := int(math.Abs(float64(matched - targetCount)))
		if matched > 0 && requiredOK && diff < minDiff {
			minDiff = diff
			bestFlag, bestA, bestO, bestN = cloneMConf(flag, a, o, n)
			bestProfiles = cloneIntVectors(profiles)
			bestHashes = append([]string(nil), hashes...)
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

	if bestMatched == 0 || len(bestProfiles) == 0 {
		return nil, fmt.Errorf("PolicyGen failed: no mconf-compatible policy matched any profile")
	}

	spaceDigest := digestProfileSpace(space)
	profilePath := ""
	if cfg != nil {
		spaceDigest = cfg.SpaceDigest
		profilePath = cfg.ProfileSpacePath
	}
	return &PolicyGenResult{
		Flag:             bestFlag,
		SelAnd:           bestA,
		SelOr:            bestO,
		SelNop:           bestN,
		AcceptedProfiles: bestProfiles,
		AcceptedHashes:   bestHashes,
		TargetCount:      targetCount,
		Matched:          bestMatched,
		ActualSigma:      float64(bestMatched) / float64(len(space)),
		TargetSigma:      targetSigma,
		ProfileTotal:     len(space),
		SpaceDigest:      spaceDigest,
		ProfileSpacePath: profilePath,
	}, nil
}

func makeUnifiedPolicyJSON(pg *PolicyGenResult) []byte {
	if pg == nil {
		return nil
	}
	disk := UnifiedPolicyDisk{
		Format:           "zkguard-polylock-unified-policy-v1",
		AttrNum:          AttrNum,
		ProfileTotal:     pg.ProfileTotal,
		TargetSigma:      pg.TargetSigma,
		TargetCount:      pg.TargetCount,
		Matched:          pg.Matched,
		ActualSigma:      pg.ActualSigma,
		PolicyModel:      "mconf-compatible AND/OR access structure over systemInit-generated S*",
		ProfileSpacePath: pg.ProfileSpacePath,
		SpaceDigest:      pg.SpaceDigest,
		Flag:             cloneIntVector(pg.Flag),
		SelAnd:           cloneIntVector(pg.SelAnd),
		SelOr:            cloneIntVector(pg.SelOr),
		SelNop:           cloneIntVector(pg.SelNop),
		AcceptedHashes:   append([]string(nil), pg.AcceptedHashes...),
		CreatedAt:        time.Now().Format(time.RFC3339),
	}
	b, _ := json.MarshalIndent(disk, "", "  ")
	return b
}

func writePolicyArtifacts(user, rootCID, mconfB64 string, policyJSON []byte) (string, string, error) {
	if err := os.MkdirAll(polyLockObjectsDir, 0o755); err != nil {
		return "", "", err
	}
	mconfPath := filepath.Join(polyLockObjectsDir, fmt.Sprintf("mconf_%s_%s.b64", user, rootCID))
	policyPath := filepath.Join(polyLockObjectsDir, fmt.Sprintf("policy_%s_%s.json", user, rootCID))
	if err := os.WriteFile(mconfPath, []byte(mconfB64), 0o644); err != nil {
		return "", "", err
	}
	if len(policyJSON) > 0 {
		if err := os.WriteFile(policyPath, policyJSON, 0o644); err != nil {
			return "", "", err
		}
	}
	return mconfPath, policyPath, nil
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

func parseVersion(verBytes []byte, fallback uint64) uint64 {
	verBI, ok := new(big.Int).SetString(strings.TrimSpace(string(verBytes)), 10)
	if !ok {
		return fallback
	}
	return verBI.Uint64()
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
		ver := parseVersion([]byte(v), 0)
		out[strings.TrimSpace(k)] = ver
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
		// All explicit VerMap entries have already been observed.  A repeated
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

func buildBucketCoeffsAndStateFromJobs(pp *PolyPublicParams, jobs []polyLockRootJob, roots []ring.Poly, lockState *LockStateDisk, stats *PolyLockCompileStats) ([][]ring.Poly, error) {
	if len(jobs) != len(roots) {
		return nil, fmt.Errorf("root job/result mismatch: jobs=%d roots=%d", len(jobs), len(roots))
	}

	bucketRootGroups := make([][]ring.Poly, 0, (len(jobs)+polyLockBucketDegree-1)/polyLockBucketDegree)
	bucketBits := make([][]int, 0, polyLockBucketDegree)
	bucketKeys := make([]string, 0, polyLockBucketDegree)
	bucketRoots := make([]ring.Poly, 0, polyLockBucketDegree)

	flushBucket := func() {
		if len(bucketRoots) == 0 {
			return
		}
		bucketIdx := len(bucketRootGroups)
		bucketRootGroups = append(bucketRootGroups, append([]ring.Poly(nil), bucketRoots...))
		lockState.Buckets = append(lockState.Buckets, BucketStateDisk{
			Index:    bucketIdx,
			Roots:    cloneIntVectors(bucketBits),
			RootKeys: append([]string(nil), bucketKeys...),
		})
		bucketRoots = bucketRoots[:0]
		bucketBits = bucketBits[:0]
		bucketKeys = bucketKeys[:0]
	}

	for i, job := range jobs {
		bucketIdx := len(bucketRootGroups)
		lockState.RootToBucket[job.RootKey] = bucketIdx
		bucketRoots = append(bucketRoots, roots[i])
		bucketBits = append(bucketBits, cloneIntVector(job.Bits))
		bucketKeys = append(bucketKeys, job.RootKey)
		if stats != nil {
			stats.EffectiveRoots++
		}
		if len(bucketRoots) == polyLockBucketDegree {
			flushBucket()
		}
	}
	flushBucket()

	return compileRootBucketsParallel(pp, bucketRootGroups), nil
}

func preResolvePolicyBucketsFromMConf(pp *PolyPublicParams, flag, selA, selO, selN []int, resolver *VersionResolver) ([][]ring.Poly, *LockStateDisk, PolyLockCompileStats, error) {
	space := makeLegalAttributeSpace()
	stats := PolyLockCompileStats{
		LegalConfigs: len(space),
		BucketDegree: polyLockBucketDegree,
	}
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
		// IMPORTANT: PolyLock accepted set must use the same mconf semantics as zk-Guard.
		// Do not use evalPolicy(PNode, bits) here, otherwise the data layer may accept
		// a different user set from the control layer.
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
		jobs = append(jobs, polyLockRootJob{
			Bits:     cloneIntVector(bits),
			AttrHash: attrHash,
			Version:  ver,
			RootKey:  rootKey,
		})
	}

	if len(jobs) == 0 {
		return nil, nil, stats, fmt.Errorf("mconf policy has no effective roots in legal attribute space")
	}
	roots := resolveRootJobsParallel(pp, jobs)
	buckets, err := buildBucketCoeffsAndStateFromJobs(pp, jobs, roots, lockState, &stats)
	if err != nil {
		return nil, nil, stats, err
	}

	stats.BucketCount = len(buckets)
	lockState.EffectiveRoots = stats.EffectiveRoots
	lockState.BucketCount = stats.BucketCount
	return buckets, lockState, stats, nil
}

func preResolvePolicyBucketsFromProfiles(pp *PolyPublicParams, acceptedProfiles [][]int, flag, selA, selO, selN []int, resolver *VersionResolver) ([][]ring.Poly, *LockStateDisk, PolyLockCompileStats, error) {
	stats := PolyLockCompileStats{
		LegalConfigs:   0,
		EffectiveRoots: 0,
		BucketDegree:   polyLockBucketDegree,
	}
	lockState := &LockStateDisk{
		Format:       "zkguard-polylock-lock-state-v1",
		AttrNum:      AttrNum,
		BucketDegree: polyLockBucketDegree,
		Flag:         cloneIntVector(flag),
		SelAnd:       cloneIntVector(selA),
		SelOr:        cloneIntVector(selO),
		SelNop:       cloneIntVector(selN),
		Buckets:      make([]BucketStateDisk, 0),
		RootToBucket: make(map[string]int),
		CreatedAt:    time.Now().Format(time.RFC3339),
	}

	jobs := make([]polyLockRootJob, 0, len(acceptedProfiles))
	seenRoots := make(map[string]bool)
	for _, bits := range acceptedProfiles {
		if !localPolicySatisfied(bits, flag, selA, selO, selN) {
			return nil, nil, stats, fmt.Errorf("accepted profile does not satisfy mconf: %s", hashCalc(bits))
		}
		attrHash := hashCalc(bits)
		ver := resolver.Resolve(attrHash)
		rootKey := fmt.Sprintf("%s:%d", attrHash, ver)
		if seenRoots[rootKey] {
			continue
		}
		seenRoots[rootKey] = true
		jobs = append(jobs, polyLockRootJob{
			Bits:     cloneIntVector(bits),
			AttrHash: attrHash,
			Version:  ver,
			RootKey:  rootKey,
		})
	}

	if len(jobs) == 0 {
		return nil, nil, stats, fmt.Errorf("policy has no effective roots in system profile space")
	}
	roots := resolveRootJobsParallel(pp, jobs)
	buckets, err := buildBucketCoeffsAndStateFromJobs(pp, jobs, roots, lockState, &stats)
	if err != nil {
		return nil, nil, stats, err
	}

	stats.BucketCount = len(buckets)
	lockState.LegalConfigs = stats.LegalConfigs
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

func encapsBucket(pp *PolyPublicParams, coeffs []ring.Poly, K []byte) [][]byte {
	polyKey := encodeKey(pp.RingQ, K)
	powersOfA := precomputePowersOfA(pp, len(coeffs))
	return encapsBucketWithPrecomp(pp, coeffs, polyKey, powersOfA)
}

func encryptDataAndLock(pp *PolyPublicParams, plain []byte, bucketCoeffs [][]ring.Poly) ([]byte, []byte, []byte, error) {
	K := make([]byte, polyLockKeySize)
	if _, err := io.ReadFull(rand.Reader, K); err != nil {
		return nil, nil, nil, err
	}
	block, err := aes.NewCipher(K)
	if err != nil {
		return nil, nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, err
	}
	payload := gcm.Seal(nil, nonce, plain, nil)
	dataPayload := append(nonce, payload...)

	lockCT := PolyLockOnlyCT{SubLocks: make([][][]byte, len(bucketCoeffs))}
	if len(bucketCoeffs) > 0 {
		maxDegree := 1
		for _, coeffs := range bucketCoeffs {
			if len(coeffs) > maxDegree {
				maxDegree = len(coeffs)
			}
		}
		polyKey := encodeKey(pp.RingQ, K)
		powersOfA := precomputePowersOfA(pp, maxDegree)
		workers := polyLockWorkerCount(len(bucketCoeffs))
		idxCh := make(chan int, workers)
		var wg sync.WaitGroup
		wg.Add(workers)
		for w := 0; w < workers; w++ {
			go func() {
				defer wg.Done()
				for i := range idxCh {
					lockCT.SubLocks[i] = encapsBucketWithPrecomp(pp, bucketCoeffs[i], polyKey, powersOfA)
				}
			}()
		}
		for i := range bucketCoeffs {
			idxCh <- i
		}
		close(idxCh)
		wg.Wait()
	}
	lockBytes, err := marshalPolyLockCTBinary(&lockCT)
	if err != nil {
		return nil, nil, nil, err
	}
	return K, dataPayload, lockBytes, nil
}

func buildProtectedObject(dataPayload []byte, lockBytes []byte, attrHash string, ver uint64) ([]byte, []byte, ProtectedObjectFooter, error) {
	padLen := (ipfsChunkSize - (len(dataPayload) % ipfsChunkSize)) % ipfsChunkSize
	paddedData := make([]byte, 0, len(dataPayload)+padLen)
	paddedData = append(paddedData, dataPayload...)
	if padLen > 0 {
		paddedData = append(paddedData, make([]byte, padLen)...)
	}
	footer := ProtectedObjectFooter{
		Format:    "zkguard-polylock-object-v1",
		ChunkSize: ipfsChunkSize,
		DataLen:   len(dataPayload),
		PadLen:    padLen,
		LockOff:   len(paddedData),
		LockLen:   len(lockBytes),
		Version:   ver,
		AttrHash:  attrHash,
		CreatedAt: time.Now().Format(time.RFC3339),
	}
	footerBytes, err := json.Marshal(footer)
	if err != nil {
		return nil, nil, footer, err
	}
	obj := make([]byte, 0, len(paddedData)+len(lockBytes)+len(footerBytes)+8)
	obj = append(obj, paddedData...)
	obj = append(obj, lockBytes...)
	obj = append(obj, footerBytes...)
	lenBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBuf, uint64(len(footerBytes)))
	obj = append(obj, lenBuf...)
	return obj, paddedData, footer, nil
}

func ipfsAddLockObject(path string) (string, time.Duration, error) {
	start := time.Now()

	// go-ipfs chunker 最大只允许 1048576 bytes，即 1MB。
	// 对于 targetSigma=0.10 下约 800KB 的 lock.ct，这可以保证 lock.ct 不再被切块。
	cmd := exec.Command(
		"ipfs", "add",
		"--chunker=size-1048576",
		"-q",
		path,
	)

	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)

	if err != nil {
		return "", elapsed, fmt.Errorf("ipfs add lock.ct failed: %v\n%s", err, string(out))
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[len(lines)-1]) == "" {
		return "", elapsed, fmt.Errorf("ipfs add lock.ct returned empty output")
	}

	return strings.TrimSpace(lines[len(lines)-1]), elapsed, nil
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

// buildTwoLinkRootFromCIDs constructs the access-control root as a real
// two-link UnixFS/DAG root without re-adding or re-chunking data.ct.
//
// Important difference from `ipfs add -r <dir>`:
//   - `ipfs add -r` reads data.ct from disk and re-walks/re-hashes the file.
//   - This function uses MFS `ipfs files cp /ipfs/<cid>` to create directory
//     links to existing DataCID and LockCID. Therefore policyUpdate only adds
//     the new lock.ct and creates a tiny new root node; it does not re-upload
//     or re-chunk the data object.
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

	mfsDir := fmt.Sprintf("/zkguard-polylock-twolink-%d-%d", os.Getpid(), time.Now().UnixNano())
	// Best-effort cleanup in case of an extremely unlikely name collision.
	_ = exec.Command("ipfs", "files", "rm", "-r", mfsDir).Run()

	if _, err := ipfsRun("files", "mkdir", "-p", mfsDir); err != nil {
		return "", time.Since(start), err
	}
	if _, err := ipfsRun("files", "cp", "/ipfs/"+dataCID, mfsDir+"/data.ct"); err != nil {
		return "", time.Since(start), fmt.Errorf("link data.ct -> %s failed: %v", dataCID, err)
	}
	if _, err := ipfsRun("files", "cp", "/ipfs/"+lockCID, mfsDir+"/lock.ct"); err != nil {
		return "", time.Since(start), fmt.Errorf("link lock.ct -> %s failed: %v", lockCID, err)
	}

	rootCID, err := ipfsRun("files", "stat", "--hash", mfsDir)
	if err != nil {
		return "", time.Since(start), err
	}
	if rootCID == "" {
		return "", time.Since(start), fmt.Errorf("ipfs files stat --hash returned empty RootCID")
	}

	// Keep the MFS path instead of removing it. This preserves the root node in
	// the local IPFS repository without recursively pinning or re-walking the
	// large data DAG. The actual access-control identifier remains rootCID.
	return rootCID, time.Since(start), nil
}

func publishTwoLinkObject(dataPath, lockPath string) (rootCID, dataCID, lockCID string, elapsed time.Duration, err error) {
	start := time.Now()

	dataCID, _, err = ipfsAddObject(dataPath)
	if err != nil {
		return "", "", "", time.Since(start), fmt.Errorf("ipfs add data.ct failed: %v", err)
	}
	lockCID, _, err = ipfsAddLockObject(lockPath)
	if err != nil {
		return "", "", "", time.Since(start), fmt.Errorf("ipfs add lock.ct failed: %v", err)
	}

	rootCID, _, err = buildTwoLinkRootFromCIDs(dataCID, lockCID)
	if err != nil {
		return "", "", "", time.Since(start), err
	}

	return rootCID, dataCID, lockCID, time.Since(start), nil
}

func writeOwnerState(user, pid, cid, objectPath, dataPartPath, lockPartPath, plainPath, dataCID, lockCID string, K []byte, footer ProtectedObjectFooter, mconfPath, policyPath, lockStatePath string) error {
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
		PolicyPath:      policyPath,
		LockStatePath:   lockStatePath,
	}
	if err := os.MkdirAll(polyLockObjectsDir, 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(state, "", "  ")
	return os.WriteFile(filepath.Join(polyLockObjectsDir, fmt.Sprintf("state_%s_%s.json", user, cid)), b, 0o600)
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

func encryptUploadIfFile(input, pid, user string, requiredProfile []int, profileTotal int, acceptedProfiles [][]int, flag, selA, selO, selN []int, mconfB64 string, policyJSON []byte, contract *client.Contract) (string, time.Duration, error) {
	st, err := os.Stat(input)
	if err != nil || st.IsDir() {
		// Backward-compatible mode: input is already a CID.
		return input, 0, nil
	}

	start := time.Now()
	ms := func(d time.Duration) float64 {
		return float64(d.Microseconds()) / 1000.0
	}

	/* ---------- 1. 本地准备与明文读取 ---------- */
	t0 := time.Now()
	if err := os.MkdirAll(polyLockObjectsDir, 0o755); err != nil {
		return "", 0, err
	}
	tPrepareDir := time.Since(t0)

	t0 = time.Now()
	plain, err := os.ReadFile(input)
	if err != nil {
		return "", 0, err
	}
	tReadPlain := time.Since(t0)

	/* ---------- 2. 一次性下载 VerMap ---------- */
	t0 = time.Now()
	verMap, err := queryAllConfigVersions(contract)
	if err != nil {
		return "", 0, fmt.Errorf("QueryAllConfigVersions failed: %v", err)
	}
	tQueryVerMap := time.Since(t0)

	t0 = time.Now()
	resolver := NewVersionResolver(verMap)
	ownerAttr := cloneIntVector(requiredProfile)
	attrHash := hashCalc(ownerAttr)
	ver := resolver.Resolve(attrHash)
	tResolveOwnerVersion := time.Since(t0)

	/* ---------- 3. PolyLock 公共参数加载 ---------- */
	t0 = time.Now()
	polySystem, err := plintegration.LoadPublic(polyLockSystemDir)
	if err != nil {
		return "", 0, err
	}
	defer polySystem.Close()
	tPolySetup := time.Since(t0)

	/* ---------- 4. PreResolve：版本绑定 root + 低次聚合多项式编译 ---------- */
	t0 = time.Now()
	versions := make([]uint64, len(acceptedProfiles))
	for i := range acceptedProfiles {
		versions[i] = resolver.Resolve(hashCalc(acceptedProfiles[i]))
	}
	versionedProfiles, err := plintegration.VersionedProfiles(acceptedProfiles, versions)
	if err != nil {
		return "", 0, err
	}
	resolved, err := polySystem.PreResolveVersionedProfiles(versionedProfiles)
	if err != nil {
		return "", 0, err
	}
	defer resolved.Close()
	metadata, err := plintegration.Metadata(resolved)
	if err != nil {
		return "", 0, err
	}
	stats := PolyLockCompileStats{
		LegalConfigs: profileTotal, EffectiveRoots: metadata.EffectiveRoots,
		BucketCount: metadata.BucketCount, BucketDegree: metadata.BucketDegree,
	}
	lockState := &LockStateDisk{
		Format: "zkguard-polylock-lockstate-v3-ring", AttrNum: AttrNum,
		BucketDegree: stats.BucketDegree, LegalConfigs: profileTotal,
		EffectiveRoots: stats.EffectiveRoots, BucketCount: stats.BucketCount,
		Flag: cloneIntVector(flag), SelAnd: cloneIntVector(selA),
		SelOr: cloneIntVector(selO), SelNop: cloneIntVector(selN),
		VersionedProfiles: versionedProfiles, CreatedAt: time.Now().Format(time.RFC3339),
	}
	tPreResolve := time.Since(t0)

	/* ---------- 5. 数据加密 + PolyLock 锁封装 + lock.ct 序列化 ---------- */
	t0 = time.Now()
	aad := []byte(fmt.Sprintf("zkguard-polylock-v2|%s|%d", attrHash, ver))
	K, dataPayload, lockBytes, err := encryptDataAndLockV2(polySystem, plain, resolved, aad)
	if err != nil {
		return "", 0, err
	}
	tEncryptDataAndLock := time.Since(t0)

	/* ---------- 6. 构造 footer 与 lock component ---------- */
	t0 = time.Now()
	_, paddedData, footer, err := buildProtectedObject(dataPayload, lockBytes, attrHash, ver)
	if err != nil {
		return "", 0, err
	}
	footer.EffectiveRoots = stats.EffectiveRoots
	footer.BucketCount = stats.BucketCount
	footer.BucketDegree = stats.BucketDegree
	footer.Format = "zkguard-polylock-object-v2-ring"
	footer.SecurityProfile = plintegration.SecurityProfile
	footer.AADBase64 = base64.StdEncoding.EncodeToString(aad)

	lockComponent, err := buildLockComponent(lockBytes, footer)
	if err != nil {
		return "", 0, err
	}
	tBuildObject := time.Since(t0)

	/* ---------- 7. 本地写入 data.ct / lock.ct ---------- */
	t0 = time.Now()
	tag := fmt.Sprintf("%s_%d", user, time.Now().UnixNano())
	rootDirPath := filepath.Join(polyLockObjectsDir, "root_"+tag)
	dataPartPath := filepath.Join(rootDirPath, "data.ct")
	lockPartPath := filepath.Join(rootDirPath, "lock.ct")

	if err := os.MkdirAll(rootDirPath, 0o755); err != nil {
		return "", 0, err
	}
	if err := os.WriteFile(dataPartPath, paddedData, 0o600); err != nil {
		return "", 0, err
	}
	if err := os.WriteFile(lockPartPath, lockComponent, 0o600); err != nil {
		return "", 0, err
	}
	tLocalWriteObject := time.Since(t0)

	/* ---------- 8. IPFS 发布：data.ct + lock.ct + two-link root ---------- */
	t0 = time.Now()
	rootCID, dataCID, lockCID, tIPFSAdd, err := publishTwoLinkObject(dataPartPath, lockPartPath)
	if err != nil {
		return "", 0, err
	}
	tPublishIPFS := time.Since(t0)

	/* ---------- 9. 打印对象信息 ---------- */
	fmt.Printf("✓ PolyLock two-link object built and uploaded\n")
	fmt.Printf("  Plain file       : %s\n", input)
	fmt.Printf("  RootCID          : %s\n", rootCID)
	fmt.Printf("  DataCID          : %s\n", dataCID)
	fmt.Printf("  LockCID          : %s\n", lockCID)
	fmt.Printf("  IPFSAddTime      : %.3f ms\n", float64(tIPFSAdd.Microseconds())/1000)
	fmt.Printf("  DataPayload      : %.3f KB\n", float64(len(dataPayload))/1024.0)
	fmt.Printf("  Padding          : %.3f KB\n", float64(footer.PadLen)/1024.0)
	fmt.Printf("  CT_data          : %.3f KB\n", float64(len(paddedData))/1024.0)
	fmt.Printf("  CT_lock+footer   : %.3f KB\n", float64(len(lockComponent))/1024.0)
	fmt.Printf("  Legal configs    : %d\n", stats.LegalConfigs)
	fmt.Printf("  Effective roots  : %d\n", stats.EffectiveRoots)
	fmt.Printf("  Lock buckets     : %d x degree<=%d\n", stats.BucketCount, stats.BucketDegree)
	fmt.Printf("  VerMap snapshot  : %d explicit versions\n", len(verMap))
	fmt.Printf("  Version resolves : matched=%d defaultZero=%d skippedAfterAll=%d\n", resolver.Found, resolver.DefaultZero, resolver.SkippedAfter)
	fmt.Printf("  Data blocks fixed: %d x 256KB\n", len(paddedData)/ipfsChunkSize)

	/* ---------- 10. 写入本地状态文件 ---------- */
	_ = pid // kept for symmetry with owner-state and future checks

	t0 = time.Now()
	lockStatePath, err := writeLockState(user, rootCID, lockState)
	if err != nil {
		return "", 0, err
	}
	tWriteLockState := time.Since(t0)

	t0 = time.Now()
	mconfPath, policyPath, err := writePolicyArtifacts(user, rootCID, mconfB64, policyJSON)
	if err != nil {
		return "", 0, err
	}
	tWritePolicyArtifacts := time.Since(t0)

	t0 = time.Now()
	if err := writeOwnerState(user, pid, rootCID, rootDirPath, dataPartPath, lockPartPath, input, dataCID, lockCID, K, footer, mconfPath, policyPath, lockStatePath); err != nil {
		return "", 0, err
	}
	tWriteOwnerState := time.Since(t0)

	tTotal := time.Since(start)
	tStateArtifacts := tWriteLockState + tWritePolicyArtifacts + tWriteOwnerState
	tAccounted := tPrepareDir +
		tReadPlain +
		tQueryVerMap +
		tResolveOwnerVersion +
		tPolySetup +
		tPreResolve +
		tEncryptDataAndLock +
		tBuildObject +
		tLocalWriteObject +
		tPublishIPFS +
		tStateArtifacts

	tUnaccounted := tTotal - tAccounted
	if tUnaccounted < 0 {
		tUnaccounted = 0
	}

	/* ---------- 11. 细粒度计时输出 ---------- */
	fmt.Println("----- PolyLockStorage breakdown (ms) -----")
	fmt.Printf("  prepareDir            : %.3f ms\n", ms(tPrepareDir))
	fmt.Printf("  readPlain             : %.3f ms\n", ms(tReadPlain))
	fmt.Printf("  queryAllVerMap        : %.3f ms\n", ms(tQueryVerMap))
	fmt.Printf("  resolveOwnerVersion   : %.3f ms\n", ms(tResolveOwnerVersion))
	fmt.Printf("  polySetup             : %.3f ms\n", ms(tPolySetup))
	fmt.Printf("  preResolveBuckets     : %.3f ms\n", ms(tPreResolve))
	fmt.Printf("  encryptDataAndLock    : %.3f ms  (AES + lock encaps + lock binary serialization)\n", ms(tEncryptDataAndLock))
	fmt.Printf("  buildObjectFooter     : %.3f ms\n", ms(tBuildObject))
	fmt.Printf("  localWriteDataLock    : %.3f ms\n", ms(tLocalWriteObject))
	fmt.Printf("  publishIPFS           : %.3f ms\n", ms(tPublishIPFS))
	fmt.Printf("    reportedIPFSAddTime : %.3f ms\n", ms(tIPFSAdd))
	fmt.Printf("  writeLockState        : %.3f ms\n", ms(tWriteLockState))
	fmt.Printf("  writePolicyArtifacts  : %.3f ms\n", ms(tWritePolicyArtifacts))
	fmt.Printf("  writeOwnerState       : %.3f ms\n", ms(tWriteOwnerState))
	fmt.Printf("  stateArtifactsTotal   : %.3f ms\n", ms(tStateArtifacts))
	fmt.Printf("  unaccountedOverhead   : %.3f ms\n", ms(tUnaccounted))
	fmt.Printf("  polylockStorageCore   : %.3f ms  (excluding owner local bookkeeping)\n", ms(tTotal-tStateArtifacts))
	fmt.Printf("  polylockStorageTotal  : %.3f ms\n", ms(tTotal))

	return rootCID, tTotal - tStateArtifacts, nil
}

/* -------------------- main -------------------- */

func main() {
	start := time.Now()
	mrand.Seed(start.UnixNano())

	if len(os.Args) < 3 {
		log.Fatalf("用法: %s <plainFileOrRcid> <pid> [username]", os.Args[0])
	}
	input := os.Args[1]
	pid := os.Args[2]
	user := "ipfs-Alice"
	if len(os.Args) > 3 && os.Args[3] != "" {
		user = os.Args[3]
	}

	// === 1) 加载 systemInit 生成的全局合法属性空间 S* ===
	cfg, profileSpace, err := loadSystemProfileSpace()
	if err != nil {
		log.Fatalf("加载系统合法属性空间失败: %v", err)
	}
	targetSigma := cfg.TargetSigma
	if targetSigma <= 0 {
		targetSigma = polyLockTargetSigma
	}
	requiredProfile := loadRequiredProfile(profileSpace)
	fmt.Printf("System profile space loaded: U=%d |S|=%d sigma=%.2f digest=%s\n", AttrNum, len(profileSpace), targetSigma, cfg.SpaceDigest)
	fmt.Printf("Required registered profile hash: %s\n", hashCalc(requiredProfile))

	// === 2) PolicyGen: 在同一个 S* 上搜索 mconf-compatible 策略，使 |R_eff|≈|S*|×sigma ===
	t0 := time.Now()
	pg, err := generateUnifiedPolicyFromSpace(profileSpace, targetSigma, requiredProfile, cfg)
	if err != nil {
		log.Fatalf("PolicyGen 失败: %v", err)
	}
	tPolicyGen := time.Since(t0)
	fmt.Printf("PolicyGen targetSigma=%.2f target=%d matched=%d actualSigma=%.4f\n", pg.TargetSigma, pg.TargetCount, pg.Matched, pg.ActualSigma)
	fmt.Printf("Required profile satisfied by mconf: %v\n", localPolicySatisfied(requiredProfile, pg.Flag, pg.SelAnd, pg.SelOr, pg.SelNop))
	if !localPolicySatisfied(requiredProfile, pg.Flag, pg.SelAnd, pg.SelOr, pg.SelNop) {
		log.Fatalf("generated mconf does not authorize the required registered profile")
	}

	// === 3) 序列化统一 mconf 和策略归档 ===
	t1 := time.Now()
	mjson, _ := json.Marshal(struct {
		Flag, SelAnd, SelOr, SelNop []int
	}{pg.Flag, pg.SelAnd, pg.SelOr, pg.SelNop})
	tEncodePolicy := time.Since(t1)
	mconf := gzipB64(mjson)
	policyJSON := makeUnifiedPolicyJSON(pg)

	// === 4) 读取私钥 / 公钥 PEM（带 username） ===
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

	// === 5) Fabric Gateway 连接 ===
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

	// === 6) 若输入为本地文件，则 PolyLock 加密并 ipfs add，得到 rootCID；否则兼容旧 rcid 模式 ===
	rcid, tPolyStorage, err := encryptUploadIfFile(input, pid, user, requiredProfile, len(profileSpace), pg.AcceptedProfiles, pg.Flag, pg.SelAnd, pg.SelOr, pg.SelNop, mconf, policyJSON, contract)
	if err != nil {
		log.Fatalf("PolyLock/IPFS 存储失败: %v", err)
	}
	if _, _, err := writePolicyArtifacts(user, rcid, mconf, policyJSON); err != nil {
		log.Printf("保存对象策略归档失败: %v", err)
	}

	// 兼容旧脚本：仍保留当前用户最近一次 mconf/sig 文件。
	mconfPath := fmt.Sprintf(mconfPathTemplate, user)
	if err := os.WriteFile(mconfPath, []byte(mconf), 0o644); err != nil {
		log.Fatalf("写入 %s 失败: %v", mconfPath, err)
	}

	// === 7) 调用 DataStorage: (rcid, pid, sig, pubKeyPEM, mconf) ===
	sigB64, err := signPID(privAny, mconf)
	if err != nil {
		log.Fatalf("签名失败: %v", err)
	}
	sigPath := fmt.Sprintf(sigPathTemplate, user)
	if err := os.WriteFile(sigPath, []byte(sigB64), 0o644); err != nil {
		log.Fatalf("写入 %s 失败: %v", sigPath, err)
	}

	tSubmit := time.Now()
	_, err = contract.SubmitTransaction(
		"DataStorage",
		rcid,
		pid,
		sigB64,
		string(pubPEM),
		mconf,
	)
	if err != nil {
		log.Fatalf("DataStorage 调用失败: %v", err)
	}
	tBlockChain := time.Since(tSubmit)

	fmt.Printf("----- 计时 (毫秒) -----\n")
	fmt.Printf("PolicyGen            : %.3f ms\n", float64(tPolicyGen.Microseconds())/1000)
	fmt.Printf("encodePolicy         : %.3f ms\n", float64(tEncodePolicy.Microseconds())/1000)
	if tPolyStorage > 0 {
		fmt.Printf("polylockStorage      : %.3f ms\n", float64(tPolyStorage.Microseconds())/1000)
	}
	fmt.Printf("blockchainStorage    : %.3f ms\n", float64(tBlockChain.Microseconds())/1000)
	fmt.Printf("M矩阵大小           : %.3f KB\n", float64(len(mconf))/1024.0)
	fmt.Printf("✓ DataStorage 成功，rootCID=%s，耗时 %.3f ms\n", rcid, float64(time.Since(start).Microseconds())/1000)
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
