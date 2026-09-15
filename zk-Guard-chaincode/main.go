// system_init_chaincode.go
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	//"crypto"
	"crypto/ed25519"
	"crypto/elliptic"

	"crypto/x509"
	"encoding/pem"
	"math/big"

	"github.com/consensys/gnark/std/hash/mimc"
	lpcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	//"crypto/rsa"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	//"github.com/consensys/gnark/frontend/cs/r1cs"
	//"github.com/consensys/gnark/std/hash/mimc"
	//"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	//"github.com/consensys/gnark/backend/witness" // alias 可直接使用 witness
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

/* ------------------------------------------------------------------ */
/*                          数据结构 / 常量                           */
/* ------------------------------------------------------------------ */

const (
	AttrNum   = 100          // 叶槽位
	IntNum    = AttrNum - 1   // 内部节点
	TotalNode = 2*AttrNum - 1 // 满二叉堆大小
	GroupSz   = 253           // MiMC 聚合位数
)

// AttrRecord  ——  链上仅保存 pid ↔ hashAttr 的映射
type AttrRecord struct {
	HashAttr string `json:"hashAttr"`
}

// VersionRecord —— VerMap 中保存 hashAttr ↔ version
type VersionRecord struct {
	Version uint64 `json:"version"`
}

type MetaInfo struct {
	Pid string `json:"pid"`
}

// helper: 写二进制到 <rcid>~<tag>
func putBinary(ctx contractapi.TransactionContextInterface, rcid, tag string, data []byte) error {
	k, _ := ctx.GetStub().CreateCompositeKey(rcid, []string{tag})
	return ctx.GetStub().PutState(k, data)
}
func getBinary(ctx contractapi.TransactionContextInterface, rcid, tag string) ([]byte, error) {
	k, _ := ctx.GetStub().CreateCompositeKey(rcid, []string{tag})
	return ctx.GetStub().GetState(k)
}

// verMapKey 生成 VerMap 的组合键：vermap~hashAttr
func verMapKey(ctx contractapi.TransactionContextInterface, hashAttr string) (string, error) {
	return ctx.GetStub().CreateCompositeKey("vermap", []string{hashAttr})
}

// ensureVersion 确保 VerMap[hashAttr] 存在；若不存在，则初始化为 0。
// 若已存在，则保持原版本号不变。
func ensureVersion(ctx contractapi.TransactionContextInterface, hashAttr string) (uint64, error) {
	k, err := verMapKey(ctx, hashAttr)
	if err != nil {
		return 0, fmt.Errorf("create vermap key: %v", err)
	}

	raw, err := ctx.GetStub().GetState(k)
	if err != nil {
		return 0, fmt.Errorf("read VerMap[%s]: %v", hashAttr, err)
	}

	if raw != nil {
		var rec VersionRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return 0, fmt.Errorf("unmarshal VerMap[%s]: %v", hashAttr, err)
		}
		return rec.Version, nil
	}

	rec := VersionRecord{Version: 0}
	out, err := json.Marshal(rec)
	if err != nil {
		return 0, fmt.Errorf("marshal VerMap[%s]: %v", hashAttr, err)
	}
	if err := ctx.GetStub().PutState(k, out); err != nil {
		return 0, fmt.Errorf("init VerMap[%s]: %v", hashAttr, err)
	}
	return 0, nil
}

// getVersion 查询 VerMap[hashAttr]。
// 如果不存在，按系统语义视为 0，但不主动写链。
func getVersion(ctx contractapi.TransactionContextInterface, hashAttr string) (uint64, error) {
	k, err := verMapKey(ctx, hashAttr)
	if err != nil {
		return 0, fmt.Errorf("create vermap key: %v", err)
	}

	raw, err := ctx.GetStub().GetState(k)
	if err != nil {
		return 0, fmt.Errorf("read VerMap[%s]: %v", hashAttr, err)
	}

	if raw == nil {
		return 0, nil
	}

	var rec VersionRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return 0, fmt.Errorf("unmarshal VerMap[%s]: %v", hashAttr, err)
	}
	return rec.Version, nil
}

// incrementVersion 执行 VerMap[hashAttr] += 1。
// 如果该 hashAttr 不存在，则视为 0 并更新为 1。
func incrementVersion(ctx contractapi.TransactionContextInterface, hashAttr string) (uint64, error) {
	oldVer, err := getVersion(ctx, hashAttr)
	if err != nil {
		return 0, err
	}

	newVer := oldVer + 1

	k, err := verMapKey(ctx, hashAttr)
	if err != nil {
		return 0, fmt.Errorf("create vermap key: %v", err)
	}

	rec := VersionRecord{Version: newVer}
	out, err := json.Marshal(rec)
	if err != nil {
		return 0, fmt.Errorf("marshal VerMap[%s]: %v", hashAttr, err)
	}

	if err := ctx.GetStub().PutState(k, out); err != nil {
		return 0, fmt.Errorf("update VerMap[%s]: %v", hashAttr, err)
	}

	return newVer, nil
}

// GetParam 用于获取 UPK, UVK, UCS 这样的全局参数
// GetParam 统一返回 Base64 字符串（即便链上是原始二进制）
func (s *SmartContract) GetParamB64(ctx contractapi.TransactionContextInterface, key string) (string, error) {
	val, err := ctx.GetStub().GetState(key)
	if err != nil {
		return "", fmt.Errorf("GetParam failed: %v", err)
	}
	if val == nil {
		return "", fmt.Errorf("param %s not found", key)
	}
	// 一律 Base64 编码后返回
	return base64.StdEncoding.EncodeToString(val), nil
}

// GetParam 直接返回链上存储的原始字节（例如：gzip 压缩后的内容）
func (s *SmartContract) GetParam(ctx contractapi.TransactionContextInterface, key string) ([]byte, error) {
	val, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, fmt.Errorf("GetParam failed: %v", err)
	}
	if val == nil {
		return nil, fmt.Errorf("param %s not found", key)
	}
	return val, nil
}

// 建议新名字，避免旧 schema 缓存：GetParamRawB64
func (s *SmartContract) GetParamRaw(ctx contractapi.TransactionContextInterface, key string) (string, error) {
	val, err := ctx.GetStub().GetState(key)
	if err != nil {
		return "", fmt.Errorf("GetParamRawB64 failed: %v", err)
	}
	if val == nil {
		return "", fmt.Errorf("param %s not found", key)
	}
	return base64.StdEncoding.EncodeToString(val), nil
}

// ----------------  GetBinary 方法 -------------------
// Args: rcid, tag   ★tag 取值: "pk" | "vk" | "ccs" | "mconf"
// 返回: gzip 压缩后的字节，Base64 编码
func (s *SmartContract) GetBinary(
	ctx contractapi.TransactionContextInterface,
	rcid string,
	tag string,
) (string, error) {

	blob, err := getBinary(ctx, rcid, tag) // 你之前的 helper
	if err != nil {
		return "", fmt.Errorf("binary %s not found for %s: %v", tag, rcid, err)
	}
	return base64.StdEncoding.EncodeToString(blob), nil
}

// SmartContract  ——  链码主体
type SmartContract struct {
	contractapi.Contract
}

type Circuit struct {
	// secret
	X    [AttrNum]frontend.Variable `gnark:",secret"`
	Rand frontend.Variable          `gnark:",secret"`
	// public
	Hash   frontend.Variable          `gnark:",public"`
	Flag   [AttrNum]frontend.Variable `gnark:",public"`
	SelAnd [IntNum]frontend.Variable  `gnark:",public"`
	SelOr  [IntNum]frontend.Variable  `gnark:",public"`
	SelNop [IntNum]frontend.Variable  `gnark:",public"`
}

// === Circuit.Define ===
// 依赖: import "math/big"
func (c *Circuit) Define(api frontend.API) error {
	/* 1) 布尔约束 */
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

	/* 2) MiMC 承诺：每 248bit 聚一 limb，LSB-first，小端线性组合 */
	const LimbBits = 253
	// 预计算 2^k 常量
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
		// acc = Σ X[j] * 2^(j-i) （LSB-first）
		acc := frontend.Variable(0) // 用 0 作为初值即可
		for j := i; j < end; j++ {
			term := api.Mul(c.X[j], pow2[j-i]) // 常量乘
			acc = api.Add(acc, term)
		}
		h, _ := mimc.NewMiMC(api)
		h.Write(acc)
		grp = append(grp, h.Sum())
	}
	// 把各 limb 哈希再聚合一次，并加入随机因子 r：Reg[pid] = H(w || r)
	hf, _ := mimc.NewMiMC(api)
	for _, g := range grp {
		hf.Write(g)
	}
	hf.Write(c.Rand)
	api.AssertIsEqual(c.Hash, hf.Sum())

	/* 3) 叶值 = Flag·X */
	node := make([]frontend.Variable, TotalNode) // 0 = root
	for i := 0; i < AttrNum; i++ {
		node[IntNum+i] = api.Mul(c.Flag[i], c.X[i])
	}

	/* 4) 自底向上评估 (AND / OR / NOP) */
	for i := IntNum - 1; i >= 0; i-- {
		l, r := node[2*i+1], node[2*i+2]
		andV := api.Mul(l, r)
		orV := api.Sub(api.Add(l, r), andV)
		nopV := l
		a, o, n := c.SelAnd[i], c.SelOr[i], c.SelNop[i]
		node[i] = api.Add(api.Add(api.Mul(a, andV), api.Mul(o, orV)), api.Mul(n, nopV))
	}

	/* 5) 根 == 1 */
	api.AssertIsEqual(node[0], 1)
	return nil
}

/* ------------------------------------------------------------------ */
/*                         业务接口  (Init)                           */
/* ------------------------------------------------------------------ */
func (s *SmartContract) UniSetup(
	ctx contractapi.TransactionContextInterface,
	pkRaw string,
	vkRaw string,
	ccsRaw string,
) (string, error) {
	// 直接把收到的 gzip 压缩字节落库（不做 base64/gzip 解码）
	pkBytes := []byte(pkRaw)
	vkBytes := []byte(vkRaw)
	ccsBytes := []byte(ccsRaw)

	stub := ctx.GetStub()

	// UPK
	if val, _ := stub.GetState("UPK"); val == nil {
		if err := stub.PutState("UPK", pkBytes); err != nil {
			return "", fmt.Errorf("put UPK error: %v", err)
		}
	}
	// UVK
	if val, _ := stub.GetState("UVK"); val == nil {
		if err := stub.PutState("UVK", vkBytes); err != nil {
			return "", fmt.Errorf("put UVK error: %v", err)
		}
	}
	// UCS
	if val, _ := stub.GetState("UCS"); val == nil {
		if err := stub.PutState("UCS", ccsBytes); err != nil {
			return "", fmt.Errorf("put UCS error: %v", err)
		}
	}

	// 可选：记录一个标记说明这些值是 gzip 压缩过的（将来读取端据此解压）
	if err := stub.PutState("UFLAG", []byte("gzip=1")); err != nil {
		return "", fmt.Errorf("put UFLAG error: %v", err)
	}

	// 回执：返回压缩后的长度，便于客户端确认大小
	summary := fmt.Sprintf("stored (gzip) sizes — pk=%d, vk=%d, ccs=%d bytes",
		len(pkBytes), len(vkBytes), len(ccsBytes))
	return summary, nil
}

// UserRegister only updates the zk-Guard randomized user binding.
//
// Args:
//   - pid: user pseudonymous identifier, e.g., libp2p PeerID
//   - userCommit: randomized user commitment H(w || r)
//
// This function intentionally does NOT update VerMap. After introducing
// Reg[pid] = H(w || r), VerMap must remain profile-level and be indexed by
// H(w), not by H(w || r). Therefore profile-version initialization is handled
// by ProfileVersionRegister(profileHash), which does not take pid.
func (s *SmartContract) UserRegister(
	ctx contractapi.TransactionContextInterface,
	pid string,
	userCommit string,
) error {
	pid = strings.TrimSpace(pid)
	userCommit = strings.TrimSpace(userCommit)
	if pid == "" {
		return fmt.Errorf("pid is empty")
	}
	if userCommit == "" {
		return fmt.Errorf("userCommit is empty")
	}

	// 1) The pid must not have been registered.
	exist, err := getBinary(ctx, pid, "pid")
	if err != nil {
		return fmt.Errorf("failed to access pid record: %v", err)
	}
	if exist != nil {
		return fmt.Errorf("pid %s already registered", pid)
	}

	// 2) Write Reg[pid] = userCommit = H(w || r).
	rec := AttrRecord{HashAttr: userCommit}
	raw, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal AttrRecord: %v", err)
	}
	if err := putBinary(ctx, pid, "pid", raw); err != nil {
		return fmt.Errorf("put pid record: %v", err)
	}

	return nil
}

// ProfileVersionRegister initializes the PolyLock profile-level version map.
//
// Args:
//   - profileHash: deterministic profile hash H(w)
//
// Privacy rationale:
//
//	This function does not take pid and therefore does not reveal, within this
//	contract call, which user owns profileHash. It only ensures the profile-level
//	VerMap entry exists.
//
// Version semantics:
//   - If VerMap[profileHash] exists, keep the current version unchanged.
//   - If it does not exist, initialize VerMap[profileHash] = 0.
func (s *SmartContract) ProfileVersionRegister(
	ctx contractapi.TransactionContextInterface,
	profileHash string,
) error {
	profileHash = strings.TrimSpace(profileHash)
	if profileHash == "" {
		return fmt.Errorf("profileHash is empty")
	}
	if _, err := ensureVersion(ctx, profileHash); err != nil {
		return fmt.Errorf("ensure profile version for %s: %v", profileHash, err)
	}
	return nil
}

// SystemInit(pidB64, hashAttr)
//
//	由 CA 调用；若 pid 已存在则返回错误。
func (s *SmartContract) SystemInit(
	ctx contractapi.TransactionContextInterface,
	pidB64 string,
	hashAttr string,
	pkB64 string,
	vkB64 string,
	ccsB64 string,
) error {

	// 1. 检查 pid 是否已注册
	exist, err := ctx.GetStub().GetState(pidB64)
	if err != nil {
		return fmt.Errorf("failed to access state: %v", err)
	}
	if exist != nil {
		return fmt.Errorf("pid %s already registered", pidB64)
	}

	// 2. 写 pid -> hashAttr
	rec := AttrRecord{HashAttr: hashAttr}
	raw, _ := json.Marshal(rec)
	if err := ctx.GetStub().PutState(pidB64, raw); err != nil {
		return fmt.Errorf("put state error: %v", err)
	}

	// (2) base64 → []byte，同时做 gzip 完整性校验
	decodeGz := func(b64 string) ([]byte, error) {
		blob, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, err
		}
		gr, err := gzip.NewReader(bytes.NewReader(blob))
		if err != nil {
			return nil, err
		}
		if _, err = io.ReadAll(gr); err != nil {
			return nil, err
		}
		_ = gr.Close()
		return blob, nil
	}

	pkGz, err := decodeGz(pkB64)
	if err != nil {
		return fmt.Errorf("pk: %v", err)
	}
	vkGz, err := decodeGz(vkB64)
	if err != nil {
		return fmt.Errorf("vk: %v", err)
	}
	ccsGz, err := decodeGz(ccsB64)
	if err != nil {
		return fmt.Errorf("ccs: %v", err)
	}

	// 3. 若 UPK 不存在，则写入
	upk, err := ctx.GetStub().GetState("UPK")
	if err != nil {
		return fmt.Errorf("read UPK error: %v", err)
	}
	if upk == nil {
		if err := ctx.GetStub().PutState("UPK", []byte(pkGz)); err != nil {
			return fmt.Errorf("put UPK error: %v", err)
		}
	}

	// 4. 若 UVK 不存在，则写入
	uvk, err := ctx.GetStub().GetState("UVK")
	if err != nil {
		return fmt.Errorf("read UVK error: %v", err)
	}
	if uvk == nil {
		if err := ctx.GetStub().PutState("UVK", []byte(vkGz)); err != nil {
			return fmt.Errorf("put UVK error: %v", err)
		}
	}

	// 5. 若 UCS 不存在，则写入
	ucs, err := ctx.GetStub().GetState("UCS")
	if err != nil {
		return fmt.Errorf("read UCS error: %v", err)
	}
	if ucs == nil {
		if err := ctx.GetStub().PutState("UCS", []byte(ccsGz)); err != nil {
			return fmt.Errorf("put UCS error: %v", err)
		}
	}

	return nil
}

/* ------------------------------------------------------------------ */
/*                          查询接口                                  */
/* ------------------------------------------------------------------ */
// QueryConfigVersion(hashAttr) → version
func (s *SmartContract) QueryConfigVersion(
	ctx contractapi.TransactionContextInterface,
	hashAttr string,
) (string, error) {
	ver, err := getVersion(ctx, hashAttr)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d", ver), nil
}

// QueryHashAttr(pidB64) → hashAttr
func (s *SmartContract) QueryHashAttr(
	ctx contractapi.TransactionContextInterface,
	pidB64 string,
) (string, error) {

	data, err := getBinary(ctx, pidB64, "pid")
	if err != nil {
		return "", fmt.Errorf("failed to read pid record: %v", err)
	}
	if data == nil {
		return "", fmt.Errorf("pid %s not found", pidB64)
	}

	var rec AttrRecord
	if err = json.Unmarshal(data, &rec); err != nil {
		return "", fmt.Errorf("unmarshal error: %v", err)
	}
	return rec.HashAttr, nil
}

func (s *SmartContract) DataStorage(
	ctx contractapi.TransactionContextInterface,
	rcid string,
	pid string,
	sigB64 string,
	pubKeyPEM string,
	mconfB64 string,
) error {
	// rcid 不允许重复
	if raw, _ := ctx.GetStub().GetState(rcid); raw != nil {
		return fmt.Errorf("rcid %s already exists", rcid)
	}

	// 解析 pubKey
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return fmt.Errorf("invalid pubKey PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse pubKey: %v", err)
	}

	// === ① PID 绑定验证（完全复制测试逻辑） ===
	switch pk := pubAny.(type) {
	case ed25519.PublicKey:
		expected, err := peerIDFromEd25519(pk)
		if err != nil {
			return fmt.Errorf("peerID derive: %v", err)
		}
		if pid != expected {
			return fmt.Errorf("PID mismatch: got %s, expect %s", pid, expected)
		}

	case *ecdsa.PublicKey:
		raw := elliptic.Marshal(pk.Curve, pk.X, pk.Y)
		sum := sha256.Sum256(raw)
		expect := base64.RawURLEncoding.EncodeToString(sum[:])
		if pid != expect {
			return fmt.Errorf("PID mismatch: got %s, expect %s", pid, expect)
		}

	default:
		return fmt.Errorf("unsupported key type %T", pubAny)
	}

	// === ② 签名验证（msg = sha256(pid)) ===
	msg := sha256.Sum256([]byte(mconfB64))
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("sig decode: %v", err)
	}

	switch pk := pubAny.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(pk, msg[:], sig) {
			return fmt.Errorf("invalid signature (ed25519)")
		}
	case *ecdsa.PublicKey:
		var rs struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(sig, &rs); err != nil {
			return fmt.Errorf("ecdsa sig DER: %v", err)
		}
		if !ecdsa.Verify(pk, msg[:], rs.R, rs.S) {
			return fmt.Errorf("invalid signature (ecdsa)")
		}
	}

	// === ③ mconf gzip 校验 & 保存 ===
	blob, err := base64.StdEncoding.DecodeString(mconfB64)
	if err != nil {
		return fmt.Errorf("mconf decode: %v", err)
	}
	r, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		return fmt.Errorf("mconf gunzip: %v", err)
	}
	_, _ = io.ReadAll(r)
	r.Close()

	metaRaw, _ := json.Marshal(MetaInfo{Pid: pid})
	if err := ctx.GetStub().PutState(rcid, metaRaw); err != nil {
		return err
	}
	if err := putBinary(ctx, rcid, "mconf", blob); err != nil { // ← 关键：组合键写入
		return err
	}
	return nil
}

// ---------------- QueryMConf ----------------
func (s *SmartContract) QueryMConf(
	ctx contractapi.TransactionContextInterface,
	rcid string,
) (string, error) {

	metaBytes, err := ctx.GetStub().GetState(rcid)
	if err != nil || metaBytes == nil {
		return "", fmt.Errorf("rcid not found")
	}
	var meta MetaInfo
	_ = json.Unmarshal(metaBytes, &meta)

	mconfGz, _ := getBinary(ctx, rcid, "mconf")

	// 返回概要：长度（gzip后字节数）
	summary := struct {
		Pid    string `json:"pid"`
		MBytes int    `json:"mconfBytes"`
	}{
		meta.Pid,
		len(mconfGz),
	}
	out, _ := json.Marshal(summary)
	return string(out), nil
}

/* ------------------------------------------------------------------ */
/*                    简单 Key–Value 辅助接口                         */
/* ------------------------------------------------------------------ */

// Storage(key, value)  ——  调试用：链上写入任意键值
func (s *SmartContract) Storage(
	ctx contractapi.TransactionContextInterface,
	key string,
	value string,
) error {
	return ctx.GetStub().PutState(key, []byte(value))
}

// Query(key)  ——  调试用：链上读取任意键值
func (s *SmartContract) Query(
	ctx contractapi.TransactionContextInterface,
	key string,
) (string, error) {
	val, err := ctx.GetStub().GetState(key)
	if err != nil {
		return "", fmt.Errorf("failed to get key %s: %v", key, err)
	}
	if val == nil {
		return "", fmt.Errorf("key %s not found", key)
	}
	return string(val), nil
}

// gunzip 原始 []byte
func gunzipRaw(gz []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(gr)
	_ = gr.Close()
	return out, err
}

// gunzip(Base64)
func gunzipB64(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return gunzipRaw(raw)
}

func (s *SmartContract) DataRetrieve(
	ctx contractapi.TransactionContextInterface,
	rcid string,
	pid string,
	proofB64 string,
	sigB64 string,
	pubKeyPEM string,
) (string, error) {

	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return "", fmt.Errorf("invalid pubKey PEM")
	}

	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse pubKey: %v", err)
	}

	// 1. PID 绑定验证：pid 必须由 pubKeyPEM 中的公钥派生得到。
	switch pk := pubAny.(type) {
	case ed25519.PublicKey:
		expected, err := peerIDFromEd25519(pk)
		if err != nil {
			return "", fmt.Errorf("peerID derive: %v", err)
		}
		if pid != expected {
			return "", fmt.Errorf("PID mismatch: got %s, expect %s", pid, expected)
		}

	case *ecdsa.PublicKey:
		raw := elliptic.Marshal(pk.Curve, pk.X, pk.Y)
		sum := sha256.Sum256(raw)
		expect := base64.RawURLEncoding.EncodeToString(sum[:])
		if pid != expect {
			return "", fmt.Errorf("PID mismatch: got %s, expect %s", pid, expect)
		}

	default:
		return "", fmt.Errorf("unsupported public key type: %T", pubAny)
	}

	// 2. 验签：msg = sha256(pid || rcid || proofB64)
	T := pid + rcid + proofB64
	msg := sha256.Sum256([]byte(T))

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return "", fmt.Errorf("sig decode: %v", err)
	}

	switch pk := pubAny.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(pk, msg[:], sig) {
			return "", fmt.Errorf("invalid signature (ed25519)")
		}

	case *ecdsa.PublicKey:
		var rs struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(sig, &rs); err != nil {
			return "", fmt.Errorf("ecdsa sig DER: %v", err)
		}
		if rs.R == nil || rs.S == nil {
			return "", fmt.Errorf("invalid ecdsa signature values")
		}
		if !ecdsa.Verify(pk, msg[:], rs.R, rs.S) {
			return "", fmt.Errorf("invalid signature (ecdsa)")
		}

	default:
		return "", fmt.Errorf("unsupported public key type for signature verification: %T", pubAny)
	}

	// 3. 读取链上 VK / mconf / 用户承诺。
	vkBytes, err := ctx.GetStub().GetState("UVK")
	if err != nil {
		return "", fmt.Errorf("failed to read UVK: %v", err)
	}
	if vkBytes == nil {
		return "", fmt.Errorf("UVK not found")
	}

	vkRaw, err := gunzipRaw(vkBytes)
	if err != nil {
		return "", fmt.Errorf("vk gunzip: %v", err)
	}

	mconfGz, err := getBinary(ctx, rcid, "mconf")
	if err != nil {
		return "", fmt.Errorf("mconf not found: %v", err)
	}

	mconfBytes, err := gunzipRaw(mconfGz)
	if err != nil {
		return "", fmt.Errorf("mconf gunzip: %v", err)
	}

	userBytes, err := getBinary(ctx, pid, "pid")
	if err != nil {
		return "", fmt.Errorf("binary pid not found for %s: %v", pid, err)
	}

	var user AttrRecord
	if err := json.Unmarshal(userBytes, &user); err != nil {
		return "", fmt.Errorf("user unmarshal: %v", err)
	}

	// 4. 反序列化 verifying key。
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(bytes.NewReader(vkRaw)); err != nil {
		return "", fmt.Errorf("vk deserialize: %v", err)
	}

	type mConfJSON struct {
		Flag   []int `json:"flag"`
		SelAnd []int `json:"selAnd"`
		SelOr  []int `json:"selOr"`
		SelNop []int `json:"selNop"`
	}

	var M mConfJSON
	if err := json.Unmarshal(mconfBytes, &M); err != nil {
		return "", fmt.Errorf("mconf unmarshal: %v", err)
	}

	if len(M.Flag) != AttrNum || len(M.SelAnd) != IntNum || len(M.SelOr) != IntNum || len(M.SelNop) != IntNum {
		return "", fmt.Errorf(
			"mconf shape mismatch: flag=%d selAnd=%d selOr=%d selNop=%d, expect %d/%d/%d/%d",
			len(M.Flag), len(M.SelAnd), len(M.SelOr), len(M.SelNop),
			AttrNum, IntNum, IntNum, IntNum,
		)
	}

	// 5. 反序列化 proof。
	proofBytes, err := base64.StdEncoding.DecodeString(proofB64)
	if err != nil {
		return "", fmt.Errorf("proof base64: %v", err)
	}

	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return "", fmt.Errorf("proof deserialize: %v", err)
	}

	// 6. 构造 public witness。
	var pub Circuit

	hashInt, ok := new(big.Int).SetString(user.HashAttr, 10)
	if !ok {
		return "", fmt.Errorf("invalid hashAttr: %s", user.HashAttr)
	}

	pub.Hash = hashInt

	for i, v := range M.Flag {
		pub.Flag[i] = v
	}
	for i, v := range M.SelAnd {
		pub.SelAnd[i] = v
	}
	for i, v := range M.SelOr {
		pub.SelOr[i] = v
	}
	for i, v := range M.SelNop {
		pub.SelNop[i] = v
	}

	wit, err := frontend.NewWitness(&pub, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return "", fmt.Errorf("new witness: %v", err)
	}

	pubOnly, err := wit.Public()
	if err != nil {
		return "", fmt.Errorf("public witness: %v", err)
	}

	// 7. 验证 proof。
	startVerify := time.Now()
	err = groth16.Verify(proof, vk, pubOnly)
	verifyCost := time.Since(startVerify)

	if err != nil {
		return "", fmt.Errorf("proof verify failed: %v", err)
	}

	// 8. 只有成功时返回 Permit。
	return fmt.Sprintf("Permit|VerifyCost=%.3fms", float64(verifyCost.Microseconds())/1000.0), nil
}

// ------------------ PolicyUpdate ------------------
// Args: rcid, pid, sigB64, pubKeyPEM, mconfB64
func (s *SmartContract) PolicyUpdate(
	ctx contractapi.TransactionContextInterface,
	rcid string,
	pid string,
	sigB64 string,
	pubKeyPEM string,
	mconfB64 string,
) error {

	// 1) 解析公钥
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return fmt.Errorf("invalid pubKey PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse pubKey: %v", err)
	}

	// 2) PID 绑定校验（与 dataStorage 完全一致）
	switch pk := pubAny.(type) {
	case ed25519.PublicKey:
		expected, err := peerIDFromEd25519(pk)
		if err != nil {
			return fmt.Errorf("peerID derive: %v", err)
		}
		if pid != expected {
			return fmt.Errorf("PID mismatch: got %s, expect %s", pid, expected)
		}
	case *ecdsa.PublicKey:
		if pk.Curve != elliptic.P256() {
			return fmt.Errorf("unsupported curve")
		}
		raw := elliptic.Marshal(pk.Curve, pk.X, pk.Y)
		sum := sha256.Sum256(raw)
		expect := base64.RawURLEncoding.EncodeToString(sum[:])
		if pid != expect {
			return fmt.Errorf("PID mismatch: got %s, expect %s", pid, expect)
		}
	default:
		return fmt.Errorf("unsupported key type %T", pubAny)
	}

	// 3) 验签 —— 注意：消息是 sha256(mconfB64)（与你的客户端一致）
	msg := sha256.Sum256([]byte(mconfB64))
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("sig decode: %v", err)
	}
	switch pk := pubAny.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(pk, msg[:], sig) {
			return fmt.Errorf("invalid signature (ed25519)")
		}
	case *ecdsa.PublicKey:
		var rs struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(sig, &rs); err != nil {
			return fmt.Errorf("ecdsa sig DER: %v", err)
		}
		if !ecdsa.Verify(pk, msg[:], rs.R, rs.S) {
			return fmt.Errorf("invalid signature (ecdsa)")
		}
	}

	// 4) 检查 rcid 归属（必须是同一 pid）
	metaBytes, err := ctx.GetStub().GetState(rcid)
	if err != nil || metaBytes == nil {
		return fmt.Errorf("rcid %s not found", rcid)
	}
	var meta MetaInfo
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return fmt.Errorf("meta unmarshal: %v", err)
	}
	if meta.Pid != pid {
		return fmt.Errorf("pid mismatch: expect %s got %s", meta.Pid, pid)
	}

	// 5) 解码 mconfB64 → gunzip → 基本结构校验
	rawGz, err := base64.StdEncoding.DecodeString(mconfB64)
	if err != nil {
		return fmt.Errorf("mconf base64: %v", err)
	}
	gr, err := gzip.NewReader(bytes.NewReader(rawGz))
	if err != nil {
		return fmt.Errorf("mconf gunzip: %v", err)
	}
	mjson, err := io.ReadAll(gr)
	_ = gr.Close()
	if err != nil {
		return fmt.Errorf("mconf read: %v", err)
	}

	var M struct {
		Flag   []int `json:"flag"`
		SelAnd []int `json:"selAnd"`
		SelOr  []int `json:"selOr"`
		SelNop []int `json:"selNop"`
	}
	if err := json.Unmarshal(mjson, &M); err != nil {
		return fmt.Errorf("mconf json: %v", err)
	}
	if len(M.Flag) != AttrNum || len(M.SelAnd) != IntNum || len(M.SelOr) != IntNum || len(M.SelNop) != IntNum {
		return fmt.Errorf("mconf shape mismatch: flag=%d selAnd=%d selOr=%d selNop=%d (expect %d/%d/%d/%d)",
			len(M.Flag), len(M.SelAnd), len(M.SelOr), len(M.SelNop),
			AttrNum, IntNum, IntNum, IntNum)
	}

	// 6) 覆盖存储 mconf（组合键 rcid~mconf）
	if err := putBinary(ctx, rcid, "mconf", rawGz); err != nil {
		return fmt.Errorf("update mconf: %v", err)
	}

	return nil
}

// AttributeUpdate only updates the zk-Guard randomized user binding.
//
// Args:
//   - pid: user pseudonymous identifier, e.g., libp2p PeerID
//   - newUserCommit: randomized user commitment H(new_w || new_r)
//
// This function intentionally does NOT update VerMap.  After introducing
// Reg[pid] = H(w || r), VerMap must remain profile-level and be indexed by
// H(w), not by H(w || r).  Therefore PolyLock version updates are handled by
// ProfileVersionUpdate(oldProfileHash, newProfileHash).
func (s *SmartContract) AttributeUpdate(
	ctx contractapi.TransactionContextInterface,
	pid string,
	newUserCommit string,
) error {
	pid = strings.TrimSpace(pid)
	newUserCommit = strings.TrimSpace(newUserCommit)
	if pid == "" {
		return fmt.Errorf("pid is empty")
	}
	if newUserCommit == "" {
		return fmt.Errorf("newUserCommit is empty")
	}

	// 1) The pid must have been registered.
	raw, err := getBinary(ctx, pid, "pid")
	if err != nil {
		return fmt.Errorf("failed to access pid record: %v", err)
	}
	if raw == nil {
		return fmt.Errorf("pid %s not registered", pid)
	}

	// 2) Decode current randomized commitment record.
	var rec AttrRecord
	if err = json.Unmarshal(raw, &rec); err != nil {
		return fmt.Errorf("unmarshal AttrRecord: %v", err)
	}

	oldUserCommit := strings.TrimSpace(rec.HashAttr)
	if oldUserCommit == newUserCommit {
		// No Reg[pid] change.  VerMap is deliberately untouched here.
		return nil
	}

	// 3) Update Reg[pid] = H(new_w || new_r).
	rec.HashAttr = newUserCommit
	out, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal AttrRecord: %v", err)
	}

	if err = putBinary(ctx, pid, "pid", out); err != nil {
		return fmt.Errorf("put current pid record: %v", err)
	}

	// 4) Optional: keep a pid history record.  This stores only the randomized
	// user commitment and does not store profileHash.
	txid := ctx.GetStub().GetTxID()
	if err = putBinary(ctx, pid, "pid_history_"+txid, out); err != nil {
		return fmt.Errorf("put pid history: %v", err)
	}

	return nil
}

// ProfileVersionUpdate updates only the PolyLock profile-level version map.
//
// Args:
//   - oldProfileHash: deterministic profile hash H(old_w)
//   - newProfileHash: deterministic profile hash H(new_w)
//
// Privacy rationale:
//
//	This function does not take pid and therefore does not reveal, within this
//	contract call, which user moved away from oldProfileHash.  It may still
//	reveal that some profile was updated.  Stronger unlinkability can be
//	obtained by batching or delaying these profile-version transactions.
//
// Version semantics:
//   - If oldProfileHash != newProfileHash, increment VerMap[oldProfileHash]
//     so old USK(old_w, v) cannot decrypt future lock ciphertexts generated
//     under VerMap[oldProfileHash] = v+1.
//   - Ensure VerMap[newProfileHash] exists; if it already exists, do not change
//     it.  The current user receives USK(new_w, VerMap[newProfileHash]).
func (s *SmartContract) ProfileVersionUpdate(
	ctx contractapi.TransactionContextInterface,
	oldProfileHash string,
	newProfileHash string,
) error {
	oldProfileHash = strings.TrimSpace(oldProfileHash)
	newProfileHash = strings.TrimSpace(newProfileHash)
	if oldProfileHash == "" {
		return fmt.Errorf("oldProfileHash is empty")
	}
	if newProfileHash == "" {
		return fmt.Errorf("newProfileHash is empty")
	}

	if oldProfileHash != newProfileHash {
		if _, err := incrementVersion(ctx, oldProfileHash); err != nil {
			return fmt.Errorf("increment old profile version for %s: %v", oldProfileHash, err)
		}
	} else {
		// No profile transition; ensure the profile exists in VerMap.
		if _, err := ensureVersion(ctx, oldProfileHash); err != nil {
			return fmt.Errorf("ensure version for unchanged profile %s: %v", oldProfileHash, err)
		}
		return nil
	}

	if _, err := ensureVersion(ctx, newProfileHash); err != nil {
		return fmt.Errorf("ensure version for new profile %s: %v", newProfileHash, err)
	}

	return nil
}

// QueryAllConfigVersions returns a snapshot of the profile-level version map.
//
// Return format:
//
//	{
//	  "<profileHash>": <version>,
//	  ...
//	}
//
// It scans only composite keys created by verMapKey(ctx, profileHash), i.e.,
// "vermap" composite-key entries. Therefore it does not expose or mix Reg[pid]
// entries, mconf records, UPK/UVK/UCS, or other ledger states.
//
// Semantics:
//   - VerMap contains only deterministic profile hashes H(w).
//   - Missing VerMap[H(w)] is interpreted by clients as version 0.
func (s *SmartContract) QueryAllConfigVersions(
	ctx contractapi.TransactionContextInterface,
) (string, error) {
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey("vermap", []string{})
	if err != nil {
		return "", fmt.Errorf("scan VerMap failed: %v", err)
	}
	defer iter.Close()

	out := make(map[string]uint64)

	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return "", fmt.Errorf("VerMap iterator next failed: %v", err)
		}

		objectType, parts, err := ctx.GetStub().SplitCompositeKey(kv.Key)
		if err != nil {
			return "", fmt.Errorf("split VerMap key failed: %v", err)
		}
		if objectType != "vermap" || len(parts) != 1 {
			continue
		}

		profileHash := strings.TrimSpace(parts[0])
		if profileHash == "" {
			continue
		}

		var rec VersionRecord
		if err := json.Unmarshal(kv.Value, &rec); err != nil {
			return "", fmt.Errorf("unmarshal VerMap[%s]: %v", profileHash, err)
		}

		out[profileHash] = rec.Version
	}

	b, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("marshal VerMap snapshot failed: %v", err)
	}
	return string(b), nil
}

// ====== Ed25519 → PeerID (libp2p) ======
func peerIDFromEd25519(pk ed25519.PublicKey) (string, error) {
	// libp2p expects its own PubKey type
	lpPub, err := lpcrypto.UnmarshalEd25519PublicKey(pk)
	if err != nil {
		return "", fmt.Errorf("unmarshal Ed25519 pubkey for libp2p: %v", err)
	}

	id, err := peer.IDFromPublicKey(lpPub)
	if err != nil {
		return "", fmt.Errorf("peer.IDFromPublicKey: %v", err)
	}

	return id.String(), nil
}

// getLatestAttrHash —— 返回 pid 最新一次 AttributeUpdate 写入的 hashAttr
// 兼容老数据：若查不到组合键，则回退到 pid 的旧结构 AttrRecord.HashAttr
func getLatestAttrHash(ctx contractapi.TransactionContextInterface, pid string) (string, error) {
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey("attr", []string{pid})
	if err != nil {
		return "", fmt.Errorf("scan composite attrs: %v", err)
	}
	defer iter.Close()

	var latest []byte
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return "", fmt.Errorf("iter next: %v", err)
		}
		// 由于 ver 使用 20 位零填充 unixNano，字典序即时间序，最后一个即最新
		latest = kv.Value
	}
	if latest != nil {
		return string(latest), nil
	}

	// 兼容旧版：从 pid 的 AttrRecord 读取
	raw, err := ctx.GetStub().GetState(pid)
	if err != nil {
		return "", fmt.Errorf("read legacy attr: %v", err)
	}
	if raw == nil {
		return "", fmt.Errorf("no attributes found for %s", pid)
	}
	var rec AttrRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return "", fmt.Errorf("unmarshal legacy AttrRecord: %v", err)
	}
	if rec.HashAttr == "" {
		return "", fmt.Errorf("empty legacy HashAttr for %s", pid)
	}
	return rec.HashAttr, nil
}

/* ------------------------------------------------------------------ */
/*                             主函数                                 */
/* ------------------------------------------------------------------ */

func main() {
	cc, err := contractapi.NewChaincode(new(SmartContract))
	if err != nil {
		fmt.Printf("Error creating chaincode: %s", err)
		return
	}
	if err := cc.Start(); err != nil {
		fmt.Printf("Error starting chaincode: %s", err)
	}
}
