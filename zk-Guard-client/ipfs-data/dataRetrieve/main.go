// dataRetrieve.go — DU 侧检索客户端（Ed25519/Libp2p PeerID 适配版本）
// 用法： ./dataRetrieve <rcid> <pid> [username]
// username 默认 ipfs-Bob

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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	lpcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/consensys/gnark-crypto/ecc"
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

/* --- constants & paths (保持原样) --- */

const (
	AttrNum   = 100
	IntNum    = AttrNum - 1
	GroupSz   = 253
	TotalNode = 2*AttrNum - 1

	privPathTpl       = "./zk-guard_priv_%s.pem"
	pubPathTpl        = "./zk-guard_pub_%s.pem"
	attrPath          = "./zk-guard_attrs.json"
	credentialPathTpl = "./zk-guard_credential_%s.json"
	sigPathTpl        = "./sig_%s.b64"
	proofPathTpl      = "./proof_%s.b64"

	polyLockUSKPathTpl = "./polylock_state/polylock_usk_%s.json"

	mspID         = "Org1MSP"
	cryptoPath    = "../../../organizations/peerOrganizations/org1.example.com"
	certPath      = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem"
	keyPath       = cryptoPath + "/users/User1@org1.example.com/msp/keystore/"
	tlsCertPath   = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint  = "peer0.org1.example.com:7051"
	gatewayPeer   = "peer0.org1.example.com"
	chaincodeName = "acmc"
	channelName   = "mychannel"
)

type PolyLockUSKDisk struct {
	Format         string `json:"format"`
	Username       string `json:"username"`
	PID            string `json:"pid"`
	AttrNum        int    `json:"attr_num"`
	AttrHash       string `json:"attr_hash"` // profile hash H(w), kept for PolyLock
	UserCommit     string `json:"user_commit"`
	AttrRand       string `json:"attr_rand"`
	AttrRandBase64 string `json:"attr_rand_base64"`
	Version        uint64 `json:"version"`
	AttrVector     []int  `json:"attr_vector"`
}

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

func loadLocalAttrVector(user string) ([]int, string, error) {
	uskPath := fmt.Sprintf(polyLockUSKPathTpl, user)
	if raw, err := os.ReadFile(uskPath); err == nil {
		var usk PolyLockUSKDisk
		if err := json.Unmarshal(raw, &usk); err != nil {
			return nil, "", fmt.Errorf("parse %s failed: %v", uskPath, err)
		}
		if len(usk.AttrVector) != AttrNum {
			return nil, "", fmt.Errorf("%s attr vector length=%d, expect %d", uskPath, len(usk.AttrVector), AttrNum)
		}
		localHash := hashCalc(usk.AttrVector)
		if usk.AttrHash != "" && usk.AttrHash != localHash {
			return nil, "", fmt.Errorf("%s attrHash mismatch: file=%s computed=%s", uskPath, usk.AttrHash, localHash)
		}
		return usk.AttrVector, uskPath, nil
	}

	raw, err := os.ReadFile(attrPath)
	if err != nil {
		return nil, "", fmt.Errorf("read attr file failed: neither %s nor %s is available", uskPath, attrPath)
	}
	bits := make([]int, 0, AttrNum)
	if err := json.Unmarshal(raw, &bits); err != nil {
		return nil, "", fmt.Errorf("parse %s failed: %v", attrPath, err)
	}
	if len(bits) != AttrNum {
		return nil, "", fmt.Errorf("%s attr vector length=%d, expect %d", attrPath, len(bits), AttrNum)
	}
	return bits, attrPath, nil
}

type LocalCredential struct {
	AttrVector  []int
	AttrRand    *big.Int
	ProfileHash string
	UserCommit  string
	Source      string
}

func parseCredentialRand(randDec, randB64, source string) (*big.Int, error) {
	if strings.TrimSpace(randDec) != "" {
		r := new(big.Int)
		if _, ok := r.SetString(strings.TrimSpace(randDec), 10); ok {
			return r, nil
		}
	}
	if strings.TrimSpace(randB64) != "" {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(randB64))
		if err != nil {
			return nil, fmt.Errorf("decode attr_rand_base64 in %s failed: %v", source, err)
		}
		return new(big.Int).SetBytes(raw), nil
	}
	return nil, fmt.Errorf("%s does not contain attr_rand/attr_rand_base64; randomized zk-Guard proof needs r", source)
}

func loadLocalCredential(user, pid string) (*LocalCredential, error) {
	credPath := fmt.Sprintf(credentialPathTpl, user)
	if raw, err := os.ReadFile(credPath); err == nil {
		var cred ZKGuardCredentialDisk
		if err := json.Unmarshal(raw, &cred); err != nil {
			return nil, fmt.Errorf("parse %s failed: %v", credPath, err)
		}
		if len(cred.AttrVector) != AttrNum {
			return nil, fmt.Errorf("%s attr vector length=%d, expect %d", credPath, len(cred.AttrVector), AttrNum)
		}
		randBI, err := parseCredentialRand(cred.AttrRand, cred.AttrRandBase64, credPath)
		if err != nil {
			return nil, err
		}
		profileHash := hashCalc(cred.AttrVector)
		if cred.ProfileHash != "" && cred.ProfileHash != profileHash {
			return nil, fmt.Errorf("%s profileHash mismatch: file=%s computed=%s", credPath, cred.ProfileHash, profileHash)
		}
		userCommit := hashCalcUserCommit(cred.AttrVector, randBI)
		if cred.UserCommit != "" && cred.UserCommit != userCommit {
			return nil, fmt.Errorf("%s userCommit mismatch: file=%s computed=%s", credPath, cred.UserCommit, userCommit)
		}
		if cred.PID != "" && cred.PID != pid {
			fmt.Printf("[WARN] credential PID mismatch: file=%s request=%s\n", cred.PID, pid)
		}
		return &LocalCredential{
			AttrVector:  cred.AttrVector,
			AttrRand:    randBI,
			ProfileHash: profileHash,
			UserCommit:  userCommit,
			Source:      credPath,
		}, nil
	}

	uskPath := fmt.Sprintf(polyLockUSKPathTpl, user)
	if raw, err := os.ReadFile(uskPath); err == nil {
		var usk PolyLockUSKDisk
		if err := json.Unmarshal(raw, &usk); err != nil {
			return nil, fmt.Errorf("parse %s failed: %v", uskPath, err)
		}
		if len(usk.AttrVector) != AttrNum {
			return nil, fmt.Errorf("%s attr vector length=%d, expect %d", uskPath, len(usk.AttrVector), AttrNum)
		}
		randBI, err := parseCredentialRand(usk.AttrRand, usk.AttrRandBase64, uskPath)
		if err != nil {
			return nil, err
		}
		profileHash := hashCalc(usk.AttrVector)
		if usk.AttrHash != "" && usk.AttrHash != profileHash {
			return nil, fmt.Errorf("%s attrHash/profileHash mismatch: file=%s computed=%s", uskPath, usk.AttrHash, profileHash)
		}
		userCommit := hashCalcUserCommit(usk.AttrVector, randBI)
		if usk.UserCommit != "" && usk.UserCommit != userCommit {
			return nil, fmt.Errorf("%s userCommit mismatch: file=%s computed=%s", uskPath, usk.UserCommit, userCommit)
		}
		return &LocalCredential{
			AttrVector:  usk.AttrVector,
			AttrRand:    randBI,
			ProfileHash: profileHash,
			UserCommit:  userCommit,
			Source:      uskPath,
		}, nil
	}

	return nil, fmt.Errorf("randomized zk-Guard credential not found: neither %s nor %s is available", credPath, uskPath)
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
	// 把各 limb 哈希再聚合一次
	hf, _ := mimc.NewMiMC(api)
	for _, g := range grp {
		hf.Write(g)
	}
	// Randomized user binding commitment: Reg[pid] = H(w || r).
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

/* ---------- helper: 构造 witness ---------- */

func makeWitness(bits []int, randBI *big.Int, f, aS, oS, nS []int) Circuit {
	var w Circuit
	for i, b := range bits {
		w.X[i] = b
	}
	for i, v := range f {
		w.Flag[i] = v
	}
	for i, v := range aS {
		w.SelAnd[i] = v
	}
	for i, v := range oS {
		w.SelOr[i] = v
	}
	for i, v := range nS {
		w.SelNop[i] = v
	}
	w.Rand = randBI
	w.Hash = hashCalcUserCommit(bits, randBI)
	return w
}

func validateWitnessShape(bits, f, aS, oS, nS []int) error {
	if len(bits) != AttrNum {
		return fmt.Errorf("attribute vector length=%d, expect AttrNum=%d", len(bits), AttrNum)
	}
	if len(f) != AttrNum || len(aS) != IntNum || len(oS) != IntNum || len(nS) != IntNum {
		return fmt.Errorf("mconf shape mismatch: flag=%d selAnd=%d selOr=%d selNop=%d, expect %d/%d/%d/%d",
			len(f), len(aS), len(oS), len(nS), AttrNum, IntNum, IntNum, IntNum)
	}
	return nil
}

func localPolicySatisfied(bits, f, aS, oS, nS []int) bool {
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

/* ---------- 本地 MiMC-BN254 承诺 ---------- */

// === 本地承诺：hashCalc ===
// 依赖: import ( "math/big"; "github.com/consensys/gnark-crypto/hash" )
func hashCalc(bits []int) string {
	const LimbBits = 253
	var seg []*big.Int

	for i := 0; i < len(bits); i += LimbBits {
		end := i + LimbBits
		if end > len(bits) {
			end = len(bits)
		}
		// LSB-first: 第 (j-i) 位对应 bits[j]
		val := big.NewInt(0)
		for j := i; j < end; j++ {
			if bits[j] == 1 {
				val.SetBit(val, j-i, 1)
			}
		}
		h := hash.MIMC_BN254.New()
		h.Write(val.Bytes()) // 与电路一致：吸收一个场元素
		seg = append(seg, new(big.Int).SetBytes(h.Sum(nil)))
	}

	hf := hash.MIMC_BN254.New()
	for _, s := range seg {
		hf.Write(s.Bytes())
	}
	return new(big.Int).SetBytes(hf.Sum(nil)).String() // 十进制字符串
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

/* ------------------- gzip helpers ------------------- */

// 新：仅解压“原始 gzip 字节”（无 base64）
func gunzipBytes(enc []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(enc))
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(gr)
	_ = gr.Close()
	return out, err
}

// 旧：兼容以前“base64+gzip”的返回
func gunzipB64(b64 string) ([]byte, error) {
	enc, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return gunzipBytes(enc)
}

/* --- Ed25519 PeerID derive from saved PEM --- */

func derivePeerIDFromSavedPEM(pubPath string) (string, error) {
	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		return "", fmt.Errorf("read pub: %v", err)
	}

	block, _ := pem.Decode(pubPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return "", fmt.Errorf("invalid PUB KEY PEM")
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse pkix: %v", err)
	}

	stdPub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return "", nil // not Ed25519, skip match
	}

	lpPub, err := lpcrypto.UnmarshalEd25519PublicKey(stdPub)
	if err != nil {
		return "", fmt.Errorf("unmarshal lp ed25519: %v", err)
	}

	id, err := peer.IDFromPublicKey(lpPub)
	if err != nil {
		return "", fmt.Errorf("peer.IDFromPublicKey: %v", err)
	}

	return id.String(), nil
}

/* --- sign digest (原样) --- */

func signTdigest(privAny interface{}, digest [32]byte) (string, error) {
	switch k := privAny.(type) {
	case ed25519.PrivateKey:
		sig := ed25519.Sign(k, digest[:])
		return base64.StdEncoding.EncodeToString(sig), nil
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
		if err != nil {
			return "", err
		}
		der, _ := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		return base64.StdEncoding.EncodeToString(der), nil
	default:
		return "", fmt.Errorf("unsupported priv key type: %T", privAny)
	}
}

/* --- proof bundle passing: requester-side prove / provider-side verify --- */

type ProofBundle struct {
	ProofB64  string `json:"ProofB64"`
	SigB64    string `json:"SigB64"`
	PubKeyPEM string `json:"PubKeyPEM"`
}

const proofExchangeDir = "./proof_exchange"

func safeFileToken(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "empty"
	}
	repl := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		" ", "_",
		"\t", "_",
		"\n", "_",
		"\r", "_",
	)
	return repl.Replace(s)
}

func defaultProofBundlePath(rcid, pid string) string {
	return filepath.Join(proofExchangeDir, fmt.Sprintf("proof_%s_%s.json", safeFileToken(rcid), safeFileToken(pid)))
}

func normalizeProofBundlePath(rcid, pid, path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		path = defaultProofBundlePath(rcid, pid)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return abs, nil
}

func writeProofBundleAtomic(path string, bundle ProofBundle) error {
	if strings.TrimSpace(bundle.ProofB64) == "" || strings.TrimSpace(bundle.SigB64) == "" || strings.TrimSpace(bundle.PubKeyPEM) == "" {
		return fmt.Errorf("invalid proof bundle: ProofB64/SigB64/PubKeyPEM must be non-empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readProofBundle(path string) (ProofBundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ProofBundle{}, err
	}
	var bundle ProofBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return ProofBundle{}, err
	}
	if strings.TrimSpace(bundle.ProofB64) == "" || strings.TrimSpace(bundle.SigB64) == "" || strings.TrimSpace(bundle.PubKeyPEM) == "" {
		return ProofBundle{}, fmt.Errorf("invalid proof bundle %s: ProofB64/SigB64/PubKeyPEM must be non-empty", path)
	}
	return bundle, nil
}

func connectFabric() (*client.Contract, func()) {
	conn := newGrpcConnection(tlsCertPath, gatewayPeer, peerEndpoint)
	gw, err := client.Connect(
		newIdentity(certPath, mspID),
		client.WithSign(newSign(keyPath)),
		client.WithClientConnection(conn),
		client.WithEvaluateTimeout(5*time.Second),
	)
	if err != nil {
		_ = conn.Close()
		log.Fatalf("Fabric Gateway connect failed: %v", err)
	}
	contract := gw.GetNetwork(channelName).GetContract(chaincodeName)
	cleanup := func() {
		gw.Close()
		_ = conn.Close()
	}
	return contract, cleanup
}

func getParamRaw(contract *client.Contract, k string) []byte {
	b64, err := contract.EvaluateTransaction("GetParamRaw", k)
	if err != nil {
		log.Fatalf("GetParamRaw(%s) failed: %v", k, err)
	}
	z, err := gunzipB64(string(b64))
	if err != nil {
		log.Fatalf("gunzip GetParamRaw(%s) failed: %v", k, err)
	}
	return z
}

func getBinary(contract *client.Contract, rcid, tag string) []byte {
	b64, err := contract.EvaluateTransaction("GetBinary", rcid, tag)
	if err != nil {
		log.Fatalf("GetBinary(%s,%s) failed: %v", rcid, tag, err)
	}
	z, err := gunzipB64(string(b64))
	if err != nil {
		log.Fatalf("gunzip GetBinary(%s,%s) failed: %v", rcid, tag, err)
	}
	return z
}

func runProve(rcid, pid, user, proofPath string) {
	start := time.Now()

	privPath := fmt.Sprintf(privPathTpl, user)
	pubPath := fmt.Sprintf(pubPathTpl, user)

	privPEM, err := os.ReadFile(privPath)
	if err != nil {
		log.Fatalf("read private key %s: %v", privPath, err)
	}
	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		log.Fatalf("read public key %s: %v", pubPath, err)
	}

	if derivedPID, err := derivePeerIDFromSavedPEM(pubPath); err == nil && derivedPID != "" && derivedPID != pid {
		log.Fatalf("PID mismatch before proving: request pid=%s, public key derives pid=%s", pid, derivedPID)
	}

	privBlock, _ := pem.Decode(privPEM)
	if privBlock == nil {
		log.Fatalf("invalid private key PEM: %s", privPath)
	}
	privAny, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		log.Fatalf("parse priv: %v", err)
	}

	contract, cleanup := connectFabric()
	defer cleanup()

	/* ---------- pull VK/UCS & mconf ---------- */
	pkBytes := getParamRaw(contract, "UPK")
	ccsBytes := getParamRaw(contract, "UCS")
	mjson := getBinary(contract, rcid, "mconf")

	if len(pkBytes) == 0 {
		log.Fatalf("UPK empty after gunzip")
	}
	if len(ccsBytes) == 0 {
		log.Fatalf("UCS empty after gunzip")
	}
	if len(mjson) == 0 {
		log.Fatalf("mconf empty after gunzip")
	}

	pk := groth16.NewProvingKey(ecc.BN254)
	pk.ReadFrom(bytes.NewReader(pkBytes))
	ccs := groth16.NewCS(ecc.BN254)
	ccs.ReadFrom(bytes.NewReader(ccsBytes))

	var M struct {
		Flag   []int `json:"flag"`
		SelAnd []int `json:"selAnd"`
		SelOr  []int `json:"selOr"`
		SelNop []int `json:"selNop"`
	}
	if err := json.Unmarshal(mjson, &M); err != nil {
		log.Fatalf("mconf JSON 解析失败: %v", err)
	}

	/* ---------- load and validate the registered local credential ---------- */
	startCredential := time.Now()
	cred, err := loadLocalCredential(user, pid)
	if err != nil {
		log.Fatalf("读取用户随机化属性凭证失败: %v", err)
	}
	tCredential := time.Since(startCredential)

	bits := cred.AttrVector
	if err = validateWitnessShape(bits, M.Flag, M.SelAnd, M.SelOr, M.SelNop); err != nil {
		log.Fatalf("Witness 形状检查失败: %v", err)
	}

	fmt.Printf("Local credential source: %s\n", cred.Source)
	fmt.Printf("Local profileHash=H(w) = %s\n", cred.ProfileHash)
	fmt.Printf("Local userCommit=H(w||r) = %s\n", cred.UserCommit)

	// Optional requester-side fail-fast check. It is not a security boundary:
	// the Groth16 circuit enforces policy satisfaction and the verifier binds the
	// public commitment to Reg[pid]. Keep it disabled in formal experiments.
	preflightEnabled := false
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ZKGUARD_PROVE_PREFLIGHT"))) {
	case "1", "true", "yes", "on":
		preflightEnabled = true
	}
	var tPreflight time.Duration
	if preflightEnabled {
		startPreflight := time.Now()
		localOK := localPolicySatisfied(bits, M.Flag, M.SelAnd, M.SelOr, M.SelNop)
		tPreflight = time.Since(startPreflight)
		fmt.Printf("Local policy satisfied (diagnostic): %v\n", localOK)
		if !localOK {
			log.Fatalf("本地属性向量不满足当前 mconf 策略")
		}
	}

	/* ---------- WitnessGen: core algorithm only ---------- */
	startWitness := time.Now()
	w := makeWitness(bits, cred.AttrRand, M.Flag, M.SelAnd, M.SelOr, M.SelNop)
	pi, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatalf("NewWitness 失败: %v", err)
	}
	tWitness := time.Since(startWitness)

	/* ---------- ProofGen ---------- */
	startProof := time.Now()
	proof, err := groth16.Prove(ccs, pk, pi)
	if err != nil {
		log.Fatalf("groth16.Prove 失败: %v", err)
	}
	tProof := time.Since(startProof)

	var buf bytes.Buffer
	if _, err := proof.WriteRawTo(&buf); err != nil {
		log.Fatalf("proof WriteRawTo: %v", err)
	}
	proofB64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	/* ---------- Sign pid||rcid||proofB64 ---------- */
	T := pid + rcid + proofB64
	d := sha256.Sum256([]byte(T))
	sigB64, err := signTdigest(privAny, d)
	if err != nil {
		log.Fatalf("sign digest failed: %v", err)
	}

	bundlePath, err := normalizeProofBundlePath(rcid, pid, proofPath)
	if err != nil {
		log.Fatalf("proof bundle path failed: %v", err)
	}
	bundle := ProofBundle{
		ProofB64:  proofB64,
		SigB64:    sigB64,
		PubKeyPEM: string(pubPEM),
	}
	startWrite := time.Now()
	if err := writeProofBundleAtomic(bundlePath, bundle); err != nil {
		log.Fatalf("write proof bundle failed: %v", err)
	}
	tWrite := time.Since(startWrite)

	total := time.Since(start)
	coreTotal := tWitness + tProof

	fmt.Println("============== ⏱️ Prove 时间统计（毫秒） ==============")
	fmt.Printf("CredentialLoad  : %.3f ms\n", float64(tCredential.Microseconds())/1000)
	if preflightEnabled {
		fmt.Printf("PolicyPreflight : %.3f ms\n", float64(tPreflight.Microseconds())/1000)
	}
	fmt.Printf("WitnessGen      : %.3f ms\n", float64(tWitness.Microseconds())/1000)
	fmt.Printf("ProofGen        : %.3f ms\n", float64(tProof.Microseconds())/1000)
	fmt.Printf("ProveCoreTotal  : %.3f ms\n", float64(coreTotal.Microseconds())/1000)
	fmt.Printf("ProofBundleWrite: %.3f ms\n", float64(tWrite.Microseconds())/1000)
	fmt.Printf("ProveTotal      : %.3f ms\n", float64(total.Microseconds())/1000)
	fmt.Println("====================================================")
	fmt.Printf("证明大小: %.3f KB\n", float64(len(proofB64))/1024)
	fmt.Printf("PROOF_BUNDLE_PATH=%s\n", bundlePath)
}

func runVerify(rcid, pid, proofPath string) {
	start := time.Now()
	bundlePath, err := normalizeProofBundlePath(rcid, pid, proofPath)
	if err != nil {
		log.Fatalf("proof bundle path failed: %v", err)
	}

	startRead := time.Now()
	bundle, err := readProofBundle(bundlePath)
	if err != nil {
		log.Fatalf("read proof bundle %s failed: %v", bundlePath, err)
	}
	tRead := time.Since(startRead)

	contract, cleanup := connectFabric()
	defer cleanup()

	startChain := time.Now()
	result, err := contract.EvaluateTransaction("DataRetrieve", rcid, pid, bundle.ProofB64, bundle.SigB64, bundle.PubKeyPEM)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			fmt.Println("gRPC:", st.Message())
		}
		log.Fatalf("DataRetrieve verify failed: %v", err)
	}
	tChain := time.Since(startChain)
	total := time.Since(start)

	fmt.Println("============== ⏱️ Verify 时间统计（毫秒） ==============")
	fmt.Printf("ProofBundleRead : %.3f ms\n", float64(tRead.Microseconds())/1000)
	fmt.Printf("ChainDecision   : %.3f ms\n", float64(tChain.Microseconds())/1000)
	fmt.Printf("VerifyTotal     : %.3f ms\n", float64(total.Microseconds())/1000)
	fmt.Println("=====================================================")
	fmt.Printf("PROOF_BUNDLE_PATH=%s\n", bundlePath)
	fmt.Printf("链码返回: %s\n", result)
}

func usage() {
	log.Fatalf("用法:\n  %s prove  <rcid> <pid> [username] [proofBundlePath]\n  %s verify <rcid> <pid> [proofBundlePath]\n  %s <rcid> <pid> [proofBundlePath]   # legacy provider mode = verify", os.Args[0], os.Args[0], os.Args[0])
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("用法:\n  %s prove <rcid> <pid> [username] [proofBundlePath]\n  %s verify <rcid> <pid> [proofBundlePath]",
			os.Args[0], os.Args[0])
	}

	mode := os.Args[1]

	switch mode {
	case "prove":
		if len(os.Args) < 4 {
			log.Fatalf("用法: %s prove <rcid> <pid> [username] [proofBundlePath]", os.Args[0])
		}
		rcid := os.Args[2]
		pid := os.Args[3]

		user := "ipfs-Eve"
		if len(os.Args) > 4 && strings.TrimSpace(os.Args[4]) != "" {
			user = os.Args[4]
		}

		bundlePath := defaultProofBundlePath(rcid, pid)
		if len(os.Args) > 5 && strings.TrimSpace(os.Args[5]) != "" {
			bundlePath = os.Args[5]
		}

		runProve(rcid, pid, user, bundlePath)

	case "verify":
		if len(os.Args) < 4 {
			log.Fatalf("用法: %s verify <rcid> <pid> [proofBundlePath]", os.Args[0])
		}
		rcid := os.Args[2]
		pid := os.Args[3]

		bundlePath := defaultProofBundlePath(rcid, pid)
		if len(os.Args) > 4 && strings.TrimSpace(os.Args[4]) != "" {
			bundlePath = os.Args[4]
		}

		runVerify(rcid, pid, bundlePath)

	default:
		log.Fatalf("unknown mode %q; expected prove or verify", mode)
	}
}

/* --- Fabric helpers (原样) --- */

func newGrpcConnection(_ string, gw, ep string) *grpc.ClientConn {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	creds := credentials.NewTLS(tlsConfig)
	conn, _ := grpc.Dial(ep,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(120*1024*1024),
			grpc.MaxCallRecvMsgSize(120*1024*1024)))
	return conn
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
