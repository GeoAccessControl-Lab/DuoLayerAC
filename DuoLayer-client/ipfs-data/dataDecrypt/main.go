// dataDecrypt.go — 本地 PolyLock 解密工具
//
// 用法：
//
//	./dataDecrypt <cipherObjectPath> <username> [outPlainPath]
//
// 说明：
//   - 本程序不访问 Fabric 链码，也不执行 zk-Guard 策略决策。
//   - zk-Guard 的授权由 IPFS provider 端在发送 block 前完成。
//   - systemInit 负责生成合法属性空间 S* 与用户 PolyLock USK；dataStorage
//     负责根据同一 S* 生成策略并构造 two-link RootCID。
//   - 本程序只负责本地解密：读取 ipfs get 得到的 two-link 目录
//     RootCID/{data.ct,lock.ct}，加载本地 PolyLock USK，执行 Decaps + AES-GCM。
//   - 为兼容旧实验，若输入是旧版单文件对象，本程序仍可解析：
//     CT_data_payload || padding || CT_lock_serialized || footer_json || footer_len_8bytes。
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/ring"
	plintegration "polylock-thesis/go-bridge/integration"
	polylockv2 "polylock-thesis/go-bridge/polylock"
)

const (
	polyLockLogN      = 10
	polyLockLogQ      = 27
	polyLockKeySize   = 32
	polyLockCompress  = 11
	polyLockStateDir  = "./polylock_state"
	polyLockObjectFmt = "zkguard-polylock-object-v1"
)

type PolyLockUSKDisk struct {
	Format           string `json:"format"`
	Username         string `json:"username"`
	PID              string `json:"pid"`
	AttrNum          int    `json:"attr_num"`
	AttrHash         string `json:"attr_hash"`
	Version          uint64 `json:"version"`
	VersionedHash    string `json:"versioned_hash"`
	RingLogN         int    `json:"ring_log_n"`
	RingLogQ         int    `json:"ring_log_q"`
	SignatureSBase64 string `json:"signature_s_base64"`
	Encoding         string `json:"encoding"`
	AttrVector       []int  `json:"attr_vector"`
	CreatedAt        string `json:"created_at"`
}

type PolyLockOnlyCT struct {
	SubLocks [][][]byte `json:"sub_locks"`
}

const polyLockCTBinaryMagic = "PLK1"

// unmarshalPolyLockCT parses both the new compact binary lock format and the
// previous JSON format.  The JSON fallback keeps old lock.ct objects readable.
func unmarshalPolyLockCT(raw []byte) (PolyLockOnlyCT, error) {
	if len(raw) >= len(polyLockCTBinaryMagic) && string(raw[:len(polyLockCTBinaryMagic)]) == polyLockCTBinaryMagic {
		return unmarshalPolyLockCTBinary(raw)
	}

	var ct PolyLockOnlyCT
	if err := json.Unmarshal(raw, &ct); err != nil {
		return PolyLockOnlyCT{}, err
	}
	return ct, nil
}

func unmarshalPolyLockCTBinary(raw []byte) (PolyLockOnlyCT, error) {
	pos := 0
	read := func(n int) ([]byte, error) {
		if n < 0 || pos+n > len(raw) {
			return nil, fmt.Errorf("truncated binary lock ciphertext at offset %d need=%d total=%d", pos, n, len(raw))
		}
		out := raw[pos : pos+n]
		pos += n
		return out, nil
	}

	magic, err := read(len(polyLockCTBinaryMagic))
	if err != nil {
		return PolyLockOnlyCT{}, err
	}
	if string(magic) != polyLockCTBinaryMagic {
		return PolyLockOnlyCT{}, fmt.Errorf("invalid binary lock magic: %q", string(magic))
	}

	bucketCountRaw, err := read(4)
	if err != nil {
		return PolyLockOnlyCT{}, err
	}
	bucketCount := int(binary.BigEndian.Uint32(bucketCountRaw))
	ct := PolyLockOnlyCT{SubLocks: make([][][]byte, bucketCount)}

	for i := 0; i < bucketCount; i++ {
		sampleCountRaw, err := read(2)
		if err != nil {
			return PolyLockOnlyCT{}, err
		}
		sampleCount := int(binary.BigEndian.Uint16(sampleCountRaw))
		ct.SubLocks[i] = make([][]byte, sampleCount)

		for j := 0; j < sampleCount; j++ {
			sampleLenRaw, err := read(4)
			if err != nil {
				return PolyLockOnlyCT{}, err
			}
			sampleLen := int(binary.BigEndian.Uint32(sampleLenRaw))
			sample, err := read(sampleLen)
			if err != nil {
				return PolyLockOnlyCT{}, err
			}
			ct.SubLocks[i][j] = append([]byte(nil), sample...)
		}
	}

	if pos != len(raw) {
		return PolyLockOnlyCT{}, fmt.Errorf("binary lock ciphertext has %d trailing bytes", len(raw)-pos)
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

type EncryptedObjectParts struct {
	Mode        string
	DataPayload []byte
	LockBytes   []byte
	LockCT      PolyLockOnlyCT
	Footer      ProtectedObjectFooter
}

func polyRing() (*ring.Ring, error) {
	params, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN:    polyLockLogN,
		LogQ:    []int{polyLockLogQ},
		NTTFlag: true,
	})
	if err != nil {
		return nil, err
	}
	return params.RingQ(), nil
}

func loadPolyLockUSK(user string, r *ring.Ring) (*PolyLockUSKDisk, ring.Poly, error) {
	path := filepath.Join(polyLockStateDir, fmt.Sprintf("polylock_usk_%s.json", user))
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, ring.Poly{}, fmt.Errorf("read PolyLock USK %s: %v", path, err)
	}

	var usk PolyLockUSKDisk
	if err := json.Unmarshal(raw, &usk); err != nil {
		return nil, ring.Poly{}, fmt.Errorf("parse PolyLock USK: %v", err)
	}
	if usk.Format != "zkguard-polylock-usk-v1" {
		return nil, ring.Poly{}, fmt.Errorf("unexpected PolyLock USK format: %s", usk.Format)
	}
	if usk.RingLogN != polyLockLogN || usk.RingLogQ != polyLockLogQ {
		return nil, ring.Poly{}, fmt.Errorf("PolyLock parameter mismatch in USK: LogN=%d LogQ=%d, expect LogN=%d LogQ=%d",
			usk.RingLogN, usk.RingLogQ, polyLockLogN, polyLockLogQ)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(usk.SignatureSBase64)
	if err != nil {
		return nil, ring.Poly{}, fmt.Errorf("decode SignatureS: %v", err)
	}

	N := r.N()
	if len(sigBytes) < N*8 {
		return nil, ring.Poly{}, fmt.Errorf("SignatureS too short: got %d bytes, need %d", len(sigBytes), N*8)
	}

	s := r.NewPoly()
	for i := 0; i < N; i++ {
		s.Coeffs[0][i] = binary.LittleEndian.Uint64(sigBytes[i*8 : (i+1)*8])
	}
	return &usk, s, nil
}

// parseFooterFromTail parses footer_json || footer_len_8bytes from the end of a byte slice.
func parseFooterFromTail(buf []byte) (ProtectedObjectFooter, int, error) {
	var footer ProtectedObjectFooter
	if len(buf) < 8 {
		return footer, 0, fmt.Errorf("object too short")
	}
	footerLen := int(binary.BigEndian.Uint64(buf[len(buf)-8:]))
	if footerLen <= 0 || footerLen > len(buf)-8 {
		return footer, 0, fmt.Errorf("invalid footer length: %d", footerLen)
	}
	footerStart := len(buf) - 8 - footerLen
	if err := json.Unmarshal(buf[footerStart:len(buf)-8], &footer); err != nil {
		return footer, 0, fmt.Errorf("parse footer: %v", err)
	}
	if footer.Format != polyLockObjectFmt && footer.Format != "zkguard-polylock-object-v2-ring" {
		return footer, 0, fmt.Errorf("unexpected object format: %s", footer.Format)
	}
	return footer, footerStart, nil
}

// parseTwoLinkParts parses the current dissertation prototype object layout:
// data.ct = CT_data_payload || padding
// lock.ct = CT_lock_serialized || footer_json || footer_len_8bytes
func parseTwoLinkParts(dataBytes, lockComponent []byte) (*EncryptedObjectParts, error) {
	footer, footerStart, err := parseFooterFromTail(lockComponent)
	if err != nil {
		return nil, err
	}
	if footer.DataLen < 0 || footer.DataLen > len(dataBytes) {
		return nil, fmt.Errorf("invalid data length in footer: dataLen=%d dataFileLen=%d", footer.DataLen, len(dataBytes))
	}
	if footer.LockLen < 0 || footer.LockLen > footerStart {
		return nil, fmt.Errorf("invalid lock length in footer: lockLen=%d lockBytesAvailable=%d", footer.LockLen, footerStart)
	}

	dataPayload := append([]byte(nil), dataBytes[:footer.DataLen]...)
	lockBytes := lockComponent[:footerStart]
	if footer.LockLen > 0 && footer.LockLen <= footerStart {
		lockBytes = lockComponent[:footer.LockLen]
	}

	var lockCT PolyLockOnlyCT
	if footer.Format == polyLockObjectFmt {
		lockCT, err = unmarshalPolyLockCT(lockBytes)
		if err != nil {
			return nil, fmt.Errorf("parse lock ciphertext: %v", err)
		}
	}
	return &EncryptedObjectParts{
		Mode:        "two-link",
		DataPayload: dataPayload,
		LockBytes:   append([]byte(nil), lockBytes...),
		LockCT:      lockCT,
		Footer:      footer,
	}, nil
}

// parseLegacyCombinedObject keeps compatibility with the old single-file object layout:
// CT_data_payload || padding || CT_lock_serialized || footer_json || footer_len_8bytes.
func parseLegacyCombinedObject(obj []byte) (*EncryptedObjectParts, error) {
	footer, footerStart, err := parseFooterFromTail(obj)
	if err != nil {
		return nil, err
	}
	if footer.DataLen < 0 || footer.LockOff < 0 || footer.LockLen < 0 || footer.DataLen > len(obj) || footer.LockOff+footer.LockLen > footerStart {
		return nil, fmt.Errorf("invalid object offsets: dataLen=%d lockOff=%d lockLen=%d objectLen=%d",
			footer.DataLen, footer.LockOff, footer.LockLen, len(obj))
	}

	dataPayload := append([]byte(nil), obj[:footer.DataLen]...)
	lockBytes := obj[footer.LockOff : footer.LockOff+footer.LockLen]

	var lockCT PolyLockOnlyCT
	if footer.Format == polyLockObjectFmt {
		lockCT, err = unmarshalPolyLockCT(lockBytes)
		if err != nil {
			return nil, fmt.Errorf("parse lock ciphertext: %v", err)
		}
	}
	return &EncryptedObjectParts{
		Mode:        "legacy-combined",
		DataPayload: dataPayload,
		LockBytes:   append([]byte(nil), lockBytes...),
		LockCT:      lockCT,
		Footer:      footer,
	}, nil
}

func candidateTwoLinkPaths(inPath string) (dataPath, lockPath string, ok bool) {
	st, err := os.Stat(inPath)
	if err == nil && st.IsDir() {
		return filepath.Join(inPath, "data.ct"), filepath.Join(inPath, "lock.ct"), true
	}

	base := filepath.Base(inPath)
	dir := filepath.Dir(inPath)
	switch base {
	case "data.ct":
		return inPath, filepath.Join(dir, "lock.ct"), true
	case "lock.ct":
		return filepath.Join(dir, "data.ct"), inPath, true
	default:
		// Some `ipfs get` versions create a directory named by CID. If the user
		// passes that directory path, it is handled above. Other names are treated
		// as legacy single-file objects.
		return "", "", false
	}
}

func loadEncryptedObject(inPath string) (*EncryptedObjectParts, error) {
	if dataPath, lockPath, ok := candidateTwoLinkPaths(inPath); ok {
		dataBytes, err := os.ReadFile(dataPath)
		if err != nil {
			return nil, fmt.Errorf("read data component %s: %v", dataPath, err)
		}
		lockBytes, err := os.ReadFile(lockPath)
		if err != nil {
			return nil, fmt.Errorf("read lock component %s: %v", lockPath, err)
		}
		parts, err := parseTwoLinkParts(dataBytes, lockBytes)
		if err != nil {
			return nil, fmt.Errorf("parse two-link object (%s, %s): %v", dataPath, lockPath, err)
		}
		return parts, nil
	}

	objBytes, err := os.ReadFile(inPath)
	if err != nil {
		return nil, fmt.Errorf("read ciphertext object %s: %v", inPath, err)
	}
	parts, err := parseLegacyCombinedObject(objBytes)
	if err != nil {
		return nil, fmt.Errorf("parse legacy combined object %s: %v", inPath, err)
	}
	return parts, nil
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

func decompressPoly(r *ring.Ring, data []byte) ring.Poly {
	N := r.N()
	p := r.NewPoly()
	modulus := r.SubRings[0].Modulus
	bytesPerCoeff := len(data) / N

	for i := 0; i < N; i++ {
		var shifted uint64
		if bytesPerCoeff == 2 {
			shifted = uint64(data[i*2]) | (uint64(data[i*2+1]) << 8)
		} else {
			shifted = uint64(data[i*4]) | (uint64(data[i*4+1]) << 8) | (uint64(data[i*4+2]) << 16) | (uint64(data[i*4+3]) << 24)
		}
		restored := shifted << polyLockCompress
		if restored >= modulus {
			restored -= modulus
		}
		p.Coeffs[0][i] = restored
	}

	r.NTT(p, p)
	r.MForm(p, p)
	return p
}

func getScaleShift(r *ring.Ring) uint64 {
	q := r.SubRings[0].Modulus
	logQ := math.Log2(float64(q))
	return uint64(logQ) - 2
}

func decodeKey(r *ring.Ring, p ring.Poly) []byte {
	tmp := r.NewPoly()
	copy(tmp.Coeffs[0], p.Coeffs[0])
	r.INTT(tmp, tmp)
	r.IMForm(tmp, tmp)

	k := make([]byte, polyLockKeySize)
	shift := getScaleShift(r)
	rounding := uint64(1) << (shift - 1)

	for i := 0; i < polyLockKeySize; i++ {
		var b byte
		for j := 0; j < 8; j++ {
			val := tmp.Coeffs[0][i*8+j]
			bit := ((val + rounding) >> shift) & 1
			b |= byte(bit << j)
		}
		k[i] = b
	}
	return k
}

func tryOpenData(key []byte, dataPayload []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	if len(dataPayload) < gcm.NonceSize() {
		return nil
	}

	nonce := dataPayload[:gcm.NonceSize()]
	payload := dataPayload[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, payload, nil)
	if err != nil {
		return nil
	}
	return plain
}

func decapsBucketAndDecrypt(r *ring.Ring, sigS ring.Poly, samples [][]byte, dataPayload []byte) []byte {
	degree := len(samples)
	if degree == 0 {
		return nil
	}

	powersOfS := make([]ring.Poly, degree)
	powersOfS[0] = mapCoefStringToPoly(r, "1")
	for k := 1; k < degree; k++ {
		powersOfS[k] = r.NewPoly()
		r.MulCoeffsMontgomery(powersOfS[k-1], sigS, powersOfS[k])
	}

	result := r.NewPoly()
	for k := 0; k < degree; k++ {
		L_i := decompressPoly(r, samples[k])
		term := r.NewPoly()
		r.MulCoeffsMontgomery(L_i, powersOfS[k], term)
		r.Add(result, term, result)
	}

	candidateKey := decodeKey(r, result)
	return tryOpenData(candidateKey, dataPayload)
}

func decapsAndDecrypt(r *ring.Ring, sigS ring.Poly, lockCT PolyLockOnlyCT, dataPayload []byte) ([]byte, bool) {
	bucketCount := len(lockCT.SubLocks)
	if bucketCount == 0 {
		return nil, false
	}

	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	if workers > bucketCount {
		workers = bucketCount
	}

	jobs := make(chan int, workers)
	resultCh := make(chan []byte, 1)
	var found int32
	var wg sync.WaitGroup

	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if atomic.LoadInt32(&found) == 1 {
					continue
				}
				plain := decapsBucketAndDecrypt(r, sigS, lockCT.SubLocks[idx], dataPayload)
				if plain != nil && atomic.CompareAndSwapInt32(&found, 0, 1) {
					resultCh <- plain
				}
			}
		}()
	}

	for i := range lockCT.SubLocks {
		if atomic.LoadInt32(&found) == 1 {
			break
		}
		jobs <- i
	}
	close(jobs)

	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case plain := <-resultCh:
		<-doneCh
		return plain, true
	case <-doneCh:
		select {
		case plain := <-resultCh:
			return plain, true
		default:
			return nil, false
		}
	}
}

func defaultOutputPath(user, inPath string) string {
	base := filepath.Base(inPath)
	base = strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(base)
	return filepath.Join(polyLockStateDir, "retrieved", fmt.Sprintf("plain_%s_%s", user, base))
}

func decryptObjectFile(inPath, user, outPath string) (time.Duration, int, ProtectedObjectFooter, string, error) {
	startDec := time.Now()
	parts, err := loadEncryptedObject(inPath)
	if err != nil {
		return 0, 0, ProtectedObjectFooter{}, "", err
	}
	footer := parts.Footer
	var plain []byte
	if footer.Format == "zkguard-polylock-object-v2-ring" {
		uskPath := filepath.Join(polyLockStateDir, fmt.Sprintf("polylock_usk_%s.json", user))
		usk, key, err := plintegration.LoadUserKey(uskPath)
		if err != nil {
			return time.Since(startDec), 0, footer, parts.Mode, err
		}
		defer key.Close()
		if footer.AttrHash != "" && footer.AttrHash != usk.AttrHash {
			fmt.Printf("[INFO] PolyLock reference attrHash differs from USK: object=%s, usk=%s\n", footer.AttrHash, usk.AttrHash)
		}
		aad, err := base64.StdEncoding.DecodeString(footer.AADBase64)
		if err != nil {
			return time.Since(startDec), 0, footer, parts.Mode, err
		}
		data, err := plintegration.ParseDataPayload(parts.DataPayload, aad)
		if err != nil {
			return time.Since(startDec), 0, footer, parts.Mode, err
		}
		profile := footer.SecurityProfile
		if profile == "" {
			profile = plintegration.SecurityProfile
		}
		context, err := polylockv2.NewDecapsulationContext(profile)
		if err != nil {
			return time.Since(startDec), 0, footer, parts.Mode, err
		}
		defer context.Close()
		keyHex, ok, err := context.DecapsSerialized(key, parts.LockBytes, plintegration.CoreDataCiphertext(data))
		if err != nil {
			return time.Since(startDec), 0, footer, parts.Mode, err
		}
		if !ok {
			return time.Since(startDec), 0, footer, parts.Mode, fmt.Errorf("PolyLock Decaps/AES-GCM authentication failed")
		}
		plain, err = plintegration.DecryptData(keyHex, data)
		if err != nil {
			return time.Since(startDec), 0, footer, parts.Mode, err
		}
	} else {
		r, err := polyRing()
		if err != nil {
			return 0, 0, ProtectedObjectFooter{}, "", err
		}
		usk, sigS, err := loadPolyLockUSK(user, r)
		if err != nil {
			return 0, 0, ProtectedObjectFooter{}, "", err
		}

		// This is only a diagnostic check. The footer records the reference attribute
		// configuration used when the object was created, while a valid recipient may
		// hold a different AttrHash that is nevertheless included in one lock bucket.
		if footer.AttrHash != "" && footer.AttrHash != usk.AttrHash {
			fmt.Printf("[INFO] PolyLock reference attrHash differs from USK: object=%s, usk=%s\n", footer.AttrHash, usk.AttrHash)
		}
		if footer.Version != usk.Version {
			fmt.Printf("[INFO] PolyLock reference version differs from USK: object=%d, usk=%d\n", footer.Version, usk.Version)
		}

		legacyPlain, ok := decapsAndDecrypt(r, sigS, parts.LockCT, parts.DataPayload)
		if !ok {
			return time.Since(startDec), 0, footer, parts.Mode, fmt.Errorf("PolyLock Decaps/AES-GCM decrypt failed")
		}
		plain = legacyPlain
	}

	if outPath == "" {
		outPath = defaultOutputPath(user, inPath)
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return time.Since(startDec), 0, footer, parts.Mode, err
	}
	if err := os.WriteFile(outPath, plain, 0o644); err != nil {
		return time.Since(startDec), 0, footer, parts.Mode, err
	}

	return time.Since(startDec), len(plain), footer, parts.Mode, nil
}

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("用法: %s <cipherObjectPathOrRootDir> <username> [outPlainPath]", os.Args[0])
	}

	inPath := os.Args[1]
	user := os.Args[2]
	outPath := ""
	if len(os.Args) > 3 && os.Args[3] != "" {
		outPath = os.Args[3]
	}
	if outPath == "" {
		outPath = defaultOutputPath(user, inPath)
	}

	tDec, plainSize, footer, mode, err := decryptObjectFile(inPath, user, outPath)
	if err != nil {
		log.Fatalf("PolyLock 本地解密失败: %v", err)
	}

	fmt.Println("============== PolyLock Local Decrypt ==============")
	fmt.Printf("Input object : %s\n", inPath)
	fmt.Printf("Object mode  : %s\n", mode)
	fmt.Printf("Output plain : %s\n", outPath)
	fmt.Printf("Plain size   : %.3f KB\n", float64(plainSize)/1024.0)
	fmt.Printf("DataLen      : %.3f KB\n", float64(footer.DataLen)/1024.0)
	fmt.Printf("PadLen       : %.3f KB\n", float64(footer.PadLen)/1024.0)
	fmt.Printf("LockLen      : %.3f KB\n", float64(footer.LockLen)/1024.0)
	fmt.Printf("EffectiveRoot: %d\n", footer.EffectiveRoots)
	fmt.Printf("Buckets      : %d x degree<=%d\n", footer.BucketCount, footer.BucketDegree)
	fmt.Printf("AttrHash     : %s\n", footer.AttrHash)
	fmt.Printf("Version      : %d\n", footer.Version)
	fmt.Printf("PolyLockDec  : %.3f ms\n", float64(tDec.Microseconds())/1000.0)
	fmt.Println("✓ PolyLock 本地解密成功")
}
