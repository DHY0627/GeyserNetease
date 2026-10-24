// Command zlogdecrypt 解密 GeyserNetease 扩展上传的 .zlog 调试日志。
//
// 协议与 GeyserNetease 仓库的 docs/ZLOG.md（以及 ML-KEM-完整技术文档.md 第 4.2 / 5.5 节）一致：
//
//	.zlog = kem_ct(1568) || nonce(16) || tag(32) || ct'
//	ss    = ML-KEM-1024.Decaps(private.key, kem_ct)
//	ks    = HKDF-Expand(ss, "data-enc||" || nonce, len(ct'))
//	plain = ct' XOR ks      （明文是 gzip 压缩过的日志文本）
//	tag   = HMAC-SHA256(ss, nonce || ct')
//
// 用法：
//
//	zlogdecrypt -key kem_private.key -in abc123defg.zlog -out latest.log
//	zlogdecrypt -key kem_private.key abc123defg.zlog > latest.log
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
)

const (
	// ML-KEM-1024 的密文长度（FIPS 203）。
	kemCtSize = 1568
	// nonce 长度。
	nonceSize = 16
	// HMAC-SHA256 标签长度。
	tagSize = 32
	// RFC 5869 单链上限 255 × 32。
	hkdfChunk = 8160
	// 密钥流推导的上下文前缀。
	infoPrefix = "data-enc||"
)

func main() {
	keyPath := flag.String("key", "kem_private.key", "ML-KEM-1024 私钥文件路径（PEM / 裸 base64 / 裸二进制均可）")
	inPath := flag.String("in", "", ".zlog 文件路径")
	outPath := flag.String("out", "", "解密后日志的输出路径（默认写到标准输出）")
	selfTest := flag.Bool("selftest", false, "本地自检：随机生成密钥对，验证加解密闭环")
	flag.Parse()

	if *selfTest {
		if err := runSelfTest(); err != nil {
			fmt.Fprintln(os.Stderr, "自检失败:", err)
			os.Exit(1)
		}
		return
	}

	if *inPath == "" && flag.NArg() > 0 {
		*inPath = flag.Arg(0)
	}
	if *inPath == "" {
		fmt.Fprintln(os.Stderr, "用法: zlogdecrypt -key <私钥> -in <.zlog> [-out <输出>]")
		flag.PrintDefaults()
		os.Exit(2)
	}

	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取私钥失败:", err)
		os.Exit(1)
	}

	zlog, err := os.ReadFile(*inPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取 .zlog 失败:", err)
		os.Exit(1)
	}

	plain, err := decrypt(priv, zlog)
	if err != nil {
		fmt.Fprintln(os.Stderr, "解密失败:", err)
		os.Exit(1)
	}

	if *outPath == "" {
		os.Stdout.Write(plain)
		fmt.Fprintln(os.Stderr, "\n解密成功，共", len(plain), "字节")
		return
	}
	if err := os.WriteFile(*outPath, plain, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "写出日志失败:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "解密成功：%s（%d 字节）\n", *outPath, len(plain))
}

// decrypt 按协议解开一个 .zlog。
func decrypt(priv kem.PrivateKey, zlog []byte) ([]byte, error) {
	headerLen := kemCtSize + nonceSize + tagSize
	if len(zlog) < headerLen {
		return nil, fmt.Errorf(".zlog 长度不足: %d（至少需要 %d）", len(zlog), headerLen)
	}

	kemCt := zlog[:kemCtSize]
	nonce := zlog[kemCtSize : kemCtSize+nonceSize]
	tag := zlog[kemCtSize+nonceSize : headerLen]
	ct := zlog[headerLen:]

	ss, err := mlkem1024.Scheme().Decapsulate(priv, kemCt)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM 解封失败: %w", err)
	}
	if len(ss) != 32 {
		return nil, fmt.Errorf("共享密钥长度异常: %d", len(ss))
	}

	// 先验 MAC 再解密（encrypt-then-MAC）
	expect := hmacSHA256(ss, concat(nonce, ct))
	if !hmac.Equal(expect, tag) {
		return nil, errors.New("认证失败：数据被篡改，或私钥与公钥不匹配")
	}

	ks := expand(ss, concat([]byte(infoPrefix), nonce), len(ct))
	plain := make([]byte, len(ct))
	for i := range ct {
		plain[i] = ct[i] ^ ks[i]
	}

	// 明文是 gzip(日志)；若数据本身不是 gzip（历史版本或未压缩），原样返回
	if len(plain) >= 2 && plain[0] == 0x1f && plain[1] == 0x8b {
		if out, err := gunzip(plain); err == nil {
			return out, nil
		}
	}
	return plain, nil
}

// expand 从共享密钥展开任意长度的密钥流（ML-KEM-完整技术文档.md 5.5 节）。
// 注意：直接用 ss 当 HMAC 密钥，不是 RFC 5869 的 Extract+Expand 两步式。
func expand(key, info []byte, length int) []byte {
	out := make([]byte, 0, length+hkdfChunk)
	var block uint32
	for len(out) < length {
		chunk := length - len(out)
		if chunk > hkdfChunk {
			chunk = hkdfChunk
		}
		prev := make([]byte, 0, hkdfChunk)
		for i := 1; len(prev) < chunk; i++ {
			mac := hmac.New(sha256.New, key)
			mac.Write(info)
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], block)
			mac.Write(b[:])
			mac.Write([]byte{byte(i)})
			prev = mac.Sum(prev)
		}
		out = append(out, prev[:chunk]...)
		block++
	}
	return out[:length]
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}

func gunzip(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

// loadPrivateKey 读取 ML-KEM-1024 私钥，兼容 PEM、裸 base64、裸二进制，
// 以及外面套了一层 ASN.1 DER OCTET STRING 的情况。
func loadPrivateKey(path string) (kem.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	der, err := decodeKeyFile(raw)
	if err != nil {
		return nil, fmt.Errorf("解析私钥文件失败: %w", err)
	}
	der = unwrapDEROctetString(der)
	if len(der) != 3168 {
		return nil, fmt.Errorf("私钥长度异常: %d（ML-KEM-1024 应为 3168）", len(der))
	}
	return mlkem1024.Scheme().UnmarshalBinaryPrivateKey(der)
}

func decodeKeyFile(raw []byte) ([]byte, error) {
	text := string(raw)
	if strings.Contains(text, "-----BEGIN") {
		var b strings.Builder
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "-----") {
				continue
			}
			b.WriteString(line)
		}
		return base64.StdEncoding.DecodeString(b.String())
	}
	// 没有 PEM 头：先试 base64（文档里的 .key 都是 base64 文本）
	compact := strings.Join(strings.Fields(text), "")
	if compact != "" && len(compact)%4 == 0 {
		if decoded, err := base64.StdEncoding.DecodeString(compact); err == nil && len(decoded) >= 3000 {
			return decoded, nil
		}
	}
	return raw, nil
}

// unwrapDEROctetString 剥离 ASN.1 DER 的 OCTET STRING 包装（04 / 04 81 / 04 82 / 04 83）。
func unwrapDEROctetString(der []byte) []byte {
	if len(der) < 2 || der[0] != 0x04 {
		return der
	}
	var headerLen, declared int
	switch der[1] {
	case 0x81:
		headerLen = 3
		if len(der) >= 3 {
			declared = int(der[2])
		}
	case 0x82:
		headerLen = 4
		if len(der) >= 4 {
			declared = int(der[2])<<8 | int(der[3])
		}
	case 0x83:
		headerLen = 5
		if len(der) >= 5 {
			declared = int(der[2])<<16 | int(der[3])<<8 | int(der[4])
		}
	default:
		if der[1] < 0x80 {
			headerLen = 2
			declared = int(der[1])
		} else {
			return der
		}
	}
	if headerLen >= len(der) {
		return der
	}
	body := der[headerLen:]
	if declared > 0 && declared <= len(body) {
		body = body[:declared]
	}
	return body
}

// runSelfTest 用临时密钥对跑一遍「封装 → 加密 → 解密」，验证本工具逻辑自洽。
func runSelfTest() error {
	scheme := mlkem1024.Scheme()
	pub, priv, err := scheme.GenerateKeyPair()
	if err != nil {
		return err
	}
	logText := bytes.Repeat([]byte("第 0 行：网易客户端调试日志 test log line\n"), 500)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(logText); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}

	kemCt, ss, err := scheme.Encapsulate(pub)
	if err != nil {
		return err
	}
	nonce := make([]byte, nonceSize)
	for i := range nonce {
		nonce[i] = byte(i * 7)
	}
	ks := expand(ss, concat([]byte(infoPrefix), nonce), buf.Len())
	ct := make([]byte, buf.Len())
	for i := range ct {
		ct[i] = buf.Bytes()[i] ^ ks[i]
	}
	tag := hmacSHA256(ss, concat(nonce, ct))

	zlog := append(append(append(append([]byte{}, kemCt...), nonce...), tag...), ct...)
	out, err := decrypt(priv, zlog)
	if err != nil {
		return err
	}
	if !bytes.Equal(out, logText) {
		return errors.New("解密结果与原日志不一致")
	}
	fmt.Printf("自检通过：kem_ct=%d nonce=%d tag=%d ct'=%d，还原 %d 字节日志\n",
		len(kemCt), nonceSize, tagSize, len(ct), len(out))
	return nil
}
