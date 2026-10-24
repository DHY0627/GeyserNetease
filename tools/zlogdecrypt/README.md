# zlogdecrypt —— 解密 `.zlog` 调试日志

GeyserNetease 扩展在 debug 打开时，会在 Geyser 结束时把日志加密上传成 `<10位id>.zlog`。
这个命令行工具用 **ML-KEM-1024 私钥**把 `.zlog` 解回原始日志文本（已自动 gunzip）。

协议与 `docs/ZLOG.md`、`ML-KEM-完整技术文档.md` 第 4.2 / 5.5 节一致：

```
.zlog = kem_ct(1568) ‖ nonce(16) ‖ tag(32) ‖ ct'
ss    = ML-KEM-1024.Decaps(private.key, kem_ct)
ks    = HKDF-Expand(ss, "data-enc||" ‖ nonce, len(ct'))
plain = ct' XOR ks        # 明文是 gzip(日志文本)
tag   = HMAC-SHA256(ss, nonce ‖ ct')
```

## 用法

```bash
# 直接输出到终端
./zlogdecrypt -key kem_private.key -in abc123defg.zlog

# 写到文件
./zlogdecrypt -key kem_private.key -in abc123defg.zlog -out latest.log

# 也可以把 .zlog 作为位置参数
./zlogdecrypt -key kem_private.key abc123defg.zlog > latest.log
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `-key` | `kem_private.key` | ML-KEM-1024 私钥路径 |
| `-in` | 空 | `.zlog` 文件路径 |
| `-out` | 空（stdout） | 解密后的日志输出路径 |
| `-selftest` | false | 本地自检：随机生成密钥对，验证加解密闭环 |

## 私钥格式

以下几种都能直接读：

- PEM（`-----BEGIN ML-KEM-1024 PRIVATE KEY-----`，文档 3.3 节生成的 `private.key`）
- 裸 base64 文本（3168 字节密钥的 base64）
- 裸二进制 3168 字节
- 外面套了 ASN.1 DER `OCTET STRING`（`04 82 0C 60 …`）的版本，会自动剥离

## 编译

```bash
cd tools/zlogdecrypt
go build -o zlogdecrypt .
```

交叉编译（例如放到 Linux ARM64 服务器上用）：

```bash
GOOS=linux   GOARCH=arm64 go build -o zlogdecrypt-linux-arm64 .
GOOS=linux   GOARCH=amd64 go build -o zlogdecrypt-linux-amd64 .
GOOS=windows GOARCH=amd64 go build -o zlogdecrypt.exe .
```

依赖只有 [`github.com/cloudflare/circl`](https://github.com/cloudflare/circl)（ML-KEM 实现）。

## 验证

```bash
$ ./zlogdecrypt -selftest
自检通过：kem_ct=1568 nonce=16 tag=32 ct'=187，还原 27000 字节日志
```

与 Java 侧交叉验证过：`ZLogSelfTest <目录>` 会导出 `test.zlog` / `test_priv.key` / `test.log`，
用本工具解 `test.zlog` 得到的日志与 `test.log` 逐字节一致。

## 常见错误

| 报错 | 原因 |
|---|---|
| `认证失败：数据被篡改，或私钥与公钥不匹配` | 私钥和上传时用的公钥不是一对；或文件被改过 |
| `私钥长度异常: N（ML-KEM-1024 应为 3168）` | 私钥文件不完整，或不是 ML-KEM-1024 |
| `.zlog 长度不足` | 文件不完整（至少 1616 字节） |
| `解密成功` 但内容是乱码 | 该 `.zlog` 不是本扩展生成的 |
