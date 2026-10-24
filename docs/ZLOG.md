# 调试日志上传（.zlog）

当 **debug 打开**时（`-DGeyserNetease.Debug=true`，或 `config.yml` 里 `debug-mode: true`），
扩展会在 Geyser 结束时把本次日志加密压缩后上传到 `log.4f4t.top`，便于远程排查网易客户端问题。

## 生命周期

1. **Geyser 启动**（扩展初始化后）：后台线程拉取
   - `https://cdn.redstone.xin/key/kem_public.key` —— base64 编码的 **ML-KEM-1024** 公钥。
     裸 base64 或 PEM（`-----BEGIN ML-KEM-1024 PUBLIC KEY-----`）都可以；
     PEM 里若外面套了 ASN.1 DER `OCTET STRING`（`04 82 06 20` + 1568 字节），会自动剥离。
   - `https://cdn.redstone.xin/key/kem.enc` —— 服务端预置的密文（原样字节，不 base64）。
     **只做可用性探测、不参与加密**，原因见下方说明。
2. **Geyser 结束**（关闭事件，JVM shutdown hook 兜底，只执行一次）：
   1. 读取本次日志（优先 `logs/latest.log`，读不到则用扩展自采日志）
   2. GZIP 压缩
   3. 用 ML-KEM-1024 公钥 **encapsulate**，得到共享密钥 `ss` 和 KEM 密文 `kem_ct`
   4. 用 `ss` 做 **encrypt-then-MAC** 加密压缩后的日志
   5. 拼接 `.zlog` 并 `POST https://log.4f4t.top/<id>.zlog`
3. 上传完成后进程继续正常退出。

> **为什么客户端要自己 encapsulate**：ML-KEM 是密钥封装机制，公钥只能**封装**（产生共享密钥 + 密文），
> 只有私钥能**解封**。客户端手里只有公钥，所以只能由客户端封装、服务端用 `private.key` 解封。
> `kem.enc` 是服务端用自己公钥封装出来的示例密文，**客户端解不开**（解它需要私钥），
> 因此它不参与加密，只用来确认 CDN 上的密钥文件可访问。

## 环境变量 / 系统属性

| 属性 | 默认 | 说明 |
|---|---|---|
| `GeyserNetease.Debug` | `false` | 打开调试日志与日志上传 |
| `GeyserNetease.ZLogFile` | 空 | 显式指定要上传的日志文件 |
| `GeyserNetease.ZLogMaxBytes` | `8388608` | 日志上限，超出只保留末尾 |
| `GeyserNetease.KemPublicKeyUrl` | `https://cdn.redstone.xin/key/kem_public.key` | 公钥地址 |
| `GeyserNetease.KemEncUrl` | `https://cdn.redstone.xin/key/kem.enc` | 预置密文地址 |
| `GeyserNetease.ZLogUploadUrl` | `https://log.4f4t.top` | 上传地址 |
| `GeyserNetease.ZLogApiKey` | 内置 | 上传用 API Key |

## `.zlog` 格式

与 `ML-KEM-完整技术文档.md` 第 4.2 节逐字节一致（自包含，服务端只需要 `private.key`）：

| offset | size | 字段 | 说明 |
|---|---|---|---|
| 0 | 1568 | `kem_ct` | ML-KEM-1024 封装密文 |
| 1568 | 16 | `nonce` | 随机数，同时作为密钥流推导的 info |
| 1584 | 32 | `tag` | `HMAC-SHA256(ss, nonce ‖ ct')` |
| 1616 | n | `ct'` | `gzip(日志文本) XOR HKDF-Expand(ss, "data-enc||" ‖ nonce)` |

其中 `ss = ML-KEM-1024.Decaps(private.key, kem_ct)`（32 字节）。

**注意**：这里的 `HKDF-Expand` 是文档 5.5 节的形式——**直接把 `ss` 当 HMAC 密钥**，
info = `"data-enc||" ‖ nonce`，消息体 = `info ‖ block(4B 大端) ‖ i(1B)`；
不是 RFC 5869 的 Extract+Expand 两步式。两者结果不同，服务端必须按下面这份代码来。

## 服务端解密（Python）

```bash
pip install pqcrypto
```

```python
import gzip, hmac, hashlib
from pqcrypto.kem import ml_kem_1024

NONCE_SIZE, TAG_SIZE, HKDF_CHUNK = 16, 32, 8160


def expand(key: bytes, info: bytes, length: int) -> bytes:
    """从共享密钥展开任意长度的密钥流（处理 HKDF 计数器上限）。"""
    out, block = b"", 0
    while len(out) < length:
        chunk = min(HKDF_CHUNK, length - len(out))
        prev, i = b"", 1
        while len(prev) < chunk:
            prev += hmac.new(key, info + block.to_bytes(4, "big") + bytes([i]),
                             hashlib.sha256).digest()
            i += 1
        out += prev[:chunk]
        block += 1
    return out[:length]


sk = open("kem_private.key", "rb").read()
blob = open("abc123defg.zlog", "rb").read()

kem_ct = blob[:1568]
nonce = blob[1568:1568 + NONCE_SIZE]
tag = blob[1568 + NONCE_SIZE:1568 + NONCE_SIZE + TAG_SIZE]
ct = blob[1568 + NONCE_SIZE + TAG_SIZE:]

ss = ml_kem_1024.decrypt(sk, kem_ct)          # 解封得到共享密钥
expect = hmac.new(ss, nonce + ct, hashlib.sha256).digest()
assert hmac.compare_digest(expect, tag), "认证失败：数据被篡改或密钥不匹配"

ks = expand(ss, b"data-enc||" + nonce, len(ct))
plain = bytes(a ^ b for a, b in zip(ct, ks))
print(gzip.decompress(plain).decode("utf-8"))
```

> 私钥文件名以你实际存放的为准；`pqcrypto` 的 `ml_kem_1024.generate_keypair()`
> 生成的私钥是原始 3168 字节，与 `private.key` 的存储方式保持一致即可。

## 上传接口

```
POST https://log.4f4t.top/<sid>.zlog
X-API-Key: <你的 key>
Content-Type: application/octet-stream
```

响应 JSON 中的 `downloadUrl` 会被写进 Geyser 控制台日志：

```
GET https://log.4f4t.top/<sid>
```
