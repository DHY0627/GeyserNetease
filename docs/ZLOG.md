# 调试日志上传（.zlog）

当 **debug 打开**时（`-DGeyserNetease.Debug=true`，或 `config.yml` 里 `debug-mode: true`），
扩展会在 Geyser 结束时把本次日志加密压缩后上传到 `log.4f4t.top`，便于远程排查网易客户端问题。

## 生命周期

1. **Geyser 启动**（扩展初始化后）：后台线程拉取
   - `https://cdn.redstone.xin/key/kem_public.key` —— base64 编码的 **ML-KEM-1024** 公钥（1568 字节）
   - `https://cdn.redstone.xin/key/kem.enc` —— 服务端预置的加密密文（原样字节，不 base64）
2. **Geyser 结束**（关闭事件，JVM shutdown hook 兜底，只执行一次）：
   1. 读取本次日志（优先 `logs/latest.log`，读不到则用扩展自采日志）
   2. GZIP 压缩
   3. 用 ML-KEM-1024 公钥做 **encapsulate**，得到共享密钥和密文
   4. `HKDF-SHA256(ss)` 派生 **AES-256** 密钥，GCM 模式加密压缩后的日志
   5. 打包成 `<10位id>.zlog`，`POST https://log.4f4t.top/<id>.zlog`
3. 上传完成后进程继续正常退出。

> **为什么客户端要自己 encapsulate**：ML-KEM 是密钥封装机制，公钥只能用来**封装**（产生共享密钥 + 密文），
> 只有私钥才能**解封**。客户端手里只有公钥，所以由客户端封装、服务端用私钥解封，这是唯一可行的方向。
> `kem.enc` 会原样放进 `.zlog` 的 `aux` 段，服务端可按需忽略。

## 环境变量 / 系统属性

| 属性 | 默认 | 说明 |
|---|---|---|
| `GeyserNetease.Debug` | `false` | 打开调试日志与日志上传 |
| `GeyserNetease.ZLogFile` | 空 | 显式指定要上传的日志文件 |
| `GeyserNetease.ZLogMaxBytes` | `8388608` | 日志上限，超出只保留末尾 |

## `.zlog` 格式（版本 1）

| offset | size | 字段 | 说明 |
|---|---|---|---|
| 0 | 4 | `magic` | `"ZLOG"` |
| 4 | 1 | `version` | `1` |
| 5 | 1 | `kemAlg` | `1`=ML-KEM-512，`2`=ML-KEM-768，`3`=**ML-KEM-1024** |
| 6 | 2 | `ctLen` | 大端 uint16 |
| 8 | ctLen | `ct` | ML-KEM 封装密文（ML-KEM-1024 为 1568 字节） |
| … | 4 | `auxLen` | 大端 uint32 |
| … | auxLen | `aux` | `kem.enc` 的原始字节，可为 0 |
| … | 12 | `iv` | AES-GCM 96 bit IV |
| … | n | `payload` | `AES-256-GCM(gzip(日志文本))`，末尾 16 字节为认证标签 |

**密钥派生**（必须与客户端一致）：

```
ss  = ML-KEM-1024.Decapsulate(sk, ct)
key = HKDF-SHA256(ikm = ss, salt = "GeyserNetease-zlog-v1",
                  info = "GeyserNetease debug log upload", L = 32)
```

## 服务端解密（Python）

```bash
pip install pqcrypto cryptography
```

```python
import gzip, struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem import ml_kem_1024

# 首次生成，私钥妥善保存，公钥 base64 后放到 cdn.redstone.xin/key/kem_public.key
# pk, sk = ml_kem_1024.generate_keypair()
# import base64; open("kem_public.key","w").write(base64.b64encode(pk).decode())
sk = open("kem_private.key", "rb").read()
raw_pk = open("kem_public.key", "rb").read()

blob = open("abc123defg.zlog", "rb").read()
assert blob[0:4] == b"ZLOG"
version, kem_alg = blob[4], blob[5]
ct_len = struct.unpack(">H", blob[6:8])[0]
off = 8
ct = blob[off:off + ct_len]; off += ct_len
aux_len = struct.unpack(">I", blob[off:off + 4])[0]; off += 4
aux = blob[off:off + aux_len]; off += aux_len
iv = blob[off:off + 12]; off += 12
payload = blob[off:]

ss = ml_kem_1024.decrypt(sk, ct)          # 解封得到共享密钥
key = HKDF(algorithm=hashes.SHA256(), length=32,
           salt=b"GeyserNetease-zlog-v1",
           info=b"GeyserNetease debug log upload").derive(ss)
plain = AESGCM(key).decrypt(iv, payload, None)
print(gzip.decompress(plain).decode("utf-8"))
```

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
