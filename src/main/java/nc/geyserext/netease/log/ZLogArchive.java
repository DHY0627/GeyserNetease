/*
 * Copyright (c) 2026 EiluDick/ZDarkZ
 * Released under the MIT License.
 */

package nc.geyserext.netease.log;

/**
 * <code>.zlog</code> 文件内容，与 <code>ML-KEM-完整技术文档.md</code> 4.2 节的载荷定义逐字节一致：
 *
 * <pre>
 * payload = kem_ct(1568) ‖ nonce(16) ‖ tag(32) ‖ ct'
 *           └── ML-KEM 密文 ──┘ └──── 对称加密部分（seal 的输出） ────┘
 * </pre>
 *
 * <p>KEM 密文也拼在里面，所以解密只需要服务端的 <code>private.key</code>，
 * 不需要额外传递 <code>kem.enc</code>，整个文件自包含。</p>
 *
 * <p>服务端解密步骤：</p>
 * <ol>
 *   <li>{@code ss = Decaps(private.key, payload[0:1568])}，得到 32 字节共享密钥；</li>
 *   <li>{@code blob = payload[1568:]}，前 16 字节是 nonce、接着 32 字节是 HMAC 标签、其余是 ct'；</li>
 *   <li>校验 {@code HMAC-SHA256(ss, nonce ‖ ct') == tag}，不匹配说明被篡改；</li>
 *   <li>{@code ks = HKDF-Expand(ss, "data-enc||" ‖ nonce, len(ct'))}，{@code plaintext = ct' XOR ks}；</li>
 *   <li>对明文做 GZIP 解压，得到 UTF-8 日志文本。</li>
 * </ol>
 */
final class ZLogArchive {

    private ZLogArchive() {
    }

    /**
     * 组装一个 .zlog 文件：KEM 密文 + seal 输出。
     *
     * @param kemCt    ML-KEM 封装密文（ML-KEM-1024 为 1568 字节）
     * @param sealBlob {@code nonce(16) ‖ tag(32) ‖ ct'}
     */
    static byte[] build(byte[] kemCt, byte[] sealBlob) {
        return ZLogCrypto.concat(kemCt, sealBlob);
    }
}
