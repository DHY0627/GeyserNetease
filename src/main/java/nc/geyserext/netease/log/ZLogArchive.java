/*
 * Copyright (c) 2026 EiluDick/ZDarkZ
 * Released under the MIT License.
 */

package nc.geyserext.netease.log;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * <code>.zlog</code> 归档格式（版本 1）。
 *
 * <pre>
 * offset  size       field
 * 0       4          magic = "ZLOG"
 * 4       1          version = 1
 * 5       1          kemAlg: 1 = ML-KEM-512, 2 = ML-KEM-768, 3 = ML-KEM-1024
 * 6       2          ctLen (uint16, big-endian)
 * 8       ctLen      ct: ML-KEM 封装密文（encapsulation），服务端用它 + 私钥解出共享密钥
 * ...     4          auxLen (uint32, big-endian)
 * ...     auxLen     aux: kem.enc 的原始字节（服务端预置的“加密过的密钥”），可为空
 * ...     12         iv: AES-GCM 的 96 bit IV
 * ...     n          payload: AES-256-GCM( gzip(日志文本) )
 * </pre>
 *
 * <p>服务端解密步骤：</p>
 * <ol>
 *   <li>读 ct，用 ML-KEM 私钥 {@code extractSecret(ct)} 得到共享密钥 ss；</li>
 *   <li>{@code key = HKDF-SHA256(ss, salt="GeyserNetease-zlog-v1",
 *       info="GeyserNetease debug log upload", 32)}；</li>
 *   <li>用 key + iv 做 AES-256-GCM 解密 payload（末尾 16 字节是认证标签）；</li>
 *   <li>对结果做 GZIP 解压，得到 UTF-8 日志文本。</li>
 * </ol>
 */
final class ZLogArchive {

    static final byte[] MAGIC = {'Z', 'L', 'O', 'G'};
    static final int VERSION = 1;

    static final byte KEM_ML_KEM_512 = 1;
    static final byte KEM_ML_KEM_768 = 2;
    static final byte KEM_ML_KEM_1024 = 3;

    private ZLogArchive() {
    }

    /**
     * 组装一个 .zlog 文件。
     *
     * @param kemAlg  KEM 参数标识
     * @param ct      封装密文
     * @param aux     kem.enc 原始内容（可为 null / 空）
     * @param iv      AES-GCM IV
     * @param payload 已加密的压缩日志
     */
    static byte[] build(byte kemAlg, byte[] ct, byte[] aux, byte[] iv, byte[] payload)
        throws IOException {
        byte[] ctBytes = ct == null ? new byte[0] : ct;
        byte[] auxBytes = aux == null ? new byte[0] : aux;
        if (ctBytes.length > 0xFFFF) {
            throw new IOException("encapsulation too long: " + ctBytes.length);
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream(
            ctBytes.length + auxBytes.length + payload.length + 64);
        DataOutputStream out = new DataOutputStream(bos);
        out.write(MAGIC);
        out.writeByte(VERSION);
        out.writeByte(kemAlg & 0xFF);
        out.writeShort(ctBytes.length);
        out.write(ctBytes);
        out.writeInt(auxBytes.length);
        out.write(auxBytes);
        out.write(iv);
        out.write(payload);
        out.flush();
        return bos.toByteArray();
    }
}
