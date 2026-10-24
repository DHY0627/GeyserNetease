/*
 * Copyright (c) 2026 EiluDick/ZDarkZ
 * Released under the MIT License.
 */

package nc.geyserext.netease.log;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.zip.GZIPOutputStream;

/**
 * 调试日志上传用到的密码学原语：HKDF-SHA256、AES-256-GCM、GZIP。
 *
 * <p>KEM 得到的共享密钥不直接当 AES 密钥用，而是先过一次 HKDF（RFC 5869），
 * 避免把 KEM 输出直接暴露为对称密钥。</p>
 */
final class ZLogCrypto {

    /** HKDF 的 salt / info 固定值，服务端解密时必须用同样的值。 */
    static final byte[] HKDF_SALT = ascii("GeyserNetease-zlog-v1");
    static final byte[] HKDF_INFO = ascii("GeyserNetease debug log upload");

    /** AES-GCM 的 IV 长度（96 bit，GCM 推荐值）。 */
    static final int IV_LENGTH = 12;
    /** AES-GCM 认证标签长度（bit）。 */
    static final int TAG_LENGTH_BITS = 128;

    private ZLogCrypto() {
    }

    static byte[] ascii(String s) {
        byte[] out = new byte[s.length()];
        for (int i = 0; i < s.length(); i++) {
            out[i] = (byte) s.charAt(i);
        }
        return out;
    }

    /**
     * RFC 5869 HKDF-SHA256。
     *
     * @param ikm    KEM 输出的共享密钥
     * @param salt   盐（可为空）
     * @param info   上下文信息
     * @param outLen 需要的输出长度
     */
    static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int outLen)
        throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");

        // Extract
        byte[] realSalt = (salt == null || salt.length == 0) ? new byte[32] : salt;
        mac.init(new SecretKeySpec(realSalt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);

        // Expand
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        byte[] okm = new byte[outLen];
        byte[] t = new byte[0];
        int pos = 0;
        int counter = 1;
        while (pos < outLen) {
            mac.update(t);
            if (info != null && info.length > 0) {
                mac.update(info);
            }
            mac.update((byte) counter);
            t = mac.doFinal();
            int n = Math.min(t.length, outLen - pos);
            System.arraycopy(t, 0, okm, pos, n);
            pos += n;
            counter++;
        }
        return okm;
    }

    /** GZIP 压缩。 */
    static byte[] gzip(byte[] data) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(Math.max(256, data.length / 3 + 64));
        try (GZIPOutputStream gz = new GZIPOutputStream(bos, 1 << 16)) {
            gz.write(data);
        }
        return bos.toByteArray();
    }

    /** AES-256-GCM 加密，返回的数组末尾是 16 字节认证标签。 */
    static byte[] aesGcmEncrypt(byte[] key, byte[] iv, byte[] plain) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
            new GCMParameterSpec(TAG_LENGTH_BITS, iv));
        return cipher.doFinal(plain);
    }
}
