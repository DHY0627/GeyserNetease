/*
 * Copyright (c) 2026 EiluDick/ZDarkZ
 * Released under the MIT License.
 */

package nc.geyserext.netease.log;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.GZIPOutputStream;

/**
 * 调试日志上传用到的密码学原语：HKDF-Expand 密钥流、encrypt-then-MAC、GZIP。
 *
 * <p>协议与 {@code ML-KEM-完整技术文档.md} 第 4.2 / 5.5 节完全一致，服务端拿到
 * {@code private.key} 后可以直接用文档里的 {@code unseal()} 解开：</p>
 *
 * <pre>
 * 共享密钥 ss  = Decaps(dk, kem_ct)                      // 32 B
 * 密钥流   ks  = HKDF-Expand(ss, "data-enc||" || nonce)  // 与明文等长
 * 密文     ct' = plaintext XOR ks
 * 认证标签 tag = HMAC-SHA256(ss, nonce || ct')           // 32 B
 * 对称段   blob = nonce(16) || tag(32) || ct'
 * 完整载荷 payload = kem_ct(1568) || nonce(16) || tag(32) || ct'
 * </pre>
 *
 * <p>注意这里用的是文档里的 <b>直接以 ss 为 HMAC 密钥</b>的密钥流推导，
 * 不是 RFC 5869 的 HKDF-Extract + Expand 两步式；两者结果不同，必须与服务端保持一致。</p>
 */
final class ZLogCrypto {

    /** nonce 长度，16 字节（128 bit）。 */
    static final int NONCE_SIZE = 16;
    /** HMAC-SHA256 认证标签长度。 */
    static final int TAG_SIZE = 32;
    /** RFC 5869 单链上限 255 × 32 = 8160 字节，超过要换一个 block 序号。 */
    static final int HKDF_CHUNK = 8160;
    /** 密钥流推导的上下文前缀，服务端必须一致。 */
    static final byte[] INFO_PREFIX = ascii("data-enc||");

    private static final SecureRandom RANDOM = new SecureRandom();

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
     * 从共享密钥展开任意长度的密钥流（对应文档里的 {@code _expand}）。
     *
     * @param key    共享密钥 ss
     * @param info   {@code "data-enc||" || nonce}
     * @param length 需要的密钥流长度
     */
    static byte[] expand(byte[] key, byte[] info, int length) throws GeneralSecurityException {
        if (length < 0) throw new GeneralSecurityException("密钥流长度不能为负: " + length);
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(32, length));
        Mac mac = Mac.getInstance("HmacSHA256");
        int block = 0;
        while (out.size() < length) {
            int chunk = Math.min(HKDF_CHUNK, length - out.size());
            ByteArrayOutputStream prev = new ByteArrayOutputStream(HKDF_CHUNK);
            int i = 1;
            while (prev.size() < chunk) {
                mac.init(new SecretKeySpec(key, "HmacSHA256"));
                mac.update(info);
                mac.update(new byte[] {
                    (byte) (block >>> 24), (byte) (block >>> 16),
                    (byte) (block >>> 8), (byte) block
                });
                mac.update((byte) i);
                byte[] digest = mac.doFinal();
                prev.write(digest, 0, digest.length);
                i++;
            }
            byte[] chunkBytes = prev.toByteArray();
            out.write(chunkBytes, 0, chunk);
            block++;
        }
        byte[] ok = out.toByteArray();
        return ok.length == length ? ok : Arrays.copyOf(ok, length);
    }

    static byte[] hmacSha256(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    /**
     * 认证加密：返回 {@code nonce(16) || tag(32) || ct'}。
     * 与文档 5.5 的 {@code seal()} 逐字节兼容。
     */
    static byte[] seal(byte[] ss, byte[] plaintext) throws GeneralSecurityException {
        byte[] nonce = new byte[NONCE_SIZE];
        RANDOM.nextBytes(nonce);
        byte[] ks = expand(ss, concat(INFO_PREFIX, nonce), plaintext.length);
        byte[] ct = new byte[plaintext.length];
        for (int i = 0; i < ct.length; i++) {
            ct[i] = (byte) (plaintext[i] ^ ks[i]);
        }
        byte[] tag = hmacSha256(ss, concat(nonce, ct));
        return concat(nonce, tag, ct);
    }

    /**
     * 解密并校验完整性（服务端同款逻辑，单元测试里用来验证互通）。
     *
     * @throws GeneralSecurityException 长度不足或认证失败
     */
    static byte[] unseal(byte[] ss, byte[] blob) throws GeneralSecurityException {
        if (blob.length < NONCE_SIZE + TAG_SIZE) {
            throw new GeneralSecurityException("密文长度不足: " + blob.length);
        }
        byte[] nonce = Arrays.copyOfRange(blob, 0, NONCE_SIZE);
        byte[] tag = Arrays.copyOfRange(blob, NONCE_SIZE, NONCE_SIZE + TAG_SIZE);
        byte[] ct = Arrays.copyOfRange(blob, NONCE_SIZE + TAG_SIZE, blob.length);
        byte[] expect = hmacSha256(ss, concat(nonce, ct));
        if (!MessageDigest.isEqual(expect, tag)) {
            throw new GeneralSecurityException("认证失败：数据被篡改或共享密钥不匹配");
        }
        byte[] ks = expand(ss, concat(INFO_PREFIX, nonce), ct.length);
        byte[] pt = new byte[ct.length];
        for (int i = 0; i < pt.length; i++) {
            pt[i] = (byte) (ct[i] ^ ks[i]);
        }
        return pt;
    }

    /** GZIP 压缩（明文先压缩再加密，服务端解密后需要 gunzip）。 */
    static byte[] gzip(byte[] data) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(Math.max(256, data.length / 3 + 64));
        try (GZIPOutputStream gz = new GZIPOutputStream(bos, 1 << 16)) {
            gz.write(data);
        }
        return bos.toByteArray();
    }

    static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) {
            total += a.length;
        }
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, out, pos, a.length);
            pos += a.length;
        }
        return out;
    }
}
