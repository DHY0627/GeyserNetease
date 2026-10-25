/*
 * Copyright (c) 2026 EiluDick/ZDarkZ
 * Released under the MIT License.
 */

package nc.geyserext.netease.log;

import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

/**
 * 从 CDN 拉取 ML-KEM 公钥与预置的“加密过的密钥”。
 *
 * <ul>
 *   <li><code>https://cdn.redstone.xin/key/kem_public.key</code>：base64 编码的 ML-KEM 公钥</li>
 *   <li><code>https://cdn.redstone.xin/key/kem.enc</code>：服务端预置的加密密文，原样字节</li>
 * </ul>
 */
final class KemKeyRing {

    static final String PUBLIC_KEY_URL = System.getProperty(
        "GeyserNetease.KemPublicKeyUrl", "https://cdn.redstone.xin/key/kem_public.key");
    static final String ENC_KEY_URL = System.getProperty(
        "GeyserNetease.KemEncUrl", "https://cdn.redstone.xin/key/kem.enc");

    /** ML-KEM 各参数集的公钥编码长度（FIPS 203）。 */
    private static final int PK_LEN_512 = 800;
    private static final int PK_LEN_768 = 1184;
    private static final int PK_LEN_1024 = 1568;

    private final byte[] publicKeyRaw;
    private final byte[] encryptedKey;
    /** kem.enc 拉取失败的原因；为空表示拉取成功（或没尝试）。 */
    private final String encError;

    private KemKeyRing(byte[] publicKeyRaw, byte[] encryptedKey, String encError) {
        this.publicKeyRaw = publicKeyRaw;
        this.encryptedKey = encryptedKey;
        this.encError = encError;
    }

    byte[] publicKeyRaw() {
        return publicKeyRaw;
    }

    byte[] encryptedKey() {
        return encryptedKey;
    }

    /** kem.enc 拉取失败原因（null 表示成功或无错误）。 */
    String encError() {
        return encError;
    }

    /** 根据公钥长度判断 KEM 参数（.zlog 里不写标识，长度本身就是唯一线索）。 */
    static MLKEMParameters parametersFor(int publicKeyLength) {
        switch (publicKeyLength) {
            case PK_LEN_512:
                return MLKEMParameters.ml_kem_512;
            case PK_LEN_1024:
                return MLKEMParameters.ml_kem_1024;
            case PK_LEN_768:
            default:
                return MLKEMParameters.ml_kem_768;
        }
    }

    static HttpClient newClient() {
        return HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
    }

    /**
     * 拉取两个密钥文件。公钥是必需的；kem.enc 只是服务端预置的参考密文，
     * 缺失不影响加密与解密（解密只需要 private.key，本次的 KEM 密文已经拼在 .zlog 里），
     * 因此失败时降级为空字节并记录原因，便于排查。
     */
    static KemKeyRing fetch(HttpClient client, Duration timeout) throws Exception {
        byte[] publicKeyRaw = fetchPublicKey(client, timeout);
        byte[] encryptedKey;
        String encError = null;
        try {
            encryptedKey = fetchRaw(client, ENC_KEY_URL, timeout);
        } catch (Exception e) {
            encryptedKey = new byte[0];
            encError = e.getMessage() == null ? e.toString() : e.getMessage();
        }
        return new KemKeyRing(publicKeyRaw, encryptedKey, encError);
    }

    private static byte[] fetchPublicKey(HttpClient client, Duration timeout) throws Exception {
        byte[] body = fetchRaw(client, PUBLIC_KEY_URL, timeout);
        String text = new String(body, StandardCharsets.UTF_8);
        // 按行处理：跳过空行和 PEM 分隔行（-----BEGIN …----- / -----END …-----），
        // 其余行的空白字符全部去掉后拼起来就是 base64 正文。
        // 注意不能简单用 indexOf("END") 截断：base64 正文里本来就可能出现 "END" 三个字母。
        StringBuilder sb = new StringBuilder(text.length());
        for (String line : text.split("\\R")) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("-----")) {
                continue;
            }
            for (int i = 0; i < t.length(); i++) {
                char c = t.charAt(i);
                if (c != ' ' && c != '\t') {
                    sb.append(c);
                }
            }
        }
        byte[] decoded = Base64.getDecoder().decode(sb.toString());
        decoded = unwrapDerOctetString(decoded);
        if (decoded.length != PK_LEN_512 && decoded.length != PK_LEN_768
            && decoded.length != PK_LEN_1024) {
            throw new IOException("unexpected ML-KEM public key length: " + decoded.length
                + " (expected 800/1184/1568)");
        }
        return decoded;
    }

    /**
     * PEM 里常见的是 ASN.1 DER 的 {@code OCTET STRING} 包装，例如
     * {@code 04 82 06 20 <1568 字节公钥>}（04=OCTET STRING，82=后两字节是长度，0620h=1568）。
     * 直接按长度取内容；如果不是这种包装就原样返回。
     */
    private static byte[] unwrapDerOctetString(byte[] der) {
        if (der.length < 2 || (der[0] & 0xFF) != 0x04) {
            return der;
        }
        int lenByte = der[1] & 0xFF;
        int headerLen;
        long contentLen;
        if (lenByte < 0x80) {
            headerLen = 2;
            contentLen = lenByte;
        } else if (lenByte == 0x81 && der.length >= 3) {
            headerLen = 3;
            contentLen = der[2] & 0xFFL;
        } else if (lenByte == 0x82 && der.length >= 4) {
            headerLen = 4;
            contentLen = ((der[2] & 0xFFL) << 8) | (der[3] & 0xFFL);
        } else if (lenByte == 0x83 && der.length >= 5) {
            headerLen = 5;
            contentLen = ((der[2] & 0xFFL) << 16) | ((der[3] & 0xFFL) << 8) | (der[4] & 0xFFL);
        } else {
            return der;
        }
        if (headerLen + contentLen != der.length) {
            return der;
        }
        return java.util.Arrays.copyOfRange(der, headerLen, der.length);
    }

    private static byte[] fetchRaw(HttpClient client, String url, Duration timeout)
        throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
            .timeout(timeout)
            .header("User-Agent", "GeyserNetease/" + nc.geyserext.netease.NeteaseExtension.BUILD_TAG)
            .GET()
            .build();
        HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() / 100 != 2) {
            throw new IOException("HTTP " + response.statusCode() + " for " + url);
        }
        return response.body();
    }
}
