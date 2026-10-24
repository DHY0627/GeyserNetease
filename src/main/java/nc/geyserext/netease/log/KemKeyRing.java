/*
 * Copyright (c) 2026 EiluDick/ZDarkZ
 * Released under the MIT License.
 */

package nc.geyserext.netease.log;

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

    static final String PUBLIC_KEY_URL = "https://cdn.redstone.xin/key/kem_public.key";
    static final String ENC_KEY_URL = "https://cdn.redstone.xin/key/kem.enc";

    /** ML-KEM 各参数集的公钥编码长度（FIPS 203）。 */
    private static final int PK_LEN_512 = 800;
    private static final int PK_LEN_768 = 1184;
    private static final int PK_LEN_1024 = 1568;

    private final byte[] publicKeyRaw;
    private final byte[] encryptedKey;

    private KemKeyRing(byte[] publicKeyRaw, byte[] encryptedKey) {
        this.publicKeyRaw = publicKeyRaw;
        this.encryptedKey = encryptedKey;
    }

    byte[] publicKeyRaw() {
        return publicKeyRaw;
    }

    byte[] encryptedKey() {
        return encryptedKey;
    }

    /** 根据公钥长度推断 .zlog 头里该写哪个 KEM 标识。 */
    byte kemAlgorithmId() {
        switch (publicKeyRaw.length) {
            case PK_LEN_512:
                return ZLogArchive.KEM_ML_KEM_512;
            case PK_LEN_1024:
                return ZLogArchive.KEM_ML_KEM_1024;
            case PK_LEN_768:
            default:
                return ZLogArchive.KEM_ML_KEM_768;
        }
    }

    static HttpClient newClient() {
        return HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
    }

    /**
     * 拉取两个密钥文件。公钥是必需的，kem.enc 缺失不致命（只把空字节写进归档）。
     */
    static KemKeyRing fetch(HttpClient client, Duration timeout) throws Exception {
        byte[] publicKeyRaw = fetchPublicKey(client, timeout);
        byte[] encryptedKey;
        try {
            encryptedKey = fetchRaw(client, ENC_KEY_URL, timeout);
        } catch (Exception e) {
            encryptedKey = new byte[0];
        }
        return new KemKeyRing(publicKeyRaw, encryptedKey);
    }

    private static byte[] fetchPublicKey(HttpClient client, Duration timeout) throws Exception {
        byte[] body = fetchRaw(client, PUBLIC_KEY_URL, timeout);
        String text = new String(body, StandardCharsets.UTF_8);
        // 公钥文件是 base64；去掉换行/空格/PEM 头尾
        StringBuilder sb = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '-' || c == ' ' || c == '\r' || c == '\n' || c == '\t') {
                continue;
            }
            sb.append(c);
        }
        String b64 = sb.toString();
        // 容忍 "BEGIN ... KEY" 一类的 PEM 头
        int cut = b64.indexOf("BEGIN");
        if (cut >= 0) {
            int end = b64.indexOf("KEY", cut);
            if (end > 0) {
                b64 = b64.substring(end + 3);
            }
            int idx = b64.indexOf("END");
            if (idx > 0) {
                b64 = b64.substring(0, idx);
            }
        }
        byte[] decoded = Base64.getDecoder().decode(b64);
        if (decoded.length != PK_LEN_512 && decoded.length != PK_LEN_768
            && decoded.length != PK_LEN_1024) {
            throw new IOException("unexpected ML-KEM public key length: " + decoded.length
                + " (expected 800/1184/1568)");
        }
        return decoded;
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
