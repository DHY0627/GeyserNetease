package nc.geyserext.netease.log;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;

/**
 * 真实上传联调：用本地生成的 ML-KEM-1024 密钥对构造 .zlog，POST 到 log.4f4t.top，
 * 再用私钥解封验证整条链路（格式 / 加密 / 上传接口 / 解密）。
 */
public class ZLogUploadTest {

    private static final String UPLOAD_BASE = "https://log.4f4t.top";
    /** 联调时用 -DGeyserNetease.ZLogApiKey=... 或环境变量 ZLOG_API_KEY 传入，避免把 key 写进仓库。 */
    private static final String API_KEY = System.getProperty("GeyserNetease.ZLogApiKey",
        System.getenv().getOrDefault("ZLOG_API_KEY", ""));

    public static void main(String[] args) throws Exception {
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 200; i++) {
            sb.append("GeyserNetease ZLog 联调测试行 ").append(i).append('\n');
        }
        byte[] raw = sb.toString().getBytes(StandardCharsets.UTF_8);
        byte[] gz = ZLogCrypto.gzip(raw);

        MLKEMKeyPairGenerator kpg = new MLKEMKeyPairGenerator();
        kpg.init(new MLKEMKeyGenerationParameters(rnd, MLKEMParameters.ml_kem_1024));
        var kp = kpg.generateKeyPair();
        MLKEMPublicKeyParameters pub = (MLKEMPublicKeyParameters) kp.getPublic();
        MLKEMPrivateKeyParameters priv = (MLKEMPrivateKeyParameters) kp.getPrivate();

        SecretWithEncapsulation sw = new MLKEMGenerator(rnd).generateEncapsulated(pub);
        byte[] ct = sw.getEncapsulation();
        byte[] ss = sw.getSecret();
        byte[] key = ZLogCrypto.hkdfSha256(ss, ZLogCrypto.HKDF_SALT, ZLogCrypto.HKDF_INFO, 32);
        byte[] iv = new byte[ZLogCrypto.IV_LENGTH];
        rnd.nextBytes(iv);
        byte[] payload = ZLogCrypto.aesGcmEncrypt(key, iv, gz);
        byte[] archive = ZLogArchive.build(ZLogArchive.KEM_ML_KEM_1024, ct, new byte[0], iv, payload);

        String id = ZLogUploader.newId();
        String url = UPLOAD_BASE + "/" + id + ".zlog";
        System.out.println("id=" + id + " (长度 " + id.length() + ")  url=" + url
            + "  归档大小=" + archive.length);

        HttpClient client = KemKeyRing.newClient();
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
            .timeout(Duration.ofSeconds(40))
            .header("X-API-Key", API_KEY)
            .header("Content-Type", "application/octet-stream")
            .header("User-Agent", "GeyserNetease-zlog-test/1")
            .POST(HttpRequest.BodyPublishers.ofByteArray(archive))
            .build();
        HttpResponse<String> response =
            client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        System.out.println("HTTP " + response.statusCode());
        System.out.println("响应: " + response.body());

        String downloadUrl = "";
        try {
            JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
            if (json.has("downloadUrl")) {
                downloadUrl = json.get("downloadUrl").getAsString();
            }
        } catch (Throwable ignored) {
            // 非 JSON 响应
        }

        // 服务端解封验证
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(archive));
        byte[] magic = new byte[4];
        in.readFully(magic);
        in.readUnsignedByte();
        in.readUnsignedByte();
        int ctLen = in.readUnsignedShort();
        byte[] ct2 = new byte[ctLen];
        in.readFully(ct2);
        int auxLen = in.readInt();
        in.skipBytes(auxLen);
        byte[] iv2 = new byte[ZLogCrypto.IV_LENGTH];
        in.readFully(iv2);
        byte[] payload2 = in.readAllBytes();

        byte[] ss2 = new MLKEMExtractor(priv).extractSecret(ct2);
        byte[] key2 = ZLogCrypto.hkdfSha256(ss2, ZLogCrypto.HKDF_SALT, ZLogCrypto.HKDF_INFO, 32);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key2, "AES"),
            new GCMParameterSpec(ZLogCrypto.TAG_LENGTH_BITS, iv2));
        byte[] raw2 = new GZIPInputStream(new ByteArrayInputStream(c.doFinal(payload2))).readAllBytes();

        System.out.println("服务端解封后还原一致 = " + Arrays.equals(raw, raw2));
        if (!downloadUrl.isEmpty()) {
            // 顺带验证下载接口
            HttpResponse<byte[]> dl = client.send(
                HttpRequest.newBuilder(URI.create(downloadUrl)).timeout(Duration.ofSeconds(30)).GET().build(),
                HttpResponse.BodyHandlers.ofByteArray());
            System.out.println("下载 " + downloadUrl + " → HTTP " + dl.statusCode()
                + " 字节数=" + dl.body().length + " 与上传一致=" + Arrays.equals(dl.body(), archive));
        }
        System.out.println("TEST " + (response.statusCode() == 200 && Arrays.equals(raw, raw2) ? "OK" : "FAIL"));
    }
}
