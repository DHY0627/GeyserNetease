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
    /** 与 ZLogUploader 内置的 key 一致；可用 -DGeyserNetease.ZLogApiKey 或 ZLOG_API_KEY 覆盖。 */
    private static final String API_KEY = System.getProperty("GeyserNetease.ZLogApiKey",
        System.getenv().getOrDefault("ZLOG_API_KEY", "sk-api_9GQIx9p640A0UOwL4FSHdeCoBp6onWjB"));

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
        byte[] sealBlob = ZLogCrypto.seal(ss, gz);
        byte[] archive = ZLogArchive.build(ct, sealBlob);

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

        // 服务端解封验证：.zlog = kem_ct(1568) || nonce(16) || tag(32) || ct'
        byte[] ct2 = Arrays.copyOfRange(archive, 0, ct.length);
        byte[] blob2 = Arrays.copyOfRange(archive, ct.length, archive.length);
        byte[] ss2 = new MLKEMExtractor(priv).extractSecret(ct2);
        byte[] raw2 = new GZIPInputStream(
            new ByteArrayInputStream(ZLogCrypto.unseal(ss2, blob2))).readAllBytes();

        System.out.println("服务端解封后还原一致 = " + Arrays.equals(raw, raw2));
        if (!downloadUrl.isEmpty()) {
            // 顺带验证下载接口
            HttpResponse<byte[]> dl = client.send(
                HttpRequest.newBuilder(URI.create(downloadUrl)).timeout(Duration.ofSeconds(30)).GET().build(),
                HttpResponse.BodyHandlers.ofByteArray());
            System.out.println("下载 " + downloadUrl + " → HTTP " + dl.statusCode()
                + " 字节数=" + dl.body().length + " 与上传一致=" + Arrays.equals(dl.body(), archive));
        }
        boolean ok = response.statusCode() / 100 == 2 && Arrays.equals(raw, raw2);
        System.out.println("TEST " + (ok ? "OK" : "FAIL"));
    }
}
