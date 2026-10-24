/*
 * Copyright (c) 2026 EiluDick/ZDarkZ
 * Released under the MIT License.
 */

package nc.geyserext.netease.log;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import nc.geyserext.netease.NeteaseExtension;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

import java.io.RandomAccessFile;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * 调试日志上传：仅在 debug 打开时启用。
 *
 * <p>生命周期：</p>
 * <ol>
 *   <li>Geyser 启动（扩展初始化）时，后台线程从 CDN 拉取 ML-KEM 公钥与预置密文；</li>
 *   <li>Geyser 结束时（关闭事件 / JVM shutdown hook，二者只触发一次），读取本次日志文件，
 *       GZIP 压缩后用 ML-KEM 封装出的共享密钥做 encrypt-then-MAC 加密
 *       （XOR 密钥流 + HMAC-SHA256，见 {@link ZLogCrypto}），
 *       打包成 <code>&lt;10位id&gt;.zlog</code> 并 POST 到 <code>log.4f4t.top</code>；</li>
 *   <li>上传完成后进程继续正常退出。</li>
 * </ol>
 */
public final class ZLogUploader {

    /** 上传目标：POST {BASE}/{id}.zlog（可用 -DGeyserNetease.ZLogUploadUrl 覆盖）。 */
    private static final String UPLOAD_BASE = System.getProperty(
        "GeyserNetease.ZLogUploadUrl", "https://log.4f4t.top");
    /** 上传用的 API Key（可用 -DGeyserNetease.ZLogApiKey 覆盖）。 */
    private static final String API_KEY = System.getProperty(
        "GeyserNetease.ZLogApiKey", "zlog_l_PotxY2TeD4mwZ40v_l9Uv9XGSKjHEWhvUTeueLPgo");

    private static final String BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz";
    /** 日志最多上传这么多字节（超出只保留尾部）。 */
    private static final long MAX_LOG_BYTES = Long.getLong("GeyserNetease.ZLogMaxBytes", 8L * 1024 * 1024);
    /** 自采缓冲最多保留的行数。 */
    private static final int RING_LINES = 4000;

    private static final Deque<String> RING = new ArrayDeque<>();
    private static final Object LOCK = new Object();
    private static final SecureRandom RANDOM = new SecureRandom();

    private static volatile boolean initialized;
    private static volatile boolean finished;
    private static volatile KemKeyRing keyRing;
    private static volatile Thread keyFetchThread;

    private ZLogUploader() {
    }

    /** 扩展初始化时调用（仅 debug 打开时）。 */
    public static void init() {
        synchronized (LOCK) {
            if (initialized) {
                return;
            }
            initialized = true;
        }
        Thread t = new Thread(ZLogUploader::fetchKeysQuietly, "GeyserNetease-ZLog-KeyFetch");
        t.setDaemon(true);
        keyFetchThread = t;
        t.start();
        Runtime.getRuntime().addShutdownHook(new Thread(ZLogUploader::finishQuietly,
            "GeyserNetease-ZLog-Shutdown"));
        log("ZLog: 调试日志上传已启用，" + KemKeyRing.PUBLIC_KEY_URL + " / " + KemKeyRing.ENC_KEY_URL);
    }

    /** 收集一条自采日志（debug 输出会被同时记录，作为拿不到 Geyser 日志文件时的兜底）。 */
    public static void tap(String line) {
        if (!initialized || line == null) {
            return;
        }
        synchronized (RING) {
            if (RING.size() >= RING_LINES) {
                RING.removeFirst();
            }
            RING.addLast(line);
        }
    }

    /** Geyser 关闭事件 / shutdown hook 调用；幂等。 */
    public static void shutdown() {
        if (!initialized || finished) {
            return;
        }
        synchronized (LOCK) {
            if (finished) {
                return;
            }
            finished = true;
        }
        try {
            uploadOnce();
        } catch (Throwable t) {
            log("ZLog: 上传失败: " + t);
        }
    }

    private static void finishQuietly() {
        try {
            shutdown();
        } catch (Throwable ignored) {
            // 关闭阶段不再抛异常
        }
    }

    private static void fetchKeysQuietly() {
        try {
            long started = System.currentTimeMillis();
            KemKeyRing ring = KemKeyRing.fetch(KemKeyRing.newClient(), Duration.ofSeconds(20));
            keyRing = ring;
            log("ZLog: 已获取 ML-KEM 公钥（" + ring.publicKeyRaw().length + " 字节）与预置密文（"
                + ring.encryptedKey().length + " 字节），耗时 "
                + (System.currentTimeMillis() - started) + " ms");
        } catch (Throwable t) {
            log("ZLog: 获取密钥失败: " + t);
        }
    }

    private static void uploadOnce() throws Exception {
        KemKeyRing ring = awaitKeyRing();
        if (ring == null) {
            log("ZLog: 未取得 ML-KEM 公钥，跳过本次日志上传");
            return;
        }

        byte[] rawLog = collectLogs();
        if (rawLog.length == 0) {
            log("ZLog: 没有可上传的日志内容，跳过");
            return;
        }
        byte[] gz = ZLogCrypto.gzip(rawLog);

        // ML-KEM 封装：客户端产生共享密钥 + 密文，服务端用私钥解出同一共享密钥
        MLKEMParameters params = paramsFor(ring.publicKeyRaw().length);
        MLKEMPublicKeyParameters publicKey = new MLKEMPublicKeyParameters(params, ring.publicKeyRaw());
        SecretWithEncapsulation encapsulated =
            new MLKEMGenerator(RANDOM).generateEncapsulated(publicKey);
        byte[] kemCt = encapsulated.getEncapsulation();
        byte[] sharedSecret = encapsulated.getSecret();

        // 与 ML-KEM-完整技术文档.md 4.2 / 5.5 节一致：encrypt-then-MAC，XOR 密钥流 + HMAC-SHA256
        byte[] sealBlob = ZLogCrypto.seal(sharedSecret, gz);

        byte[] archive = ZLogArchive.build(kemCt, sealBlob);
        String id = newId();
        String url = UPLOAD_BASE + "/" + id + ".zlog";

        HttpClient client = KemKeyRing.newClient();
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
            .timeout(Duration.ofSeconds(40))
            .header("X-API-Key", API_KEY)
            .header("Content-Type", "application/octet-stream")
            .header("User-Agent", "GeyserNetease/" + NeteaseExtension.BUILD_TAG)
            .POST(HttpRequest.BodyPublishers.ofByteArray(archive))
            .build();
        HttpResponse<String> response =
            client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

        String downloadUrl = "";
        try {
            JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
            if (json.has("downloadUrl")) {
                downloadUrl = json.get("downloadUrl").getAsString();
            }
        } catch (Throwable ignored) {
            // 响应不是 JSON 时只记录原文
        }
        log("ZLog: 上传 " + archive.length + " 字节（原始日志 " + rawLog.length + " 字节，id=" + id
            + "）→ HTTP " + response.statusCode()
            + (downloadUrl.isEmpty() ? "" : "，下载地址 " + downloadUrl));
        if (response.statusCode() / 100 != 2) {
            log("ZLog: 服务端响应: " + truncate(response.body(), 400));
        }
    }

    private static KemKeyRing awaitKeyRing() {
        KemKeyRing ring = keyRing;
        if (ring != null) {
            return ring;
        }
        Thread t = keyFetchThread;
        if (t != null) {
            try {
                t.join(Duration.ofSeconds(20).toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        return keyRing;
    }

    private static MLKEMParameters paramsFor(int publicKeyLength) {
        return KemKeyRing.parametersFor(publicKeyLength);
    }

    /** 10 位、只含数字和小写字母的会话 id：8 位时间戳（base36）+ 2 位随机。 */
    static String newId() {
        String ts = Long.toString(System.currentTimeMillis(), 36);
        if (ts.length() > 8) {
            ts = ts.substring(ts.length() - 8);
        }
        StringBuilder sb = new StringBuilder(10);
        for (int i = ts.length(); i < 8; i++) {
            sb.append('0');
        }
        sb.append(ts);
        sb.append(BASE36.charAt(RANDOM.nextInt(36)));
        sb.append(BASE36.charAt(RANDOM.nextInt(36)));
        return sb.toString();
    }

    /**
     * 读取本次日志：优先 Geyser/Velocity 的 <code>logs/latest.log</code>，
     * 找不到时使用扩展自采缓冲。
     */
    private static byte[] collectLogs() {
        for (Path path : logCandidates()) {
            try {
                if (!Files.isRegularFile(path)) {
                    continue;
                }
                long size = Files.size(path);
                if (size <= 0) {
                    continue;
                }
                byte[] data = readTail(path, size, MAX_LOG_BYTES);
                return data;
            } catch (Throwable ignored) {
                // 换下一个候选
            }
        }
        return ringBytes();
    }

    private static List<Path> logCandidates() {
        List<Path> list = new ArrayList<>();
        String explicit = System.getProperty("GeyserNetease.ZLogFile", "");
        if (!explicit.isEmpty()) {
            list.add(Paths.get(explicit));
        }
        String userDir = System.getProperty("user.dir");
        if (userDir != null) {
            Path base = Paths.get(userDir).toAbsolutePath();
            list.add(base.resolve("logs").resolve("latest.log"));
            Path parent = base.getParent();
            if (parent != null) {
                list.add(parent.resolve("logs").resolve("latest.log"));
            }
            list.add(base.resolve("logs").resolve("debug.log"));
            list.add(base.resolve("logs").resolve("latest.log.gz"));
        }
        return list;
    }

    private static byte[] readTail(Path path, long size, long maxBytes) throws Exception {
        long start = Math.max(0, size - maxBytes);
        int length = (int) (size - start);
        try (RandomAccessFile raf = new RandomAccessFile(path.toFile(), "r")) {
            raf.seek(start);
            byte[] buf = new byte[length];
            raf.readFully(buf);
            if (start > 0) {
                byte[] header = ("[ZLog] 日志超过 " + maxBytes + " 字节，以下只保留末尾 "
                    + length + " 字节。\n").getBytes(StandardCharsets.UTF_8);
                byte[] merged = new byte[header.length + buf.length];
                System.arraycopy(header, 0, merged, 0, header.length);
                System.arraycopy(buf, 0, merged, header.length, buf.length);
                return merged;
            }
            return buf;
        }
    }

    private static byte[] ringBytes() {
        StringBuilder sb = new StringBuilder(4096);
        sb.append("[ZLog] 未能读取 Geyser 的 logs/latest.log，以下为扩展自采日志。\n");
        sb.append("build: ").append(NeteaseExtension.BUILD_TAG).append('\n');
        synchronized (RING) {
            for (String line : RING) {
                sb.append(line).append('\n');
            }
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void log(String message) {
        try {
            if (NeteaseExtension.LOG != null) {
                NeteaseExtension.LOG.info(message);
            }
        } catch (Throwable ignored) {
            // 日志系统还没就绪时忽略
        }
        tap(message);
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
