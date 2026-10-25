/*
 * Copyright (c) 2026 EiluDick/ZDarkZ
 * Released under the MIT License.
 */

package nc.geyserext.netease.log;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import nc.geyserext.netease.NeteaseExtension;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
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
        "GeyserNetease.ZLogApiKey", "sk-api_9GQIx9p640A0UOwL4FSHdeCoBp6onWjB");

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
        // 注意：这里**不能**注册 JVM shutdown hook。
        // Velocity 关闭时 JVM hook 会先于 Geyser 的 GeyserShutdownEvent 执行，
        // 此时扩展的 ClassLoader 已经不可用，BouncyCastle 的 ML-KEM 类首次加载会抛
        // NoClassDefFoundError，导致上传必然失败。改为只依赖 GeyserShutdownEvent
        // （该事件触发时扩展还没被禁用，ClassLoader 与网络都可用）。
        // 但即便在 GeyserShutdownEvent 阶段，ClassLoader 也已开始关闭，
        // 任何“首次加载”的类（包括本扩展自己的 ZLogCrypto）同样会抛 NoClassDefFoundError，
        // 因此必须在启动时就把整条加密链路预热一遍。
        warmUp();
        log("ZLog: 调试日志上传已启用，" + KemKeyRing.PUBLIC_KEY_URL + " / " + KemKeyRing.ENC_KEY_URL);
    }

    /**
     * 预热加密链路：用临时密钥完整走一遍「封装 → seal → unseal → extract」，
     * 把 BouncyCastle ML-KEM 与本扩展 ZLogCrypto / ZLogArchive 的类全部加载进内存。
     *
     * <p>原因：Geyser 关闭时扩展 ClassLoader 已进入关闭流程，此刻首次加载类会抛
     * {@code NoClassDefFoundError}（实测关服上传失败于
     * {@code nc/geyserext/netease/log/ZLogCrypto}）。类在启动阶段加载过之后就不会再失败。</p>
     */
    private static void warmUp() {
        try {
            MLKEMKeyPairGenerator generator = new MLKEMKeyPairGenerator();
            generator.init(new MLKEMKeyGenerationParameters(RANDOM, MLKEMParameters.ml_kem_1024));
            AsymmetricCipherKeyPair pair = generator.generateKeyPair();
            MLKEMPublicKeyParameters publicKey = (MLKEMPublicKeyParameters) pair.getPublic();
            MLKEMPrivateKeyParameters privateKey = (MLKEMPrivateKeyParameters) pair.getPrivate();

            SecretWithEncapsulation encapsulated = new MLKEMGenerator(RANDOM).generateEncapsulated(publicKey);
            byte[] kemCt = encapsulated.getEncapsulation();
            byte[] sharedSecret = encapsulated.getSecret();

            byte[] blob = ZLogCrypto.seal(sharedSecret, new byte[] {0x1f, (byte) 0x8b, 1, 2, 3, 4, 5});
            ZLogCrypto.unseal(sharedSecret, blob);
            ZLogArchive.build(kemCt, blob);
            new MLKEMExtractor(privateKey).extractSecret(kemCt);
            log("ZLog: 加密组件预热完成");
        } catch (Throwable t) {
            log("ZLog: 加密组件预热失败: " + t);
        }
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
            StringBuilder sb = new StringBuilder();
            sb.append("ZLog: 已获取 ML-KEM 公钥（").append(ring.publicKeyRaw().length).append(" 字节）");
            // kem.enc 只是服务端预置的参考密文，本次上传的 KEM 密文是客户端现封装的，
            // 所以它缺失只是少一份参考，不影响加密与解密。这里把原因打出来避免误解。
            if (ring.encError() != null) {
                sb.append("；预置密文 kem.enc 获取失败（").append(KemKeyRing.ENC_KEY_URL)
                    .append("）：").append(ring.encError())
                    .append("，不影响日志加密与解密（解密只需要 private.key）");
            } else {
                sb.append("与预置密文（").append(ring.encryptedKey().length).append(" 字节）");
            }
            sb.append("，耗时 ").append(System.currentTimeMillis() - started).append(" ms");
            log(sb.toString());
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
            + "）→ HTTP " + response.statusCode());
        if (response.statusCode() / 100 == 2) {
            // 服务端返回 downloadUrl 就用它，否则按约定 /{id} 拼接
            String pageUrl = downloadUrl.isEmpty() ? UPLOAD_BASE + "/" + id : downloadUrl;
            log("ZLog: 日志已上传，访问地址：" + pageUrl);
            log("ZLog: 分享给开发者时直接给上面这个链接即可。");
        } else {
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
        // 关闭阶段 Geyser 的 logger 可能已经关闭 appender，info 会丢失。
        // 这里再写一份 stderr + 一个状态文件，保证"上传成功 / 访问地址"一定能看到。
        System.err.println("[geyser-netease] " + message);
        appendStatusFile(message);
        tap(message);
    }

    /** 把关键事件追加到 <code>logs/zlog-status.log</code>，便于关服后回看上传结果。 */
    private static void appendStatusFile(String message) {
        try {
            String base = System.getProperty("user.dir", ".");
            java.nio.file.Path p = java.nio.file.Path.of(
                System.getProperty("GeyserNetease.ZLogStatusFile",
                    base + java.io.File.separator + "logs" + java.io.File.separator + "zlog-status.log"));
            java.nio.file.Path parent = p.getParent();
            if (parent != null) {
                java.nio.file.Files.createDirectories(parent);
            }
            String line = java.time.LocalDateTime.now() + " " + message + System.lineSeparator();
            java.nio.file.Files.writeString(p, line, StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
            // 状态文件写不了就算了，不影响上传
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
