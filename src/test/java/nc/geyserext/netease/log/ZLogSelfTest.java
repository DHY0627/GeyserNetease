package nc.geyserext.netease.log;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;

/**
 * 端到端自检：客户端加密 + 服务端解密，验证 .zlog 与
 * <code>ML-KEM-完整技术文档.md</code> 4.2 / 5.5 节的协议一致。
 *
 * <pre>
 * .zlog = kem_ct(1568) || nonce(16) || tag(32) || ct'
 * </pre>
 */
public class ZLogSelfTest {

    public static void main(String[] args) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 500; i++) {
            sb.append("第 ").append(i).append(" 行：网易客户端调试日志 test log line\n");
        }
        byte[] raw = sb.toString().getBytes(StandardCharsets.UTF_8);
        byte[] gz = ZLogCrypto.gzip(raw);

        SecureRandom rnd = new SecureRandom();
        MLKEMKeyPairGenerator kpg = new MLKEMKeyPairGenerator();
        kpg.init(new MLKEMKeyGenerationParameters(rnd, MLKEMParameters.ml_kem_1024));
        var kp = kpg.generateKeyPair();
        MLKEMPublicKeyParameters pub = (MLKEMPublicKeyParameters) kp.getPublic();
        MLKEMPrivateKeyParameters priv = (MLKEMPrivateKeyParameters) kp.getPrivate();
        byte[] pk = pub.getEncoded();
        System.out.println("公钥长度 = " + pk.length + "（ML-KEM-1024 应为 1568）");

        // 客户端
        SecretWithEncapsulation sw = new MLKEMGenerator(rnd).generateEncapsulated(pub);
        byte[] kemCt = sw.getEncapsulation();
        byte[] ss = sw.getSecret();
        byte[] sealBlob = ZLogCrypto.seal(ss, gz);
        byte[] zlog = ZLogArchive.build(kemCt, sealBlob);
        System.out.println("原始 " + raw.length + " → gzip " + gz.length + " → seal " + sealBlob.length
            + " → .zlog " + zlog.length + " 字节");

        // 服务端：按文档切分
        byte[] kemCt2 = Arrays.copyOfRange(zlog, 0, kemCt.length);
        byte[] blob2 = Arrays.copyOfRange(zlog, kemCt.length, zlog.length);
        byte[] ss2 = new MLKEMExtractor(priv).extractSecret(kemCt2);
        byte[] gz2 = ZLogCrypto.unseal(ss2, blob2);
        byte[] raw2 = new GZIPInputStream(new ByteArrayInputStream(gz2)).readAllBytes();

        System.out.println("kem_ct=" + kemCt.length + " nonce=" + ZLogCrypto.NONCE_SIZE
            + " tag=" + ZLogCrypto.TAG_SIZE + " ct'=" + (blob2.length - ZLogCrypto.NONCE_SIZE - ZLogCrypto.TAG_SIZE));
        System.out.println("共享密钥一致 = " + Arrays.equals(ss, ss2));
        System.out.println("日志还原一致 = " + Arrays.equals(raw, raw2));
        System.out.println("CKSUM " + (Arrays.equals(raw, raw2) && Arrays.equals(ss, ss2) ? "OK" : "FAIL"));
    }
}
