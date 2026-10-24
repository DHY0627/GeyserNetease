package nc.geyserext.netease.log;

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
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;

/** 端到端自检：客户端加密 + 服务端解密，验证 .zlog 格式与 ML-KEM-1024 / AES-256 闭环。 */
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
        byte[] ct = sw.getEncapsulation();
        byte[] ss = sw.getSecret();
        byte[] key = ZLogCrypto.hkdfSha256(ss, ZLogCrypto.HKDF_SALT, ZLogCrypto.HKDF_INFO, 32);
        byte[] iv = new byte[ZLogCrypto.IV_LENGTH];
        rnd.nextBytes(iv);
        byte[] payload = ZLogCrypto.aesGcmEncrypt(key, iv, gz);
        byte[] aux = "kem.enc 原样内容".getBytes(StandardCharsets.UTF_8);
        byte[] archive = ZLogArchive.build(ZLogArchive.KEM_ML_KEM_1024, ct, aux, iv, payload);
        System.out.println("原始 " + raw.length + " → gzip " + gz.length + " → 加密 " + payload.length
            + " → .zlog " + archive.length + " 字节");

        // 服务端
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(archive));
        byte[] magic = new byte[4];
        in.readFully(magic);
        int ver = in.readUnsignedByte();
        int alg = in.readUnsignedByte();
        int ctLen = in.readUnsignedShort();
        byte[] ct2 = new byte[ctLen];
        in.readFully(ct2);
        int auxLen = in.readInt();
        byte[] aux2 = new byte[auxLen];
        in.readFully(aux2);
        byte[] iv2 = new byte[ZLogCrypto.IV_LENGTH];
        in.readFully(iv2);
        byte[] payload2 = in.readAllBytes();

        byte[] ss2 = new MLKEMExtractor(priv).extractSecret(ct2);
        byte[] key2 = ZLogCrypto.hkdfSha256(ss2, ZLogCrypto.HKDF_SALT, ZLogCrypto.HKDF_INFO, 32);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key2, "AES"),
            new GCMParameterSpec(ZLogCrypto.TAG_LENGTH_BITS, iv2));
        byte[] gz2 = c.doFinal(payload2);
        byte[] raw2 = new GZIPInputStream(new ByteArrayInputStream(gz2)).readAllBytes();

        System.out.println("magic=" + new String(magic, StandardCharsets.US_ASCII) + " version=" + ver
            + " kemAlg=" + alg + " ctLen=" + ctLen + " auxLen=" + auxLen);
        System.out.println("aux 还原 = " + new String(aux2, StandardCharsets.UTF_8));
        System.out.println("共享密钥一致 = " + Arrays.equals(ss, ss2));
        System.out.println("日志还原一致 = " + Arrays.equals(raw, raw2));
        System.out.println("CKSUM " + (Arrays.equals(raw, raw2) && Arrays.equals(ss, ss2) ? "OK" : "FAIL"));
    }
}
