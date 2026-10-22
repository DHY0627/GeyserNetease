/*
 * Copyright (c) 2026 EiluDick/ZDarkZ
 * Released under the MIT License.
 */

package nc.geyserext.netease.util.protocol;

import org.cloudburstmc.protocol.bedrock.codec.*;
import org.cloudburstmc.protocol.bedrock.codec.v630_netease.Bedrock_v630_NetEase;
import org.cloudburstmc.protocol.bedrock.codec.v686_netease.Bedrock_v686_NetEase;
import org.cloudburstmc.protocol.bedrock.codec.v766_netease.Bedrock_v766_NetEase;
import org.cloudburstmc.protocol.bedrock.codec.v819_netease.Bedrock_v819_NetEase;
import org.cloudburstmc.protocol.bedrock.codec.v860_netease.Bedrock_v860_NetEase;
import org.cloudburstmc.protocol.bedrock.data.EncodingSettings;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class NeteaseCodecRegistry {

    private static final Map<Integer, BedrockCodec> CODECS = new ConcurrentHashMap<>();

    static {
        register(Bedrock_v630_NetEase.CODEC);
        register(Bedrock_v686_NetEase.CODEC);
        register(Bedrock_v766_NetEase.CODEC);
        register(Bedrock_v819_NetEase.CODEC);
        register(Bedrock_v860_NetEase.CODEC);
    }

    /**
     * 解码上限。
     *
     * <p>这里曾经全部设为 {@link Integer#MAX_VALUE}，等于把 bedrock-codec 内置的畸形包防护
     * 整体关掉：客户端只要在包里声明一个超大长度（例如 BiomeDefinitionList 的 tag 数量），
     * 就能让服务端按该长度预分配内存，直接 OutOfMemoryError 杀掉整个 JVM。
     * 现在改用与上游 Geyser/bedrock-codec 一致的上限，既保留防护，又足够容纳正常网易包
     * （皮肤贴图 &lt; 1MB、geo JSON &lt; 32KB、列表条目远小于 1536）。</p>
     */
    private static void register(BedrockCodec c) {
        BedrockCodecHelper h = c.createHelper();
        h.setEncodingSettings(EncodingSettings.builder()
            .maxListSize(1536)
            .maxByteArraySize(1024 * 1024)
            .maxNetworkNBTSize(512 * 1024 * 1024)
            .maxItemNBTSize(100 * 1024)
            .maxStringLength(32 * 1024)
            .build());
        CODECS.put(c.getProtocolVersion(), c.toBuilder().helper(() -> h).build());
    }

    public static BedrockCodec getCodec(int version) { return CODECS.get(version); }
}
