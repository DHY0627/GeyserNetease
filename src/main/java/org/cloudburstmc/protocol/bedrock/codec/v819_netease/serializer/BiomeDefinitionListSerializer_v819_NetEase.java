package org.cloudburstmc.protocol.bedrock.codec.v819_netease.serializer;

import io.netty.buffer.ByteBuf;
import org.cloudburstmc.protocol.bedrock.codec.BedrockCodecHelper;
import org.cloudburstmc.protocol.bedrock.codec.v800.serializer.BiomeDefinitionListSerializer_v800;
import org.cloudburstmc.protocol.bedrock.data.biome.BiomeDefinitionChunkGenData;
import org.cloudburstmc.protocol.bedrock.data.biome.BiomeDefinitionData;
import org.cloudburstmc.protocol.common.util.Preconditions;
import org.cloudburstmc.protocol.common.util.SequencedHashSet;
import org.cloudburstmc.protocol.common.util.VarInts;

import java.awt.Color;
import java.util.ArrayList;
import java.util.List;

public class BiomeDefinitionListSerializer_v819_NetEase extends BiomeDefinitionListSerializer_v800 {
    public static final BiomeDefinitionListSerializer_v819_NetEase INSTANCE = new BiomeDefinitionListSerializer_v819_NetEase();

    /** 单个生物群系允许的最大 tag 数（远大于任何正常数据，仅用于拦截畸形包）。 */
    private static final int MAX_TAGS_PER_BIOME = 4096;

    @Override
    protected BiomeDefinitionData readDefinition(ByteBuf buffer, BedrockCodecHelper helper, List<String> strings) {
        Integer id = readDefinitionId(buffer, helper);
        float temperature = buffer.readFloatLE();
        float downfall = buffer.readFloatLE();
        float redSporeDensity = buffer.readFloatLE();
        float blueSporeDensity = buffer.readFloatLE();
        float ashDensity = buffer.readFloatLE();
        float whiteAshDensity = buffer.readFloatLE();
        float depth = buffer.readFloatLE();
        float scale = buffer.readFloatLE();
        Color mapWaterColor = new Color(buffer.readIntLE(), true);
        boolean rain = buffer.readBoolean();
        buffer.readIntLE();
        helper.readString(buffer);

        List<String> tags = helper.readOptional(buffer, null, byteBuf -> {
            int length = VarInts.readUnsignedInt(byteBuf);
            // 防御畸形包：length 由客户端控制，原先 length * 2 会整数溢出（负值使 isReadable 恒真），
            // 随后 new ArrayList<>(length) 直接按该值预分配 → 远程 OOM。这里先做范围校验。
            Preconditions.checkArgument(length >= 0 && length <= MAX_TAGS_PER_BIOME,
                    "Too many biome tags: " + length);
            Preconditions.checkArgument(byteBuf.isReadable(length * 2), "Not enough readable bytes for tags");
            List<String> tagList = new ArrayList<>(Math.min(length, 16));
            for (int i = 0; i < length; i++) {
                int index = byteBuf.readUnsignedShortLE();
                Preconditions.checkArgument(index < strings.size(), "Invalid biome tag string index: " + index);
                tagList.add(strings.get(index));
            }
            return tagList;
        });

        BiomeDefinitionChunkGenData chunkGenData = helper.readOptional(buffer, null,
                (buf, aHelper) -> readDefinitionChunkGen(buf, aHelper, strings));

        return new BiomeDefinitionData(id, temperature, downfall, redSporeDensity, blueSporeDensity,
                ashDensity, whiteAshDensity, 0f, depth, scale, mapWaterColor, rain, tags, chunkGenData);
    }

    @Override
    protected void writeDefinition(ByteBuf buffer, BedrockCodecHelper helper, BiomeDefinitionData definition, SequencedHashSet<String> strings) {
        writeDefinitionId(buffer, helper, definition);
        buffer.writeFloatLE(definition.getTemperature());
        buffer.writeFloatLE(definition.getDownfall());
        buffer.writeFloatLE(definition.getRedSporeDensity());
        buffer.writeFloatLE(definition.getBlueSporeDensity());
        buffer.writeFloatLE(definition.getAshDensity());
        buffer.writeFloatLE(definition.getWhiteAshDensity());
        buffer.writeFloatLE(definition.getDepth());
        buffer.writeFloatLE(definition.getScale());
        buffer.writeIntLE(definition.getMapWaterColor().getRGB());
        buffer.writeBoolean(definition.isRain());
        buffer.writeIntLE(0);
        helper.writeString(buffer, "");

        helper.writeOptionalNull(buffer, definition.getTags(), (byteBuf, aHelper, tags) -> {
            VarInts.writeUnsignedInt(byteBuf, tags.size());
            for (String tag : tags) {
                byteBuf.writeShortLE(strings.addAndGetIndex(tag));
            }
        });
        helper.writeOptionalNull(buffer, definition.getChunkGenData(),
                (buf, aHelper, data) -> writeDefinitionChunkGen(buf, aHelper, data, strings));
    }
}
