package org.cloudburstmc.protocol.bedrock.codec.v630_netease.serializer;

import io.netty.buffer.ByteBuf;
import org.cloudburstmc.protocol.bedrock.codec.BedrockCodecHelper;
import org.cloudburstmc.protocol.bedrock.codec.v554.serializer.TextSerializer_v554;
import org.cloudburstmc.protocol.bedrock.packet.TextPacket;

public class TextSerializer_v630_NetEase extends TextSerializer_v554 {
    public static final TextSerializer_v630_NetEase INSTANCE = new TextSerializer_v630_NetEase();

    @Override
    public void serialize(ByteBuf buffer, BedrockCodecHelper helper, TextPacket packet) {
        super.serialize(buffer, helper, packet);

        TextPacket.Type type = packet.getType();
        if (type == TextPacket.Type.CHAT || type == TextPacket.Type.POPUP) {
            helper.writeString(buffer, textExtra(packet));
        }
    }

    /**
     * 网易客户端 CHAT/POPUP 包在标准字段之后还有一个额外字符串字段，其确切语义尚未确认。
     * 默认写空串（与历史行为一致）；如果实测发现聊天不显示，可用
     * <code>-DGeyserNetease.TextExtraField=message</code> 改为写消息原文来验证该字段的作用。
     */
    private static String textExtra(TextPacket packet) {
        if ("message".equals(System.getProperty("GeyserNetease.TextExtraField"))
                && packet.getMessage() != null) {
            return packet.getMessage();
        }
        return "";
    }

    @Override
    public void deserialize(ByteBuf buffer, BedrockCodecHelper helper, TextPacket packet) {
        super.deserialize(buffer, helper, packet);

        TextPacket.Type type = packet.getType();
        if (type == TextPacket.Type.CHAT || type == TextPacket.Type.POPUP) {
            helper.readString(buffer);
        }
    }
}
