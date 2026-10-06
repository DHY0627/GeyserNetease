/*
 * Copyright (c) 2026 EiluDick/ZDarkZ
 * Released under the MIT License.
 */

package nc.geyserext.netease.initializer;

import io.netty.channel.Channel;
import nc.geyserext.netease.NeteaseExtension;
import nc.geyserext.netease.handler.NetEaseUpstreamHandler;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.cloudburstmc.netty.channel.raknet.config.RakChannelOption;
import org.cloudburstmc.protocol.bedrock.BedrockPeer;
import org.cloudburstmc.protocol.bedrock.BedrockServerSession;
import org.cloudburstmc.protocol.bedrock.netty.codec.compression.CompressionCodec;
import org.cloudburstmc.protocol.bedrock.netty.codec.compression.NoopCompression;
import org.cloudburstmc.protocol.bedrock.netty.codec.compression.SimpleCompressionStrategy;
import org.cloudburstmc.protocol.bedrock.netty.codec.packet.BedrockPacketCodec;
import org.cloudburstmc.protocol.bedrock.netty.codec.packet.BedrockPacketCodec_v3;
import org.geysermc.geyser.GeyserImpl;
import org.geysermc.geyser.network.GeyserServerInitializer;
import org.geysermc.geyser.network.bedrock.InvalidPacketHandler;
import org.geysermc.geyser.network.bedrock.UpstreamPacketHandler;
import org.geysermc.geyser.session.GeyserSession;

/**
 * 网易（NetEase）专用服务器初始化器。
 *
 * <p>与 Geyser 2.11 的 {@link GeyserServerInitializer} 兼容：RakNet 协议版本 8 的连接
 * 使用 NoopCompression + BedrockPacketCodec_v3，并交给 {@link NetEaseUpstreamHandler} 处理。</p>
 */
public class NeteaseServerInitializer extends GeyserServerInitializer {
    private static final int NETEASE_RAKNET = 8;

    private final boolean rakCookie;
    private final boolean onlyNeteaseClients;

    public NeteaseServerInitializer(GeyserImpl geyser, boolean rakCookie, boolean onlyNeteaseClients) {
        super(geyser, "Geyser player thread");
        this.rakCookie = rakCookie;
        this.onlyNeteaseClients = onlyNeteaseClients;
    }

    @Override
    protected void preInitChannel(Channel channel) throws Exception {
        if (!rakCookie) {
            channel.setOption(RakChannelOption.RAK_PROTOCOL_VERSION, 11);
        }
        super.preInitChannel(channel);

        int rakVer = channel.config().getOption(RakChannelOption.RAK_PROTOCOL_VERSION);
        if (rakVer == NETEASE_RAKNET) {
            channel.pipeline().replace(CompressionCodec.NAME, CompressionCodec.NAME,
                new CompressionCodec(new SimpleCompressionStrategy(new NoopCompression()), false));
        }
    }

    @Override
    protected void initPacketCodec(Channel channel) throws Exception {
        int rakVer = channel.config().getOption(RakChannelOption.RAK_PROTOCOL_VERSION);
        if (rakVer == NETEASE_RAKNET) {
            channel.pipeline().addLast(BedrockPacketCodec.NAME, new BedrockPacketCodec_v3());
            return;
        }
        super.initPacketCodec(channel);
    }

    @Override
    public void initSession(@NonNull BedrockServerSession srv) {
        try {
            srv.setLogging(this.geyser.config().debugMode());
            GeyserSession session = new GeyserSession(this.geyser, srv, getEventLoopGroup().next());

            if (!srv.isSubClient()) {
                Channel channel = srv.getPeer().getChannel();
                try {
                    channel.pipeline().addAfter(BedrockPeer.NAME, InvalidPacketHandler.NAME, new InvalidPacketHandler(session));
                } catch (Exception ignored) {
                }
            }

            int rakVer = srv.getPeer().getChannel().config().getOption(RakChannelOption.RAK_PROTOCOL_VERSION);
            if (rakVer == NETEASE_RAKNET) {
                srv.setPacketHandler(new NetEaseUpstreamHandler(this.geyser, session));
            } else {
                if (onlyNeteaseClients) {
                    session.disconnect(NeteaseExtension.CONFIG.disconnectMessage());
                    return;
                }
                srv.setPacketHandler(new UpstreamPacketHandler(this.geyser, session));
            }
        } catch (Throwable e) {
            this.geyser.getLogger().error("Error occurred while initializing player!", e);
            srv.disconnect(e.getMessage());
        }
    }
}
