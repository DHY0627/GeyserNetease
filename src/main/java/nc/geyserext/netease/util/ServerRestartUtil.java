/*
 * Copyright (c) 2026 EiluDick/ZDarkZ
 * Released under the MIT License.
 */

package nc.geyserext.netease.util;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.EventLoopGroup;
import io.netty.util.NettyRuntime;
import io.netty.util.concurrent.DefaultThreadFactory;
import io.netty.util.internal.SystemPropertyUtil;
import nc.geyserext.netease.initializer.NeteaseServerInitializer;
import org.cloudburstmc.netty.channel.raknet.RakChannelFactory;
import org.cloudburstmc.netty.channel.raknet.config.RakChannelOption;
import org.cloudburstmc.netty.channel.raknet.config.RakServerCookieMode;
import org.cloudburstmc.netty.handler.codec.raknet.server.RakServerOfflineHandler;
import org.geysermc.geyser.GeyserImpl;
import org.geysermc.geyser.configuration.GeyserConfig;
import org.geysermc.geyser.network.BedrockPingHandler;
import org.geysermc.geyser.network.RaknetServer;
import org.geysermc.geyser.network.bedrock.raknet.Bootstraps;
import org.geysermc.geyser.network.bedrock.raknet.RakConnectionRequestHandler;
import org.geysermc.geyser.network.bedrock.raknet.RakPingHandler;
import org.geysermc.mcprotocollib.network.helper.TransportHelper;

import java.lang.reflect.Field;
import java.net.InetSocketAddress;

import static org.cloudburstmc.netty.channel.raknet.RakConstants.DEFAULT_GLOBAL_PACKET_LIMIT;
import static org.cloudburstmc.netty.channel.raknet.RakConstants.DEFAULT_PACKET_LIMIT;

/**
 * 用网易专用的 {@link NeteaseServerInitializer} 替换 Geyser 默认的 RakNet 监听器。
 *
 * <p>Geyser 2.11 起 {@code GeyserImpl.getGeyserServer()} 返回 {@link RaknetServer}
 * （final 类，内部字段私有），因此这里：先 shutdown 旧监听器，再按相同参数用
 * NetEase 初始化器重新绑定同一端口，最后把新的 EventLoop / 绑定句柄通过反射写回，
 * 保证 Geyser 后续的 shutdown / reload 仍然正常。</p>
 */
public final class ServerRestartUtil {
    private static final TransportHelper.TransportType TRANSPORT = TransportHelper.TRANSPORT_TYPE;

    private ServerRestartUtil() {
    }

    public static void restart(boolean onlyNeteaseClients) {
        try {
            doRestart(onlyNeteaseClients);
        } catch (NoClassDefFoundError e) {
            GeyserImpl.getInstance().getLogger().info(
                "[GeyserNetease] Mod platform detected; skipping server restart. NetEase support active through channel hook.");
        } catch (Throwable e) {
            // 注意：NoSuchMethodError 等属于 Error，必须用 Throwable 捕获，否则扩展会静默失效
            GeyserImpl.getInstance().getLogger().error("[GeyserNetease] Failed to restart bedrock listener", e);
        }
    }

    private static void doRestart(boolean onlyNeteaseClients) throws Exception {
        GeyserImpl geyser = GeyserImpl.getInstance();
        RaknetServer server = geyser.getGeyserServer();
        if (server == null) {
            geyser.getLogger().warning("[GeyserNetease] RakNet server not started yet; NetEase listener was not installed.");
            return;
        }
        server.shutdown();

        int bedrockThreadCount = Integer.getInteger("Geyser.BedrockNetworkThreads", -1);
        if (bedrockThreadCount == -1) {
            bedrockThreadCount = Math.max(1,
                SystemPropertyUtil.getInt("io.netty.eventLoopThreads", NettyRuntime.availableProcessors() * 2));
        }

        int listenCount = Bootstraps.isReusePortAvailable() ? Integer.getInteger("Geyser.ListenCount", 1) : 1;
        EventLoopGroup group = TRANSPORT.eventLoopGroupFactory()
            .apply(listenCount, new DefaultThreadFactory("GeyserServer", true));
        EventLoopGroup childGroup = TRANSPORT.eventLoopGroupFactory()
            .apply(bedrockThreadCount, new DefaultThreadFactory("GeyserServerChild", true));

        GeyserConfig cfg = geyser.config();
        boolean rakCookie = Boolean.parseBoolean(System.getProperty("Geyser.RakSendCookie", "true"));

        NeteaseServerInitializer initializer = new NeteaseServerInitializer(geyser, rakCookie, onlyNeteaseClients);

        BedrockPingHandler pingResponder = new BedrockPingHandler(geyser);
        RakConnectionRequestHandler connectionHandler = new RakConnectionRequestHandler(server);
        RakPingHandler pingHandler = new RakPingHandler(pingResponder);

        ServerBootstrap bootstrap = new ServerBootstrap()
            .channelFactory(RakChannelFactory.server(TRANSPORT.datagramChannelClass()))
            .group(group, childGroup)
            .option(RakChannelOption.RAK_HANDLE_PING, true)
            .option(RakChannelOption.RAK_MAX_MTU, cfg.advanced().bedrock().mtu())
            .option(RakChannelOption.RAK_PACKET_LIMIT, positiveProp("Geyser.RakPacketLimit", DEFAULT_PACKET_LIMIT))
            .option(RakChannelOption.RAK_GLOBAL_PACKET_LIMIT, positiveProp("Geyser.RakGlobalPacketLimit", DEFAULT_GLOBAL_PACKET_LIMIT))
            .option(RakChannelOption.RAK_SERVER_COOKIE_MODE,
                rakCookie ? RakServerCookieMode.ACTIVE : RakServerCookieMode.INVALID)
            .option(RakChannelOption.RAK_PROXY_PROTOCOL, cfg.advanced().bedrock().useHaproxyProtocol())
            .childHandler(initializer);
        Bootstraps.setupBootstrap(bootstrap, TRANSPORT);

        ChannelFuture[] futures = new ChannelFuture[listenCount];
        InetSocketAddress bindAddress = new InetSocketAddress(cfg.bedrock().address(), cfg.bedrock().raknetPort());
        for (int i = 0; i < listenCount; i++) {
            ChannelFuture future = bootstrap.bind(bindAddress);
            future.addListener((ChannelFutureListener) f -> {
                if (!f.isSuccess()) {
                    return;
                }
                Channel channel = f.channel();
                channel.pipeline()
                    .addBefore(RakServerOfflineHandler.NAME, RakConnectionRequestHandler.NAME, connectionHandler)
                    .addAfter(RakServerOfflineHandler.NAME, RakPingHandler.NAME, pingHandler);
            });
            futures[i] = future;
        }
        Bootstraps.allOf(futures).join();

        // 把新的 EventLoop 与绑定句柄写回 Geyser 的 RaknetServer 实例
        setField("group", server, group);
        setField("childGroup", server, childGroup);
        setField("playerGroup", server, initializer.getEventLoopGroup());
        setField("bootstrapFutures", server, futures);

        geyser.getLogger().info("[GeyserNetease] NetEase RakNet listener installed (port "
            + cfg.bedrock().raknetPort() + ").");
    }

    private static void setField(String name, Object target, Object value) throws Exception {
        Field field = RaknetServer.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static int positiveProp(String property, int defaultValue) {
        String value = System.getProperty(property);
        try {
            int parsed = value != null ? Integer.parseInt(value) : defaultValue;
            return Math.max(parsed, 1);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}
