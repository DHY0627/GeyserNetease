/*
 * Copyright (c) 2026 EiluDick/ZDarkZ
 * Released under the MIT License.
 */

package nc.geyserext.netease.util;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.util.NettyRuntime;
import io.netty.util.concurrent.DefaultThreadFactory;
import io.netty.util.internal.SystemPropertyUtil;
import nc.geyserext.netease.initializer.NeteaseServerInitializer;
import org.cloudburstmc.netty.channel.raknet.RakChannelFactory;
import org.cloudburstmc.netty.channel.raknet.config.*;
import org.cloudburstmc.netty.handler.codec.raknet.server.RakServerOfflineHandler;
import org.geysermc.geyser.*;
import org.geysermc.geyser.configuration.GeyserConfig;
import org.geysermc.geyser.network.netty.*;
import org.geysermc.geyser.network.netty.handler.*;
import org.geysermc.mcprotocollib.network.helper.TransportHelper;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import static org.cloudburstmc.netty.channel.raknet.RakConstants.*;

public final class ServerRestartUtil {
    private static final TransportHelper.TransportType TRANSPORT = TransportHelper.TRANSPORT_TYPE;
    private ServerRestartUtil() {}

    public static void restart(boolean onlyNeteaseClients) {
        try { doRestart(onlyNeteaseClients); }
        catch (NoClassDefFoundError e) {
            GeyserImpl.getInstance().getLogger().info("[GeyserNetease] Mod platform detected; skipping server restart. NetEase support active through channel hook.");
        }
        catch (Throwable t) {
            // 版本不匹配抛的是 NoSuchMethodError / NoSuchFieldError（属于 Error，不是 Exception），
            // 必须 catch Throwable，否则会直接冒泡打断 onPostInit。
            String hint = versionMismatchHint();
            GeyserImpl.getInstance().getLogger().error("[GeyserNetease] Failed to restart bedrock listener: " + t
                + (hint.isEmpty() ? "" : System.lineSeparator() + hint));
        }
    }

    /** 版本不匹配时给出可读的原因与解决办法；版本正常则返回空串。 */
    private static String versionMismatchHint() {
        try {
            java.lang.reflect.Method m = GeyserImpl.class.getMethod("getGeyserServer");
            String returnType = m.getReturnType().getName();
            if (returnType.endsWith(".GeyserServer")) {
                return "";
            }
            return "[GeyserNetease] 当前 Geyser 的 getGeyserServer() 返回 " + returnType
                + "，而本扩展是按 Geyser 2.9.4 ~ 2.10.1 编译的（返回 GeyserServer）。"
                + "请在 Geyser 2.9.4 ~ 2.10.1 上使用本 jar；"
                + "如果必须用 Geyser 2.11.x，请改用 2.11.3 分支构建的扩展（Release v1.4.1 及更早版本）。";
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static void doRestart(boolean onlyNeteaseClients) throws Exception {
        GeyserImpl geyser = GeyserImpl.getInstance();
        geyser.getGeyserServer().shutdown();

        Integer bt = Integer.getInteger("Geyser.BedrockNetworkThreads");
        if (bt == null) bt = Math.max(1, SystemPropertyUtil.getInt("io.netty.eventLoopThreads", NettyRuntime.availableProcessors() * 2));

        EventLoopGroup g = TRANSPORT.eventLoopGroupFactory().apply(Bootstraps.isReusePortAvailable() ? Integer.getInteger("Geyser.ListenCount", 1) : 1, new DefaultThreadFactory("GeyserServer", true));
        EventLoopGroup cg = TRANSPORT.eventLoopGroupFactory().apply(bt, new DefaultThreadFactory("GeyserServerChild", true));

        GeyserConfig cfg = geyser.config();
        boolean rakCookie = Boolean.parseBoolean(System.getProperty("Geyser.RakSendCookie", "true"));

        NeteaseServerInitializer init = new NeteaseServerInitializer(geyser, rakCookie, onlyNeteaseClients);

        ServerBootstrap bs = new ServerBootstrap()
            .channelFactory(RakChannelFactory.server(TRANSPORT.datagramChannelClass()))
            .group(g, cg)
            .option(RakChannelOption.RAK_HANDLE_PING, true)
            .option(RakChannelOption.RAK_MAX_MTU, cfg.advanced().bedrock().mtu())
            .option(RakChannelOption.RAK_PACKET_LIMIT, positiveProp("Geyser.RakPacketLimit", DEFAULT_PACKET_LIMIT))
            .option(RakChannelOption.RAK_GLOBAL_PACKET_LIMIT, positiveProp("Geyser.RakGlobalPacketLimit", DEFAULT_GLOBAL_PACKET_LIMIT))
            .option(RakChannelOption.RAK_SERVER_COOKIE_MODE, rakCookie ? RakServerCookieMode.ACTIVE : RakServerCookieMode.INVALID)
            .childHandler(init);
        Bootstraps.setupBootstrap(bs, TRANSPORT);

        Field fld = GeyserServer.class.getDeclaredField("bootstrapFutures"); fld.setAccessible(true);
        ChannelFuture[] futures = (ChannelFuture[]) fld.get(geyser.getGeyserServer());
        for (int i = 0; i < futures.length; i++) {
            ChannelFuture fut = bs.bind(new InetSocketAddress(cfg.bedrock().address(), cfg.bedrock().port()));
            fut.addListener((ChannelFutureListener) f -> {
                if (!f.isSuccess()) return;
                Channel c = f.channel();
                c.pipeline().addFirst(RakConnectionRequestHandler.NAME, new RakConnectionRequestHandler(geyser.getGeyserServer()))
                    .addAfter(RakServerOfflineHandler.NAME, RakPingHandler.NAME, new RakPingHandler(geyser.getGeyserServer()));
            });
            futures[i] = fut;
        }
        Bootstraps.allOf(futures).join();

        setField(GeyserServer.class, "group", geyser.getGeyserServer(), g);
        setField(GeyserServer.class, "childGroup", geyser.getGeyserServer(), cg);
        setField(GeyserServer.class, "playerGroup", geyser.getGeyserServer(), init.eventLoopGroup());
    }

    private static void setField(Class<?> c, String n, Object t, Object v) throws Exception { Field f = c.getDeclaredField(n); f.setAccessible(true); f.set(t, v); }
    private static int positiveProp(String p, int d) { String v = System.getProperty(p); try { int x = v != null ? Integer.parseInt(v) : d; return Math.max(x, 1); } catch (NumberFormatException e) { return d; } }
}
