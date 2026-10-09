/*
 * Copyright (c) 2026 EiluDick/ZDarkZ
 * Released under the MIT License.
 */

package nc.geyserext.netease.handler;

import nc.geyserext.netease.NeteaseExtension;
import nc.geyserext.netease.session.NeteaseSession;
import nc.geyserext.netease.util.protocol.NeteaseCodecRegistry;
import org.cloudburstmc.math.vector.Vector3i;
import org.cloudburstmc.netty.channel.raknet.config.RakChannelOption;
import org.cloudburstmc.protocol.bedrock.codec.BedrockCodec;
import org.cloudburstmc.protocol.bedrock.data.PacketCompressionAlgorithm;
import org.cloudburstmc.protocol.bedrock.data.auth.CertificateChainPayload;
import org.cloudburstmc.protocol.bedrock.data.inventory.transaction.InventoryActionData;
import org.cloudburstmc.protocol.bedrock.data.inventory.transaction.InventorySource;
import org.cloudburstmc.protocol.bedrock.data.inventory.transaction.InventoryTransactionType;
import org.cloudburstmc.protocol.bedrock.netty.codec.compression.*;
import org.cloudburstmc.protocol.bedrock.packet.*;
import org.cloudburstmc.protocol.bedrock.util.*;
import org.cloudburstmc.protocol.common.PacketSignal;
import org.geysermc.geyser.GeyserImpl;
import org.geysermc.geyser.api.event.bedrock.SessionInitializeEvent;
import org.geysermc.geyser.event.type.SessionLoadResourcePacksEventImpl;
import org.geysermc.geyser.network.bedrock.GameProtocol;
import org.geysermc.geyser.registry.BlockRegistries;
import org.geysermc.geyser.registry.Registries;
import org.geysermc.geyser.session.GeyserSession;
import org.geysermc.geyser.api.network.AuthType;
import org.geysermc.geyser.session.auth.*;
import org.geysermc.geyser.text.GeyserLocale;
import org.geysermc.mcprotocollib.protocol.data.game.entity.object.Direction;
import org.geysermc.mcprotocollib.protocol.data.game.entity.player.PlayerAction;
import org.geysermc.mcprotocollib.protocol.packet.ingame.serverbound.player.ServerboundPlayerActionPacket;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.*;

public class NetEaseUpstreamHandler extends UpstreamHandlerBase {

    /**
     * 是否跳过 Bedrock 层加密握手。
     *
     * <p>网易客户端通过 NetherNet（WebRTC/SCTP，本身已由 DTLS 加密）连接，
     * 实测它收到 {@code ServerToClientHandshake} 后会静默忽略并最终超时
     * （4 种批次封装格式均如此），即局域网流程不做 Bedrock 层加密。
     * 因此默认跳过加密握手，直接进入资源包阶段。</p>
     *
     * <p>可用 {@code -DGeyserNetease.SkipEncryption=false} 关闭。</p>
     */
    private static final boolean SKIP_ENCRYPTION =
        !"false".equalsIgnoreCase(System.getProperty("GeyserNetease.SkipEncryption", "true"));

    private NeteaseSession neteaseSession;

    /** 是否已经下发过 PlayStatus / ResourcePacksInfo，避免重复发送。 */
    private boolean loginFlowCompleted;

    public NetEaseUpstreamHandler(GeyserImpl geyser, GeyserSession session) {
        super(geyser, session);
    }

    @Override
    public PacketSignal handle(RequestNetworkSettingsPacket packet) {
        Integer rakVer = getRakVersion();
        boolean isNetEase = rakVer != null && rakVer == 8;
        if (!isNetEase) {
            NeteaseExtension.debug("[GeyserNetease] 非网易连接（rakVer=" + rakVer + "），交回标准处理");
            return super.handle(packet);
        }

        BedrockCodec codec = NeteaseCodecRegistry.getCodec(packet.getProtocolVersion());
        if (codec == null) {
            NeteaseExtension.debug("[GeyserNetease] 未注册的网易协议版本 " + packet.getProtocolVersion() + "，交回标准处理");
            return super.handle(packet);
        }
        NeteaseExtension.debug("[GeyserNetease] 网易路径已激活：rakVer=" + rakVer
            + " 协议=" + packet.getProtocolVersion() + " 跳过加密=" + SKIP_ENCRYPTION);

        session.getUpstream().getSession().setCodec(codec);
        neteaseSession = new NeteaseSession(session, packet.getProtocolVersion(), codec);

        NetworkSettingsPacket resp = new NetworkSettingsPacket();
        resp.setCompressionAlgorithm(PacketCompressionAlgorithm.ZLIB);
        resp.setCompressionThreshold(512);
        session.sendUpstreamPacketImmediately(resp);

        NetEaseCompression nc = new NetEaseCompression();
        nc.setLevel(geyser.config().advanced().bedrock().compressionLevel());
        session.getUpstream().getSession().getPeer().setCompression(new SimpleCompressionStrategy(nc));

        networkSettingsRequested = true;
        return PacketSignal.HANDLED;
    }

    @Override
    public PacketSignal handle(LoginPacket packet) {
        if (neteaseSession == null) return super.handle(packet);
        if (!networkSettingsRequested) { session.disconnect("Protocol error"); return PacketSignal.HANDLED; }
        if (receivedLoginPacket) { session.disconnect("Duplicate login"); session.forciblyCloseUpstream(); return PacketSignal.HANDLED; }
        receivedLoginPacket = true;

        try {
            if (packet.getAuthPayload() instanceof CertificateChainPayload chain) {
                ChainValidationResult result = NetEaseEncryptionUtils.validateChain(chain);
                var extra = result.identityClaims().extraData;
                String name = extra.displayName != null ? extra.displayName : "NetEasePlayer";
                Long iat = (Long) result.rawIdentityClaims().get("iat");

                long neteaseUid = 0;
                Object red = result.rawIdentityClaims().get("extraData");
                if (red instanceof Map) {
                    Object u = ((Map<?, ?>) red).get("uid");
                    if (u instanceof Number) neteaseUid = ((Number) u).longValue();
                }
                if (neteaseUid == 0) neteaseUid = Math.abs(name.hashCode());
                neteaseSession.setUid(neteaseUid);

                String rawId = extra.identity != null ? extra.identity.toString() : null;
                UUID javaUuid = toStableUUID(rawId, neteaseUid);

                String xuid = String.valueOf(neteaseUid);

                session.setAuthData(new AuthData(name, javaUuid, xuid, iat != null ? iat : -1, extra.minecraftId != null ? extra.minecraftId : ""));
                session.setCertChainData(chain.getChain());

                if (packet.getClientJwt() != null && !packet.getClientJwt().isEmpty()) {
                    try {
                        byte[] cd = EncryptionUtils.verifyClientData(packet.getClientJwt(), result.identityClaims().parsedIdentityPublicKey());
                        if (cd != null) { BedrockClientData bcd = GeyserImpl.GSON.fromJson(new String(cd), BedrockClientData.class); bcd.setOriginalString(packet.getClientJwt()); session.setClientData(bcd); }
                    } catch (Exception ignored) {}
                }
                if (session.getClientData() == null)
                    session.setClientData(buildFakeClientData(name));
                patchServerAddress(session.getClientData());

                if (!SKIP_ENCRYPTION) {
                    NeteaseExtension.debug("[GeyserNetease] 发送 ServerToClientHandshake（加密握手）");
                    startEncryptionHandshake(session, result.identityClaims().parsedIdentityPublicKey());
                    if (session.isClosed()) { session.forciblyCloseUpstream(); return PacketSignal.HANDLED; }
                    neteaseSession.setLoginDeferred(true);
                } else {
                    // 网易局域网流程不做 Bedrock 层加密：不发送握手、不启用加密
                    NeteaseExtension.debug("[GeyserNetease] 已跳过 ServerToClientHandshake（网易局域网流程不做 Bedrock 层加密）");
                    neteaseSession.setLoginDeferred(false);
                }
            }
        } catch (Exception e) { session.disconnect("disconnectionScreen.internalError.cantConnect"); NeteaseExtension.LOG.error("NetEase auth failed", e); return PacketSignal.HANDLED; }

        int spoofedVersion = GameProtocol.DEFAULT_BEDROCK_PROTOCOL;
        var shared = BlockRegistries.BLOCKS.forVersion(spoofedVersion);
        var blockMappings = shared;
        try { blockMappings = nc.geyserext.netease.session.SpoofedUpstream.cloneBlockMappings(shared); }
        catch (Throwable e) { NeteaseExtension.LOG.error("BlockMappings clone failed, using shared: " + e.getMessage()); }
        session.setBlockMappings(blockMappings);
        session.setItemMappings(Registries.ITEMS.forVersion(spoofedVersion));

        boolean patched = false;
        try { patched = nc.geyserext.netease.session.SpoofedUpstream.patchAll(blockMappings); }
        catch (Throwable e) { NeteaseExtension.LOG.error("BlockMappings Unsafe: " + e.getMessage()); }

        int maxId = 0;
        for (int i = 0; blockMappings.getDefinition(i) != null; i++) maxId = i;
        int[] rtToHash = new int[maxId + 1];
        boolean[] hValid = new boolean[maxId + 1];
        for (int i = 0; i <= maxId; i++) {
            var block = blockMappings.getDefinition(i);
            if (block != null) {
                var gb = (org.geysermc.geyser.registry.type.GeyserBedrockBlock) block;
                if (gb.getState() != null) {
                    rtToHash[i] = nc.geyserext.netease.util.BlockHashUtils.fnv1a32Nbt(gb.getState());
                    hValid[i] = true;
                }
            }
        }

        try {
            var spoofed = new nc.geyserext.netease.session.SpoofedUpstream(
                session.getUpstream(), session.getUpstream().getSession(), rtToHash, hValid, patched, neteaseSession.uid());
            java.lang.reflect.Field upF = org.geysermc.geyser.session.GeyserSession.class.getDeclaredField("upstream");
            upF.setAccessible(true); upF.set(session, spoofed);
        } catch (Exception e) { NeteaseExtension.LOG.error("SpoofedUpstream inject failed: " + e.getMessage()); }

        geyser.getSessionManager().addPendingSession(session);
        geyser.eventBus().fire(new SessionInitializeEvent(session));
        this.resourcePackLoadEvent = new SessionLoadResourcePacksEventImpl(session);
        this.geyser.eventBus().fireEventElseKick(this.resourcePackLoadEvent, session);
        if (session.isClosed()) return PacketSignal.HANDLED;
        session.integratedPackActive(resourcePackLoadEvent.isIntegratedPackActive());
        GeyserLocale.loadGeyserLocale(session.locale());

        if (SKIP_ENCRYPTION && !loginFlowCompleted) {
            // 没有加密握手，客户端不会发 ClientToServerHandshake，
            // 因此这里直接下发 PlayStatus + ResourcePacksInfo
            sendLoginSuccessAndPacks();
        }
        return PacketSignal.HANDLED;
    }

    /** 发送 PlayStatus(LOGIN_SUCCESS) 与 ResourcePacksInfo，进入资源包阶段。 */
    private void sendLoginSuccessAndPacks() {
        if (loginFlowCompleted || session.isClosed()) return;
        loginFlowCompleted = true;
        NeteaseExtension.debug("[GeyserNetease] 下发 PlayStatus(LOGIN_SUCCESS) + ResourcePacksInfo");

        PlayStatusPacket ps = new PlayStatusPacket();
        ps.setStatus(PlayStatusPacket.Status.LOGIN_SUCCESS);
        session.sendUpstreamPacket(ps);
        if (session.isClosed()) return;

        ResourcePacksInfoPacket rpi = new ResourcePacksInfoPacket();
        rpi.getResourcePackInfos().addAll(this.resourcePackLoadEvent.infoPacketEntries());
        rpi.setVibrantVisualsForceDisabled(!session.isAllowVibrantVisuals());
        rpi.setForcedToAccept(geyser.config().gameplay().forceResourcePacks() || resourcePackLoadEvent.isIntegratedPackActive());
        rpi.setWorldTemplateId(java.util.UUID.randomUUID()); rpi.setWorldTemplateVersion("*");
        session.sendUpstreamPacket(rpi);
    }

    @Override
    public PacketSignal handle(PlayerAuthInputPacket packet) {
        return defaultHandler(packet);
    }

    @Override
    public PacketSignal handle(ClientToServerHandshakePacket packet) {
        if (neteaseSession != null && neteaseSession.loginDeferred()) {
            neteaseSession.setLoginDeferred(false);
            if (this.resourcePackLoadEvent == null) {
                this.resourcePackLoadEvent = new org.geysermc.geyser.event.type.SessionLoadResourcePacksEventImpl(session);
                this.geyser.eventBus().fireEventElseKick(this.resourcePackLoadEvent, session);
            }
            if (session.isClosed()) return PacketSignal.HANDLED;
            session.integratedPackActive(resourcePackLoadEvent.isIntegratedPackActive());
            sendLoginSuccessAndPacks();
            return PacketSignal.HANDLED;
        }
        return super.handle(packet);
    }

    @Override
    public PacketSignal handle(ResourcePackClientResponsePacket packet) {
        if (neteaseSession == null) return super.handle(packet);
        if (session.getUpstream().isClosed() || session.isClosed()) return PacketSignal.HANDLED;
        if (finishedResourcePackSending) return PacketSignal.HANDLED;

        switch (packet.getStatus()) {
            case COMPLETED -> {
                finishedResourcePackSending = true;
                if (geyser.config().java().authType() != AuthType.ONLINE) {
                    String javaName = javaLoginName(session.getAuthData().name(), neteaseSession.uid());
                    NeteaseExtension.debug("[GeyserNetease] Java 侧登录名 = " + javaName
                        + "（Bedrock 显示名 = " + session.getAuthData().name() + "，ASCII=" + ASCII_JAVA_NAME + "）");
                    session.authenticate(javaName);
                } else if (!couldLoginUserByName(session.getAuthData().name())) {
                    session.connect();
                }
                neteaseSession.setAuthenticated(true);
                // authenticate() 会同步创建 downstream 会话对象，返回后立刻挂监听器，
                // 这样第一个包（握手/LoginStart）也能被记录到。
                attachJavaSniffer();
            }
            case SEND_PACKS -> { if (!packet.getPackIds().isEmpty()) { packsToSend.addAll(packet.getPackIds()); sendPackDataInfo(packsToSend.pop()); } return PacketSignal.HANDLED; }
            case HAVE_ALL_PACKS -> {
                ResourcePackStackPacket sp = new ResourcePackStackPacket();
                sp.setExperimentsPreviouslyToggled(false); sp.setForcedToAccept(false);
                sp.setGameVersion(session.getClientData() != null ? session.getClientData().getGameVersion() : "1.21.40");
                sp.getResourcePacks().addAll(this.resourcePackLoadEvent.orderedPacks()); session.sendUpstreamPacket(sp);
            }
            case REFUSED -> session.disconnect("disconnectionScreen.resourcePack");
            default -> session.disconnect("disconnectionScreen.resourcePack");
        }
        return PacketSignal.HANDLED;
    }

    public PacketSignal handle(NetEaseJsonPacket p)  { return PacketSignal.HANDLED; }
    public PacketSignal handle(PyRpcPacket p)         { return PacketSignal.HANDLED; }
    public PacketSignal handle(StoreBuySuccessPacket p) { return PacketSignal.HANDLED; }
    public PacketSignal handle(ConfirmSkinPacket p)   { return PacketSignal.HANDLED; }

    public PacketSignal handle(InventoryTransactionPacket packet) {
        if (neteaseSession != null && packet.getTransactionType() == InventoryTransactionType.NORMAL
                && packet.getActions().size() == 2) {
            List<InventoryActionData> actions = packet.getActions();
            InventoryActionData action0 = actions.get(0);
            InventoryActionData action1 = actions.get(1);
            InventoryActionData worldAction = action0.getSource().getType() == InventorySource.Type.WORLD_INTERACTION ? action0 : action1;
            InventoryActionData containerAction = (worldAction == action0) ? action1 : action0;
            if (worldAction.getSource().getType() != InventorySource.Type.WORLD_INTERACTION
                    || containerAction.getSource().getType() != InventorySource.Type.CONTAINER)
                return defaultHandler(packet);

            boolean dropAll = worldAction.getToItem().getCount() > 1;
            var inventory = session.getPlayerInventory();
            if (inventory.getItemInHand().isEmpty()) return PacketSignal.HANDLED;

            session.sendDownstreamGamePacket(new ServerboundPlayerActionPacket(
                dropAll ? PlayerAction.DROP_ITEM_STACK : PlayerAction.DROP_ITEM, Vector3i.ZERO, Direction.DOWN, 0));

            if (dropAll) inventory.setItemInHand(org.geysermc.geyser.inventory.GeyserItemStack.EMPTY);
            else inventory.getItemInHand().sub(1);

            return PacketSignal.HANDLED;
        }
        return defaultHandler(packet);
    }

    private static void startEncryptionHandshake(GeyserSession session, PublicKey clientKey) throws Exception {
        KeyPair serverKeyPair = EncryptionUtils.createKeyPair();
        byte[] token = EncryptionUtils.generateRandomToken();

        ServerToClientHandshakePacket handshake = new ServerToClientHandshakePacket();
        handshake.setJwt(EncryptionUtils.createHandshakeJwt(serverKeyPair, token));
        session.sendUpstreamPacketImmediately(handshake);

        SecretKey encryptionKey = EncryptionUtils.getSecretKey(serverKeyPair.getPrivate(), clientKey, token);
        session.getUpstream().getSession().enableEncryption(encryptionKey);
    }

    private Integer getRakVersion() {
        try { return session.getUpstream().getSession().getPeer().getChannel().config().getOption(RakChannelOption.RAK_PROTOCOL_VERSION); }
        catch (Exception e) { return null; }
    }
    private boolean couldLoginUserByName(String name) {
        if (geyser.config().savedUserLogins().contains(name)) {
            String chain = geyser.authChainFor(name);
            if (chain != null) { session.authenticateWithAuthChain(chain); return true; }
        }
        return false;
    }

    public NeteaseSession neteaseSession() { return neteaseSession; }

    /**
     * Java 侧登录名。
     *
     * <p>网易客户端的显示名是中文（如 "锕钼铽镧锶"）。Geyser 会原样把它交给 MCProtocolLib
     * 作为 java 版 LoginStart 的用户名，而实测该用户名会让 Velocity 侧在登录阶段静默掐断连接
     * （Velocity 的 MinecraftConnection.exceptionCaught 对 InitialLoginSessionHandler /
     * HandshakeSessionHandler 这类"前线"处理器不打任何日志，直接 ctx.close()）。
     * 因此默认改用纯 ASCII、稳定的 java 登录名；Bedrock 侧显示名不变。</p>
     *
     * <p>可用 {@code -DGeyserNetease.AsciiJavaName=false} 关闭，恢复原来的中文名登录。</p>
     */
    private static final boolean ASCII_JAVA_NAME =
        "true".equalsIgnoreCase(System.getProperty("GeyserNetease.AsciiJavaName", "false"));

    private static String javaLoginName(String bedrockName, long uid) {
        if (!ASCII_JAVA_NAME) return bedrockName;
        String base = "NE" + Math.abs(uid);
        if (base.length() > 16) base = base.substring(0, 16);
        return base;
    }

    /**
     * Java 侧地址（用于 Geyser 的 {@code session.joinAddress()}，也就是 java 握手的 hostname）。
     *
     * <p>网易局域网客户端的客户端数据里 {@code ServerAddress} 是 {@code ":0"}，
     * 于是 {@code GeyserSession.joinAddress()} = {@code substring(0, 0)} = 空字符串，
     * 若 Geyser 配置了 {@code forward-hostname: true}，java 握手就会带着空 hostname 发给代理；
     * Velocity 收到空 hostname 会在登录阶段直接静默掐断连接（
     * {@code MinecraftConnection.exceptionCaught} 对 InitialLoginSessionHandler 不打日志）。
     * 这里强制填一个真实的公开地址。可用 {@code -DGeyserNetease.ServerAddress=...} 覆盖。</p>
     */
    private static final String FORCED_SERVER_ADDRESS =
        System.getProperty("GeyserNetease.ServerAddress", "example.com:19132");

    /** 从 {@link #FORCED_SERVER_ADDRESS} 取主机部分（去掉端口）。 */
    private static String handshakeHost() {
        String v = FORCED_SERVER_ADDRESS;
        int i = v.lastIndexOf(':');
        return i > 0 ? v.substring(0, i) : v;
    }

    /** 把客户端数据里的 ServerAddress 从 ":0" 修成一个正常地址；已经是正常值则不动。 */
    private static void patchServerAddress(BedrockClientData bcd) {
        if (bcd == null) return;
        try {
            String cur = bcd.getServerAddress();
            if (cur != null && !cur.isEmpty() && !cur.startsWith(":")) return;
            boolean ok = false;
            try {
                var m = BedrockClientData.class.getDeclaredMethod("setServerAddress", String.class);
                m.setAccessible(true);
                m.invoke(bcd, FORCED_SERVER_ADDRESS);
                ok = true;
            } catch (Throwable ignored) {
            }
            if (!ok) {
                var f = BedrockClientData.class.getDeclaredField("serverAddress");
                f.setAccessible(true);
                f.set(bcd, FORCED_SERVER_ADDRESS);
            }
            NeteaseExtension.debug("[GeyserNetease] 客户端 ServerAddress \"" + cur + "\" → \""
                + FORCED_SERVER_ADDRESS + "\"（java 握手 hostname 依赖它）");
        } catch (Throwable e) {
            NeteaseExtension.LOG.error("[GeyserNetease] 修正 ServerAddress 失败: " + e);
        }
    }

    // ==================== Java 侧嗅探（诊断用） ====================
    //
    // 目的：网易玩家在 "Geyser → Velocity" 这一跳会被静默断流（Velocity 的
    // MinecraftConnection.exceptionCaught 对 InitialLoginSessionHandler /
    // HandshakeSessionHandler 这类"前线"处理器不打任何日志，直接 ctx.close()；
    // 解码失败又是 QuietRuntimeException），因此服务器日志里什么都看不到。
    //
    // 这里在 Geyser 的 downstream（MCProtocolLib）会话上挂一个 SessionListener：
    //   packetSending  → Geyser 发往 Velocity 的每一个包（含握手/LoginStart）
    //   packetReceived → Velocity 发来的每一个包（含 LoginSuccess/Disconnect）
    //   packetError / disconnecting / disconnected → 异常与断开原因
    // 结果写入运行目录下的 geyser-netease-java.log。
    private static volatile java.io.PrintWriter SNIFF_OUT;
    private static volatile String SNIFF_PATH = "(未初始化)";
    private static final java.util.concurrent.atomic.AtomicBoolean SNIFF_STARTED =
        new java.util.concurrent.atomic.AtomicBoolean();
    private static final java.util.concurrent.atomic.AtomicInteger SNIFF_CONSOLE =
        new java.util.concurrent.atomic.AtomicInteger();

    private static final boolean SNIFF_ENABLED =
        Boolean.parseBoolean(System.getProperty("GeyserNetease.Sniff", "false"));

    private void attachJavaSniffer() {
        if (!SNIFF_ENABLED) return;
        if (!SNIFF_STARTED.compareAndSet(false, true)) return;
        try {
            java.io.File f = new java.io.File("geyser-netease-java.log");
            SNIFF_PATH = f.getAbsolutePath();
            SNIFF_OUT = new java.io.PrintWriter(new java.io.FileWriter(f, true), true);
            NeteaseExtension.debug("[GeyserNetease] Java 侧嗅探日志: " + SNIFF_PATH);
            sniff("===== 嗅探启动 bedrockName="
                + (session.getAuthData() != null ? session.getAuthData().name() : "?")
                + " xuid=" + session.xuid() + " path=" + SNIFF_PATH, null);

            var ds = session.getDownstream();
            if (ds == null || ds.getSession() == null) {
                sniff("!! downstream 尚未创建，无法挂监听器", null);
                return;
            }
            var javaSession = ds.getSession();
            sniff("downstream session = " + javaSession.getClass().getName(), null);
            try {
                var rs = session.remoteServer();
                sniff("诊断: forwardHostname=" + geyser.config().java().forwardHostname()
                    + " joinAddress=\"" + session.joinAddress() + "\""
                    + " remoteServer=" + (rs != null ? (rs.address() + ":" + rs.port() + " auth=" + rs.authType()) : "null")
                    + " clientData.ServerAddress=\"" + (session.getClientData() != null
                        ? session.getClientData().getServerAddress() : "null") + "\""
                    + " 强制地址=" + FORCED_SERVER_ADDRESS, null);
            } catch (Throwable t) {
                sniff("诊断信息读取失败: " + t, null);
            }

            javaSession.addListener(new org.geysermc.mcprotocollib.network.event.session.SessionAdapter() {
                @Override
                public void packetSending(
                        org.geysermc.mcprotocollib.network.event.session.PacketSendingEvent event) {
                    var p = event.getPacket();
                    // 兜底：handshake 的 hostname 为空会导致 Velocity 静默断流
                    if (p instanceof org.geysermc.mcprotocollib.protocol.packet.handshake.serverbound.ClientIntentionPacket ip
                            && (ip.getHostname() == null || ip.getHostname().isEmpty())) {
                        String host = handshakeHost();
                        event.setPacket(ip.withHostname(host));
                        sniff("!! 握手 hostname 为空 → 改写为 \"" + host + "\"", null);
                        p = event.getPacket();
                    }
                    sniff("出→ " + p.getClass().getSimpleName() + " " + brief(p), null);
                }

                @Override
                public void packetReceived(org.geysermc.mcprotocollib.network.Session s,
                                           org.geysermc.mcprotocollib.network.packet.Packet p) {
                    sniff("入← " + p.getClass().getSimpleName() + " " + brief(p), null);
                }

                @Override
                public void packetError(
                        org.geysermc.mcprotocollib.network.event.session.PacketErrorEvent event) {
                    sniff("!! 包错误: " + event.getCause() + " packet=" + event.getPacketClass(), null);
                }

                @Override
                public void connected(org.geysermc.mcprotocollib.network.event.session.ConnectedEvent event) {
                    sniff("== Java 通道建立（即将发送握手）==", null);
                }

                @Override
                public void disconnecting(
                        org.geysermc.mcprotocollib.network.event.session.DisconnectingEvent event) {
                    sniff("== 正在断开: reason=" + event.getReason() + " cause=" + event.getCause(), null);
                }

                @Override
                public void disconnected(
                        org.geysermc.mcprotocollib.network.event.session.DisconnectedEvent event) {
                    sniff("== 已断开: reason=" + event.getReason() + " cause=" + event.getCause(), null);
                }
            });
            sniff("已注册 Java 会话监听器（监听器数=" + javaSession.getListeners().size() + "）", null);
        } catch (Throwable e) {
            sniff("!! 嗅探器挂载失败: " + e, null);
        }
    }

    /** 只记录关键包的细节，避免日志爆炸。 */
    private static String brief(Object p) {
        String n = p.getClass().getSimpleName();
        boolean key = n.contains("Hello") || n.contains("Intention") || n.contains("Acknowledged")
            || n.contains("Disconnect") || n.contains("Finished") || n.contains("Compression")
            || n.contains("LoginSuccess") || n.contains("CustomQuery");
        if (!key) return "";
        String s = String.valueOf(p);
        return s.length() > 400 ? s.substring(0, 400) + "..." : s;
    }

    private static void sniff(String tag, byte[] raw) {
        String line = "[" + java.time.LocalTime.now().withNano(0) + "] " + tag
            + (raw != null ? " len=" + raw.length + " " + hex(raw) : "");
        java.io.PrintWriter out = SNIFF_OUT;
        if (out != null) {
            out.println(line);
        } else {
            NeteaseExtension.LOG.info("[GeyserNetease][JavaSniff] " + line);
        }
        if (SNIFF_CONSOLE.incrementAndGet() <= 120) {
            NeteaseExtension.LOG.info("[GeyserNetease][JavaSniff] " + line);
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xf, 16));
            sb.append(Character.forDigit(x & 0xf, 16));
        }
        return sb.toString();
    }

    private static BedrockClientData buildFakeClientData(String name) {
        return GeyserImpl.GSON.fromJson(
            "{\"GameVersion\":\"1.21.40\",\"LanguageCode\":\"en_us\",\"DeviceOS\":1," +
            "\"DeviceModel\":\"NetEase\",\"ThirdPartyName\":\"" + name + "\"," +
            "\"SkinId\":\"\",\"SkinData\":\"\",\"SkinImageWidth\":64,\"SkinImageHeight\":64," +
            "\"CapeId\":\"\",\"CapeData\":\"\",\"CapeImageWidth\":64,\"CapeImageHeight\":32," +
            "\"SkinGeometryData\":\"\",\"SkinResourcePatch\":\"\"," +
            "\"SkinGeometryDataEngineVersion\":\"\",\"PlayFabId\":\"\"," +
            "\"PersonaSkin\":false,\"PremiumSkin\":false,\"IsEditorMode\":false," +
            "\"SkinColor\":\"#0\",\"ArmSize\":\"wide\",\"PersonaPieces\":[],\"PieceTintColors\":[]}",
            BedrockClientData.class);
    }

    private static UUID toStableUUID(String rawIdentity, long neteaseUid) {
        if (rawIdentity != null && !rawIdentity.isEmpty()) {
            String hex = rawIdentity.replace("-", "");
            if (hex.length() == 32) {
                try {
                    return UUID.fromString(
                        hex.substring(0, 8) + "-" + hex.substring(8, 12) + "-" + hex.substring(12, 16) + "-"
                        + hex.substring(16, 20) + "-" + hex.substring(20));
                } catch (IllegalArgumentException ignored) {}
            }
        }
        String seed = "netease:player:" + neteaseUid;
        return UUID.nameUUIDFromBytes(seed.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
