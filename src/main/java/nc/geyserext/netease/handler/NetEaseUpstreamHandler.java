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
import org.geysermc.geyser.network.GameProtocol;
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
     * 网易局域网客户端的客户端数据里 ServerAddress 常为 ":0" 或含 '|' 的非法值
     * （形如 "host|port"）。GeyserSession.joinAddress() 会原样取用，
     * forward-hostname=true 时 java 握手就带着这个非法 hostname 发给 Velocity，
     * Velocity 在登录阶段直接静默掐断连接（前线处理器不打日志）。
     */
    private static final String FORCED_SERVER_ADDRESS =
        System.getProperty("GeyserNetease.ServerAddress", "example.com:19132");

    private static void patchServerAddress(BedrockClientData bcd) {
        if (bcd == null) return;
        try {
            String cur = bcd.getServerAddress();
            NeteaseExtension.LOG.info("[GeyserNetease] 客户端 ServerAddress=" + (cur == null ? "null" : "\"" + cur + "\""));
            if (cur != null && !cur.isEmpty() && !cur.startsWith(":") && !cur.contains("|")) return;
            boolean ok = false;
            try {
                java.lang.reflect.Method m = BedrockClientData.class.getDeclaredMethod("setServerAddress", String.class);
                m.setAccessible(true); m.invoke(bcd, FORCED_SERVER_ADDRESS); ok = true;
            } catch (Throwable ignored) {}
            if (!ok) {
                java.lang.reflect.Field fl = BedrockClientData.class.getDeclaredField("serverAddress");
                fl.setAccessible(true); fl.set(bcd, FORCED_SERVER_ADDRESS);
            }
            NeteaseExtension.LOG.info("[GeyserNetease] 已修正 ServerAddress -> \"" + FORCED_SERVER_ADDRESS + "\"（java 握手 hostname 依赖它）");
        } catch (Throwable e) {
            NeteaseExtension.LOG.error("[GeyserNetease] 修正 ServerAddress 失败: " + e);
        }
    }

    private NeteaseSession neteaseSession;
    public NetEaseUpstreamHandler(GeyserImpl geyser, GeyserSession session) {
        super(geyser, session);
    }

    @Override
    public PacketSignal handle(RequestNetworkSettingsPacket packet) {
        Integer rakVer = getRakVersion();
        boolean isNetEase = rakVer != null && rakVer == 8;
        if (!isNetEase) return super.handle(packet);

        BedrockCodec codec = NeteaseCodecRegistry.getCodec(packet.getProtocolVersion());
        if (codec == null) return super.handle(packet);

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

                neteaseSession.setLoginDeferred(false);
                NeteaseExtension.LOG.info("[GeyserNetease] 已跳过 ServerToClientHandshake（网易客户端收到该包会静默忽略并超时）");
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
        try {
            for (int i = 0; i <= maxId; i++) {
                var block = blockMappings.getDefinition(i);
                if (block instanceof org.geysermc.geyser.registry.type.GeyserBedrockBlock) {
                    var gb = (org.geysermc.geyser.registry.type.GeyserBedrockBlock) block;
                    if (gb.getState() != null) {
                        rtToHash[i] = nc.geyserext.netease.util.BlockHashUtils.fnv1a32Nbt(gb.getState());
                        hValid[i] = true;
                    }
                }
            }
        } catch (Throwable t) {
            // 单个方块定义异常不应影响整局游戏，保留已构建的部分哈希表。
            NeteaseExtension.LOG.error("Block hash table build failed", t);
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
        PlayStatusPacket ps = new PlayStatusPacket();
        ps.setStatus(PlayStatusPacket.Status.LOGIN_SUCCESS);
        session.sendUpstreamPacket(ps);

        ResourcePacksInfoPacket rpi = new ResourcePacksInfoPacket();
        rpi.getResourcePackInfos().addAll(this.resourcePackLoadEvent.infoPacketEntries());
        rpi.setVibrantVisualsForceDisabled(!session.isAllowVibrantVisuals());
        rpi.setForcedToAccept(geyser.config().gameplay().forceResourcePacks() || resourcePackLoadEvent.isIntegratedPackActive());
        rpi.setWorldTemplateId(java.util.UUID.randomUUID());
        rpi.setWorldTemplateVersion("*");
        session.sendUpstreamPacket(rpi);
        NeteaseExtension.LOG.info("[GeyserNetease] 已下发 PlayStatus(LOGIN_SUCCESS) + ResourcePacksInfo");

        if (SNIFF_ENABLED) startJavaSniffer();
        GeyserLocale.loadGeyserLocale(session.locale());
        return PacketSignal.HANDLED;
    }

    @Override
    public PacketSignal handle(PlayerAuthInputPacket packet) {
        return defaultHandler(packet);
    }

    @Override
    public PacketSignal handle(ClientToServerHandshakePacket packet) {
        if (neteaseSession != null && neteaseSession.loginDeferred()) {
            neteaseSession.setLoginDeferred(false);
            PlayStatusPacket ps = new PlayStatusPacket();
            ps.setStatus(PlayStatusPacket.Status.LOGIN_SUCCESS);
            session.sendUpstreamPacket(ps);
            if (this.resourcePackLoadEvent == null) {
                this.resourcePackLoadEvent = new org.geysermc.geyser.event.type.SessionLoadResourcePacksEventImpl(session);
                this.geyser.eventBus().fireEventElseKick(this.resourcePackLoadEvent, session);
            }
            if (session.isClosed()) return PacketSignal.HANDLED;
            session.integratedPackActive(resourcePackLoadEvent.isIntegratedPackActive());
            ResourcePacksInfoPacket rpi = new ResourcePacksInfoPacket();
            rpi.getResourcePackInfos().addAll(this.resourcePackLoadEvent.infoPacketEntries());
            rpi.setVibrantVisualsForceDisabled(!session.isAllowVibrantVisuals());
            rpi.setForcedToAccept(geyser.config().gameplay().forceResourcePacks() || resourcePackLoadEvent.isIntegratedPackActive());
            rpi.setWorldTemplateId(java.util.UUID.randomUUID()); rpi.setWorldTemplateVersion("*");
            session.sendUpstreamPacket(rpi);
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
                    session.authenticate(session.getAuthData().name());
                } else if (!couldLoginUserByName(session.getAuthData().name())) {
                    session.connect();
                }
                neteaseSession.setAuthenticated(true);
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
            // source / toItem 都由客户端数据构造，畸形包可能为 null，先判空再取字段。
            InventorySource source0 = action0.getSource();
            InventorySource source1 = action1.getSource();
            if (source0 == null || source1 == null) return defaultHandler(packet);
            InventoryActionData worldAction = source0.getType() == InventorySource.Type.WORLD_INTERACTION ? action0 : action1;
            InventoryActionData containerAction = (worldAction == action0) ? action1 : action0;
            if (worldAction.getSource().getType() != InventorySource.Type.WORLD_INTERACTION
                    || containerAction.getSource().getType() != InventorySource.Type.CONTAINER)
                return defaultHandler(packet);

            if (worldAction.getToItem() == null) return defaultHandler(packet);
            boolean dropAll = worldAction.getToItem().getCount() > 1;
            var inventory = session.getPlayerInventory();
            if (inventory == null || inventory.getItemInHand() == null || inventory.getItemInHand().isEmpty())
                return PacketSignal.HANDLED;

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

    // ==================== Java 侧嗅探（诊断用，-DGeyserNetease.Sniff=true 开启）====================
    private static final boolean SNIFF_ENABLED =
        Boolean.parseBoolean(System.getProperty("GeyserNetease.Sniff", "false"));
    private static volatile java.io.PrintWriter SNIFF_OUT;
    private static final java.util.concurrent.atomic.AtomicInteger SNIFF_TRIES =
        new java.util.concurrent.atomic.AtomicInteger();
    private static final java.util.concurrent.atomic.AtomicInteger SNIFF_CONSOLE =
        new java.util.concurrent.atomic.AtomicInteger();

    /** 反射取值，成员不存在/抛错都只返回标记，绝不影响主流程。 */
    private static String refl(Object target, String method) {
        try { return String.valueOf(target.getClass().getMethod(method).invoke(target)); }
        catch (Throwable e) { return "<" + e.getClass().getSimpleName() + ">"; }
    }

    private void startJavaSniffer() {
        if (!SNIFF_ENABLED) return;
        NeteaseExtension.LOG.info("[GeyserNetease][JSniff] 诊断: forwardHostname=" + refl(geyser.config().java(), "forwardHostname")
            + " joinAddress=" + refl(session, "joinAddress")
            + " remoteServer=" + refl(session, "remoteServer")
            + " clientData.ServerAddress=" + refl(session.getClientData(), "getServerAddress")
            + " 强制地址=" + FORCED_SERVER_ADDRESS);
        session.scheduleInEventLoop(this::attachJavaSniffer, 20, java.util.concurrent.TimeUnit.MILLISECONDS);
    }

    private void attachJavaSniffer() {
        if (!SNIFF_ENABLED) return;
        try {
            if (session.getDownstream() == null || session.getDownstream().getSession() == null) {
                if (SNIFF_TRIES.incrementAndGet() < 300) {
                    session.scheduleInEventLoop(this::attachJavaSniffer, 20, java.util.concurrent.TimeUnit.MILLISECONDS);
                } else {
                    NeteaseExtension.LOG.info("[GeyserNetease][JSniff] downstream 始终未创建，放弃");
                }
                return;
            }
            try {
                java.io.File ff = new java.io.File("geyser-netease-java.log");
                SNIFF_OUT = new java.io.PrintWriter(new java.io.FileWriter(ff, true), true);
                sniff("===== 嗅探启动 path=" + ff.getAbsolutePath(), null);
            } catch (Throwable ignored) {}

            var javaSession = session.getDownstream().getSession();
            sniff("downstream=" + javaSession.getClass().getName()
                + " forwardHostname=" + refl(geyser.config().java(), "forwardHostname")
                + " joinAddress=" + refl(session, "joinAddress")
                + " clientData.ServerAddress=" + refl(session.getClientData(), "getServerAddress"), null);

            javaSession.addListener(new org.geysermc.mcprotocollib.network.event.session.SessionAdapter() {
                @Override
                public void connected(org.geysermc.mcprotocollib.network.event.session.ConnectedEvent event) {
                    sniff("== Java 通道建立 ==", null);
                }

                @Override
                public void packetSending(org.geysermc.mcprotocollib.network.event.session.PacketSendingEvent event) {
                    Object p = event.getPacket();
                    String n = p.getClass().getSimpleName();
                    boolean key = n.contains("Intention") || n.contains("Hello") || n.contains("LoginSuccess")
                        || n.contains("Disconnect") || n.contains("Finished") || n.contains("Compression")
                        || n.contains("Acknowledged") || n.contains("CustomQuery");
                    sniff("出-> " + n + (key ? " " + p : ""), null);
                }

                @Override
                public void packetReceived(org.geysermc.mcprotocollib.network.Session s,
                                           org.geysermc.mcprotocollib.network.packet.Packet p) {
                    sniff("入<- " + p.getClass().getSimpleName() + " " + p, null);
                }

                @Override
                public void packetError(org.geysermc.mcprotocollib.network.event.session.PacketErrorEvent event) {
                    sniff("!! 包错误: " + event.getCause() + " packet=" + event.getPacketClass(), null);
                }

                @Override
                public void disconnecting(org.geysermc.mcprotocollib.network.event.session.DisconnectingEvent event) {
                    sniff("== 正在断开: reason=" + event.getReason() + " cause=" + event.getCause(), null);
                }

                @Override
                public void disconnected(org.geysermc.mcprotocollib.network.event.session.DisconnectedEvent event) {
                    sniff("== 已断开: reason=" + event.getReason() + " cause=" + event.getCause(), null);
                }
            });
            sniff("已挂载 Java 会话监听器（监听器数=" + javaSession.getListeners().size() + "）", null);
        } catch (Throwable e) {
            NeteaseExtension.LOG.error("[GeyserNetease][JSniff] 嗅探器挂载失败", e);
        }
    }

    private static void sniff(String tag, byte[] raw) {
        String line = "[" + java.time.LocalTime.now().withNano(0) + "] " + tag;
        java.io.PrintWriter out = SNIFF_OUT;
        if (out != null) out.println(line);
        if (SNIFF_CONSOLE.incrementAndGet() <= 150) {
            NeteaseExtension.LOG.info("[GeyserNetease][JSniff] " + line);
        }
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
