/*
 * Copyright (c) 2026 EiluDick/ZDarkZ
 * Released under the MIT License.
 */

package nc.geyserext.netease.session;

import nc.geyserext.netease.NeteaseExtension;
import nc.geyserext.netease.util.BlockHashUtils;
import org.cloudburstmc.nbt.NbtMap;
import org.cloudburstmc.protocol.bedrock.BedrockServerSession;
import org.cloudburstmc.protocol.bedrock.data.definitions.BlockDefinition;
import org.cloudburstmc.protocol.bedrock.data.skin.SerializedSkin;
import org.cloudburstmc.protocol.bedrock.packet.*;
import org.geysermc.geyser.registry.type.BlockMappings;
import org.geysermc.geyser.registry.type.GeyserBedrockBlock;
import org.geysermc.geyser.session.UpstreamSession;
import sun.misc.Unsafe;
import java.lang.reflect.Field;
import java.util.*;

public class SpoofedUpstream extends UpstreamSession {

    /** Geyser 扩展命令的根命令名；网易客户端会把命令补全渲染成 "geyser:xxx" 提示，需要从下发的命令表里剔除。 */
    private static final String GEYSER_COMMAND_ROOT = "geyser";

    /**
     * Geyser 用 TIP 类型的 TextPacket 向客户端"隐藏"地传 JSON UI 数据（<code>GeyserSession#sendJsonUIData</code>
     * 拼出 "geyseropt:cooldown:non"），依赖 Geyser 集成资源包里改过的 hud_screen.json 把它解析成冷却指示器。
     * 网易客户端不加载 / 不认这套 JSON UI 补丁，会把这串文本直接显示在屏幕上，因此在下发前丢弃。
     */
    private static final String GEYSER_UI_TEXT_PREFIX = "geyseropt:";

    private final UpstreamSession real;
    private final int[] rtToHash;
    private final boolean[] hValid;
    private final boolean hashing;
    private final long neteaseUid;
    private boolean skinConfirmed;

    public SpoofedUpstream(UpstreamSession real, BedrockServerSession s,
            int[] rt, boolean[] hv, boolean hashing, long neteaseUid) {
        super(s);
        this.real = real;
        this.rtToHash = rt;
        this.hValid = hv;
        this.hashing = hashing;
        this.neteaseUid = neteaseUid;
    }

    @Override public void disconnect(String r) { real.disconnect(r); }
    @Override public BedrockServerSession getSession() { return real.getSession(); }
    @Override public boolean isClosed() { return real.isClosed(); }

    @Override public void sendPacket(BedrockPacket p) {
        if (skipUnknownPacket(p)) return;
        if (dropGeyserUiText(p)) return;
        stripGeyserCommands(p);
        real.sendPacket(rewrite(p));
        hook(p, false);
    }

    @Override public void sendPacketImmediately(BedrockPacket p) {
        if (skipUnknownPacket(p)) return;
        if (dropGeyserUiText(p)) return;
        stripGeyserCommands(p);
        real.sendPacketImmediately(rewrite(p));
        hook(p, true);
    }

    /** 已警告过"当前 codec 不认识"的包类型，避免同类包把日志刷爆。 */
    private final Set<Class<?>> unknownPacketWarned = new HashSet<>();

    /**
     * 双保险：正常情况下 {@link #getProtocolVersion()} 直接取真实 codec 版本，Geyser 不会发当前
     * codec 里没有的包。但若将来 Geyser 换版本、或某个包没在网易 codec 中注册，
     * 编码阶段会抛 {@code NullPointerException: getPacketDefinition(...) is null} 并直接踢掉玩家
     * （表现为 "Exception caught in session of ..."，随后与 Java 服断开）。
     * 这类包不能硬发，只能跳过并记一条日志，保证玩家还能继续游玩。
     */
    private boolean skipUnknownPacket(BedrockPacket p) {
        BedrockServerSession s = real.getSession();
        if (s == null) return false;
        var codec = s.getCodec();
        if (codec == null || codec.getPacketDefinition(p.getClass()) != null) return false;
        if (unknownPacketWarned.add(p.getClass())) {
            NeteaseExtension.LOG.warning("[netease] 当前 codec(v" + codec.getProtocolVersion()
                + ") 未注册包 " + p.getClass().getSimpleName()
                + "，已跳过（Geyser 版本与本扩展的 bedrock-codec 版本可能不一致）");
        }
        NeteaseExtension.debug("[netease] 已跳过未注册包: " + p.getClass().getSimpleName());
        return true;
    }

    /**
     * 网易客户端不使用标准 Bedrock 的命令补全表：<code>AvailableCommandsPacket</code> 里由
     * Geyser 扩展导出的 <code>geyser</code> 根命令（help/list/quickactions 等）会在玩家点击屏幕时
     * 以 "geyser:xxx" 的形式弹在聊天栏下方。这里在下发前把该根命令剔除，Java 服务器的原生命令保持不变。
     */
    private static void stripGeyserCommands(BedrockPacket p) {
        if (p instanceof AvailableCommandsPacket available) {
            int before = available.getCommands().size();
            available.getCommands().removeIf(command -> GEYSER_COMMAND_ROOT.equals(command.getName()));
            int removed = before - available.getCommands().size();
            if (removed > 0) {
                NeteaseExtension.debug("[netease] 已从 AvailableCommandsPacket 移除 " + removed + " 个 geyser 命令，剩余 "
                    + available.getCommands().size() + " 个");
            }
        }
    }

    /**
     * 丢弃 Geyser 用来驱动 JSON UI 的 TIP 文本（如 <code>geyseropt:cooldown:non</code>）。
     * 网易客户端会把这些文本原样渲染出来（表现为屏幕下方出现 "geyser:cooldown:non" 之类的提示）。
     */
    private static boolean dropGeyserUiText(BedrockPacket p) {
        if (!(p instanceof TextPacket text)) return false;
        if (text.getType() != TextPacket.Type.TIP) return false;
        String message = text.getMessage();
        if (message == null || !message.startsWith(GEYSER_UI_TEXT_PREFIX)) return false;
        NeteaseExtension.debug("[netease] 已丢弃 JSON UI 文本: " + message);
        return true;
    }

    private BedrockPacket rewrite(BedrockPacket p) {
        if (!hashing) return p;
        if (p instanceof UpdateBlockPacket ub) ub.setDefinition(wrapDef(ub.getDefinition()));
        else if (p instanceof StartGamePacket sg) rewriteStartGame(sg);
        return p;
    }

    private void hook(BedrockPacket p, boolean immediate) {
        if (!hashing) return;
        // 注意：这里刻意不再在 StartGame 时发“空占位”ConfirmSkin。
        // ConfirmSkinSerializer 会对 uuid / skinBytes / geoStr 做 checkNotNull，
        // 早期实现只填了 valid + uidStr，编码阶段必然抛异常，导致网易客户端等不到确认。
        // 本地玩家皮肤由随后的 PlayerSkinPacket 分支补发。
        if (p instanceof StartGamePacket) {
            skinConfirmed = true;
        } else if (p instanceof PlayerSkinPacket ps && ps.getSkin() != null) {
            sendSkinCsp(ps.getUuid(), ps.getSkin(), immediate);
        } else if (p instanceof PlayerListPacket pl && pl.getAction() == PlayerListPacket.Action.ADD) {
            for (PlayerListPacket.Entry entry : pl.getEntries()) {
                if (entry.getSkin() != null) {
                    sendSkinCsp(entry.getUuid(), entry.getSkin(), immediate);
                }
            }
        }
    }

    private void sendSkinCsp(UUID uuid, SerializedSkin skin, boolean immediate) {
        if (uuid == null) return;

        byte[] image = null;
        String geo = null;
        try {
            if (skin.getSkinData() != null) {
                image = skin.getSkinData().getImage();
            }
            geo = skin.getGeometryData();
        } catch (Throwable ignored) {
            // 老版本 / 异常皮肤数据，按“无皮肤图”处理
        }

        ConfirmSkinPacket csp = new ConfirmSkinPacket();
        ConfirmSkinPacket.SkinEntry e = new ConfirmSkinPacket.SkinEntry();
        e.setUuid(uuid);
        e.setUidStr(String.valueOf(Math.abs(uuid.toString().replace("-", "").hashCode())));

        if (image != null && image.length > 0) {
            e.setValid(true);
            e.setSkinBytes(image);
            e.setGeoStr(geo != null ? geo : "");
            NeteaseExtension.debug("[netease] ConfirmSkin valid uuid=" + uuid
                + " image=" + image.length + " geo=" + (geo == null ? -1 : geo.length()));
        } else {
            // Persona / 4D 皮肤没有 64x64 皮肤图。ConfirmSkinSerializer 对 null 字段会抛异常
            // （writeByteArray / writeString 内部 checkNotNull），必须显式发 valid=false 的空条目，
            // 让对端回退到默认皮肤，而不是一直等待一个永远发不出去的确认包。
            e.setValid(false);
            e.setSkinBytes(new byte[0]);
            e.setGeoStr("");
            NeteaseExtension.debug("[netease] ConfirmSkin invalid(fallback) uuid=" + uuid);
        }

        csp.getEntries().add(e);
        if (immediate) real.sendPacketImmediately(csp); else real.sendPacket(csp);
    }

    private void rewriteStartGame(StartGamePacket sg) {
        sg.setBlockNetworkIdsHashed(true);
        sg.setBlockRegistryChecksum(0L);
        List<NbtMap> pal = sg.getBlockPalette();
        if (pal == null || pal.isEmpty()) return;
        TreeMap<Integer, NbtMap> sorted = new TreeMap<>();
        int idx = 0;
        for (NbtMap e : pal) {
            if (idx < hValid.length && hValid[idx]) sorted.put(rtToHash[idx], e);
            else if (idx < rtToHash.length) sorted.put(idx, e);
            idx++;
        }
        pal.clear();
        sorted.values().forEach(pal::add);
    }

    private BlockDefinition wrapDef(BlockDefinition def) {
        if (def == null) return null;
        int id = def.getRuntimeId();
        if (id >= 0 && id < hValid.length && hValid[id]) {
            int h = rtToHash[id];
            return new BlockDefinition() { public int getRuntimeId() { return h; } };
        }
        return def;
    }

    private static final Unsafe U;
    static {
        try {
            Field f = Unsafe.class.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            U = (Unsafe) f.get(null);
        } catch (Throwable e) { throw new ExceptionInInitializerError(e); }
    }

    public static boolean patchAll(BlockMappings orig) throws Throwable {
        boolean ok = patchOne(orig, "javaToBedrockBlocks");
        ok |= patchOne(orig, "bedrockRuntimeMap");
        ok |= patchOne(orig, "javaToVanillaBedrockBlocks");
        patchSingletonBlockDef(orig, "bedrockAir");
        patchSingletonBlockDef(orig, "bedrockWater");
        patchSingletonBlockDef(orig, "bedrockMovingBlock");
        return ok;
    }

    private static void patchSingletonBlockDef(BlockMappings orig, String fieldName) {
        try {
            Field f = BlockMappings.class.getDeclaredField(fieldName);
            long offset = U.objectFieldOffset(f);
            Object old = U.getObject(orig, offset);
            if (old instanceof GeyserBedrockBlock gb && gb.getState() != null) {
                U.putObject(orig, offset, new GeyserBedrockBlock(BlockHashUtils.fnv1a32Nbt(gb.getState()), gb.getState()));
            }
        } catch (Throwable ignored) {}
    }

    private static boolean patchOne(BlockMappings orig, String fieldName) {
        try {
            Field f = BlockMappings.class.getDeclaredField(fieldName);
            long offset = U.objectFieldOffset(f);
            GeyserBedrockBlock[] old = (GeyserBedrockBlock[]) U.getObject(orig, offset);
            if (old == null) return false;
            GeyserBedrockBlock[] rep = new GeyserBedrockBlock[old.length];
            for (int i = 0; i < old.length; i++) {
                GeyserBedrockBlock b = old[i];
                rep[i] = (b != null && b.getState() != null)
                    ? new GeyserBedrockBlock(BlockHashUtils.fnv1a32Nbt(b.getState()), b.getState())
                    : b;
            }
            U.putObject(orig, offset, rep);
            return true;
        } catch (Throwable e) { return false; }
    }

    public static BlockMappings cloneBlockMappings(BlockMappings orig) throws Throwable {
        BlockMappings copy = (BlockMappings) U.allocateInstance(BlockMappings.class);
        for (Field f : BlockMappings.class.getDeclaredFields()) {
            long off = U.objectFieldOffset(f);
            U.putObject(copy, off, U.getObject(orig, off));
        }
        for (String name : new String[]{"javaToBedrockBlocks", "bedrockRuntimeMap", "javaToVanillaBedrockBlocks"}) {
            Field f = BlockMappings.class.getDeclaredField(name);
            long off = U.objectFieldOffset(f);
            Object[] arr = (Object[]) U.getObject(orig, off);
            if (arr != null) U.putObject(copy, off, arr.clone());
        }
        return copy;
    }
}
