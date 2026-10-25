/*
 * Copyright (c) 2026 EiluDick/ZDarkZ
 * Released under the MIT License.
 */

package nc.geyserext.netease;

import nc.geyserext.netease.config.*;
import nc.geyserext.netease.log.ZLogUploader;
import nc.geyserext.netease.util.*;
import org.geysermc.event.subscribe.Subscribe;
import org.geysermc.geyser.api.event.lifecycle.GeyserPostInitializeEvent;
import org.geysermc.geyser.api.event.lifecycle.GeyserShutdownEvent;
import org.geysermc.geyser.api.extension.*;

public class NeteaseExtension implements Extension {

    /** 构建标识：用于在服务器日志中确认运行的是哪个版本。 */
    public static final String BUILD_TAG = "geyser2.9.4-zlog-20261025";

    /** 诊断日志开关：-DGeyserNetease.Debug=true 打开（默认关闭）。 */
    public static final boolean DEBUG =
        Boolean.parseBoolean(System.getProperty("GeyserNetease.Debug", "false"));

    public static ExtensionLogger LOG;
    public static NeteaseConfig CONFIG;

    /** 诊断日志：仅在 DEBUG 打开时输出。 */
    public static void debug(String message) {
        if (DEBUG && LOG != null) LOG.info(message);
        // 调试日志上传只采集 debug 输出，作为拿不到 Geyser 日志文件时的兜底
        ZLogUploader.tap(message);
    }

    /** debug 是否生效：系统属性 -DGeyserNetease.Debug=true 或配置文件 debug-mode: true。 */
    public static boolean debugEnabled() {
        return DEBUG || (CONFIG != null && CONFIG.debugMode());
    }

    @Subscribe
    public void onPostInit(GeyserPostInitializeEvent event) {
        LOG = logger();
        if (DEBUG) LOG.info("NetEase Extension build: " + BUILD_TAG);
        LOG.info("NetEase Extension starting...");

        CONFIG = NeteaseConfigLoader.load(this, NeteaseExtension.class);

        try {
            ServerRestartUtil.restart(CONFIG.onlyNeteaseClients());
            LOG.info("NetEase Extension initialized — RakNet v8 clients supported.");
        } catch (Exception e) { LOG.error("Init failed", e); }

        // 调试日志上传：只有 debug 打开时才启用，结束后自动加密上传
        if (debugEnabled()) {
            ZLogUploader.init();
        }
    }

    /**
     * Geyser 正常关闭时上传本次日志。
     * 之所以不注册 JVM shutdown hook：Velocity 关服时 hook 会先于本事件执行，
     * 那一刻扩展的 ClassLoader 已不可用，ML-KEM 相关类首次加载会抛 NoClassDefFoundError。
     */
    @Subscribe
    public void onShutdown(GeyserShutdownEvent event) {
        if (debugEnabled()) {
            ZLogUploader.shutdown();
        }
    }
}
