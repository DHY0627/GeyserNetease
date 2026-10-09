/*
 * Copyright (c) 2026 EiluDick/ZDarkZ
 * Released under the MIT License.
 */

package nc.geyserext.netease;

import nc.geyserext.netease.config.*;
import nc.geyserext.netease.util.*;
import org.geysermc.event.subscribe.Subscribe;
import org.geysermc.geyser.api.event.lifecycle.GeyserPostInitializeEvent;
import org.geysermc.geyser.api.extension.*;

public class NeteaseExtension implements Extension {

    /** 构建标识：用于在服务器日志中确认运行的是哪个版本。 */
    public static final String BUILD_TAG = "geyser2.11.3-hostnamefix-20261006";

    /** 诊断日志开关：-DGeyserNetease.Debug=true 打开（默认关闭）。 */
    public static final boolean DEBUG =
        Boolean.parseBoolean(System.getProperty("GeyserNetease.Debug", "false"));

    public static ExtensionLogger LOG;
    public static NeteaseConfig CONFIG;

    /** 诊断日志：仅在 DEBUG 打开时输出。 */
    public static void debug(String message) {
        if (DEBUG && LOG != null) LOG.info(message);
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
    }
}
