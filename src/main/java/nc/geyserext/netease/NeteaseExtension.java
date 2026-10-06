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

    public static ExtensionLogger LOG;
    public static NeteaseConfig CONFIG;

    @Subscribe
    public void onPostInit(GeyserPostInitializeEvent event) {
        LOG = logger();
        LOG.info("NetEase Extension starting... [build " + BUILD_TAG + "]");

        CONFIG = NeteaseConfigLoader.load(this, NeteaseExtension.class);

        try {
            ServerRestartUtil.restart(CONFIG.onlyNeteaseClients());
            LOG.info("NetEase Extension initialized — RakNet v8 clients supported. [build " + BUILD_TAG + "]");
        } catch (Exception e) { LOG.error("Init failed", e); }
    }
}
