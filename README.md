# GeyserNetease 扩展

让 **网易版 Minecraft（中国版基岩版）** 玩家连接到使用 Geyser 的服务器。

简单来说：如果你有一个 Java 版服务器并用 Geyser 让基岩版玩家进来玩，装上这个扩展之后，**网易版玩家也能进来**。

支持同时在线：

- ✅ Java 版玩家
- ✅ 国际版基岩版玩家
- ✅ **网易版基岩版玩家**（本扩展）

> 作者：EiluDick / ZDarkZ · 本仓库额外做了 **Geyser 2.11.3 / 协议 860 适配** 与 **Java 握手 hostname 修复**（见「已知问题」）

---

## 为什么需要它

网易版虽然也是基岩版，但与国际版有几处关键差异，默认 Geyser 接不了：

| 差异 | 扩展的处理 |
|---|---|
| RakNet 协议版本不同（网易 = **8**） | 重绑 Geyser 的 RakNet 监听（`ServerRestartUtil` + `NeteaseServerInitializer`），识别 `rakVer=8` 走网易链路 |
| 协议版本自定义（630 / 686 / 766 / 819 / 860 …） | 自带 `NeteaseCodecRegistry`，按客户端上报的协议版本选择 codec |
| **不做 Bedrock 层加密** | 网易局域网数据通道本身由 DTLS 加密，客户端收到 `ServerToClientHandshake` 会静默忽略，因此跳过握手直接进入资源包阶段 |
| 方块哈希与官方不同 | `SpoofedUpstream` 重写方块运行时 ID、StartGame 调色板、`ConfirmSkin` |
| 客户端数据里 `ServerAddress` 为 `":0"` | **修正为真实地址**，否则 Geyser 会带空 hostname 连代理并被静默掐断（见「已知问题 1」） |

---

## 前置要求

1. 已安装 **Geyser**（本扩展不能单独运行），扩展 API **2.9.10+**；本仓库构建目标为 **Geyser core 2.11.3-SNAPSHOT**（bedrock-codec 3.0.0.Beta13）
2. **Java 21**
3. 平台：Geyser 各平台均可（Standalone / Velocity / BungeeCord / Spigot / Fabric / NeoForge）

---

## 构建

```bash
# Windows
gradlew.bat shadowJar

# Linux / macOS
./gradlew shadowJar
```

产物：`build/libs/GeyserNeteaseExtension.jar`

> 若 gradle wrapper 下载失败（企业网络 / 证书问题），可直接用本机 Gradle 构建：
> `gradle shadowJar --offline`

## 安装

1. 把 jar 放进 Geyser 的**扩展目录**（不是 `plugins/` 根目录）：

   | 平台 | 路径 |
   |---|---|
   | Standalone | `extensions/GeyserNeteaseExtension.jar` |
   | Velocity | `plugins/Geyser-Velocity/extensions/GeyserNeteaseExtension.jar` |
   | BungeeCord | `plugins/Geyser-BungeeCord/extensions/GeyserNeteaseExtension.jar` |
   | Spigot / Paper | `plugins/Geyser-Spigot/extensions/GeyserNeteaseExtension.jar` |

2. 文件名必须是 `GeyserNeteaseExtension.jar`（与 `extension.yml` 的 id 对应）
3. 重启服务器，日志出现下面两行即加载成功：

   ```
   [geyser-netease] NetEase Extension starting... [build geyser2.11.3-...]
   [geyser-netease] NetEase Extension initialized — RakNet v8 clients supported.
   ```

> 不想自己编译？直接使用仓库里随源码提交的 **`dist/GeyserNeteaseExtension.jar`**（本版本构建，含下文「已知问题 1」的 hostname 修复）。

## 配置

首次启动会在扩展目录生成 `config.yml`：

```yaml
# true = 只允许网易客户端（RakNet 协议版本 8），国际版基岩版会被拒绝
only-netease-clients: false

# only-netease-clients: true 时给国际版玩家显示的踢出消息
disconnect-message: "This server only accepts NetEase clients."

# 详细日志（网易认证与包处理），排查连接问题时打开
debug-mode: false
```

### 可选 JVM 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-DGeyserNetease.SkipEncryption` | `true` | 跳过 Bedrock 层加密握手（网易局域网流程本就不加密）；设 `false` 可强制走 `ServerToClientHandshake` |
| `-DGeyserNetease.ServerAddress` | `example.com:49780` | 修正网易客户端 `ServerAddress`（`:0`）用的真实地址，**请换成你自己的域名:端口** |
| `-DGeyserNetease.AsciiJavaName` | `false` | `true` 时 java 侧使用纯 ASCII 登录名（`NE+uid`），Bedrock 侧显示名不变 |
| `-DGeyserNetease.Sniff` | `false` | `true` 时把 Geyser ↔ 代理 的双向包写入运行目录的 `geyser-netease-java.log`（排错用） |

---

## 已知问题 / 排错

### 1. 客户端显示「数据流终止」；Geyser 日志只有「已因 §r数据流终止 与 Java 服务器断开了连接」；**代理（Velocity）一行日志都没有**

**原因**：网易客户端上报的客户端数据里 `"ServerAddress":":0"`，而 Geyser 的 `joinAddress()` 是把它按最后一个 `:` 截断：

```java
String combined = clientData.getServerAddress();   // ":0"
int index = combined.lastIndexOf(":");
return combined.substring(0, index);               // → ""
```

当 Geyser 配置了 `forward-hostname: true` 时，java 握手就会带上**空 hostname**。Velocity 在登录阶段遇到这种情况会**静默关闭连接**：
`MinecraftConnection.exceptionCaught` 对 `InitialLoginSessionHandler` / `HandshakeSessionHandler` 这类 frontline handler 不打任何日志，直接 `ctx.close()`；
而解码失败抛出的是 `QuietRuntimeException`。日志里的 `数据流终止` 其实是 Geyser 的 Java 协议库在通道关闭时合成的原版提示
（`Component.translatable("disconnect.endOfStream")`），**不是代理发的**。

**修复**：本版本在设置客户端数据时把 `ServerAddress` 修正为真实地址，并额外做了一次握手 hostname 兜底改写。修复后的嗅探日志：

```
出→ ClientIntentionPacket(protocolVersion=776, hostname=example.com, port=25565, intent=LOGIN)
出→ ServerboundHelloPacket(username=..., profileId=...)
入← ClientboundLoginFinishedPacket(profile=GameProfile{...})
入← ClientboundLoginPacket
入← ClientboundLevelChunkWithLightPacket × 377      ← 世界数据正常下发
```

记得把 `-DGeyserNetease.ServerAddress` 设成你自己的域名与端口。

### 2. 网易客户端连上了，但一个字节都不发，最后超时

这是**房主网关**侧的问题（NetherNet 数据通道丢首包），与本扩展无关，详见
[NeteaseBedrockGateway/docs/troubleshooting.md](../NeteaseBedrockGateway/docs/troubleshooting.md)。

### 3. 国际版玩家进不来

检查 `only-netease-clients` 是否为 `true`。

### 4. 扩展没有加载

- 确认 jar 放在**扩展目录**而不是 `plugins/` 根目录（放错会报 `Did not find a valid velocity-plugin.json`）
- 确认文件名是 `GeyserNeteaseExtension.jar`
- 确认 Geyser 版本满足扩展 API 要求（2.9.10+；本版本针对 2.11.3 构建）

---

## 仓库结构

```
GeyserNetease/
├── src/main/java/nc/geyserext/netease/
│   ├── NeteaseExtension.java                       扩展入口
│   ├── initializer/NeteaseServerInitializer.java   网易链路 pipeline（codec v3 + 不压缩）
│   ├── util/ServerRestartUtil.java                 重绑 Geyser 的 RakNet 监听
│   ├── util/protocol/NeteaseCodecRegistry.java     网易各协议版本 codec
│   ├── handler/NetEaseUpstreamHandler.java         网易登录流程（跳过加密 / 修 ServerAddress / 嗅探）
│   ├── session/SpoofedUpstream.java                方块哈希与 StartGame 伪装
│   └── config/                                     扩展配置
├── src/main/resources/{extension.yml,config.yml}
├── dist/
│   └── GeyserNeteaseExtension.jar                  ★ 随源码提交的构建产物，可直接安装
├── index.html / CNAME                              项目主页（GitHub Pages）
├── .gitignore / .gitattributes                     构建产物与换行符规则
└── build.gradle.kts / settings.gradle.kts / gradlew*
```

> 诊断版（逐包嗅探）不随仓库提交：自行 `gradlew shadowJar` 构建后，启动时加 `-DGeyserNetease.Sniff=true` 即可，日志写到运行目录的 `geyser-netease-java.log`。

## 常见问题

**Q：装了这个会影响国际版玩家吗？**
A：不会。默认配置下国际版与网易版都能正常游玩，互不影响。

**Q：网易玩家进来后能玩所有内容吗？**
A：大部分内容正常。网易版特有内容（部分皮肤、商城物品等）可能无法完全兼容。

**Q：这个扩展是官方的吗？**
A：不是，这是社区开发者制作的第三方扩展。

**Q：为什么要修正 `ServerAddress`？**
A：见「已知问题 1」——不修就会在 `Geyser → 代理` 这一跳被静默掐断。

---

## 配套项目

- [NeteaseBedrockGateway](../NeteaseBedrockGateway)：网易「本地联机」程序房主网关（4399 登录 → 开房 → 把玩家流量转到本扩展所在的 Geyser）
- [GeyserMC/Geyser](https://github.com/GeyserMC/Geyser)

## 许可

MIT（见 [LICENSE](LICENSE)）。作者：EiluDick / ZDarkZ。
