# GeyserNetease 扩展 1.1.0（2026-10-10 构建）

让**网易版 Minecraft（中国版）原版客户端**通过「本地联机」输入房间号，直接进你的 Geyser / 基岩版服务器。
玩家侧**不需要 mod、不需要改包、不需要装插件** —— 房间由配套网关
[NeteaseBedrockGateway](https://github.com/DHY0627/NeteaseBedrockGateway) 程序化创建。

## 这次修了什么

两个坑的症状一样（客户端进房后卡住不进服），原因完全不同：

1. **`ServerAddress` 是 `":0"`** —— 网易局域网客户端上报的客户端数据里该字段就是 `":0"`。
   Geyser 的 `joinAddress()` 按「最后一个 `:` 之前」截断会得到**空字符串**，配合 `forward-hostname: true`，
   Java 握手就带着空 hostname 发给代理，代理在登录阶段**静默关闭连接**（一条日志都不打）。
   现象：客户端显示「数据流终止」，Geyser 侧是「已连接到 Java 服务器」后立刻「数据流终止」。
   → 现在在设置客户端数据时把它修正为真实地址。

2. **加密握手会让网易客户端超时** —— 网易客户端收到 `ServerToClientHandshake` 后**静默忽略**，
   永远不回 `ClientToServerHandshake`；而上游代码发完该包就 `loginDeferred = true` 死等，
   于是卡住约 30 秒后超时断开。→ 现在默认跳过这个握手（`-DGeyserNetease.SkipEncryption=false` 可恢复原行为）。

另外：逐连接诊断日志**默认静默**，排查时用 `-DGeyserNetease.Debug=true` 打开。

## 用法

1. 把 `GeyserNeteaseExtension.jar` 放进 Geyser 的 **`extensions/`** 子目录（不是 `plugins/` 根目录）：

   | 平台 | 路径 |
   |---|---|
   | Standalone | `extensions/` |
   | Velocity | `plugins/Geyser-Velocity/extensions/` |
   | BungeeCord | `plugins/Geyser-BungeeCord/extensions/` |
   | Spigot / Paper | `plugins/Geyser-Spigot/extensions/` |

2. **必须**用你自己的地址覆盖默认值（jar 里是脱敏示例 `example.com:19132`，不能直接用）：

   ```
   java -DGeyserNetease.ServerAddress=你的域名:19132 -jar geyser.jar
   ```

3. 启动网关（`-target` 指向 Geyser 的 RakNet 端口），玩家在网易客户端「本地联机」输入网关打印的房间号即可进服。

## 实测过的版本

| Geyser | 代理 | 结果 |
|---|---|---|
| **2.10.1-b1174** | Velocity 3.5.1 | ✅ **完整验证**：网易原版客户端一路进服、正常游玩（后端日志 `logged in with entity id …` / `joined the game`） |
| 2.11.3 | Velocity 4.2.1 | 本 jar 的构建目标；客户端能进世界，但当时出现过 `StartGame` 之后客户端原生崩溃（`libminecraftpe.so` SIGSEGV），该崩溃未在 2.10.1 上复现 |
| 2.9.4 | — | 扩展可加载（需把 `extension.yml` 的 `api:` 下调到 `2.9.4`），未走完进服流程 |
| 其它 2.9.x / 2.10.0 | — | 未实测 |

> ⚠️ 本 jar 按 **Geyser 2.11.3 / Java 21** 构建，`api: 2.9.10`。**Geyser 2.9.x / 2.10.x 用不了这个 jar**
> —— fork 的接线层依赖 2.11 才有的 `network.bedrock.raknet.*` 类。
> 这些版本请改用 [NeteaseBedrockGateway/patches](https://github.com/DHY0627/NeteaseBedrockGateway/tree/main/patches)
> 里的兼容补丁：打在[上游 LoHJG/GeyserNetease](https://github.com/LoHJG/GeyserNetease) 上再构建，
> 协议行为与本版本一致（就是上面那两个修复）。

## 下载

| 文件 | 大小 | SHA256 |
|---|---|---|
| `GeyserNeteaseExtension.jar` | 3,118,577 字节 | `14712E9C77765FC453017EDF3D97847A0F34D41FEC7CF8A0109E4A21BE1E08BC` |

## 可选 JVM 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-DGeyserNetease.ServerAddress` | `example.com:19132` | ⚠️ **必须覆盖**，修正 `ServerAddress` 用的真实地址 |
| `-DGeyserNetease.SkipEncryption` | `true` | 跳过 Bedrock 层加密握手 |
| `-DGeyserNetease.Debug` | `false` | 逐连接诊断日志（网易路径 / 跳过加密 / `ServerAddress` 修正等） |
| `-DGeyserNetease.Sniff` | `false` | 逐包嗅探，写入运行目录 `geyser-netease-java.log` |
| `-DGeyserNetease.AsciiJavaName` | `false` | java 侧改用纯 ASCII 登录名（`NE+uid`），Bedrock 显示名不变 |

许可证：MIT（基于 [LoHJG/GeyserNetease](https://github.com/LoHJG/GeyserNetease) 修改）
