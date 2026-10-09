# GeyserNetease 扩展 1.1.0（2026-10-10 构建）

让网易版 Minecraft（中国版）**原版客户端**通过「本地联机」房间号直接进你的 Geyser 服务器 ——
玩家侧不需要 mod / 改包 / 插件。房间由配套网关 [NeteaseBedrockGateway](https://github.com/DHY0627/NeteaseBedrockGateway) 程序化创建。

## 更新日志

- 修正网易局域网客户端上报的 `ServerAddress`（`:0`）：否则 Java 握手 hostname 为空，会被代理静默掐断
- 默认跳过 Bedrock 层加密握手：网易客户端收到 `ServerToClientHandshake` 会静默忽略并超时
- 诊断日志默认静默（`-DGeyserNetease.Debug=true` 开启）

## 实测过的版本

| Geyser | 代理 | 结果 |
|---|---|---|
| 2.10.1-b1174 | Velocity 3.5.1 | 网易原版客户端一路进服、正常游玩 |

> 本 jar 按 Geyser **2.11.3 / Java 21** 构建；上表 2.10.1-b1174 用的是
> [兼容补丁](https://github.com/DHY0627/NeteaseBedrockGateway/tree/main/patches)构建的扩展，协议行为一致。
> 安装位置、**必须设置**的 `-DGeyserNetease.ServerAddress` 及全部开关见 [README](README.md)。
