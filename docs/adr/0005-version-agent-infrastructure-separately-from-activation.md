---
status: accepted
---

# 分离 Agent Infrastructure 源码归属与运行时装配

workspace 级 agent 基础设施统一版本化在 `https://github.com/xuelongling/.agents.git`，包括 agent 指令、上下文索引、skills、MCP server 可维护源码与锁文件、非机密配置模板、hooks、插件清单和相关测试；token、client secret、OAuth 会话、`auth.json`、个人绝对路径、缓存、日志及只有生成产物而无可维护源码的 MCP 禁止进入该仓库。Integration Manifest 将该仓库检出为根 `.agents`，其中 `.agents/skills` 原位供 Codex 发现，并以 `linkfile` 将受管内容暴露为根 `AGENTS.md`、`.codex/config.toml` 和 `.codex/hooks.json`；完整装配以从受信任 Repo Workspace 根目录启动 Codex 为前提。首次接管先逐字迁入并校验现有普通文件，再由 linkfile 替换；Windows 缺少符号链接条件或目标冲突时同步必须失败，不允许复制回退。产品、构建、契约与集成 ADR 归 `tsfg/docs/adr`，纯 agent 运行机制 ADR 归 `.agents/docs/adr`；根入口可以是只读视图，但不得成为第三份事实源。这一设计让 agent 资产可独立演进且避免密钥与重复规则进入仓库，代价是 workspace 启动位置、信任和 Windows 符号链接能力成为显式前置条件。
