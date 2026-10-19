# NLoader

[English](README.md)

NLoader 是面向尼康 EXPEED7 相机的试验性扩展框架。

> [!WARNING]
> **试验性软件，使用风险自负。** 本项目按“原样”提供，不附带任何明示或暗示的担保，且与尼康不存在隶属、认可或支持关系。我们不对任何损坏、数据丢失、相机故障或设备无法恢复承担责任。不保证产物能够构建、刷写、启动或恢复。请不要刷写自己无法承受损失的设备。

> [!NOTE]
> 代码仍在变化。设计稳定后，仓库将进行重构。

## 本仓库不提供的内容

- 官方固件镜像；
- 本地密钥（`tool/nloader/keys/local.json`）；
- 设备 profile（`profiles/<model>/<firmware>.toml`）。

这些文件不由我们提供，需要自行准备并核对。

## 仓库结构

| 路径 | 内容 |
|---|---|
| `core/` | 相机端 loader、所需汇编和电脑端测试 |
| `sdk/` | 相机程序 SDK：头文件、启动代码、libc 和示例 |
| `tool/nloader/` | 唯一的电脑端 Rust workspace、CLI 和本地密钥目录 |
| `profiles/` | 人工维护的设备 profile 和 profile 格式说明 |
| `docs/` | 公开架构与验收计划 |
| `tests/` | 跨模块检查和 QEMU 测试驱动 |

## 文档

本 README 不维护构建、配置或使用说明，这些内容在以下文档中维护：

| 文档 | 内容 |
|---|---|
| [docs/plan.md](docs/plan.md) | 范围、架构、平台 API 边界、安全要求与验收标准 |
| [profiles/schema.md](profiles/schema.md) | 设备 profile 字段与校验规则 |
| [AGENTS.md](AGENTS.md) | 开发约定、目录职责与本地检查 |

## 许可证

NLoader 自身的源码采用 MIT 许可证并附加 Commons Clause 条件，见 [LICENSE](LICENSE)。这是 source-available 许可证，不是 OSI 开源许可：MIT 的其余权限保留，只禁止销售该软件本身，包括以该软件为主提供的付费托管或服务。

第三方组件、submodule 以及闭源模块（如有）保留各自的条款，不在上述授权范围内。它们属于独立组件，其许可证不会自动覆盖程序的其他部分。分发把自身代码与这些组件组合起来的构建产物时，每个被包含组件的条款仍然适用。本仓库不声称已核对所有上游组件的许可合规。
