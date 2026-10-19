# NLoader

[中文版](README.cn.md)

NLoader is an experimental extension framework for Nikon EXPEED7 cameras.

> [!WARNING]
> **Experimental software. Use at your own risk.** This project is provided "as is", without warranty of any kind, express or implied, and is not affiliated with, endorsed by, or supported by Nikon. The authors are not liable for any damage, data loss, camera malfunction, or inability to restore a device. There is no guarantee that a package will build, flash, boot, or be recoverable. DO NOT flash hardware you cannot afford to lose.

> [!NOTE]
> The codebase is still changing. After the design stabilizes, the repository will be refactored.

## What this repository does not contain

- official firmware images;
- local keys (`tool/nloader/keys/local.json`);
- device profiles (`profiles/<model>/<firmware>.toml`).

You must supply and verify your own copies.

## Repository layout

| Path | Contents |
|---|---|
| `core/` | Camera-side loader, required assembly, and host tests |
| `sdk/` | Camera program SDK: headers, startup code, libc, and examples |
| `tool/nloader/` | The only host Rust workspace, CLI, and local key directory |
| `profiles/` | Manually maintained device profiles and the profile schema |
| `docs/` | Public architecture and acceptance plan |
| `tests/` | Cross-module checks and QEMU test drivers |

## Documentation

This README intentionally contains no build, configuration, or usage instructions. Those are maintained in the following documents:

| Document | Contents |
|---|---|
| [docs/plan.md](docs/plan.md) | Scope, architecture, platform API boundaries, safety, and acceptance criteria |
| [profiles/schema.md](profiles/schema.md) | Device profile fields and validation rules |
| [AGENTS.md](AGENTS.md) | Development conventions, directory responsibilities, and local checks |

## License

NLoader's own source code is licensed under the MIT License with the Commons Clause condition. See [LICENSE](LICENSE). This is a source-available license, not an OSI open-source license: all MIT permissions remain except the right to sell the software itself, including paid hosting or services whose value derives substantially from it.

Third-party components, submodules, and closed-source modules (if any) keep their own terms and are outside the license above. They are separate components: their licenses do not automatically extend to the rest of the program. If you distribute a build that combines them with this code, every included component's terms still apply. This repository does not claim that all upstream components have been audited.
