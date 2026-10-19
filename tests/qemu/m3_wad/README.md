# WAD 原生卡验证

本目录验证独立 `WADCHECK.NLB`，不包含游戏引擎或商业 WAD。
运行前使用当前源码重建、独立核对的 Exec 包及其真实布局。

`materials.py --out <新目录> [--resident <DATA1.NLB>]` 通过正式 Rust 命令构建
两次 WADCHECK，比较程序并独立解析 NPLD。生成五组卡目录：合法 IWAD、空 PWAD、
目录截断、条目越界与缺文件。合法目录包含零长标记、重叠内容和重复名称；首尾样本
及散列由材料生成器独立计算。可选 resident 必须是有 data/BSS 的资源扩展，旁边
需要同名 `.MANIFEST`；只在合法卡中启用，WADCHECK 始终是列表第一项。

每个目录使用 `tests/qemu/prepare_card.py` 生成独立镜像并卸载。`scenario.py`
运行前从实际镜像逐文件提取并比较，拒绝额外 loader 文件或内容不符；随后通过
`tests/qemu/run.py` 创建独立 QEMU，以原生菜单运行两次，保存原图和只读状态。

```sh
build/qemu-platform/venv/bin/python tests/qemu/m3_wad/scenario.py \
  --materials build/<材料>/materials.json --case valid \
  --delivery build/<新候选>/delivery.json \
  --spec build/<新候选>/complete-runtime-spec.json \
  --follow build/<新候选>/private-follow-spec.json \
  --card build/<材料>/valid.raw --out build/<新会话> --port 8782
```

观察声明必须由当前 C 头独立编译，并包含程序状态、trace、文字代数、16 个 API
分配槽及所有常驻槽的 used 字段；共存还需要 resident.0 的 kind、id、failed、
uncertain、allocation、allocation_bytes、code_block、data_block、code_bytes、
data_bytes，以及自动加载和菜单发布计数。旧布局不适用于修改后的候选。

通过要求：新鲜入口/返回记录、准确返回值和首尾读取摘要、文件与前台分配清空、
两次返回列表及继续导航。共存场还检查原始分配、两个完整对齐区、前台前后的
扩展身份与地址不变，以及新增菜单项仍可访问。该观察不声称覆盖运行期间每个瞬间。
实际 PNG 必须另行审阅，脚本通过不等于画面通过。结束必须确认
`owned_qemu_stopped=true`；合成 WAD、QEMU、真机与 DOOM 可玩分别记录。
