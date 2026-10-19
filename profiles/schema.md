# Profile schema 1

`nloader-profile` 是构建器与采集工具共用的配置定义与校验入口。TOML 由人工维护，只保存配置；字段依据写成文件内注释，不作为校验输入，`Profile` 类型不包含 `evidence` 或 `conflicts`。草稿可保存缺项；可保存不代表可构建。版本控制中不含真实机型地址表，也不从 Z6III 或 Z8 C3.01 数据填充 C3.11。

地址和长度写成十六进制更便于与分析结果对照，TOML 的 `0x` 字面量与十进制等价。注释不受校验约束，因此依据是否可信由人负责；数值是否正确由对照官方包实际字节的核对负责。

## 格式

必须显式填写 `schema = 1`。未知字段和类型错误在读取时拒绝，避免拼写错误被静默忽略。后续 schema 1 可增加字段，但旧版本工具会明确拒绝它尚不理解的新字段。缺少字段不填零值，使用省略的 TOML 字段；空能力段不表示已支持。

- `identity`：`model`、`firmware`、`container`、`stock_pkg`、`eg_module`。构建按支持的服务家族和输入身份核对，不以固定的 Z8/3.11 字符串决定兼容；当前构建容器仍限 `legacy-xor`，`aes-ctr` 可记录但尚不允许构建。实际完成本地与 QEMU 验证的目标仍只有 Z8 C3.11，其他机型未因此获得验收结论。设备身份必须由采集器规范化，不能把相似版本当作相同版本。
- `checks`：`package_sha256` 是原始官方包全部字节的 SHA-256；`module_sha256` 是解密后的目标模块 payload SHA-256，不包括容器模块 CRC。每个指纹必须是 64 位十六进制，比较不区分大小写。
- `storage`：`root` 是显式卡目录，如 `root = 'B:\NLOADER\'`；QEMU 的 NVMe 卡使用独立测试配置 `root = 'A:\NLOADER\'`。只接受 `A:` 或 `B:` 上以反斜杠分隔的绝对目录，末尾必须有反斜杠，目录组件须非空且仅含 ASCII 字母、数字、`_`、`-`，整体最多 64 字节；不接受相对路径、空组件、`.`、`..`、正斜杠或其他盘符。load-only、prepare-only、exec 必须填写，缺项拒绝；任何档位已填写的值都按相同规则校验。没有默认盘符，不在运行时寻找另一张卡。构建器将该目录写入生成头文件，MANIFEST、SAFE_MODE、ENABLED、AUTOLOAD_PENDING 和程序访问都使用同一根目录；修改配置后须重新构建。无读卡能力的档位和中性编译检查在缺项时仅使用不可访问的 `?:\NLOADER\` 占位目录，构建报告明确标记未配置，不获得读卡能力。
- `memory`：`xip_base` 为目标模块运行地址；`module_size` 为上述 payload 长度；`slack = { start, end, require_zero }` 为模块内可用区域；`link_base` 与 `link_size` 为完整链接预留范围；`ram_pool = { start, end }` 是可选 RAM 范围。`segments` 必须显式描述 payload 字节到运行地址的分段映射。所有范围采用左闭右开，整数运算检查溢出，空范围无效。`program_budget_blocks` 与 `program_max_resident` 是程序共存的内存预算（M2-T2）：前者是常驻扩展与运行中程序合计占用的整块执行块上限，启动会使合计超出预算的请求在任何分配前被拒绝（返回专门的预算拒绝，而不是校验失败；预算为 1 时带数据程序始终走拒绝路径）；后者是入口返回后保留常驻的资源扩展数量上限。两字段在 prepare-only/exec 档必须存在且非零，由绑定注入相机端执行服务表；数值依据写在 profile 注释中，注释不参与校验。
- `memory.program_arena_bytes`：可选的程序读入缓冲容量，未声明时明确保持原有 65,536 字节。声明值必须在 65,536..=1,048,576 字节之间且为 64 字节的整数倍；所有构建档位均拒绝非法声明。该值统一用于生成 Core 配置、原厂实际内存申请、读取容量和独立编译的布局记录。M3 隔离配置可以声明 524,288 字节；这不证明现场有足够连续空闲，申请失败仍须拒绝加载。它只容纳重定位、image 和初始化 data，不改变程序格式、各执行段 2 MiB 上限、BSS 边界或共存预算，也不自动扩大原厂内存池。
- `abi`：`ui = "z8_menu_v1"`、`task = "z8_worker_v1"`、`fs = "z8_file_v1"`、`mmu = "z8_block_v1"` 选择服务家族。未知名称在读取时拒绝；hook-only/page 起要求 ui，load-only 起另要求 task/fs，prepare-only/exec 另要求 mmu；缺项明确拒绝。家族只规定调用方式、记录结构、边界和核对规则，不保存具体固件地址、函数哈希或原厂表。识别家族名称不代表该机型已通过 QEMU 或真机验证。
- `services`：`fs_open`、`fs_read`、`fs_seek`、`fs_close`、`dcache_inv_pre`、`dcache_inv_post`、`worker_init`、`worker_start`、`flag_set`、`registry_lookup`、`mem_alloc`、`mem_free` 可选运行地址；`services.exec` 含 `page_protect`、`page_query`、`icache_inval`、`mmu_translate`、`cacheable`、`tlb_sync`、`manager`、`cache_manager` 与 `region_bytes`（规则见文末各档配置要求）。已填写地址必须 4 字节对齐、位于目标模块的 XIP 段内、避开预留区域；其来源在提取阶段另行核对。RAM 中的对象指针不能冒充服务函数。`services.file_ops` 声明文件包装函数提交的请求操作号：`op_slot`（请求块中操作字在栈上的偏移）与 `open`、`read`、`seek`、`close`。校验从每个已声明的包装函数中解出写入 `[SP, #op_slot]` 的常量（MOVZ 或 ORR 立即数），与声明不符即拒绝；入口指纹只能证明字节是声明的那段，不能证明它是哪个操作。load-only 要求全部声明。
- `ui`：NLoader 自有页面调用的原厂函数 `widget_find`、`text_store`、`text_bind`、`widget_show` 运行地址，窗口内控件容器偏移 `widget_container_offset`，以及核对这些值的原厂标题链 `[ui.title_chain] = { eg_off, stock }`（规则见“NLoader 自有页面”一节）。`task` 可记录 `core`、`priority`、`stack`、`name`。字段存在不代表对应档位已通过相机验证。
- 不再有 `hooks` 段，也不再有包裹原厂页面的 `ui.screen_entry` 与 Battery info 状态行字段（`status_*`、`[ui.status_chain]`）：2026-10-10 起任何档位都不改动原厂功能页（M1 T3.8）。仍写有这些字段的旧 profile 读取时明确拒绝。
- `updater`：可记录 `filename_glob_class`、`trailer_fwver` 与 `version_literal = { eg_off, stock, patched }`；`eg_off` 仅为模块 payload 内偏移，不能填运行地址。版本修改必须保持 UTF-8 字节长度，原字节必须匹配，不能与其他写入区域重叠。字段存在不证明相机接受更新。
- `menu`：保存两个产品位置所需的原菜单记录，字段与核对规则见下节；记录数据不代表菜单运行能力已经实现。
- `graphics`、`input`、`config`：当前仅接受空段，其结构与能力尚未实现。
- `boot_hooks`：目前只有可选的 `[boot_hooks.autoload]`，规则见“可选开机检查点”一节；段内其他字段读取时拒绝。

TOML 数值使用非负整数，地址和长度在 Rust 内采用 `u64`。TOML 自身的整数范围仍适用。严禁将当前启动中的窗口或缓冲对象地址当作长期服务或 hook 地址。

每个机型版本只有一个本地 TOML：家族声明、地址、函数体哈希、原厂表和菜单编码均保存在其中，不另建审计配置文件。接口相同的机型可复用家族规则，但必须填写并核对自己的数据；接口不同的部分需要新增家族，不能只换地址。现有家族的尺寸和上下限最初来自 Z8，例如 300 个文字槽的边界、50 字节文字、64 行列表与菜单记录尺寸；其他机型选用同一家族前必须重新确认这些条件，不能把它们当作通用相机规格。

权限编码由 `services.exec.flag_writable` 与 `flag_executable` 显式声明，相机端只表达“可写/可执行”；对应原属性表及实际服务行为仍须独立核对。

通用程序保留有界临时读入缓冲：头部全部边界通过后，重定位、image、data 总和
超过固定 arena 时才申请，最多5 MiB，另加对齐所需字节。申请失败拒绝本次文件；
超过上限的声明在申请前拒绝。该缓冲只替代本次读入，不改变执行段2 MiB上限、BSS、
共存预算或原有 arena 配置。结束后恢复原 arena；释放失败保留实际所有权并停止
继续加载，不能把原厂可分配容量当作已通过。

## 菜单定义数据

`[menu]` 只保存 Setup 正式入口和 NLoader 自有页面所需的信息。自有页面复用原厂列表页的样式与结构；已取消的回放菜单 demo 配置不再保留。其他菜单页不属于配置格式；需要时在研究阶段分析，不预先建模。旧的 `menu.playback`、`menu.pages.<名称>`、`menu.category_index`、`menu.windows`、`navigation` 与 `subpages` 格式不兼容，读取时明确拒绝。

- `window_table`：initialized RAM 中的窗口表首地址。窗口记录地址由 `window_table + window_id × window size` 推出，不单独保存，避免两处不一致。
- `record_sizes`：`window`、`page`、`item`、`event` 字节尺寸。当前解码器仅支持 `96 / 80 / 44 / 32`，其他布局明确拒绝，不按已知偏移猜读。
- `[menu.events]`：`activation`（4 个打开事件）、`back`（3 个返回事件）、`ok`、`terminator` 及 `nav_first`、`nav_back`、`nav_reenter`、`nav_last`。事件集合不得重复，OK 必须属于打开事件；导航值须满足所选家族的结构关系。`navigation_address` 与 `navigation_sha256` 指定原厂导航函数（当前家族核对完整 0x154 字节及其中实际使用的导航值）；`lookup_address` 与 `lookup_sha256` 指定原厂事件查找函数（完整 0xb0 字节，四处比较指令必须使用声明的终止码）。事件码同时对照被克隆的原厂事件表核对；扫描必须在规定上限内遇到终止记录。生成事件表与重新进入页面的绑定均读取这些字段，不回退到 Z8 常量。
- `[menu.setup]`：保存正式入口所在设定页的 `window_id`、`page_address`、`items`、`item_count`、`event_table`、`layout`。`event_table` 指每项事件表的指针数组，不是某个项目的事件记录首地址。
- `[menu.setup.firmware_version]`：`index` 与 `item_id`，标记作为 NLoader 插入位置锚点的原 Firmware version 行。只有设定页可以有该字段。
- `[menu.setup.apps]`（可选）：设定页的 Apps 行，打开 NLoader 页面中的应用列表。`index` 为插入位置（插在该原厂索引之前，0 为第一行，不超过项数）；`item_id` 不同于入口行且不超过 0xffff；`flags` 与入口行相同，须走运行期文字槽路径（bit9 置位，bit4 / bit13 清零）；`slot` 为标签的运行期文字槽：未声明 `[menu.private_text]` 时须小于 300，声明后须正好是私有家族的 Apps 编号（`token_base + apps_index`，item id 须等于 `apps_item_id`，2026-10-17 起）；均不得与入口、标题、页面行或文字平台已用的槽重复，菜单初始化时与入口文字同一处预填（私有模式只预热字体）；`text` 为 1–50 字节可显示 ASCII。记录与入口行一样从锚点行克隆，声明后设定页增加两行。Z6III 使用的槽 249 位于构建已借用的 180–251 区间，同样未证明空闲。
- `[menu.setup.cursor]`（可选，2026-10-17，G2-cursor）：原厂把 Setup 光标按原始行号存在一个设置项里，没有范围检查。声明后构建把读写这个设置的三处原厂调用改接到 core，设置里永远存原厂行号：Apps 行存为原厂第一行，NLoader 存为 Firmware version 行，其余行存为它显示的原厂行；读回时原厂第一行回到最上面一行（Apps），其余回到显示该原厂行的那一行，超出原厂行数的值回到最上面一行。同一次开机内，若 Setup 窗口里还留着离开时的光标、且它映射后正好等于读到的值，就恢复那一行（这样 Apps 与“Format memory card”、NLoader 与 Firmware version 不会互相顶替）。字段：`setting`（设置号，16 位，一条 movz 装入）、`setter` / `getter`（原厂设置写入 / 读取函数）、`cursor_offset` / `scroll_offset`（窗口记录里光标与滚动的半字偏移）、`save_site` + `save_stock`（菜单关闭时的保存：`ldrh w8,[x0,#scroll]; ldrh w9,[x0,#cursor]; movz w0,#setting; add w1,w9,w8; bl setter`，5 条）、`lookup_site` + `lookup_stock`（按 item id 查出行号后写入的那处：`tbnz w8,#31; movz w0,#setting; mov w1,w8; bl setter`，4 条）、`restore_site` + `restore_stock`（菜单打开时的恢复：从 Setup 分支的 `movz w0,#setting; b call` 起，经另两个窗口装入各自设置号并到达调用点，`bl getter; ldrh w8,[x19,#2]; mov w20,w0; strh wzr,[x19,#scroll]; strh w20,[x19,#cursor]`，10 条）。校验要求这些原厂指令正好就是字段描述的序列，并与正式模块逐字节相同；还要求声明了入口行、Apps 行位于第 0 行和 `firmware_version`。构建把三处 BL 分别改指 `nlr_setup_cursor_save`（两处写入）和 `nlr_setup_cursor_restore`（恢复）；恢复调用点是所有菜单页共用的读取，其他设置号原样透传。

窗口与页面记录须在 RAM 映射中；项目数组、事件指针数组和布局须在 XIP 映射中，并满足各自对齐与完整长度。项数必须是非零 u16。记录不得与 loader 预留空间重叠。

`validate_for` 按实际模块字节逐项核对：窗口记录的 ID 与页面指针、页面记录的项数、项目数组、事件指针数组和布局指针、布局行数关系，以及 `firmware_version` 所指索引处的实际 `item_id`。仅在其他位置找到相同字节，不能算作核对通过。

NLoader 的产品入口在设定菜单 Firmware version 之前，或在全部原厂行之后（`entry.index` 等于项数，NLoader 成为最后一行），不提供其他插入位置。原 Firmware version 行的行为以及其他原有项目的顺序、内容和可见性条件均须保留。

针对已核对的 Z8 C3.11：设定页原索引 0–41 不变，NLoader 插入索引 42，Firmware version 顺移至 43，Special shooting 顺移至 44，总数变为 45。`menubuild` 从匹配的官方包完整复制原 item 数组和每项事件表的指针数组，再插入新行；不得按配置中记录的少量字段重建页面，否则会丢失未建模事件、隐藏条件或其他原功能。

入口文字使用 `[ui].text_store` 指定的原厂 ASCII 写入函数；声明入口时必须提供该函数，hook-only / page / load-only 构建还要求 `[service_fingerprints.text_store]` 核对其原始字节。函数地址必须位于原固件 XIP 范围内。`menu.text_platform.prefill_call_site` 必须选在文字缓冲、字体缓存及语言初始化完成之后，`prefill_return` 保留该处原调用目标。构建会核对原调用指令；初始化顺序来自机型研究，不能仅靠地址校验证明。Core 不自行复制或转换原始字体记录。

### NLoader 自有页面 `[menu.page]`

声明 Setup 的 NLoader 行打开的 NLoader 自有二级页面。页面不改动任何原厂页面：窗口和 page 记录写进 window 表中原包为全零的两个空洞，内容逐字节克隆一个原厂列表页。被克隆的模板只按地址引用、按字节核对，不作为可配置的菜单页建模。

- `window_id`：页面窗口号，取全零空洞；须小于第一个导航哨兵（0x68c），且不同于设定页和模板的窗口号。
- `page_record`：借作 page 记录的第二个空洞地址（RAM，8 对齐）。page 与 window 记录运行期会被写，因此必须在可写 RAM。
- `template_window`、`template_page`：被克隆的原厂列表页。核对：窗口类型为 2、自身 ID 与 page 指针一致；page flags 为 v2 列表页、至少一行；element 列表在 XIP 内、`MENU_ELEMENT_MAX` 条以内终止，且恰好一条字符串标题。
- 处理块不在配置中：构建生成一个 5 槽块放在 loader 区域，slot 0 为 NLoader 的页面进入，slot 2 取模板处理块的底栏 handler（须存在且在 XIP 内），其余为空。模板块的其他槽是该页专用逻辑，不带入。
- `title_slot`、`title_format`：标题的专用文字编号（不同于入口行与页面行；历史非私有模式要求 < 300，私有模式按下节精确映射）与存入格式。格式须是 `[ui.title_chain]` 那段原厂代码装入 W2 的值（MOVZ 或 ORR 立即数两种写法均识别）。
- `row_event_table`：多行页原厂行事件表（XIP），须在上限内以 0x3bb 终止。各档均克隆该表；四类打开记录的 guard 保留。hook-only/page 生成单行，打开动作置空并返回；load-only及之后生成完整列表，打开 action 指向 NLoader 处理且 next=0x696（重进显示详情/结果）。多行页三项返回记录（0x285/0x2a0/0x306）的 action 交给 NLoader：详情返回列表，列表保留原返回目标。替换前原返回动作必须为空或原厂单条RET，其余上下键、滚轮、guard及字段逐字节保持。
- `row_slots`：显式逐行文字槽，当前支持64行；槽须唯一，不占入口/标题槽，首项等于item_slot。未声明 `menu.private_text` 的历史模式要求槽小于300，旧 Z8 配置曾使用251–296加232–249；当前私有模式采用下节的精确独立编号，不占原厂槽。`item_id`为连续行ID起点，整个区间须符合校验。load-only、prepare-only、exec 必须声明（2026-10-11 起）：这些档位的页面是程序列表与详情，单行页面显示不了详情的操作、结果与返回三行，缺少即拒绝，不再静默生成单行页面；hook-only、page 仍只用一行。
- `row_hide`、`row_hide_stock`：原厂隐藏行服务及入口字节，按当前模块核对；第二参数是零起始行下标，不是item ID。`selected_offset`：窗口内选中行字段，当前支持0x32。隐藏多余行由原厂完成，不能只清空文字留下可选空白行。
- `viewport_bottom`：可选显示区域下沿，支持424或480；指定时先核对原厂模板两组矩形下沿均为424，只改生成页面对应的两个下沿字段。当前480使列表占满屏幕高度。
- `row_template_event_table`：Setup 中被克隆给 NLoader 行的原厂行表；其 4 条打开记录（0x286 / 0x28b / 0x29f / 0x2ae）须都指向模板窗口且 action 非零。生成时只把这 4 条的 `next` 改为 `window_id`。
- `item_id`、`item_flags`、`item_slot`、`item_style`、`item_text`：页面行。flags 须走运行期 ASCII 文字槽路径（bit9 置位，bit4 / bit13 清零）；编号不同于入口行；历史非私有模式要求 < 300，私有模式采用下节映射；文字 1–50 字节。页面标题使用独立`title_slot`，详情显示所选程序名。

两个空洞在原包中按整条 0x60 字节核对为全零，不只核对写入的字节。声明 `[menu.page]` 时必须同时声明设定页入口。

页面进入调用原厂函数，声明 `[menu.page]` 时还要求：`ui.widget_find`、`ui.text_store`、`ui.text_bind`、`ui.widget_show`（控件显示，`(控件, 可见)`）、`ui.widget_container_offset`（8 对齐），以及 `[ui.title_chain]`——一段原厂"以文字槽给页面起标题"的代码。校验先核对这段字节与原包一致，再从中解出：容器偏移的 ADD 立即数、W2 中的标题格式，以及查找、写入、绑定、显示四个调用目标，且必须按这个顺序出现。运行期文字 element 建成后是隐藏的，原厂页面正是按这一顺序填入并显示标题。hook-only / page / load-only 构建还要求这四个函数的入口指纹。

### 独立文字空间 `[menu.private_text]`

可选家族 `z8_private_ascii_namespace_v1` 为 NLoader 提供独立的文字描述符与缓冲，不占用原厂文字槽。旧槽路径仍可表示历史配置，但其字段校验不构成空闲保证；新候选使用本段，并须重新完成实际显示验收。

- `token_base`、`token_count`：当前家族限定完整正数编号 `0x4E4C0000` 起的 68 项（2026-10-17 用户决定统一为 68 项，未声明 Apps 行的配置同样如此）。前 64 项对应列表行，`title_index=64`、`status_index=65`、`entry_index=66`、`apps_index=67`。编号不能截成 16 位，也不能把其他原厂合法或非法值纳入私有路由。
- `row_first_item`、`entry_item_id`、`apps_item_id`、`ascii_flags`：精确绑定自有行、入口、Apps 行（`apps_item_id = 0x7ffd`）和 ASCII 属性；原厂 item_builder 的 `<300` 清零处只对行（按本地序号）、入口与 Apps（按各自的 item id）放行；`menu.page.row_slots`、标题、状态和入口编号必须与此映射一致。声明本段后它们是私有编号，不再受旧 `<300` 槽规则约束；原厂全局范围检查只对这些精确对象另行处理。
- `styles`：当前只接受已核对的 3、4。继续使用原厂字体缓存及转换，不因原字体查询函数存在范围保护就接受任意可写缓存索引。
- `getter_call_sites`、`item_clamp`：完整原始读取调用点和行标签范围判断位置。构建只对经过原字节核对的调用点安装路由；非私有参数，包括原始无效参数与空指针，保留原行为。
- `value_clamp`（可选，2026-10-17）：原厂行值列构建里 `cmp w9,#0x12b` 的位置（行标签编号超出原厂池时把值列的文字槽清零）。校验要求该处前 0x40、后 0x20 字节逐字等于已审定的原厂指令窗口。构建把这条指令改为跳到 `nlr_private_text_value_clamp`：先执行被跳过的两条存储，再按原厂判断；只有行标签为私有第 k 行（k < 32）、文字槽模式（w11 = 3）、条目标志含 ASCII 位与文字值位、值等于该行自己的值编号（标签 + 32）且条目 id 为 `row_first_item + k` 时保留值，其余照原厂清零；NZCV 恢复为原厂比较的结果，回到原位置 +0x1c。与 `[menu.page.rows]` 同时声明。
- `strlen`、`memcpy` 与 `bodies`：保存原函数地址及完整函数体 `name/address/length/sha256`。家族要求文字读写、低层绑定、通用写入包装和 GUI 身份链的完整依据，缺失、重复、错误家族、字节或关系均拒绝。原 ASCII writer 使用受检重定位副本，只改变自有描述符基址与对应调用位置，其余原指令保留。
- `gui_task_name`、`gui_task_config`、`registry_cases`：原厂当前任务查询、任务登记、名称与自身指针关系的依据。可写文字只能由经过核对的 GUI 任务处理；不能固定猜测任务 ID，也不能把位图或原生存卡家族当作文字空间的隐含依赖。
- `fallback_text`：1–50 字节可显示 ASCII。没有可用运行状态、分配失败或私有空间未就绪时显示明确错误，禁止返回空文字缓冲或继续检查文件。

开机字体初始化仅使用临时输出；Setup 入口文字来自只读常量，不创建任务。Page 档使用动态文字，因此声明本段时也须提供明确的分配、释放、任务及登记服务与 `abi.task`；它仍不读卡、不执行。LoadOnly 及以后先建立并确认独立空间再发布动态文字。文字对象在本次启动期间保留，页面退出或扩展失败不能提前释放；读取函数不分配、不等待、不读卡。

六个写入入口保护精确私有编号，防止原通用包装截断编号后写入原厂位置。当前只支持 ASCII，私有 UTF16 或转换写入明确拒绝并保留错误，不宣称新增编码能力。最终包必须独立核对全部路由、续接、参数保护与原指令副本；配置和主机检查不替代实际画面。

## 页面行（page 档及之后）

page 档及之后改写 NLoader 页面自己的行，使用经过核对的原厂查找、文字与绑定函数；启用独立文字空间时，`item_slot` 对应自有完整编号，写入行自己的缓冲与 `item_style`：

- page 档：进入页面时写入行标签 `item_text` 加一个空格和结果字符。`W` 表示行控件查找成功并重新绑定，`X` 表示查找失败、只写了文字槽，因此查找失败不会显示成成功。
- load-only 档：进入页面时依次检查 SAFE_MODE、读取 MANIFEST 并做兼容判定，显示最多64个程序或无法列出的原因；在选中行按 OK 检查对应程序文件，详情分别显示应用打开/扩展设置入口、结果与返回列表。加载阶段两类入口均只检查，返回恢复原选中行。读卡在菜单任务中直接进行（M1 D14）。

行文字的上限是原厂写入函数的 50 字节；`item_text` 须为 1–50 字节，page 档追加两个字符后超出部分被原厂函数截断。

## 文件偏移与运行地址

`[[memory.segments]]` 的每项固定包含：

| 字段 | 含义 |
|---|---|
| `file_offset` | 模块 payload 中的起始字节偏移，不含容器目录或末尾 CRC |
| `runtime_start` | 此段加载后的运行地址 |
| `size` | 该段非零字节长度 |
| `kind` | `xip` 或 `ram`；`ram` 仅表示已初始化数据的加载位置 |

段的文件范围必须完整位于 `module_size` 内；文件范围与运行范围均不得溢出。任意两段在任一地址空间重叠均拒绝；当前不支持多个别名。允许段间有未映射间隙，但间隙内的地址不能用于 hook、服务或版本修改。`xip_base` 必须等于文件偏移零处的 XIP 段运行起点。

缺少 `segments` 的草稿仍可读写，但所有构建和地址转换均拒绝。不会根据 `xip_base + module_size` 猜测整个模块都是连续 XIP；旧合成样例也必须明确填写单个 XIP 段。真实机型的映射由对应识别规则提供，通用类型不保存机型地址常量。

`Memory::address_to_offset(address, length)` 与 `offset_to_address(offset, length)` 使用同一组完整检查，返回 `Result<u64, MappingError>`。每次请求必须非空并完整位于单段内，不自动跨段拼接。无论当前请求是否位于问题处，整个映射存在错误都会拒绝转换。`segment_for_address` 返回对应段；`validated_segments` 返回通过范围校验的段清单。

`slack` 与完整链接范围只能位于 XIP 段。服务与 UI 函数字段同样只允许 XIP 地址。`ram_pool` 不能覆盖已有映射的固件数据；映射到 RAM 不代表获得其长期分配所有权或执行权限。

实际固件校验通过同一映射查找 slack 与菜单记录字节。版本原值从 `eg_off` 读取，同时将其映射回运行范围，与 slack 核对重叠；不会将 RAM 地址减去 XIP 基址。完整模块指纹仍覆盖所有 payload 字节，包括映射段之间的间隙。

## 可选采集报告中的依据与冲突

只读采集的输入也保存在同一 TOML 的 `[capture]` 中，与构建能力分开校验；构建不要求存在采集配置。带官方镜像的 `profile discover/replay` 必须显式传入 `--profile`。

- `family = "z8_readonly_v1"`：当前只读采集协议仍限 Z8 C3.11，不随构建家族迁移自动开放其他机型。
- `windows`：允许读取的左闭右开地址范围；`requests`：每项的 `label`、`address`、`length`。无默认地址或默认请求。
- `range_check = { name, file_offset, length, sha256 }`：原厂读取范围检查指令的完整依据。核对模块指纹、范围检查与初始化 RAM 映射，重新解出保护区端点，再计算允许窗口；声明值必须完全一致。
- `[capture.slot]`：既有静态空间检查所需的 `descriptor_offset`、`region_getter_offset`、`overlay_getter_offset`、`flash_table_offset`、`flash_record_count`、`region_count`、`overlay_count`，以及 `instruction_windows`（每项的 `name`、`file_offset`、`length`、`sha256`）。地址、偏移、哈希由配置提供；家族仍要求 Flash 表完整 39 项，以及 bootstrap_text_mapping、overlay_consumer、shutdown_copy、late_data_copy 四个完整且不重复的指令窗口，拒绝截短后重算哈希。仍须核对原厂结构与相关指令，不能仅因配置声明就视为空闲空间。新机型必须重新确认这些家族条件。

真实设备读取只接受通过固件字节检查的窗口。设备层仍检查每个请求范围、总量、身份、两次读取一致性与会话清理。内存快照使用 schema 2 保存读取窗口；旧 schema 1 缺少窗口记录，明确拒绝，不自动补默认值。回放还须与当前已核对配置的请求和窗口一致。纯身份查询不需要 `[capture]`。

只读设备采集会产生独立报告，其 `evidence` 映射记录该次读取的来源，不写入 TOML，也不是构建凭证。路径与字段对应，如 `memory.segments`、`memory.slack`、`services.fs_open`。每项包括：

| 字段 | 含义 |
|---|---|
| `source` | `device`、`firmware_image`、`static_analysis` 或 `snapshot` |
| `status` | `unconfirmed`、`observed`、`static` 或 `device_verified` |
| `model`、`firmware` | 证据所属身份，必须与 profile 相同 |
| `rule` | 可追溯的采集或识别规则版本，不能为空 |
| `fragment_sha256` | 原始采集片段指纹，设备、镜像及快照来源必须提供 |
| `module_sha256` | 涉及地址和范围的依据必须绑定目标模块指纹 |
| `note` | 补充说明；不能代替原始片段与规则 |

镜像、静态分析与快照不能声明 `device_verified`。静态依据和读取结果只证明其记录的结论，不自动证明服务调用、内存长期归属、实际执行或重启行为。原始采集字节及片段指纹由报告和快照保留；配置中的 `checks` 仅保存实际构建时必须核对的原包及模块指纹。报告依据采用有序映射，相同输入的审计结果可复现。

报告的 `conflicts` 保存 `field`、`candidates` 字符串数组、`reason`。任何未解决冲突都会使该次采集失败，只保存报告与快照。TOML 若含 `evidence` 或 `conflicts`，读取时明确拒绝，不做隐藏字段或兼容忽略。

## 校验层次与能力边界

`Profile::draft(model, firmware)` 生成无地址草稿。`from_toml` / `to_toml` 负责类型与格式。`validate(mode)` 返回完整问题清单，包括字段、类别和原因；它只检查配置字段，不要求加载提取报告，也不等同于验证固件字节。

`validate_extraction(mode, evidence, conflicts)` 只供只读采集使用：先做相同配置校验，再核对报告中的依据身份、模块指纹一致性、来源与确认状态及未解决冲突。它不修改配置，也不能替代对实际固件字节的核对；手工维护的 profile 不需要它。

各档的配置要求：身份、包及模块指纹、完整链接范围在所有档位都是必需的。`hook-only`、`page`、`load-only` 都由 Setup 入口行与 NLoader 自有页面组成，必须声明 `menu.setup.entry`、`menu.text_platform`、`menu.events` 与 `menu.page`，以及页面调用的原厂函数及其指纹；私有文字 Page 另需上节所述任务和分配服务。`load-only` 另需全部读卡、分配与 worker 服务及其指纹、`services.file_ops` 与完整的 `task`。`prepare-only`、`exec` 另需所选家族要求的执行服务、完整函数和原厂表核对，以及页表与缓存 manager，并要求 `memory.program_budget_blocks` 与 `memory.program_max_resident` 存在且非零（见 `memory` 一节）；当前执行家族要求固定 CPU0 的 task.core=1。各档还须声明对应 `[abi]` 家族。当前执行格式支持固定返回探针与通用 v2 两类程序；头、清单类型、入口、数据和重定位必须通过相应检查，不能把格式支持当作程序运行通过。

人工维护的 profile 以 `validate_for(mode, &ValidationContext)` 为主要正确性保障，构建前必须执行：校验实际机型、版本、模块名、包和模块字节，重新计算指纹，检查模块长度、slack 全零、服务入口指纹、文件包装函数的操作号、标题链、版本原值与菜单记录。`ValidationContext` 中的身份必须来自独立校验的输入，不得用 profile 自己的声明冒充输入身份。

`nloader profile validate --firmware <官方包> --key-file <本地密钥>` 执行同一检查，用于在不出包的情况下核对手写配置。配置校验不执行补丁、不编译、不修改设备，也不表示硬件验收通过。

本 crate 的测试只使用明确标记的合成数据，覆盖草稿往返、字段类型、边界与溢出、身份与指纹、重叠写入、原字节、空白区域、菜单记录和不支持模式。


## 返回探针执行服务

`services.exec` 包含 page_query、page_protect、mmu_translate、icache_inval、cacheable、tlb_sync、manager、cache_manager、region_bytes 以及权限编码 `flag_writable`、`flag_executable`（M2 D1 步骤 4：相机端只区分可写与可执行两种语义，具体编码由本配置提供；编码的页表含义属于所选映射家族的适配器）。执行模式要求两者非零且互异。函数入口指纹仍需提供；执行模式另核对本地同一 TOML 中的完整函数指纹、属性表及 CPU 亲和表。

- `[[services.exec.bodies]]`：`name`、`address`、`length`、`sha256`。所选家族规定必需的函数名称及结构要求，拒绝缺失、重复、未知名称、错误范围和错误指纹；地址和哈希由该机型配置提供。
- `[[services.exec.tables]]`：`name`、`address`、`element_bytes`、`values`。`z8_block_v1` 要求 `affinity_table`、`attribute_table`、`attribute_dispatch`，并检查元素宽度、数量和实际字节。
- 函数地址必须与对应服务入口一致；从原厂指令核对 manager/cache_manager、内部调用及表引用的关系，属性跳转表必须指向相应函数内的指令。仅在无关位置找到匹配字节不能通过；配置声明与字节相符也不能代替这些语义核对。
- 执行适配器由 `abi.mmu` 明确选择，缺少家族或必需字段时构建失败，不生成空执行服务表。非执行档位保留中性的空执行服务表，不因此获得执行能力。
- `memalign`、`memalign_heap`（可选，2026-10-17，仅 `z8_block_v1`）：堆自己的加锁对齐入口 `(堆, 对齐, 字节) → 地址或 0`，以及存放 `mem_alloc` 第 0 号池堆句柄的字（池表首项）。两者同时声明，并带 `heap_memalign`（对齐入口本体）与 `heap_mspace_malloc`（`heap_alloc` 调用的加锁分配）两段完整函数；未声明时这两段不得出现，有 `[services.heap]`（授予账本）时拒绝。字节核对：`heap_alloc` 构造的池表地址等于 `memalign_heap`，`heap_free` 构造同一张表，`heap_alloc` 调用 `heap_mspace_malloc`，后者与对齐入口取同一把堆锁。声明后程序区块先由对齐入口按区块边界精确取得（前后余量当即还给堆），失败再走原来的余量方式；区块仍经 `mem_free` 归还。

运行时审计当前CPU、权限、页表与cache状态，完整自有区域才允许改变权限；当前Z8采用独占2MiB块，未声明 `memalign` 时申请4194303字节后在其中对齐（声明后由堆的对齐入口直接给出对齐的整块），不拆分其他对象共用的映射。保护后调用原生TLB同步，缓存清理分块进行；实际指令缓存范围仅16字节。未识别的环境明确拒绝；配置及字节校验通过不代表QEMU或真机执行通过。探针文件字段见PLAN §6.3。

## 可选程序服务 `[services.program]`

API4 原生列表需要 `menu.page.dynamic_rows = true`，使自有 RAM 页面使用实际计数
及已核对的本窗口导航。页面真实进入时再确认可用容量；缺少计数位置、导航、行槽
或原厂显示服务时，`ui_list` 在发布与等待前返回未支持，不停留在不可见的列表。
仅声明目录枚举或等待函数不能替代页面接线。

API6 的原生行（`ui_rows`：原厂开关、右侧文字值、光标跳过的文字行与灰显行）需要
`[menu.page.rows]`：开关与文字值各自加入条目记录 +0x10 的标志（`switch_flags`、
`select_flags`，不得与 `item_flags` 已用位重合；开关去掉 > 标志），开关的两张起始
值图 `switch_on` / `switch_off`（互不相同，非 0、非 0xffff），文字值的存储格式
`select_format`、文字值行改用的条目样式 `select_style`（+0x1c 两个方向的样式号，
给出更宽的值列；0 表示沿用行自身的样式），让光标跳过禁用行的页面标志位 `skip_flag`（一位），窗口中已构建行
控件表的偏移 `widget_table`，以及三个原厂函数 `row_get`（表、行、0 → 行控件）、
`switch_set`（行控件、开/关）、`widget_enable`（控件、启用），各带至少 16 字节的
原厂入口指纹（`*_stock`），构建时对照模块核对。只能与 `dynamic_rows = true` 及
64 个行槽同用：每页最多 32 行，第 k 行的文字值存放在行槽的后半（第 32+k 个）。
模块中的条目记录在 flash，core 在第一次显示原生行时把它们复制到运行时内存、改指
页面记录的条目指针并给页面记录加上 `skip_flag`；之后每次构建前写回各行自己的两个
字，再按行的种类写入标志与值，构建后存入文字值、设置开关状态、禁用文字行与灰显
行；灰显的文字值行去掉 > 标志。未声明时含非入口行的页面返回未支持。

`widget_enable_inverted`（可选，默认 false，2026-10-17）：所声明函数的第二个参数
表示“禁用”而不是“启用”（Z 8 只有这种原厂原语，原厂调用方先把启用取反再传入），
core 灰显一行时传 1。私有文字空间的 profile 声明 `[menu.page.rows]` 时，必须同时
声明 `menu.private_text.value_clamp`（见上文），否则私有行的文字值被原厂值列构建
清零；未声明 `rows` 时不得声明 `value_clamp`。

`[menu.page.keyboard]`：相机自带的文字输入键盘（ABI 6 `ui_input`）。窗口记录必须
位于窗口表中，而唯一剩下的表项就是页面记录所在的那一项，所以 `window_id` 必须正是
`page_record` 所在表项（`window_table + id × 96 == page_record`）。core 在 Setup 行
第一次打开页面时（此时页面记录上没有任何已构建的窗口）把页面记录搬到运行时内存，
让页面的两个窗口（列表与详情）改指副本，再在空出的表项里装上键盘窗口：类型与父窗口
取自 `template_window`（一个原厂键盘窗口，其记录除类型、id、父窗口、处理块、页面外
全为 0），处理块槽 0 为 core 的入口，其余四槽沿用模板；页面为模板页面的副本，事件
表为模板事件表（至多 24 条，含终止码）的副本：`save_event`（保存并离开）交给 core 的
保存动作，`menu_event` 与 `back_event` 交给 core 的放弃动作，`help_event`（0 表示无）
改为原地不动，其余事件保持引擎自己的。三个引擎入口 `open`（参数块、窗口）、`take`
（目标缓冲区，第 0 位表示接受）、`shown`（窗口、0）各带至少 16 字节原厂指纹
（`*_stock`）。只能与 `dynamic_rows = true` 同用；三个事件码互不相同且非 0，键盘、
页面、详情与模板窗口互不相同。未声明时 `ui_input` 返回未支持。

`[menu.page.caution]`：相机自带的警告框（ABI 6 `ui_caution`），与键盘共用
`[menu.page.keyboard].window_id`，必须同时声明键盘。`template_window` 是原厂两项
弹窗（页面标志含 0x100，记录除类型、id、父窗口、处理块、页面外全为 0），两张事件
表各至多 24 条，表 0 含 `yes_action`、表 1 含 `no_action`，且各含键盘的
`menu_event` 与 `back_event` 恰好一次；core 把 Yes/No 动作换成自己的，MENU 与返回
放弃。core 的入口把文字存入 `text_slot`（`text_format` 样式），再用
`panel_text(panel, value, mode)` 先转模式 1、再转模式 3 把消息面板（控件 `panel`）
改指该槽；问题的光标用 `cursor_set(window, item)` 放在 No；一键消息的按钮标签为
`ok_label`。`text_slot`：声明了独立文字空间时必须正是家族的 status 编号
（`token_base + status_index`，2026-10-17 起归警告框独占，status 行已于 2026-10-10
取消，没有其他使用者），样式须在 `styles` 内；否则为小于 300 的原厂槽。两者都不能与
行、标题或入口共用。`panel` 是 core 用 `ui.widget_find` 在窗口里找到的那个带消息
文字的控件编号（Z 8 上是弹窗外框控件 0x4bac，消息字符串挂在它身上，不是消息元素
自己的编号）。`panel_text`、`cursor_set` 各带至少 16 字节原厂指纹。未声明时 `ui_caution` 返回未支持。

API4 的 `[services.program]` 可选声明目录枚举、原生输入、屏幕布局与活动服务。
缺少服务时对应接口返回未支持，不借用其他机型地址。`task_delay`、`fs_enum`、
`input_original`、`activity` 每个已声明原厂函数在 exec 都须有
`[service_fingerprints."program.<字段>"]`，并对照当前目标模块核对原字节。
函数不能落在 loader 预留区域。输入 callback slot 必须为8字节对齐的初始化 RAM，
原包该槽的指针须等于 `input_original`；银行数量1..3、每银行步长至少20字节，
拨轮保留缓冲最多32字节，按键不得越界或包含保留的退出位。
4:2:2屏幕宽度必须为正偶数，完整像素和 alpha 行须在声明平面范围内。
这些配置检查不证明原厂对象运行期长期归属或真机可运行。

`keys`：`[bank, mask]` 列表，按 `NLR_KEY_*` 位序（第 0 项 up … 第 9 项 disp），
最多 15 项；mask 为 0 表示该位未声明。开机 escape（按住 DISP 等于 SAFE_MODE）只读
第 9 项，读的是扫描对象当前值字（bank 记录的第 0 个 u32）。读取来源只有一个：声明了
`input_slot` 与 `input_object` 时为该对象，按 `banks` / `keep_bank` / `keep_mask`
核对；否则为 `[services.platform.scan].object`（Z 8：扫描回调由 `services.exit`
承载），此时 bank 须小于该 scan 的 `banks`，且不得含其 `keep_bank` / `keep_mask` 位。
有非零 mask 却两种对象都没有时拒绝（声明了却永远读不到按下）。原生卡机型的菜单检查点
在本次流程开启前、向卡询问任何东西（SAFE_MODE、STATE.NLS）之前读 escape；承载扫描的
hook（程序输入槽，或 `services.exit` 的回调，回调槽须已由原厂占用者填入）未装上前流程
等待，与 `[boot_hooks.autoload]` 等待输入 hook 相同。按住一次即锁存到本次开机结束。
这些检查不证明真机开机时按键已被扫描，也不代替 QEMU/真机的按住验证。

## 可选前台退出服务 `[services.exit]`

仅已核对的 `z8_worker_v1` 家族支持。整个表缺省时保留原 worker 路径，不安装物理输入 hook；声明时全部字段和依据必需，缺项不生成假成功适配器。当前生产 profile 不声明该表，本批只在隔离 QEMU profile 中启用。

- `input_callback` 是原厂 combined-input callback 的 RAM 指针槽；`bank` / `mask` 为 loader 保留的 MENU+DELETE 组合。`release_mask` 指定应观察的物理 MENU 释放位；`menu_release_code` / `menu_release_mapping` 对照原厂 normalized-key→action 表核对。该事件码也可能来自其他释放或原厂排空处理，不能单凭它判定 MENU 已释放；带条件菜单事件另核对本次真实释放记录。不制造输入或在输入任务绘图。
- `suspend`、`resume`、`terminate`、`restart` 指定四个已核对的原厂 task API；适配器从同一 worker 的 `+0` 读取 kernel task ID，复用 TCB、栈和 event flag，不删除或新建 worker。
- `[[services.exit.bodies]]` 沿用 `ExecutionBody` 的 `name/address/length/sha256`。要求 `suspend`、`resume`、`terminate`、`restart`、`input_register`、`input_worker`、`input_bank`、`worker_init`、`worker_create`、`input_action` 完整窗口；四个 task API 另需 `service_fingerprints."exit.<name>"`。除指纹外，实际字节还须核对 callback 槽引用、五字段 bank 布局、创建返回的 kernel ID 与登记 ID 一致，以及 release action 表引用。
- 所声明 worker 必须固定 CPU0（`task.core = 1`），优先级数值须大于 27，使 GUI25/Menu27 可抢占。原 `ter_tsk` 要求 caller 与目标同 PCB；`sus_tsk/rsm_tsk` 没有此同 PCB 拒绝，不能把它们当作终止证明。

前台退出先 suspend 再检查 SDK 调用计数；有进行中调用则 resume 并在调用返回后走原退出上下文，无调用的纯计算则必须实际 terminate→reactivate 同 worker，再复用清理。未确认静默或清理失败保留资源并拒绝重用。此声明和主机校验不代替 QEMU/真机退出、缓存一致性或重启验收；隔离 QEMU 的 4 块/3 常驻与 priority32 不改变生产 2/1、priority20。

## 可选开机检查点 `[boot_hooks.autoload]`

`call_site` 是一条原厂 `BL` 的运行地址，`callee` 是它调用的函数。这次调用由固件自己发起：每次开机早期就开始，之后反复执行，所在任务可以读卡。Exec 档把这条 `BL` 改指 `nlr_boot_autoload_checkpoint`（`core/boot_autoload.c`），后者自己调用原函数，并把结果原样返回；在两者之间给本次开机的自动加载流程一次开启的机会，使已启用的扩展不需要用户打开 NLoader 页面就能加载（PLAN 5.5）。

- 只有 exec 档安装。其他档位只核对两个地址 4 字节对齐、落在 XIP 文本内，不改动原厂调用。
- exec 档要求 `service_fingerprints."boot_hooks.autoload"` 固定被调函数入口；对照官方模块核对 `call_site` 处确为指向 `callee` 的 `BL`，构建时再核对一次原字节与目标。
- 已声明 `services.native_card` 的机型有自己的挂载检查点，不能再声明这一项。
- 被调函数不取参数，返回值原样交回调用方。检查点第一次运行时建立页面本来会建立的 runtime（worker、读入区、输入 hook），不读卡。输入 hook 装上之后——输入任务已经开始扫描，开机时按住的 DISP 才能读到——在固件循环的第 1、2、4……2048 次询问 MANIFEST，最多 12 次；MANIFEST 能打开才开启本次流程，之后由 worker 照常推进。卡始终不应答，就把流程留给页面访问，行为与没有检查点时相同。
- 开启流程和页面访问开启流程取同一个 driver，同一时刻只有一方能读取设置、写入中断标记。

## 可选平台服务 `[services.platform]`（ABI 7 / 8）

声明平台 API 各家族用到的原厂对象。整个表缺省时 ABI 7 / 8 的对应接口返回 -ENOSYS；每个子项也各自可选，缺哪一项哪一项的接口返回未支持，不借用其他机型地址。

- `controls`：`[名称, bank, mask]` 列表，最多 40 项，位于输入扫描对象中，因此要求该对象有承载者：`services.program` 的输入扫描 hook，或非其承载的机型（Z 8：`services.exit` 的每扫描回调）用 `[services.platform.scan]` 声明。名称取自 `enum nlr_ctl`（小写、去掉前缀，如 `ok`、`sub_press`、`fn_v`），每个名称只出现一次；一个控件可占同一 bank 的几位，两个控件不共用一位，bank 须已声明，也不得含保留位（`keep_bank` / `keep_mask`）。
- `[services.platform.scan]`：输入扫描对象的几何，只在承载者不是 `services.program` 的输入槽时声明。`bank_base` / `bank_stride`（≥20）/ `banks`（1–4，退出回调承载时 ≤3，因为原厂退出路径只转发三个 bank）给出 u32[5]（current/previous/changed/pressed/released）记录的位置；`keep_bank` / `keep_mask` 为相机永远能看到的位（电源等），`keep_mask` 不得为 0：程序接管按键时 core 把扫描里除保留位以外的位全部对相机隐藏（`core/platform.c` `nlr_platform_input_pass`），与承载者是哪个 hook 无关；没有保留位会连主开关一起隐藏（Z 8 上即 bank 0 的 0x200 `ID_SW0_MAIN`，曾表现为释放快门后黑屏），规则与 `services.program.keep_mask` 相同，对各机型一致。保留哪一位由 profile 依据固件证据声明，校验不猜测；`banks`、`keep_bank`、控件与按键的 bank 号超出声明或超出 core 的 4 个 bank 时报告并拒绝，不作为数组下标；`dial_offset` / `dial_bytes`（≤32，按 4 对齐）给出 s32 拨盘字；可选 `activity`（无参活动信号，需 `service_fingerprints."platform.activity"`）与 `object`（扫描对象本身，供开机 escape 读按住键；8 对齐的运行期 RAM，不得在模块段内）。声明本项时仍须有承载 hook（`services.program.input_slot` 或 `services.exit`）。`services.program.input_slot` 与 `services.exit.input_callback` 指向同一槽时拒绝：同槽只能装一个回调，后装者会替换前者（程序 hook 盖掉退出回调即失去 MENU+DELETE），不按安装顺序决定。
- `dial_words` / `dial_alt_words` / `dial_signs`：主拨盘、副拨盘、镜头环各一项。值为承载者 `dial_offset` 处 s32 字的下标加 1（0 表示没有）；`alt` 为同一拨盘的第二个字（手柄拨盘）；`signs` 为 +1 或 -1，表示顺时针计为正或负。
- `touch_slot`、`touch_original`、`touch_record_bytes`：触摸驱动报告槽（对齐的运行期 RAM）、原占用函数与记录长度（14–64 字节），三者同时声明；占用函数须有 `service_fingerprints."platform.touch_original"`。
- `eye_state`：眼控传感器状态字，对齐的 RAM，不得是固件文本。
- `gui_redraw`：可选，GUI 任务离开保持后让原厂 GUI 整屏重绘的无参函数，需 `service_fingerprints."platform.gui_redraw"`。
- `[services.platform.props]`：设置与状态存储。`groups` / `group_count` / `group_bytes` 与其中 `group_live_at`、`group_first_at`、`group_items_at` 偏移，`items` / `item_count` / `item_bytes` 与 `item_size_at`、`item_ram_at` 偏移，`ram_lo`..`ram_hi` 为值所在的 RAM 范围（指向范围外的条目记录一律不跟随）。组表与条目表从模块读取核对，使用中的组所指条目不得越过条目表。`setter`、`setter_blob` 为菜单写入单个条目（带类型标记的编号）与 blob 条目的原厂设置服务，分别需 `platform.prop_set`、`platform.prop_set_blob` 指纹。
- `[services.platform.card]`：文件系统卷表 `volumes`（运行期 RAM，不在模块内），`volume_count` 条、每条 `volume_bytes`，状态字节偏移 `volume_state` 等于 `mounted` 时卷可用；`letters` 依卡槽顺序给出盘符。
- `[services.platform.bundle]`：发布包位置 `address`（64 对齐）与 `size`，须是代码窗口内的模块文本，原包中全部为零；`nloader build --bundle` 才使用它。core 按运行地址读包，窗口映射到 DRAM 期间该地址读到的是开机复制的副本，因此必须同时声明 `[services.platform.bundle.copy]`，缺少时拒绝。
- `[services.platform.bundle.copy]`：把发布包带进 DRAM 的原厂开机复制。`source`（该块的复制源，即窗口块起点）、`block_bytes`（复制例程映射的块长）、`destination`（`source` 复制到的 DRAM 地址）、`stock_end`（原厂复制终点）、`low_site` / `high_site`（构造终点的 MOVZ `#lo` 与 MOVK `#hi, LSL #16` 的运行地址）、`register`（二者写入的 X 寄存器）、`stock`（两处原厂指令共 8 字节，先 MOVZ 后 MOVK）。校验：`stock` 须解码为该寄存器的 MOVZ/MOVK 对且值等于 `stock_end`，并与原包逐字节一致；两处在固件文本内、4 对齐、不在包区间内；块在代码窗口内，`source < stock_end <= address`，包区间末尾不超过 `source + block_bytes`（延长后的复制不写下一块的 DRAM 副本），且低于 2^32；声明了 `services.code` 时 `destination - source` 须等于 `alias_lo - text_lo`，整个复制目的 `[destination, destination + 包末尾 - source)` 须在别名带内；目的不得与模块映射段重叠，profile 中其他任何地址值（`services.code` 与本表自身除外）不得落在目的范围内。Exec 构建放入发布包时把两条指令的立即数改为包区间末尾（其余位保持原厂），复制长度随之变为 `包末尾 - source`；不放入发布包时不改。构建另拒绝任意两处改动重叠。这些校验只证明声明与原包一致、目的范围内没有其他已声明的使用者，不证明真机 DRAM 在该范围内无人使用。
- `[[services.platform.points]]`：钩子点 `name`、`target`、`expect`（入口四条指令字）、`args`（至多 8 个寄存器参数）及仅作说明的 `task`。入口须在代码窗口内、前 16 字节不跨缓存行，四条指令须位置无关（续接在 loader 中执行它们）；构建对照模块核对四个字，并为每个点生成续接。
- `[[services.platform.tables]]`：数据表 `name`、`address`、`size`（1–262144 字节）、`class`（`ram`、`text`、`pointer`、`repack`，须与所在区域相符）、`crc`（原厂字节的 CRC-32），`pointer` 类另有 `stock_pointer`（RAM 槽原本指向的只读数据）。给出原厂固件时，`crc` 须等于模块中原厂字节的 CRC-32（`pointer` 类按 `stock_pointer` 处的 `size` 字节，其他类按表自身字节；不在模块装载段内的 `ram` 表只由 core 在运行时核对）；槽位于模块装载的已初始化 RAM 时，其初值须为 0 或 `stock_pointer`。
- `[[services.platform.functions]]`：函数 `name`、`address`、`stock`（入口 16 字节），须在固件文本内并与模块一致。
- `[[services.platform.gui_turns]]`：原厂 GUI 由多个 service 各自在自己的任务上轮流运行的机型（Z 8 的 IDLE、LV、MSG、PLAY），每项为某个 service 循环每轮在等待事件之前执行一次的调用：`name`、`site`（该 BL 的运行地址）、`callee`（它调用的无参函数，返回值原样交回）、`stock`（`site` 处原厂指令的 4 字节）。`site` 须 4 对齐、位于固件文本内（声明了 `services.code` 的代码窗口时还须在窗口内），`callee` 在固件文本内，`stock` 须是目标等于 `callee` 的 BL；各项 `site` 互不相同，不得等于 `services.native_card.menu.call_site`（菜单检查点另有入口，菜单任务不作保持点），最多 8 项；GUI 轮次是保持点，须同时声明 `[services.platform.hold]`；构建时核对原包在 `site` 处正是 `stock`。Exec 构建把每个 `site` 的 BL 改指生成的入口 `nlr_model_gui_turn_<n>`，由 core 的 `nlr_platform_gui_turn(n)` 在启动保持的两半之间调用 `callee` 并原样返回；没有 runtime 时直接调用 `callee`，不创建 runtime。shell 或开机程序持有屏幕时，保持在这些 GUI 轮次上取得；从 Apps 打开 shell 后，要等菜单退出后已有 GUI 轮次运行、且原厂 GUI 完成一次提交（原厂即取景首帧），之后的轮次才保持，否则切换到取景会被卡住，释放后首帧被取消、屏幕全黑（Z 8 QEMU）。
- `[services.platform.hold]`：GUI 保持的时机与两个等待，core 对所有机型按同一规则执行，只读这里的声明。存在保持点（`gui_turns` 非空，或声明了 `boot_hooks.autoload` 开机检查点）时必须声明，缺项拒绝，不取默认值；没有保持点却声明时也拒绝。三个字段都必填：
  - `when`：从菜单打开 shell 后何时保持。`"immediate"`：下一个保持点就保持。`"settle"`：先放行，等某个保持点运行之后、原厂 GUI 完成一次被接受的提交（由 `[services.platform.commit]` 报告；之前的提交仍算菜单自己的），之后的保持点才保持。开机检查点与 GUI 轮次用同一条规则。`"settle"` 须同时声明 `[services.platform.commit]`。
  - `wait_ms`：`screen_claim` 等原厂 GUI 到达保持点的最长时间，超时返回 -EBUSY 并放开 GUI；500–10000，10 的倍数。
  - `scanout_stable_ms`：取得保持后，显示中的缓冲地址须连续这么久不变，`screen_claim` 才交出表面；0 表示不等；0–1000，10 的倍数。core 另有 2000 ms 的固定上限，各机型相同。
  profile 注释须写明数值依据。
- `[services.platform.commit]`：原厂 GUI 的提交调用，即提交观察器。`callee`（原厂提交函数，`int32_t (uint32_t mask, void *request)`，结果 bit 0 置位表示提交被接受）、`sites`（1–4 处调用 BL 的运行地址）、`stock`（每处原厂指令 4 字节，顺序与 `sites` 相同）。每处须 4 对齐、在固件文本内（声明了代码窗口时在窗口内），`stock` 须是目标为 `callee` 的 BL，各处互不相同，不得是 GUI 轮次或 `services.native_card.menu.call_site`；构建时核对原包在各处正是 `stock`。须有读取者：`hold.when = "settle"` 或 `[services.graphics]`，否则拒绝。Exec 构建把每处 BL 改指 core 的 `nlr_platform_gui_commit`：先原样调用 `callee` 并返回其结果，loader 自有画布正在渲染时这次提交归画布计数，否则被接受的提交通知保持（`nlr_runtime_commit_seen`）。`[services.graphics]` 的画布帧计数也经此观察器，要求 `callee` 等于 `services.graphics.submit`、`sites` 正好是 `display_refresh + 0x344` 与 `+ 0x4b8` 两处。
- `[[services.platform.devices]]` 与 `[services.platform.i2c]`：设备 `name`、`bank`、7 位 `address` 与 loader 自己的 `client`（`bank << 16 | 1 << index`，不得是相机自身客户端用的位）；`i2c` 的 `attach`、`xfer`、`detach` 为 `functions` 中的名称。

名称 1–63 字节，各列表内不重复。这些核对只证明地址与原字节一致，不证明原厂对象在运行期的归属或真机可用；运行期与真机能力须另行验证。

## 可选原生卡接线 `[services.native_card]`

`family = "z8_lowfil_rpc_v1"` 使用原厂 FILESRV 请求、独占回调槽、文件系统和卷锁、原回复观察、卷生命周期观察及原存储同步。地址、完整函数、数据布局与原调用关系均需对照官方固件核对；任何缺项拒绝构建。`journal_read_flags = 2` 是 STATE 专用的已核对读写打开方式，保证原 FCB 初始化完整；不得用于创建、截断或替换 MANIFEST、ENABLED 或程序读取方式。只有完整回复、同步与独立回读均确认，才更新保存成功状态。

具体源字段由共享 `NativeCardServices` 定义，包含请求、mutex、layout、mount/unmount、真实 wait、GUI 检查点与可选事件恢复。未声明时保持原读取接线。

两个卡槽遵循同一条规则。`storage.root` 可在 `A:` 或 `B:`；根的盘符须是原厂槽表自己的卷名之一（构建时从 `slot_table_init` 的指令和字符串读出核对）。

- **卡身份**：根的盘符经 `volume_index` 找到卷（卷号是挂载时第一个空闲卷项，不等于槽号），卷须已挂载（`volume_state_offset` 处为 1）、类型为 exFAT（`volume_type_offset`、`exfat_type`，构建时与 `volume_sync` 中读该字节和比较的指令核对），设备字段须恰好指向 `media_table` 中的一项；该项 `media_slot_offset` 处的 u16 是原厂槽号，须小于 `layout.slot_count`。同一张卡指：NLoader 观察到的挂载/卸载次数、卷号和 media 项都不变。不再读取任何驱动内部对象。
- **持久**：提交时先 `volume_sync`（只写文件系统缓冲，不到达设备 flush），再调 `slot_flush(槽号)`，最后独立回读。`slot_flush` 是原厂 FILESRV 写操作后调用的按槽 flush 分发函数（槽表项 +0x80）；构建时核对它与槽表安装 `slot_install`、槽表基址 `slot_table_set`、钩子注册 `flush_hook_register` 及分发器 `dispatcher` 中调用该钩子的指令一致。它在有设备 flush 的槽上执行设备 flush（Z 8 CFexpress：NVMe flush），在原厂不做 flush 的槽上返回 0（Z 8 SD）；返回值非 0 即保存不确定。
- `layout.slot_count`：原厂槽数，须与 `slot_install` 的循环上限和 `slot_table_init` 复制的槽描述数一致（Z 8：2）。
- 已删除的字段：`flush`、`layout.media_controller_offset`、`cfe_*`、`block_io_*`、`namespace_*`、`controller_*`、`identify_*`，以及完整函数 `flush`、`flush_command`、`cfe_flush`、`namespace_init`、`controller_init`、`controller_identify`。旧配置含这些字段时会被拒绝（未知字段）。

当前验证范围为 QEMU 中固定的 NVMe 卡镜像（A:）；B: 只有静态核对和主机测试，未在 QEMU 或真机运行。物理拔卡、目录损坏被当作不存在、文件系统整体掉电恢复仍未验证。

## 可选绘图诊断 `[services.paint]`

`family = "z8_text_paint_probe_v1"` 保留原文字绘制的四参数及返回，使用独立只读服务表。`mode = "trace"` 记录真实绘制；图案模式另核对原目标记录与实际表映射。文字 draw 对象不得解释为 bitmap 描述。地址、完整原函数、原 BL、真实任务名称、窗口和绘图目标映射均需官方字节核对。

`family = "z8_text_native_bitmap_probe_v1"` 使用另一条原厂位图转换链。`native_bitmap` 显式声明转换、绘制、目标设置/恢复和源格式、目标格式、混合方式四张表；每段原函数、原调用及实际表值均须独立核对。旧入口的检查不放宽，也不接受将两条链的记录混用。表里的格式枚举不直接当作 GPU 格式或像素显示证明，实际命令和画面另行验收。

诊断只在已确认的原 GUI 任务与 NLoader 窗口绘制，返回后重新核对同一线程、窗口、根控件三元组、目标和尺寸；像素源保留整个会话。它不开放 SDK 的图形接口，也不表示 OpenGL 或 Doom 已可运行。
