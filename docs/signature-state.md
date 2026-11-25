# 签名业务状态机、当前进度与验收

唯一权威标识：`SIGNATURE-STATE`；更新日期：2026-11-25。

本文件是签名业务状态、进度和验收的唯一现行入口。完整 Goal **未完成**。
旧 HANDOFF、报告、输入快照及 Git 历史只作历史证据，不是现行状态入口。
COORDINATION 只记录调度和操作，不另立业务状态机。
原长篇过程记录已由 Git 历史及既有 before/input-versions 快照保留，不再复制归档。

## 1. 目标、基线和职责

目标：固定 QQ 9.9.33-52230 源码及当前候选，完成材料 B 全链：
真实本方请求 → 真实关联回包，或来源合法通知材料 → 校验解析 → 安装 → 更新发布 → 选材 →
**同一有效 runtime 的后续 SIGN 实际消费新材料**。
SDK、Token、Qimei、通知回调、protocolTokenHex 异步消费者和空值语义、UIN、
配置、刷新、失败、取消、关闭及所有权均在签名验收范围内。

- 137之前的代码基线：`99611c569deb1688a248734ec7d3b31e7f9cb8c7`；本次137实现的输入与证据见 [W]。
- 完整137正常域候选已冻结；CORE 10 pure 与4项 legacy、WMI 5项与 Windows 5项检查按绑定证据复用 [W]。
- wrapper SHA256：`63112ab9161e127f5f7e17998a7196e143808923fb54cbbf7b4e21426187a5f0`。
- qimei SHA256：`a6100bce0de79ea52fe80a85acce2c24c615306fd3c2dedd119b51b0f26ebcc6`。
- 用户优先本方协议自行产出；不能以历史抓取值或伪造 receipt 替代生产链。
- Claude Opus 领导治理与方案取舍，已多次实际咨询；不是技术源码核验者或逐提交审批人。
- Root 负责工程协调、Git 和唯一调度记录；技术结论由职责执行者提供证据。
- 登录算法由另一负责人维护；签名侧核对会话交接与 SDK 消费，不接管登录算法。
- 既有实际 ONLINE 只属于 experimental51728/protocol12，不可重标为 52230 互操作。

## 2. 阅读证据的规则

`A` 是本地证据根：
`G:/Hackergame/.codex-workflow/reports/pmhq-analysis-20261010/signature-audit-20261119`。
下文 `A/…` 是安全报告定位，不是发布资产或运行时依赖。
不把原始密钥、UID/UIN、主机名、profile 内容或私人捕获路径写入本文件。

| 证据层 | 能说明什么 | 不能替代什么 |
| --- | --- | --- |
| 固定源码 | 语义、调用顺序、依赖与边界 | 当前代码实现、实际执行 |
| 当前代码 | 接线和可表达行为 | 执行成功、真实来源 |
| 受控模型 / pure | 明确输入下的分支和计算 | 真实 OS、COM、网络 |
| 真实本地执行 | 所绑定本方 OS 输入和持久化 | 服务器材料、网络接受 |
| 真实网络 | 所绑定请求、响应与会话 | 解析安装、后续消费 |
| 同 runtime 消费 | 有效 owner 内的更新到 SIGN 因果链 | 其他未覆盖业务分支 |

PASS 只适用于报告绑定的输入、分支和环境；源码变化后按影响判断能否复用。
旧内部 A2 等里程碑、组件 receipt、输出非空或长度改变均不等于完整 SIGN 完成。
下图与安全不变量是**逻辑目标契约**，未证明的边不得理解为已实现或已实测。

## 3. Runtime 生命周期（目标契约）

```mermaid
stateDiagram-v2
    [*] --> Uninitialized
    Uninitialized --> Configured: 固定版本与显式配置
    Configured --> LocalReady: 本方输入与所有权就绪
    LocalReady --> Active: 会话及合法业务入口就绪
    Active --> Active: 请求、通知、刷新与SIGN
    Configured --> Failed: 初始化失败
    LocalReady --> Failed: 依赖缺失或真实失败
    Active --> Failed: 不可继续的业务失败
    Active --> Closing: 关闭runtime
    Failed --> Closing: 保留失败原因后清理
    Configured --> Closing: 关闭runtime
    LocalReady --> Closing: 关闭runtime
    Uninitialized --> Closing: 放弃构造
    Closing --> Closed: 停止消费者并释放自有资源
    Closing --> CloseBlocked: 仍有租约或关闭失败
    CloseBlocked --> Closing: 依真实状态协调
    Closed --> [*]
```

| 状态 | 进入条件 / 数据 | 退出条件 | 当前证据 |
| --- | --- | --- | --- |
| Uninitialized | 显式新 owner，尚无初始化成功资格 | 有效配置或关闭 | Qimei 局部 cold 合同成立 [Q] |
| Configured | 版本、UIN、配置及 owner 身份明确 | 完成本地依赖或真实失败 | 局部配置模型；整体待验收 |
| LocalReady | 完整本方请求输入与生命周期可用 | 合法会话和入口就绪 | a6返回137、codec及SIGN结果；输出结构已核、算法未证，close失败 [L6] |
| Active | 当前会话可用且 runtime/epoch 有效 | 正常运行、失败或关闭 | 正常全 SIGN/SSO SDK 交易未证明 |
| Failed | 保留原错误、阶段和可恢复性 | 合法恢复或关闭 | key25 真实失败及恢复一例 [D] |
| Closing | 禁止新任务，处理已有消费者和租约 | 资源回收或明确 CloseBlocked | 历史局部 close，不覆盖全生命周期 |
| Closed | 所有自有资源、任务均退出 | 终态；新工作需新 owner | 当前完整 B 路径未证明 |
| CloseBlocked | 资源仍被使用或清理失败 | 核实后继续清理 | 不得伪报 CLOSED |

目标安全不变量：身份不得跨 runtime 拼接；关闭后不得发布材料或继续消费。
请求取消须按该请求阶段及副作用契约处理，区分已发送、已回包、已安装、未开始；
取消请求不要求关闭整个 runtime，不能把未知副作用改写为成功。
关闭失败须保留仍被租约依赖的资源；这些是待验收约束，非全局已验证结论。

## 4. 材料 B 与 SIGN 生命周期（目标契约）

```mermaid
flowchart TD
    Input[本地请求输入准备] --> Request[真实本方SDK请求]
    Request --> Reply[真实回包]
    Notify[来源合法的真实通知材料] --> Parse
    Reply --> Parse[校验与解析]
    Parse --> Install[安装到有效runtime owner]
    Install --> Publish[发布新材料及更新身份]
    Publish --> Select[后续SIGN按真实分支选材]
    Old[仍有效的旧材料] --> Select
    Select --> Consume[同runtime SIGN实际读取新材料]
    Consume --> Done[该链业务验收成立]
    Publish --> Refresh[到期或真实刷新条件]
    Refresh --> Request
    Parse --> Failure[失败：保留原因及旧状态语义]
    Request --> Failure
    Refresh --> Failure
    Failure --> Boundary[无合法恢复依据时停止]
    Cancel[取消请求] --> RequestState[按请求阶段及副作用契约处理，核实在途状态]
    Close[关闭runtime] --> Quiesce[停止新增与异步发布，核实在途状态]
    Quiesce --> Release[按所有权清理或报告关闭阻塞]
```

| 材料状态 | 进入条件 | 退出条件 / 数据 | 当前证据 |
| --- | --- | --- | --- |
| InputPrepared | 真实本方输入完整 | 编码并经所需 SIGN 发请求 | a6真实137、codec及SIGN结果已返回；未发送网络请求 [L6] |
| RequestPending | 合法 session、完整载荷、真实发送 | 真实响应或明确失败 | 正常 SDK 交易未证明 |
| ReplyReceived / NotificationReceived | 真实请求关联响应或来源合法通知材料成立 | 直接校验、解析或拒绝 | 未证明完整目标路径 |
| Parsed | 格式和业务条件满足 | 安装到正确 owner | 单独 parser 不能算安装 |
| Installed | 新材料写入当前有效 owner | 发布并可供选材 | 尚无完整真实证据 |
| Published | 更新对实际消费者可见 | 后续 SIGN 真实选中 | queue/cache 写入不充分 |
| Consumed | 同一有效 runtime 后续 SIGN 读取新材料 | 记录因果证据，完成该链 | 尚未证明 |
| RefreshPending | 真实刷新条件、有效 owner | 更新成功或真实失败 | warm 行为与失败分支待全链验收 |
| Failed / Cancelled | 原因及在途副作用可诊断 | 仅按合法契约恢复 / 关闭 | 不用默认值伪装成功 |

SIGN 既是 SDK 交易的前置依赖，也是新材料的后续消费者；不能循环假定二者已成功。
本地设备值、17B、Qimei、SDK metadata/token、protocolTokenHex 是不同数据来源。
关系未证时不得等同，不能用其中一种填补另一种缺口。
刷新失败或空值是否保留旧材料须逐类遵循已核对契约，不能套一个全局兜底。

## 5. 当前已知进度与边界

### 本方本地输入

- `fc79bb8` 的 own cold 17B producer 使用真实 OS、12×4 RNG、6 次 steady 及实际容器地址。
  独立观测重算一致，资源归零 [M]；它是本地加密输入，不是服务器新材料。
  不得拼接不同 PID 捕获来声称 sameRuntime。
- `9af1040` 的 key25 本方 producer 实际使用 494 对象名、1 display 及已有 CAPI method6。
  完整 value/checkpoint 的独立数据流重算一致 [D]；原 QQProtect 与原文件未改。
- key25 a1 因错误 `_rand_s` 真实失败并留下 0B checkpoint；修为 canonical `rand_s` 后，
  a2 在同 root 恢复为有效 1028B，未删状态或另造 cold [D]。
  RESULT 的初始 offline not_run 字段不替代随后 DATAFLOW 的独立重算结果。
- CAPI method5 创建/null DACL 未授权、未 actual；profile fallback 未 actual。
  不得把权限拒绝吞为普通失败后强行走 fallback。

### 同owner共享设备值

- `owner.get_own_device_value() -> bytes` 经 WindowsSigner 原 `_operation`、PrimarySigner `public_call`
  调用 `caller_device_value(runtime)`，返回 owning bytes；它与正常 SIGN 使用同一 SLOT6751838 cached_value/1BE77F0。
  业务collector必须使用该getter返回值作为record25输入，不把provider d/token当设备值，也不注入factory缓存。
- actual a2 standalone producer 返回success并不证明其结果已发布到owner singleton；standalone own-state与owner client根不同，
  时间与rand_s header也可不同。当前结论是共享未绑定、可能不同，未观察到实际mismatch；既有独立producer算法证据仍有效。
  薄getter在a3已返回；a5返回137但SIGN未完成。Native819未覆盖输入仍保留Boundary，不绕guard。
- 存储仍沿用owner factory的显式DirectoryCheckpointStorage root；实际运行须绑定已有可信ownG root并保持
  `allow_capi_creation=False`。既有API允许显式opt-in，路径校验并非全局G盘限制；getter未增改该政策。
  既有WindowsCapiObservations在禁创建时拒绝0x68/GenKey及安全描述符/ACL/SetProvParam创建路径。

### Qimei 与 SDK 缓存

- `99611c` 的 QimeiGetterOwner 显式 UNINITIALIZED：ready0、module0、70B cache 零。
  get 合法 empty，不入 DLL、不 auto-init；不是原 QQ 正常 startup 或已初始化 a2 [Q]。
- fresh SDK config58 的源 constructor 独立零写；非空才 copy，empty 不清 warm 旧值。
  共享 SDK records27/28/89 已接入，3 pure PASS；不是完整 Qimei 或真实服务器接受 [Q]。
- initialized b 主段取 main record1、最多36B；aux32 的 690A5 未闭合。
  CONFIG refresh 两次，startup/cache 恢复另属 a2；这些未知仍是 Boundary [Q]。
- 全新 SDK metadata cache pair24 由真实源 ctor 清空；成功解析且 token 非空才更新。
  失败或 empty 不清 warm metadata；它不等同 Qimei、17B 或 protocolTokenHex [S]。

### 完整137与 Windows composition（正常域源码及受控集成已通过独立 review）

- CORE 最新执行者报告：受控 normal cold 8 WMI row/longString、
  真实 parser 选择非空 adapter、WLAN22 cold 默认1、ordered137 到既有 encoder 已贯穿。
  warm 仍 refresh；正常域源码及受控集成已通过独立 review，CORE 10 pure 与4项 legacy 检查成立 [W]。
  这些受控结果不是 genuine137 或真实 OS 采集证据。
- Windows composition 已接入既有 random_device/ANSI helpers，5项纯检查成立 [W]；
  actual a2 已进入初始cold snapshot，但止于 GetCursorPos 观察缺失，未取得真实137 snapshot。
- WMI 有5项 fake ABI 检查及独立 review：invalid BSTR 不得 clear，失败 clear 不得 retry。
  它们不证明真实 COM 已执行；阶段安全证据在 [W]。
- adapter ordinary failure 域未实现：ipconfig/all 备份 parser 与第三 backend 仍未知。
  primary 返回 AL 非零不触 fallback；真实 OS 触发未覆盖域时应 Boundary，不能强成功或空 adapter。
- identifier keys72..76 涉及 delete installStatus、3轮补读、FILETIME、randomdevice/MT、
  硬件 strings，以及 raw/digest/double 生成和配置/cache/installFlag 写入 flush。
  OWN_STORES 使用显式 G 配置/XML cache 与本方 HKCU namespace，不冒充原 QQProtect。
  actual a2 未完成137；原 HKCU Tencent QQProtect 删除或写入不在本方路径授权内。
  XML 声明/comment 等未支持输入保留 Boundary，不伪装为空。

### 本方 cold provider/bootstrap 入口

- `open_windows_signer(..., own_business_config={'uin': uint64_int, 'machine_id': persistent_bytes})`
  显式选择本方 cold profile；`host_profile_string` 必须为 `b'V1_WIN_NQ_9.9.33_52230_GW_B'`，
  必须使用 direct backend 与 owned worker bridge；与 outer login、diagnostic metadata 互斥；可选 construction hook 保留在业务初始化前执行。
- 从本方 UNINITIALIZED Qimei getter 取得合法 empty，固定源默认 QUA、规范 UIN ASCII、
  required 非空 NUL-free machine_id 构建既有 ProviderInitializationMetadata；不恢复原 QQ effective profile。
  machine_id 是本方持久 caller 配置，provider 与后续 SDK27/login handoff 须保持同值。
- 业务及 diagnostic 分别调用共有 provider-init/Host129 primitive，保留公共 owner operation fencing、
  pending bootstrap 检查及失败清理；不调用 diagnostic prepare 后重标状态。
  actual a2 的业务初始化已返回（控制流证据），不证明 SDKReady、材料安装或 actual SIGN。
  refresh/complete 仍用原公共入口；notify/update 公开映射仍未证明。

### 本方独立 cold SDK request component

- own-business owner 可经 `initialize_own_sdk_request(request_capi=..., clock_inputs=..., random_environment=..., state17_owner=..., transport_context=...)`
  一次绑定，再以 `create_own_device_request(records)` 经原公共 operation fencing 构造请求。
  clocks 显式包含 wall_seconds/monotonic_ns/clock_ns；生产环境借用 SystemRequestCapi、真实时钟及
  WindowsDeviceValueEnvironment.random_bytes(4) 的 canonical rand_s；不使用测试熵或 secrets 替代源证明。
- component 自持 fresh flags0、counter1、zero168B material及连续 MT；不是原SDK receiver/pending资格，
  不访问 receiver_state、不创建原pending、不重置warm metadata。绑定确认实际SDK cache+24 empty，构造时重读当前metadata及feature46。
  命令及getToken解码沿用固定源语义；先编码并固定decode snapshot，再type选择，最后取旧SDK序号并递增。
  编码/type失败不提前消耗SDKcounter，已发生material/MT变化不回滚；当前transport None不表示网络可用。
  feature46 ON要求同owner state17 producer及实际PID/clock/formatter状态，OFF不调用cipher。
- clock/CAPI/observation接口为借用，不由component关闭；client关闭component逻辑生命周期。
  a6已完成实际请求codec，且同owner sign_result已返回并保存artifact；独立输出结构已核，内容/算法未证，notify/update及完整Goal仍未完成 [L6]。

### actual a2 与 cursor 窄绑定

- actual a1 startup 失败历史保留，不重标为业务完成。actual a2 已返回 owner factory/business初始化、
  SDK cold fields 校验、key25 success、17B producer 和 public request初始化；这些是调用返回证据，
  不是每份材料独立重算。collector已进入初始cold snapshot，GetCursorPos缺观察使其停止；137未完成，encoder及policy2 SIGN未到达。
- 独立 collection `take(data, 'GetCursorPos', ())` 现绑定 lazy user32 GetCursorPos(POINT*)：
  native BOOL + 成功8B POINT（两个signed LONG32）；BOOL0仅返回空effect，不把默认缓冲当真实坐标。
  GetLastError保留在cursor observation；composition负责其自有DLL引用关闭。新增绑定仅经mock FFI及真实consumer相关copy语句检查，未actual查询光标。
- a2所有owned进程已reap、CIM剩余0；close路径被调用，但逐资源关闭未instrument，状态unknown，不能报资源0。
  STATE-SUPPLEMENT仅检查当前attempt树，未识别ownstate/config/cache文件；持久材料可复用性unknown，
  不证明全局不存在，不据此任意创建fresh状态。后续实际运行须另有具体授权并核对可信状态。
  安全证据：`A/own-business-bootstrap-a1/independent-live-a2/{BOUNDARY.json,STATE-SUPPLEMENT.json,RESULT.json}`。

### actual a3 FILETIME frontier

- actual a3 的 `owner.get_own_device_value()` 与 GetCursorPos 已返回（trace控制流证据，非独立材料验证）；
  collector cold snapshot下一处 GetSystemTimeAsFileTime 在composition.filetime因返回形状检查触发InputError。
  真实值未投影，不能断言观测了错误时间。137、encoder、policy2 SIGN均未到达。
- 源码定位：既有native backend按void ABI写入8B缓冲，返回 `(None, (raw8,), error)`；
  SYSTEM/PROCESS ports保留单缓冲tuple，composition原先错误要求flat bytes。filetime现严格解包一个8B输出effect，
  仍要求void None、真实8B，不填零、不更改底层ABI或失败语义。新增mock kernel FFI→backend→SYSTEM→PROCESS→composition检查通过，未actual运行修复。
- a3三个owned进程RC1并reaped、CIM剩余0，515项输入未变；close路径调用但逐资源关闭unknown。
  证据：`A/own-business-bootstrap-a1/independent-live-a3/RESULT.json`。
  后续须另有具体GO并复用可信ownstate，继续遵守ownG与 `allow_capi_creation=False`；完整Goal仍未完成。

### actual a4 与 printf options0x24 有限支持

- actual a4 collector已返回137条且count检查通过；这只是控制流及数量证据，未独立验证内容/顺序。
  actual feature46为ON，record cipher在formatter options非零guard停止；编码未完成，policy2 SIGN未到达，逐资源close细节unknown。
- 固定源printf options存储正常attach为OR0x24；RecordCipherHost现仅接受exact int 0或0x24。
  legacy-wide与standard-rounding bits对当前完整容纳的窄 `%d` signed32输出不改变字节/长度；
  其他options、其他格式、容量不足仍Boundary，不扩大截断语义。完整cipher受控0/24输出一致。
- own request ON路径调用既有 `primary_crt_stdio_options.read_options(runtime)` 获取当前qualified值，
  保留birth/backing/phase/liveowner-thread-epoch检查，不直接load或默认0。修复仅pure验证，未actual运行。
  源依据：`A/mmkv-stdio-state/RESULT.md`、stdio-getter-consumers、stdio-options-ref-closure；
  SDK10.0.26100 corecrt_stdio_config.h的04/20位定义。完整SDK/Token/Qimei异步链及Goal仍未完成。

### actual a5：请求codec完成，SIGN与正常close仍未完成

- a5实际返回137、request encoder完成，并以同owner的request.command/body进入SIGN；
  701774整数formatter因正常global options0x24被拒绝，SIGN未完成，未取得完整SIG。
- 后续OFFLINE-DATAFLOW已核对137 key顺序/schema/types、两个records快照相等、cold command选择、
  初始ordinary SDK序号、immutable168B decode snapshot及body/encoded wire结构关系。
  它不证明独立body解密、记录值语义、服务器接受或完整签名；初始RESULT中的offline not_run不替代后续检查。
- a5 cleanup实际因缺少unsuspended lease失败，最终进程AV退出（-1073741819）；CIM0仅证明进程消失。
  资源释放为failed/unknown，AV因果仍unknown。源码核对定位：stop_checkpoint在suspend内部restore，
  creator_closing在closing lease退出后restore，均不满足既有lease语义。
- 当前close候选只调整两处restore顺序，不改HostServices验证/counter、回调重试或模块释放规则；
  2个pure方法/7个subcase及独立review通过，已随6b4f6f交付；a6未报告旧lease错误，但close仍失败，不能据此宣称AV因果已闭合。
- main701774现从qualified read_options取得GLOBAL exact0/0x24（wrapper有效2/26），
  仅支持精准窄 `%d` signed32、完整容纳、非重叠及NUL语义；未知位/格式/截断仍Boundary。
  3项pure及独立review通过，已随6b4f6f交付；a6的SIGN返回事实另见 [L6]，原完整stdio fixture的PTD失败不是pass。
- 证据：`A/own-business-bootstrap-a1/independent-live-a5/{RESULT.json,OFFLINE-DATAFLOW.json}`、
  `A/own-main-sign-printf24-a1/`、`A/own-failed-close-lease-a1/`。
  a1至a4原记录及证据保留；该离线候选当时不包含C外crashhandler支持，也不授予后续运行权限。

### actual a6：SIGN返回且结构已核，response cache material String关闭失败

- a6 full137及request编码已返回；同owner `sign_result(request.command, request.body)` 已返回，
  结果artifact已保存；offline只读pickle opcode核对确认为PrimarySignatureResult，非pending/None或空物料 [L6]。
  source字段sign96B、extra12B、token141B均为非空bytes，各≤255B；当前类型无protocolTokenHex字段，外部映射未验证。
  这仅证明实际返回及source字段结构契约，长度匹配不等于SIGN算法正确；内容/算法语义及server接受仍unknown。
- 首个cleanup失败位于provider cache destroy_cache → _destroy_string → current runtime `_free_allocation`，
  报告待释放对象不是当前runtime拥有的allocation。已定位为provider response cache+0x18的material value String，
  不是singleton device value本体。源契约要求long>22B独占deep-copy或explicit move；当前首要unknown是该payload的分配→发布→临时回收身份链。
  main temporary cleanup可能回收已发布persistent payload仅为疑点，尚无allocation身份链，RCA unknown；保留_free_allocation guard。
  不绕freeguard，不把进程消失当作正常close；资源状态FAILED/UNKNOWN。
- 最终退出-1073741795（STATUS_ILLEGAL_INSTRUCTION）；三个owned进程均reaped、CIM0。
  faulthandler文件0B未给出具体nativepoint；fatal原因unknown，不能断言由freeguard导致。
  a6未报告旧lease错误，但不能推广为所有关闭路径已正确。
- a5 offline [L5]的137 schema/order/types、快照相等、request cold command/seq及immutable168B结构证据
  仍只适用于其绑定artifact；a6 records schema/order未另核。记录值语义、独立body解密、server接受仍unknown，不能由SIGN结构验证推导。
  本地“SIGN返回＋正常close”双条件仅前半的控制流达到，完整材料更新→安装→后续SIGN消费Goal未完成。
  Native a7 HOLD；未获新GO不得再次实际运行。

### SDK、异步消费者与登录

- 四 SDK 命令均消费完整 payload；status0 也加密 payload，没有纯握手空 body 捷径。
  四者均 policy2 SIGN，无合法免签证据；codec 可表达 None 不等于许可 [S]。
- protocolTokenHex 的实际异步消费者、Native12 或 V8 绑定未闭合。
  None、空、非法值不得默认补值；SDKToken 与 Qimei 等关系未证。
- SsoTransport 代码存在不等于整体 SDK、真实网络、安装到 next SIGN 已验收。
- 登录独立 owner 的历史 ONLINE 仅属于 experimental51728/protocol12。
  旧 a6 WMI checkpoint 失败既不证明 native Next 永久挂死，也不证明正常 own137 已通过。

## 6. 原范围验收矩阵

| 范围 | 必须取得的业务证据 | 当前状态 / 最早缺口 |
| --- | --- | --- |
| 固定版本及当前候选 | 固定52230源、候选身份与执行绑定 | 源码基线固定；137正常域候选已冻结 [W] |
| 本地17B | 真实输入、独立重算、资源退出 | 局部真实 PASS [M]，非材料B |
| key25 | 完整生产、持久恢复、真实分支 | method6 局部真实 PASS [D]；其他分支未 actual |
| 完整137 | 正常采集到编码的真实完整输入 | a6返回137；a5 offline schema/order/types通过；a6 records schema/order未另核，值语义未独立验证 |
| SDK请求 | 完整载荷、所需 SIGN、真实发送 | a6本地codec及SIGN结果结构已核，算法未证/未发送；正常全交易未证明 [S][L6] |
| SDK回包 / Token | 真实关联回包、校验、解析、安装 | 缺真实闭环，不以 metadata 空代替 |
| Qimei | cold / initialized / restored 各自真实契约 | cold 局部受控 PASS [Q]；完整更新未证明 |
| 通知与回调 | 来源合法、注册、分发、生命周期、安装 | 完整真实通知路径未证明 |
| protocolTokenHex | 异步真实消费者及绑定、空/非法语义 | Native12/V8 等未闭合 |
| UIN与配置 | 显式配置到实际消费者，身份一致 | 完整运行证据不足，不输出原值 |
| 刷新 | 真实触发、更新、失败保旧语义 | 仅局部源/受控证据 |
| 失败与恢复 | 原错误可见，同对象恢复且不伪成功 | key25 一例 [D]，不外推全域 |
| 取消 | 在途状态明确、停止异步副作用 | 全业务路径待验收 |
| 关闭与所有权 | 有序停止、自有资源退出、租约正确 | a6 response cache material String unowned allocation关闭失败，资源FAILED/UNKNOWN；fatal原因unknown [L6] |
| SIGN消费 | 同runtime选中新材料并实际读取 | 未证明，最终关键门禁 |
| 登录交接 | 合法会话交给签名owner，版本不混淆 | 另owner；51728不证明52230 |

## 7. 最早断点、下一步与完成标准

当前本地里程碑仍要求：**同owner本地SIGN返回并验证输出，以及正常close完成**，运行范围NO_NETWORK。
a6已返回SIGN结果并保存artifact，独立输出结构已核，内容/算法语义未证；close仍在response cache material String销毁失败 [L6]。
首要unknown是该payload分配→发布→临时回收ownership身份链；temporary cleanup疑点尚非RCA。
fatal非法指令原因unknown，不把freeguard错误与fatal建立未经证明的因果；保留原guard。
先完成只读定位和对应最小修复/有效验证；Native a7 HOLD，须Root新的明确GO才能再运行。
旧 `A/own-full-device-records-a1/live-prep/PREPARED.json` 仍为prepared=false，不用于真实GO。
不得把独立component当作source native pending/SourceEpoch receipt资格，也不以进程消失替代正常close。
真实网络、Token/Qimei异步消费者及空值、UIN/config、刷新失败、取消和完整关闭验收仍未完成；两图目标契约保持。

仅当全部适用验收成立，且以下连续证据绑定同一有效 runtime，才能把完整 Goal 标为 complete：

1. 固定源与实际候选可识别，本方输入、UIN/配置、会话及所有权合法。
2. 取得真实本方请求的关联响应，或来源合法通知材料；分别保留请求关联或通知来源证据及失败语义。
3. 该真实关联响应或合法通知材料直接经校验解析，安装并发布到该 runtime 实际材料 owner。
4. 后续正常返回的 SIGN 真实选中并读取新材料；证明因果关系而非长度比较。
5. 适用刷新、空值、失败、取消、关闭及异步所有权验收均成立，资源状态可核对。

## 8. 安全证据索引

- [M] `A/own-device-mix-producer-a1/independent-live-a1/RESULT.json`：本地17B实际与重算、资源0。
- [D] `A/own-device-value-producer-a1/rev2/independent-live-a2/RESULT.json` 及 `DATAFLOW.json`：
  本方 key25 实际恢复与后续独立重算；两个报告分工不同，不能只读初始 not_run 字段。
- [Q] `A/OWN-QIMEI-GETTER-CONTRACT-20261124.md` 与
  `A/own-qimei-cold-record-input-a1/{RESULT.json,checks.txt}`：源语义与3项受控检查。
- [S] `A/OWN-SDK-GENUINE-PAYLOAD-DEPENDENCIES-20261124.md`：载荷、SIGN依赖及缓存语义。
- [L5] `A/own-business-bootstrap-a1/independent-live-a5/{RESULT.json,OFFLINE-DATAFLOW.json}`：
  a5实际阶段、cleanup失败及其后offline结构检查；不验证记录值/独立body解密/server。
- [L6] `A/own-business-bootstrap-a1/independent-live-a6/{RESULT.json,OFFLINE-SIGN-STRUCTURE.json}`：
  a6同owner SIGN返回及source字段结构已核、response cache material String销毁失败、非法指令退出；算法/server及fatal原因unknown。
- [W] `A/own-full-device-records-a1/{core,windows,wmi}`：正常域源码及受控集成已通过独立 review；
  检查仅按冻结输入及各报告覆盖复用，不代表 actualOS 已运行；不得读取或发布 raw 捕获补正文。

本次文档修订仅核对现行契约与执行者证据，不执行代码、native、网络或旧测试。
