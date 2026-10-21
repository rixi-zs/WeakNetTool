// =============================================================================
//  weaknet_core.h —— WeakNetTool 共用引擎（命令行版与 GUI 版共用同一份实现）
// -----------------------------------------------------------------------------
//  这一层只做“引擎该做的事”：
//    * 过滤器构造与校验
//    * 管理员权限检查
//    * WinDivert 句柄生命周期、收包-丢弃循环、统计、优雅停止
//    * 参数（端口 / 时长 / 进程名）的通用解析校验
//    * 基于进程名的选择性丢包：进程名 → PID → 该进程占用的本地端口集合
//  它不做任何界面输出：所有提示/日志通过 LogFn 回调交给前端（CLI 打印到控制台，
//  GUI 追加到窗口里的日志框）。这样“怎么显示”和“怎么丢包”彻底解耦。
//
//  两种工作模式：
//    (A) 过滤器模式（默认，cfg.processName 为空）—— 传统用法：
//        WinDivert 过滤器直接选出要丢的报文，收到即丢弃、绝不回注。
//    (B) 进程模式（cfg.processName 非空）—— 选择性丢包：
//        过滤器放宽为“所有 TCP/UDP”，同时由端口刷新线程周期性调用
//        GetExtendedTcpTable / GetExtendedUdpTable，把目标进程占用的本地端口
//        抄成 std::unordered_set<uint16_t>；收包时命中该集合的报文直接丢弃，
//        其余报文一律 WinDivertSend() 原样放行（WINDIVERT_ADDRESS 保持不变）。
//
//  线程模型（与 CLI 版行为完全一致，实测验证过）：
//    * 工作线程：跑 WinDivertRecv 循环，命中即丢弃；进程模式下未命中则放行。
//                循环结束后负责收尾（见下方注释）。
//    * 看门狗线程：收到停止请求后 WinDivertShutdown + CancelIoEx + 关闭句柄。
//                真正能唤醒“已挂起的 recv”的是最后一步：关闭句柄会触发驱动
//                文件清理例程里的 WdfIoQueuePurge(read_queue)，它会无条件完成
//                队列里所有挂起的读请求。
//    * 计时线程：--duration 到期后请求停止（没有报文时也照样准时退出）。
//    * 端口刷新线程：仅进程模式启动，每 cfg.processRefreshMs 毫秒重算一次
//                “PID + 端口集合”。进程重启换了 PID、开了新连接都能自动跟上。
//  前端只需要：Start() → 轮询 GetStats() 显示状态 → Stop()/WaitForStop()。
// =============================================================================

#ifndef WEAKNET_CORE_H
#define WEAKNET_CORE_H

#include <stdint.h>

#include <string>
#include <unordered_set>
#include <vector>

namespace weaknet {

// -----------------------------------------------------------------------------
//  常量
// -----------------------------------------------------------------------------
extern const char* const kToolName;
extern const char* const kToolVersion;
extern const unsigned long long kDriverMajor;    // 期望的驱动主版本（2）
extern const unsigned long long kDriverMinor;    // 期望的驱动次版本（2）
extern const size_t kMaxPortCount;               // 端口数量上限（过滤器长度考虑）
extern const unsigned kMaxPacketLen;             // 单个 IP 报文最大长度

extern const unsigned kDefaultProcessRefreshMs;  // 进程端口集合默认刷新周期（毫秒）
extern const unsigned kMinProcessRefreshMs;      // 刷新周期下限
extern const size_t   kMaxProcessPortCount;      // 进程端口集合容量上限（防御性）

// -----------------------------------------------------------------------------
//  拦截配置
// -----------------------------------------------------------------------------
enum class Direction { Inbound, Outbound, Both };
enum class PortSide  { Src, Dst };
enum class Protocol  { Tcp, Udp, Both };

struct Config {
    std::vector<unsigned short> ports;       // 目标端口（allPorts=false 时至少一个）
    bool      allPorts = false;              // true = 不限定端口（整体断网：丢所有入站包）
    Direction dir   = Direction::Inbound;    // 默认拦下行（本机收包）
    PortSide  side  = PortSide::Src;         // 默认匹配源端口
    Protocol  proto = Protocol::Both;        // 默认 TCP+UDP
    long      durationSec = 0;               // 0 = 不限时
    bool      verbose = false;               // 是否上报每个被丢弃的报文
    bool      installConsoleHandler = true;  // CLI 需要接管 Ctrl+C；GUI 不需要

    // ---- 丢包率（v1.3.0）：按方向分别控制的“概率丢包”-------------------------
    // 100 = 全部丢弃（默认，等价于旧版的 100% 黑洞行为）
    //   0 = 该方向完全不接管（过滤器里不会有这个方向，流量原样通过，零开销）
    // 1~99 = 逐包掷随机数：命中则丢弃，未命中则 WinDivertSend 原样回注
    //
    // 方向语义（重要）：
    //   * 端口模式 / 全部端口模式：接管方向 = dir ∩ {丢包率 > 0}
    //     —— dir 仍然决定“允许碰哪些方向”，丢包率决定“碰到的里面丢多少”。
    //     若某方向不在 dir 内、但它的丢包率被设成了 1~99（明确想按比例丢），
    //     属于矛盾配置，ValidateConfig() 会直接报错，避免“设了却不生效”被静默忽略。
    //     （0 与 dir 外语义一致；100 是默认值且必须保持合法，见 ValidateConfig 注释。）
    //   * 进程模式：为保持历史行为，dir 仍被忽略（见下方 processName 说明）；
    //     接管方向纯由丢包率决定（默认 100/100 → 两个方向都接管，与旧版一致）。
    unsigned  lossDownPercent = 100;   // 下行（inbound，本机收包）
    unsigned  lossUpPercent   = 100;   // 上行（outbound，本机发包）

    // ---- 限速（v1.5.0；v1.6.0 起支持 B/s 单位与延迟上限）----------------------
    // 单位是**字节/秒**；0 = 不限（默认，与旧版行为完全一致）。
    // 命令行/界面允许带单位后缀：300B = 300 B/s、200K = 200KB/s、2M = 2MB/s，
    // 裸数字按 KB/s 解释（与 v1.5.0 兼容）。
    //
    // 和丢包率的区别（这正是本功能存在的意义）：
    //   * 丢包率：命中就掷骰子扔掉 —— 降速是 TCP 挨打之后的**反应**，不可预测；
    //   * 限速  ：超速的报文**排队等一会儿再放行**（令牌桶）—— 速率被熨平，
    //             不丢包也能降速。队列有上限，实在排不下才丢（单独统计）。
    //
    // 只作用于「被接管的报文」（命中的那些）。进程模式下未命中目标端口的报文
    // 仍然全速原样放行，不受限速影响。
    unsigned long long rateDownBytesPerSec = 0;   // 下行（inbound）
    unsigned long long rateUpBytesPerSec   = 0;   // 上行（outbound）

    // 队列里最多允许多久（毫秒）。0 = 自动（按速率算：约 3 个满包的排队时间，
    // 下限 200ms、上限 10 分钟）。超过这个时间的报文**不再排队，直接丢弃**。
    //
    // 为什么必须有这个上限：低速率的物理事实是"一个 1500 字节的满包要攒很久令牌"
    // （300 B/s 要 5 秒，100 B/s 要 15 秒）。没有上限的话，队列能压住几十秒甚至
    // 几分钟的包 —— 而 TCP 的重传超时只有秒级，这些包送到时对方早就重传过了，
    // 等于白等一场，还白占内存。有了上限，超时就如实丢弃，行为更接近真实的
    // 小缓冲瓶颈链路。
    unsigned rateMaxDelayMs = 0;
    // v2.0.4：最小包单位（对齐 tc tbf 的 mpu）。
    // 0 = 不设下限（与 tc 默认一致）。设成 64 就模拟以太网"任何帧都不小于 64 字节"，
    // 小包（例如纯 ACK）会按 64 字节扣令牌，ACK 密集的流量会限得更贴近真实链路。
    unsigned mpuBytes = 0;

    // ---- 进程模式（基于进程名选择性丢包）-------------------------------------
    // 非空即启用进程模式，例如 "chrome.exe"（也可以只写 "chrome"，大小写不敏感）。
    // 启用后：
    //   * BuildFilter() 忽略 ports/side/dir，改为“(tcp or udp)”全量旁路监听；
    //   * 后台线程周期性解析进程名 -> PID -> 本地端口集合（TCP+UDP，IPv4+IPv6）；
    //   * 收包循环里：命中本地端口集合的报文**按该方向的丢包率**决定丢弃/放行，
    //     其余报文一律 WinDivertSend 放行。
    // 注意：该模式下仅 TCP/UDP 报文被接管；TCP SYN 建立连接时端口已在表中，
    //       因此新建连接的第一批报文同样能被正确识别。
    std::string processName;
    unsigned    processRefreshMs = kDefaultProcessRefreshMs;  // 端口集合刷新周期(ms)
};

// 供界面显示的枚举文案（返回 UTF-8 中文）
const char* DirectionLabel(Direction dir);
const char* SideLabel(PortSide side);
const char* ProtocolLabel(Protocol proto);

// -----------------------------------------------------------------------------
//  通用参数解析（CLI 与 GUI 共用，保证两边校验规则完全一致）
// -----------------------------------------------------------------------------
bool ParsePortList(const std::string& text, std::vector<unsigned short>& out, std::string& err);
bool ParseDurationSeconds(const std::string& text, long& seconds, std::string& err);

// 解析丢包率（v1.3.0）：接受 0~100 的十进制整数（可带首尾空白，不认百分号外的杂字符）。
// 小于 0 或大于 100 一律报错，避免出现“设置了 150% 却按 100% 跑”这种误解。
bool ParseLossPercent(const std::string& text, unsigned& out, std::string& err);

// 解析限速值（v1.5.0 起，v1.6.0 支持单位后缀）。返回**字节/秒**。
//   300B / 300b      -> 300        B/s
//   200K / 200KB     -> 204800     B/s
//   2M  / 2MB        -> 2097152    B/s
//   200              -> 204800     B/s（裸数字 = KB/s，与 v1.5.0 写法兼容）
//   0                -> 不限速
// 上限 1 GiB/s（再高就该用别的手段了，写错数字也能被挡住）。
bool ParseRate(const std::string& text, unsigned long long& out, std::string& err);

// 把「字节/秒」格式化成人看的样子：300 B/s / 200 KB/s / 2 MB/s
std::string DescribeRate(unsigned long long bytesPerSec);

// 为 CLI 与 GUI 的计数显示添加千分位分隔符（1234567 -> 1,234,567）。
std::string FormatCount(unsigned long long value);

// 限速的自动延迟上限（毫秒）：约 3 个满包的排队时间，下限 200ms、上限 10 分钟。
unsigned AutoMaxShapeDelayMs(unsigned long long rateBytesPerSec);

// 本次配置是否启用了限速（任一方向 > 0）。启用后引擎会拉起节流线程。
bool IsShapingEnabled(const Config& cfg);

// 某个方向最终会不会被接管（= 该方向的报文会被收进用户态逐包处理）。
// 这是"接管"语义的唯一权威实现，CLI 的 --dry-run 与引擎的 BuildFilter 都调它，
// 避免两边各写一套判断而慢慢走偏（v1.7.1 之前 main.cpp 就重复实现过一次）。
//   * 丢包率 0 且没限速 -> false（过滤器里不含该方向，零开销）
//   * 丢包率 0 但有限速 -> true （限速只能作用于被接管的流量）
//   * 进程模式忽略 dir；端口模式还要落在 dir 内
bool DirectionIntercepted(const Config& cfg, bool outbound);

// 「丢包率 100% + 限速」这种自相矛盾的组合检测（v1.7.1）。
// 丢包率在限速之前判断，100% 丢包会把报文全部拦下，限速器一个包都收不到。
// 返回空串表示没有冲突；否则返回一句可以直接展示给用户的中文警告。
// 单独做成函数而不是塞进 ValidateConfig：后者在界面上每次按键都会调用，不能在里面打日志。
std::string RateLossConflictWarning(const Config& cfg);

// =============================================================================
//  每应用实时速率（v2.0.0）
// =============================================================================
//  实现基于 ETW 提供程序 Microsoft-Windows-Kernel-Network —— 它原生带
//  PID + 字节数 + 收发方向，正是任务管理器"应用网络使用"用的那一套。
//  优点：纯用户态、不抓包、不用额外驱动、TCP/UDP 全覆盖。
//  代价：**需要管理员权限**（ETW 会话）。
struct AppRate {
    unsigned long      pid = 0;
    std::string        exeName;       // 小写 exe 名，如 "chrome.exe"；取不到时是 "pid:1234"
    std::string        exePath;       // 完整路径（v2.0.0 起，界面用它取应用图标）；可能为空
    unsigned long long rxBps = 0;     // 最近一次采样区间内的接收速率（字节/秒）
    unsigned long long txBps = 0;     // 发送速率
    unsigned long long rxTotal = 0;   // 自本次监控开始累计
    unsigned long long txTotal = 0;
};

// 启动每应用速率监控。需要管理员权限；失败时写入 errorText。
bool StartAppRateMonitor(std::string& errorText);
void StopAppRateMonitor();
bool IsAppRateMonitorRunning();

// 取当前快照。速率按"距上次调用的实际时间"算，所以调用间隔不必精确。
// 默认只返回有流量的进程，按（下行+上行）降序；includeIdle=true 时连 0 的也返回。
std::vector<AppRate> GetAppRates(bool includeIdle = false);

// 监控启动以来累计收到多少个 ETW 事件（任何事件 ID，含不统计的那些）。
// 用途：诊断"监控到底有没有在工作" —— 拿到会话但收不到事件时靠它区分。
unsigned long long GetAppRateEventCount();
// 本次配置是否属于“概率丢包”（某个方向的丢包率在 1~99 之间）。
// 用途：决定是否需要把命中但未丢弃的报文回注（100% 黑洞不需要回注）。
bool IsProbabilisticLoss(const Config& cfg);

// 丢包率相关的语义检查（CLI 与 GUI 共用，保证两边规则一致）：
//   * 两个方向的丢包率都让本方向“不接管”时，没有任何流量会被处理 -> 报错；
//   * 端口模式下，某方向被设成非 100 的丢包率、但它又不在 dir 里
//     （即根本不会被接管）-> 报错，而不是静默忽略；
//   * 进程模式 + 非默认 dir -> 只是提示（dir 在进程模式下按历史行为被忽略）。
// 返回 false 时 errorText 里是可直接展示的中文原因。
bool ValidateConfig(const Config& cfg, std::string& errorText);

// 进程名规范化：去掉首尾空白、只保留文件名（"C:\x\chrome.exe" -> "chrome.exe"）、
// 统一成小写。空串返回 false。
bool NormalizeProcessName(const std::string& text, std::string& out, std::string& err);

// -----------------------------------------------------------------------------
//  端口 <-> 进程 映射（iphlpapi）
//  用途：把“进程名”翻译成“该进程当前占用的本地端口集合”，供选择性丢包使用。
//  实现要点：
//    * CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) 按进程名找 PID（大小写不敏感，
//      自动补 .exe；同名多开时返回全部 PID）；
//    * GetExtendedTcpTable / GetExtendedUdpTable 拉取全系统连接表，
//      挑出 OwnerPid 命中目标 PID 的行，取出本地端口（LocalPort）；
//    * 每个表都查 IPv4(AF_INET) 与 IPv6(AF_INET6) 两族。
//  这些函数都是纯查询，不依赖 WinDivert，也未提权也能调用。
// -----------------------------------------------------------------------------

// 按进程名（如 "chrome.exe"）查 PID 列表；返回 false 表示未找到进程。
bool FindProcessIdsByName(const std::string& processName, std::vector<unsigned long>& pids);

// 收集这些 PID 当前占用的本地端口集合（TCP+UDP、IPv4+IPv6）；失败时 errorText 说明原因。
bool CollectLocalPortsByPids(const std::vector<unsigned long>& pids,
                             std::unordered_set<uint16_t>& ports,
                             std::string& errorText,
                             std::unordered_set<uint32_t>* detailedKeys = NULL);

// 上面两步的合体（引擎内部与调试都用它）：进程名 -> 端口集合。
bool CollectProcessLocalPorts(const std::string& processName,
                              std::unordered_set<uint16_t>& ports,
                              std::vector<unsigned long>& pids,
                              std::string& errorText,
                              std::unordered_set<uint32_t>* detailedKeys = NULL);

// 连接表诊断信息：排查“进程名写对了却没有丢包”这类问题（诊断模式 / 日志用）。
struct PortTableStats {
    unsigned long long tcp4Entries = 0;   // TCP/IPv4 表条目数
    unsigned long long tcp6Entries = 0;   // TCP/IPv6 表条目数
    unsigned long long udp4Entries = 0;   // UDP/IPv4 表条目数
    unsigned long long udp6Entries = 0;   // UDP/IPv6 表条目数
    unsigned long long tablePids   = 0;   // 表里出现过的不同 PID 数
    unsigned long long matchedPids = 0;   // 其中命中目标 PID 的个数
};
bool QueryPortTableStats(const std::vector<unsigned long>& pids, PortTableStats& stats);

// -----------------------------------------------------------------------------
//  枚举“正在运行的应用程序”（v1.4.0）
//  用途：界面里的进程选择器 —— 不用手输进程名，直接从列表里挑一个。
//
//  实现要点（全部是纯查询，不需要管理员权限）：
//    * CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)  取进程表（与按名字查 PID 同一套）；
//    * EnumWindows + IsWindowVisible + 窗口标题       判断“有没有可见窗口”，
//      只有有窗口的才算“应用程序”（否则会混进两百多个系统进程，没法挑）；
//    * GetExtendedTcpTable / GetExtendedUdpTable      按 PID 统计当前连接数，
//      连接数为 0 的目标即使丢包也没有流量可丢，界面据此提示；
//    * QueryFullProcessImageNameW + 版本信息         取 exe 全路径与“程序说明”
//      （FileDescription，如 "Google Chrome"），比 chrome.exe 好认。
//
//  注意：返回的是**进程名**（exeName），不是 PID。定位粒度保持“按名字”，
//        这样目标进程重启后依然有效，Chrome/Edge 这类多进程应用也能覆盖全。
// -----------------------------------------------------------------------------
struct RunningApp {
    unsigned long pid = 0;
    std::string   exeName;          // "chrome.exe"（选中后交给引擎的就是这个）
    std::string   displayName;      // 程序说明，可能为空（取不到版本信息时）
    std::string   windowTitle;      // 主窗口标题，可能为空
    unsigned long connectionCount = 0;  // 当前 TCP+UDP 连接数（IPv4+IPv6）
    bool          hasWindow = false;    // 是否有可见的顶层窗口
    bool          isUwpHost = false;    // 是否是 UWP 宿主（ApplicationFrameHost.exe）
};

// 列出当前正在运行的应用程序。返回 false 时 errorText 说明原因。
// 排序：有窗口的在前 -> 连接数多的在前 -> 进程名升序。
bool ListRunningApps(std::vector<RunningApp>& out, std::string& errorText);

// -----------------------------------------------------------------------------
//  过滤器
// -----------------------------------------------------------------------------
// 生成 WinDivert 过滤器字符串，例如：
//   inbound and (tcp.SrcPort == 8080 or udp.SrcPort == 8080)      （指定端口）
//   inbound                                                       （全部端口 / 整体断网）
std::string BuildFilter(const Config& cfg);

// 用 WinDivertHelperCompileFilter 校验过滤器语法/长度（需要 WinDivert.dll 已加载）
bool ValidateFilter(const std::string& filter, std::string& errorText);

// -----------------------------------------------------------------------------
//  全局快捷键（断网 / 联网）
//  说明：修饰键/鼠标键取值刻意与 Win32 保持一致，这样头文件不必引入 windows.h
// -----------------------------------------------------------------------------
enum HotkeyModifier {
    kHotkeyAlt   = 0x0001,   // MOD_ALT
    kHotkeyCtrl  = 0x0002,   // MOD_CONTROL
    kHotkeyShift = 0x0004,   // MOD_SHIFT
    kHotkeyWin   = 0x0008    // MOD_WIN
};

// 鼠标侧键的“虚拟键码”（与 Win32 的 VK_XBUTTON1 / VK_XBUTTON2 相同）。
// 这两个键不是键盘键，全局监听走低级鼠标钩子（见 SetMouseHotkeyListener）。
extern const unsigned kHotkeyMouseX1;   // 侧键 1（鼠标 4 号键，通常是“后退”）
extern const unsigned kHotkeyMouseX2;   // 侧键 2（鼠标 5 号键，通常是“前进”）

struct HotkeySpec {
    unsigned modifiers = 0;  // kHotkeyCtrl | kHotkeyAlt | ... 的组合
    unsigned vk = 0;         // 虚拟键码：'A'..'Z'、'0'..'9'、VK_F1..VK_F12、
                             // 或鼠标侧键 kHotkeyMouseX1 / kHotkeyMouseX2

    bool empty() const { return vk == 0; }
};

// 是否是鼠标侧键
bool IsMouseHotkey(unsigned vk);

// 鼠标侧键的显示名（"鼠标侧键1"/"鼠标侧键2"）；非侧键返回 NULL
const char* MouseHotkeyName(unsigned vk);

// "Ctrl+Alt+B" / "鼠标侧键1" / "X1" <-> HotkeySpec
// 解析不区分大小写，支持 Ctrl/Control、Alt、Shift/Win 与
// 鼠标侧键别名：X1 / X2 / Mouse4 / Mouse5 / 侧键1 / 侧键2 / 鼠标4 / 鼠标5
bool ParseHotkey(const std::string& text, HotkeySpec& out, std::string& err);
std::string FormatHotkey(const HotkeySpec& spec);

// 合理性校验：必须有主键。
// v1.2.3 起**允许单独按键**（不带修饰键），不再强制组合键 —— 例如 F8 或 B 都可以。
// 仍会拒绝两类：修饰键本身（Ctrl/Alt/Shift/Win 不能单独成键）、
// 以及被 Windows 保留的键（Win、CapsLock、Pause、PrintScreen、鼠标左/中/右键等）。
bool IsHotkeyAcceptable(const HotkeySpec& spec, std::string& err);

// 某个键是否属于“被 Windows 保留、不适合做单键热键”的那一类
// （界面层拿它做即时提示，规则与 IsHotkeyAcceptable 完全一致）
bool IsReservedHotkeyKey(unsigned vk);

// 注册/注销系统级热键（进程退出前记得注销）。
//   windowHandle = 窗口句柄：热键消息以 WM_HOTKEY 投递到该窗口（GUI 用法）
//   windowHandle = NULL    ：热键消息投递到当前线程消息队列，用 PollHotkeyMessage 取（控制台用法）
// 注意：**鼠标侧键**在部分系统上 RegisterGlobalHotkey 会失败（错误码 0 且不生效），
//       这类绑定请改用 SetMouseHotkeyListener + PollMouseHotkey 的钩子通道。
bool RegisterGlobalHotkey(void* windowHandle, int id, const HotkeySpec& spec, unsigned long& errorCode);
void UnregisterGlobalHotkey(void* windowHandle, int id);

// 从当前线程消息队列里取一条 WM_HOTKEY；返回 false 表示当前没有热键消息
bool PollHotkeyMessage(unsigned long& hotkeyId);

// 从 WM_XBUTTON 的 wParam 高字取出被按下的侧键（0 表示不是侧键消息）。
// 返回 kHotkeyMouseX1 / kHotkeyMouseX2。
unsigned MouseButtonFromWMXButtonParam(unsigned long long wParam);

// -----------------------------------------------------------------------------
//  鼠标侧键的全局监听（低级鼠标钩子 WH_MOUSE_LL）
//  适用场景：
//    * 把侧键绑成断网/联网热键（RegisterHotKey 对侧键支持不可靠，钩子更稳）；
//    * GUI 的“请按键…”捕获：点一下侧键即可录入，并顺手屏蔽掉它在浏览器里的
//      “后退/前进”动作（只屏蔽侧键，其它鼠标动作一律放行）。
//  钩子回调运行在安装它的线程上，因此 PollMouseHotkey 由该线程的消息循环驱动即可。
// -----------------------------------------------------------------------------

// 安装/卸载全局鼠标侧键钩子（需要消息循环；返回 false 表示安装失败）
bool SetMouseHotkeyListener(bool enable);

// 钩子安装状态（用于界面显示）
bool IsMouseHotkeyListenerInstalled();

// 取一次被按下的侧键（原子取走，取走后清空）；没有则返回 false
bool PollMouseHotkey(unsigned& vk);

// 注册“侧键被按下”的通知回调：由钩子回调直接触发，界面可以立刻响应，
// 不必等定时器轮询（PollMouseHotkey 仍然可用，作为兜底）。
//
// ⚠ 重要（v1.2.3）：**不要**再用这个回调去卸载/重装钩子。
// 从 WH_MOUSE_LL 自己的回调里调用 SetMouseHotkeyListener / UnhookWindowsHookEx
// 会把整个系统的鼠标输入卡死（换绑快捷键时必然触发）。
// 请改用 SetMouseHotkeyNotifyWindow + MouseHotkeyNotifyMessage：
// 钩子只 PostMessage（异步），上层在自己的消息处理里想怎么装卸都安全。
typedef void (*MouseHotkeyFn)(unsigned vk, void* user);
void SetMouseHotkeyCallback(MouseHotkeyFn fn, void* user);

// 推荐用法：指定接收侧键通知的窗口。
// 侧键按下时钩子回调只 PostMessageW(hwnd, MouseHotkeyNotifyMessage(), vk, 0)，
// 绝不同步调用上层代码 —— 这样上层在消息处理里卸载/重装钩子是安全的。
void SetMouseHotkeyNotifyWindow(void* hwnd);

// 上面那个自定义消息的消息号（上层在自己的窗口过程里判断它）
unsigned MouseHotkeyNotifyMessage();

// 捕获模式：开启后侧键会被钩子“吃掉”并记录，不会传到前台程序
void SetMouseHotkeyCapture(bool enable);
bool IsMouseHotkeyCapturing();

// -----------------------------------------------------------------------------
//  管理员权限
// -----------------------------------------------------------------------------
enum class Elevation {
    Elevated,          // 已提权（Administrators 令牌已启用）
    AdminNotElevated,  // 属于管理员组，但当前是 UAC 过滤后的标准令牌
    StandardUser       // 普通用户
};

Elevation QueryElevation();
bool IsElevated();
// 针对权限状态的中文建议（CLI / GUI 共用同一套措辞）
std::string ElevationAdvice(Elevation state);

// -----------------------------------------------------------------------------
//  日志回调
// -----------------------------------------------------------------------------
enum class LogLevel { Info, Warning, Error, Debug, Packet };

// utf8Text 为单行 UTF-8 文本（不含换行）；回调可能来自引擎内部线程，
// 实现方需要自行保证线程安全（core 内部对回调调用做了串行化）。
typedef void (*LogFn)(LogLevel level, const char* utf8Text, void* user);

// -----------------------------------------------------------------------------
//  调试日志（weaknet_debug.log）
//  用途：出问题（报错 / 崩溃 / 卡死）之后还能回头查“到底走到哪一步”。
//  特点：**每一行立刻落盘**（fflush + _commit），所以即使程序随后崩溃，
//        已经写下的行也不会丢（普通缓冲流会丢在缓冲区里）。
//  内容：关键动作的时间戳流水 —— 会话启停、WinDivert 句柄与驱动参数、
//        各后台线程启停、端口扫描周期与拿到的端口数、被丢弃/放行的计数、
//        句柄释放、异常/停止原因。
//  归零：每次 InitDebugLog 都会截断旧文件重新开始（只保留本次运行）。
// -----------------------------------------------------------------------------

// 打开/关闭调试日志。
//   path = NULL 或空串 -> 用默认文件名 "weaknet_debug.log"（当前工作目录）
//   enable = false    -> 立即关闭（后续 DebugLogf 变成空操作）
// 返回 false 表示文件打不开（原因写进 errorText），此时日志功能整体保持关闭。
bool InitDebugLog(const char* path, bool enable, std::string& errorText);
void ShutdownDebugLog();          // 关闭并落盘（进程退出前调用）
bool EnableDebugLog(bool enable); // 运行期开关（不开新文件，沿用已打开的句柄）
bool IsDebugLogEnabled();
std::string DebugLogPath();       // 空串表示未打开

// 写一行调试日志：自动加时间戳与线程 id，自动换行，**写完立刻落盘**。
// 内部自带临界区，可从任意线程调用；未启用时几乎零开销。
void DebugLogf(const char* fmt, ...);

// -----------------------------------------------------------------------------
//  统计与停止原因
// -----------------------------------------------------------------------------
struct Stats {
    unsigned long long packets = 0;   // 已丢弃报文数
    unsigned long long bytes   = 0;   // 已丢弃字节数
    unsigned long long tcp     = 0;
    unsigned long long udp     = 0;
    unsigned long long other   = 0;

    // 被原样放行（WinDivertSend 回注）的报文数与字节数。
    //   * 纯 100% 黑洞模式（旧行为）：恒为 0（收上来的包全部丢弃）。
    //   * 概率丢包模式：命中但未被随机选中的报文会回注，计入这里。
    //   * 进程模式：未命中目标端口的报文也计入这里。
    unsigned long long forwarded       = 0;
    unsigned long long forwardedBytes  = 0;

    // 进程模式专用：当前目标进程数 / 已识别到的本地端口数
    unsigned long long processCount    = 0;
    unsigned long long portCount       = 0;

    // ---- 丢包率模式（v1.3.0）：按方向统计，便于核对实际丢包比例 --------------
    // matchedXxx = 该方向被接管（命中目标）的报文总数
    // droppedXxx = 其中真正被丢弃的报文数
    // 于是「实际丢包率 ≈ droppedXxx / matchedXxx」，可以用来验证设置是否生效。
    unsigned long long matchedDown = 0;
    unsigned long long matchedUp   = 0;
    unsigned long long droppedDown = 0;
    unsigned long long droppedUp   = 0;

    // ---- 限速模式（v1.5.0）--------------------------------------------------
    // shapedXxx = 经过限速队列的报文数（排队等过令牌的）
    // shapedBytesXxx = 对应字节数 -> 除以运行时长就是**实测速率**，可与设置值核对
    // shapeDropped = 因队列满、或停止时清队列而丢弃的报文数
    //（这个不算进 packets：packets 专指“按丢包率/黑洞丢掉的”，两者要能分开看）
    unsigned long long shapedDown      = 0;
    unsigned long long shapedUp        = 0;
    unsigned long long shapedBytesDown = 0;
    unsigned long long shapedBytesUp   = 0;
    unsigned long long shapeDropped    = 0;
    // 其中"因为排队会等太久而主动丢掉"的部分（v1.6.0）。
    // 低速率下这是主要丢弃原因：一个满包要攒几秒甚至几十秒令牌，等不起就丢。
    unsigned long long shapeLateDropped = 0;
};

enum class StopReason { None, User, Duration, ConsoleExit, Error };
const char* StopReasonText(StopReason reason);

// 进程级“该退出了”的信号：由 Ctrl+C / 关闭控制台 / --duration 到期触发，
// 与“会话停止”区分开 —— 用快捷键停止会话后，进程仍可继续待命（见 CLI 的交互模式）。
bool IsExitRequested();

// -----------------------------------------------------------------------------
//  会话
//  说明：引擎内部使用文件级状态，因此**一个进程内同时只支持一个会话**。
// -----------------------------------------------------------------------------
struct StartResult {
    bool          ok = false;
    unsigned long errorCode = 0;   // WinDivertOpen 的 Win32 错误码（0 表示非打开失败）
    std::string   message;         // 可直接展示给用户的中文提示（含排查建议）
};

class Session {
public:
    Session() {}
    ~Session();

    // 启动拦截。失败时返回 ok=false，并把原因写在 message 里。
    StartResult Start(const Config& cfg, LogFn logFn, void* logUser);

    // 请求停止并等待工作线程退出（优雅收尾，网络立即恢复）。
    void Stop();

    // 等待会话自然结束（例如 --duration 到期 / 控制台关闭）。
    // timeoutMs 默认 0xFFFFFFFF（无限等待）；超时返回 false。
    bool WaitForStop(unsigned long timeoutMs = 0xFFFFFFFFUL);

    // 会话是否已经结束（含自然结束，例如 --duration 到期）。
    // 结束后请调用 WaitForStop() 完成资源回收与结果快照。
    bool HasFinished() const;

    bool IsRunning() const;

    // 统计与停止原因：会话结束后返回的是本次运行的最终快照
    Stats GetStats() const;
    StopReason GetStopReason() const;

    // 本次会话实际使用的过滤器字符串
    const std::string& FilterText() const { return filter_; }

    // 本次会话实际生效的配置（含被规范化/校正过的值，例如进程名小写化、
    // 刷新周期被抬到下限）。用途：停止后核对“设置的丢包率”与实测结果是否一致。
    const Config& GetConfig() const { return cfg_; }

    // 已运行（或本次运行总）毫秒数
    unsigned long long ElapsedMs() const;

    // ---- 进程模式：运行期快照（供界面显示“目标进程 / 命中端口”）----------------
    // 是否处于进程模式（cfg.processName 非空）
    bool IsProcessMode() const { return processMode_; }

    // 目标进程名（规范化后的小写文件名，例如 "chrome.exe"）
    const std::string& ProcessName() const { return cfg_.processName; }

    // 当前识别到的目标 PID 列表
    std::vector<unsigned long> CurrentProcessIds() const;

    // 当前识别到的本地端口集合（拷贝一份，可安全跨线程使用）
    std::unordered_set<uint16_t> CurrentPorts() const;

private:
    Session(const Session&);
    Session& operator=(const Session&);

    Config             cfg_;
    std::string        filter_;
    bool               owns_ = false;       // 是否由本对象启动了会话
    bool               processMode_ = false; // 本次会话是否启用了进程模式
    unsigned long long startedTick_ = 0;

    // 会话结束后的结果快照（TeardownSession 之后仍然可读）
    Stats              lastStats_;
    StopReason         lastReason_ = StopReason::None;
    unsigned long long lastElapsedMs_ = 0;
    bool               hasSnapshot_ = false;
};

}  // namespace weaknet

#endif  // WEAKNET_CORE_H
