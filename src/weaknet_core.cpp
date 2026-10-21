// =============================================================================
//  weaknet_core.cpp —— 引擎实现（详见 weaknet_core.h 的说明）
// =============================================================================

// 这两个宏必须在任何系统头文件之前定义：weaknet_core.h 自己会引入 CRT/Windows
// 头文件，若放在它后面就来不及了（fopen 之类的弃用告警仍会冒出来）。
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#  define _CRT_SECURE_NO_WARNINGS
#endif

#include "weaknet_core.h"

// GetExtendedTcpTable / GetExtendedUdpTable 的 *_OWNER_PID_* 接口需要 Vista 以上。
// v2.0.0 提到 0x0601（Win7）：限速要用的 SetWaitableTimerEx 在 synchapi.h 里被
// `#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)` 挡着，0x0600 拿不到声明。
// 本工具本来只支持 Win10/11，抬这一级没有任何兼容性代价。
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0601
#endif

// 高精度等待定时器（Win10 1803+）。SDK 把这个常量挡在
// `_WIN32_WINNT >= _NT_TARGET_VERSION_WIN10_RS4` 后面，而我们上面只声明到 Win7，
// 所以这里自己补上。它就是个稳定的 ABI 常量（头文件里也是定义为 0x00000002），
// 老系统上创建会失败，我们会走退路。
#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#  define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif

// winsock2.h 必须排在 windows.h 之前，AF_INET / AF_INET6 由它提供；
// ws2tcpip.h -> ws2ipdef.h 会定义 _WS2IPDEF_，IPv6 的 MIB_*6* 结构体
// （MIB_TCP6ROW_OWNER_PID 等）只有在这个宏存在时才会由 tcpmib.h 声明。
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>      // GetExtendedTcpTable / GetExtendedUdpTable（端口 <-> 进程）
#include <tlhelp32.h>      // CreateToolhelp32Snapshot / PROCESSENTRY32（进程名 -> PID）
#include <winsvc.h>        // OpenSCManager / QueryServiceStatusEx（排查 WinDivert 服务状态）
#include <winver.h>        // GetFileVersionInfo / VerQueryValue（读程序的“说明”，进程选择器用）
#include <windivert.h>

#include <signal.h>
#include <io.h>            // _commit / _fileno（调试日志每行立即落盘）
#include <timeapi.h>       // timeBeginPeriod / timeEndPeriod（限速要毫秒级定时精度）
#include <evntrace.h>      // ETW：每应用实时速率（v2.0.0）
#include <evntcons.h>

#include <algorithm>
#include <atomic>
#include <climits>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace weaknet {

#ifdef WEAKNET_TEST_HOOKS
// 仅测试目标启用：用本地内核事件代替驱动句柄，验证失败收尾而不截获网络。
volatile LONG g_testFakeDriver = 0;
volatile LONG g_testFailDriverOpen = 0;
volatile LONG g_testFailShapeEvent = 0;
volatile LONG g_testFailShapeThread = 0;
volatile LONG g_testFailWorkerThread = 0;
volatile LONG g_testFailEtwStart = 0;
HANDLE g_testFakeDriverHandle = NULL;
#endif

// =============================================================================
//  常量与文案

const char* const kToolName    = "WeakNetTool";
const char* const kToolVersion = "2.0.11";

const unsigned long long kDriverMajor = 2;
const unsigned long long kDriverMinor = 2;

const size_t kMaxPortCount = 64;
const unsigned   kMaxPacketLen = 0xFFFF;

const unsigned kDefaultProcessRefreshMs = 1000;   // 每秒重算一次端口集合
const unsigned kMinProcessRefreshMs     = 100;    // 再快没有意义，只会白烧 CPU
const size_t   kMaxProcessPortCount     = 8192;   // 端口集合容量上限（防御性）

// 鼠标侧键的虚拟键码（与 Win32 的 VK_XBUTTON1 / VK_XBUTTON2 一致）
const unsigned kHotkeyMouseX1 = VK_XBUTTON1;
const unsigned kHotkeyMouseX2 = VK_XBUTTON2;

const char* DirectionLabel(Direction dir)
{
    switch (dir) {
    case Direction::Inbound:  return "inbound（本机收包 / 下行）";
    case Direction::Outbound: return "outbound（本机发包 / 上行）";
    case Direction::Both:
    default:                  return "both（不区分方向）";
    }
}

const char* SideLabel(PortSide side)
{
    return (side == PortSide::Src) ? "源端口 src" : "目的端口 dst";
}

const char* ProtocolLabel(Protocol proto)
{
    switch (proto) {
    case Protocol::Tcp:  return "TCP";
    case Protocol::Udp:  return "UDP";
    case Protocol::Both:
    default:             return "TCP + UDP";
    }
}

const char* StopReasonText(StopReason reason)
{
    switch (reason) {
    case StopReason::User:        return "用户请求停止（Ctrl+C / 界面上的停止按钮）";
    case StopReason::Duration:    return "达到设定运行时长";
    case StopReason::ConsoleExit: return "控制台被关闭 / 注销 / 关机";
    case StopReason::Error:       return "收包循环异常结束";
    case StopReason::None:
    default:                      return "未知";
    }
}

namespace {

const UINT  kFilterBufLen = 8192;        // 编译过滤器用的缓冲区
const DWORD kRetryDelayMs = 10;          // 非致命 recv 错误后的重试间隔
const unsigned long long kVerboseBurst = 30;     // 前 N 个包逐个上报
const unsigned long long kVerboseStep  = 10000;  // 之后每 N 个包上报一次
const unsigned long long kSendErrorBurst = 10;   // 放行失败前 N 次逐条上报
const unsigned long long kSendErrorStep  = 1000; // 之后每 N 次上报一次（避免刷屏）

// =============================================================================
//  日志回调（内部串行化，前端实现无需考虑多线程）
// =============================================================================

LogFn g_logFn   = NULL;
void* g_logUser = NULL;

// 进程级日志锁：用函数内静态对象保证只初始化一次（C++11 线程安全）
CRITICAL_SECTION& LogLock()
{
    static CRITICAL_SECTION cs;
    static const bool initialized = []() -> bool {
        InitializeCriticalSection(&cs);
        return true;
    }();
    (void)initialized;
    return cs;
}

void Emit(LogLevel level, const char* fmt, ...)
{
    if (g_logFn == NULL) {
        return;
    }
    char buffer[1024] = { 0 };
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buffer, sizeof(buffer), fmt, ap);
    va_end(ap);

    EnterCriticalSection(&LogLock());
    g_logFn(level, buffer, g_logUser);
    LeaveCriticalSection(&LogLock());
}

}  // 匿名命名空间：内部常量与日志回调（结束）

// =============================================================================
//  调试日志：weaknet_debug.log（每行立刻落盘，崩溃后仍可查）
// =============================================================================

namespace {

FILE*        g_dbgFile   = NULL;    // 打开的调试日志文件
std::string  g_dbgPath;             // 已打开的文件路径
volatile LONG g_dbgEnabled = 0;     // 0/1：是否正在记录
LONG         g_dbgThreadCounter = 0;  // 给没有 id 的线程兜底编号

CRITICAL_SECTION& DebugLock()
{
    static CRITICAL_SECTION cs;
    static const bool initialized = []() -> bool {
        InitializeCriticalSection(&cs);
        return true;
    }();
    (void)initialized;
    return cs;
}

const char* DbgLevelTag(LogLevel level)
{
    switch (level) {
    case LogLevel::Warning: return "WARN";
    case LogLevel::Error:   return "ERROR";
    case LogLevel::Debug:   return "DEBUG";
    case LogLevel::Packet:  return "PKT";
    case LogLevel::Info:
    default:                return "INFO";
    }
}

// 进程内唯一的线程编号：第一次见到某个 tid 就分配一个递增号，
// 让日志里能清楚看出“哪个线程做了什么”（同一个 tid 始终同一个号）。
unsigned DbgThreadNo(DWORD tid)
{
    struct Slot { DWORD tid; unsigned no; };
    static Slot  slots[64];
    static unsigned count = 0;

    EnterCriticalSection(&DebugLock());
    for (unsigned i = 0; i < count; ++i) {
        if (slots[i].tid == tid) {
            const unsigned no = slots[i].no;
            LeaveCriticalSection(&DebugLock());
            return no;
        }
    }
    unsigned no = 0;
    if (count < 64) {
        slots[count].tid = tid;
        slots[count].no  = ++g_dbgThreadCounter;
        no = slots[count].no;
        ++count;
    } else {
        no = static_cast<unsigned>(g_dbgThreadCounter);   // 超出表容量就不再细分
    }
    LeaveCriticalSection(&DebugLock());
    return no;
}

// 把 "2026-10-06 21:33:04.123" 之类的完整时间戳写进缓冲区
void DbgTimestamp(char* out, size_t outLen)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    std::snprintf(out, outLen, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                  static_cast<int>(st.wYear), static_cast<int>(st.wMonth),
                  static_cast<int>(st.wDay), static_cast<int>(st.wHour),
                  static_cast<int>(st.wMinute), static_cast<int>(st.wSecond),
                  static_cast<int>(st.wMilliseconds));
}

// 崩溃/异常时的“最后遗言”：写进调试日志。
// 注意：这里只能调用极少数异步信号安全的 API，所以只用 snprintf + fwrite/fclose。
LONG WINAPI DebugUnhandledFilter(EXCEPTION_POINTERS* info)
{
    if (g_dbgFile != NULL && InterlockedCompareExchange(
            const_cast<LONG*>(&g_dbgEnabled), 0, 0) != 0) {
        char stamp[32] = { 0 };
        DbgTimestamp(stamp, sizeof(stamp));

        DWORD code = 0;
        PVOID address = NULL;
        if (info != NULL && info->ExceptionRecord != NULL) {
            code = info->ExceptionRecord->ExceptionCode;
            address = info->ExceptionRecord->ExceptionAddress;
        }

        char line[320] = { 0 };
        const int n = std::snprintf(line, sizeof(line),
                                    "%s [tid=%lu] FATAL 未处理异常：code=0x%08lX address=%p"
                                    "（调试日志到此为止）\n",
                                    stamp, static_cast<unsigned long>(GetCurrentThreadId()),
                                    static_cast<unsigned long>(code), address);
        if (n > 0) {
            std::fwrite(line, 1, static_cast<size_t>(n), g_dbgFile);
        }
        std::fflush(g_dbgFile);
    }
    return EXCEPTION_EXECUTE_HANDLER;   // 不再往上抛，避免重复弹窗
}

}  // namespace

bool InitDebugLog(const char* path, bool enable, std::string& errorText)
{
    errorText.clear();
    ShutdownDebugLog();

    if (!enable) {
        return true;    // 只要求“关闭”，不算失败
    }

    const char* target = (path != NULL && *path != '\0') ? path : "weaknet_debug.log";

    // 用 _wfopen 而不是 fopen：路径是 UTF-8，fopen 走 ANSI 代码页，
    // 只要目录名里有中文（例如“桌面\弱网工具”）就会直接失败（错误码 3）。
    std::wstring wideTarget;
    {
        const int needed = MultiByteToWideChar(CP_UTF8, 0, target, -1, NULL, 0);
        if (needed > 0) {
            wideTarget.resize(static_cast<size_t>(needed - 1));
            MultiByteToWideChar(CP_UTF8, 0, target, -1, &wideTarget[0], needed);
        }
    }

    EnterCriticalSection(&DebugLock());
    g_dbgFile = wideTarget.empty() ? NULL : _wfopen(wideTarget.c_str(), L"wb");
    if (g_dbgFile == NULL) {
        const DWORD err = GetLastError();
        char buffer[256] = { 0 };
        std::snprintf(buffer, sizeof(buffer), "打开日志文件失败（%s，错误码 %lu）",
                      target, static_cast<unsigned long>(err));
        errorText = buffer;
        LeaveCriticalSection(&DebugLock());
        return false;
    }
    g_dbgPath = target;
    InterlockedExchange(const_cast<LONG*>(&g_dbgEnabled), 1);
    LeaveCriticalSection(&DebugLock());

    // 装一次崩溃兜底：让“闪退”也能在日志里留下最后一行
    SetUnhandledExceptionFilter(DebugUnhandledFilter);

    DebugLogf("==== weaknet %s 调试日志开始 ====", kToolVersion);
    DebugLogf("进程: pid=%lu  可执行文件: %s", static_cast<unsigned long>(GetCurrentProcessId()),
              []() -> const char* {
                  // 同样要走宽字符接口：exe 放在中文目录下时 GetModuleFileNameA
                  // 会因为 ANSI 代码页而拿到乱码或失败。
                  static char utf8Path[MAX_PATH * 4] = { 0 };
                  if (utf8Path[0] == '\0') {
                      wchar_t widePath[MAX_PATH] = { 0 };
                      if (GetModuleFileNameW(NULL, widePath, MAX_PATH) > 0) {
                          WideCharToMultiByte(CP_UTF8, 0, widePath, -1,
                                              utf8Path, sizeof(utf8Path) - 1, NULL, NULL);
                      }
                  }
                  return utf8Path;
              }());
    DebugLogf("日志文件: %s（每行立即落盘）", g_dbgPath.c_str());
    DebugLogf("主机: 管理员权限=%s", IsElevated() ? "是" : "否");
    return true;
}

void ShutdownDebugLog()
{
    EnterCriticalSection(&DebugLock());
    if (g_dbgFile != NULL) {
        if (InterlockedCompareExchange(const_cast<LONG*>(&g_dbgEnabled), 0, 0) != 0) {
            char stamp[32] = { 0 };
            DbgTimestamp(stamp, sizeof(stamp));
            std::fprintf(g_dbgFile, "%s [tid=%lu] INFO ==== 调试日志结束 ====\n",
                         stamp, static_cast<unsigned long>(GetCurrentThreadId()));
        }
        std::fflush(g_dbgFile);
        std::fclose(g_dbgFile);
        g_dbgFile = NULL;
    }
    InterlockedExchange(const_cast<LONG*>(&g_dbgEnabled), 0);
    g_dbgPath.clear();
    LeaveCriticalSection(&DebugLock());
}

bool EnableDebugLog(bool enable)
{
    InterlockedExchange(const_cast<LONG*>(&g_dbgEnabled), enable ? 1 : 0);
    if (enable) {
        DebugLogf("调试日志已启用");
    } else if (g_dbgFile != NULL) {
        // 关闭前留一行说明，之后文件仍然打开（只是不再写）
        char stamp[32] = { 0 };
        DbgTimestamp(stamp, sizeof(stamp));
        EnterCriticalSection(&DebugLock());
        if (g_dbgFile != NULL) {
            std::fprintf(g_dbgFile, "%s [tid=%lu] INFO 调试日志已停用（本次运行后续不再记录）\n",
                     stamp, static_cast<unsigned long>(GetCurrentThreadId()));
            std::fflush(g_dbgFile);
            _commit(_fileno(g_dbgFile));
        }
        LeaveCriticalSection(&DebugLock());
    }
    return g_dbgFile != NULL;
}

bool IsDebugLogEnabled()
{
    return InterlockedCompareExchange(const_cast<LONG*>(&g_dbgEnabled), 0, 0) != 0 &&
           g_dbgFile != NULL;
}

std::string DebugLogPath()
{
    return g_dbgPath;
}

void DebugLogf(const char* fmt, ...)
{
    if (g_dbgFile == NULL ||
        InterlockedCompareExchange(const_cast<LONG*>(&g_dbgEnabled), 0, 0) == 0) {
        return;    // 未启用：直接返回，热路径上的开销只有一次判断
    }

    char body[768] = { 0 };
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);

    char stamp[32] = { 0 };
    DbgTimestamp(stamp, sizeof(stamp));

    char line[896] = { 0 };
    const int n = std::snprintf(line, sizeof(line), "%s [tid=%lu t%u] %s\n",
                                stamp, static_cast<unsigned long>(GetCurrentThreadId()),
                                DbgThreadNo(GetCurrentThreadId()), body);
    if (n <= 0) {
        return;
    }

    EnterCriticalSection(&DebugLock());
    if (g_dbgFile != NULL) {
        std::fwrite(line, 1, static_cast<size_t>(n), g_dbgFile);
        // 关键：立刻落盘。崩溃时缓冲区里的内容是拿不回来的。
        std::fflush(g_dbgFile);
        _commit(_fileno(g_dbgFile));
    }
    LeaveCriticalSection(&DebugLock());
}

// =============================================================================
//  运行时状态
// =============================================================================

HANDLE g_handle         = NULL;   // WinDivert 句柄（NULL = 无句柄 / 已被取走关闭）
HANDLE g_stopEvent      = NULL;   // 手动重置事件：请求停止
HANDLE g_cleanupDoneEvent = NULL; // 手动重置事件：收尾完成（供控制台关闭回调等待）
HANDLE g_finishedEvent  = NULL;   // 手动重置事件：整个会话结束
HANDLE g_workerThread   = NULL;
HANDLE g_watcherThread  = NULL;
HANDLE g_timerThread    = NULL;
HANDLE g_portThread     = NULL;   // 进程模式：端口集合刷新线程

volatile LONG g_stopRequested = 0;      // 0/1：请求停止当前会话
volatile LONG g_stopReasonRaw = 0;      // StopReason
volatile LONG g_exitRequested = 0;      // 0/1：请求进程整体退出（不会被会话收尾重置）

std::atomic<unsigned long long> g_statPackets(0);
std::atomic<unsigned long long> g_statBytes(0);
std::atomic<unsigned long long> g_statTcp(0);
std::atomic<unsigned long long> g_statUdp(0);
std::atomic<unsigned long long> g_statOther(0);
std::atomic<unsigned long long> g_statForwarded(0);
std::atomic<unsigned long long> g_statForwardedBytes(0);
std::atomic<unsigned long long> g_statSendErrors(0);
std::atomic<unsigned long long> g_statTargetPids(0);
std::atomic<unsigned long long> g_statTargetPorts(0);
// 丢包率模式（v1.3.0）：按方向统计“接管了多少 / 丢了多少”，便于核对实际丢包比例
std::atomic<unsigned long long> g_statMatchedDown(0);
std::atomic<unsigned long long> g_statMatchedUp(0);
std::atomic<unsigned long long> g_statDroppedDown(0);
std::atomic<unsigned long long> g_statDroppedUp(0);
// 限速模式（v1.5.0）：限速队列的丢弃数（队列满 / 停止清空），与上面的丢包率分开统计
std::atomic<unsigned long long> g_statShapeDropped(0);
// 其中"因为排队会等太久而主动丢掉"的那部分（v1.6.0）——
// 低速率下这是主要丢弃原因，单列出来便于判断"限速是不是把流量全丢了"
std::atomic<unsigned long long> g_statShapeLateDropped(0);

ULONGLONG g_startTick  = 0;
ULONGLONG g_stopTick   = 0;       // 0 表示还在运行

bool g_consoleHandlerInstalled = false;

// ---- 进程模式：目标进程的本地端口集合 ---------------------------------------
//  写入方：端口刷新线程（低频，默认 1 次/秒）
//  读取方：收包线程（高频，每个报文都要查）
//  用一把临界区保护 + 世代号(generation)：收包线程只在世代号变化时才拷贝一次
//  集合，避免每个包都加锁拷贝（对 pps 的影响可以忽略）。
CRITICAL_SECTION& PortSetLock()
{
    static CRITICAL_SECTION cs;
    static const bool initialized = []() -> bool {
        InitializeCriticalSection(&cs);
        return true;
    }();
    (void)initialized;
    return cs;
}

std::unordered_set<uint16_t> g_processPorts;   // 目标进程当前占用的本地端口
std::unordered_set<uint32_t> g_processPortKeys; // IPv4/IPv6 + TCP/UDP + 本地端口
std::vector<unsigned long>   g_processPids;    // 目标进程当前 PID 列表
std::atomic<unsigned long long> g_processPortsGeneration(0);   // 端口集合世代号

// 取一份快照（拷贝），调用方拿到后可以随意使用
std::unordered_set<uint16_t> SnapshotProcessPorts(unsigned long long* generation)
{
    EnterCriticalSection(&PortSetLock());
    if (generation != NULL) {
        *generation = g_processPortsGeneration;
    }
    std::unordered_set<uint16_t> copy(g_processPorts);
    LeaveCriticalSection(&PortSetLock());
    return copy;
}

uint32_t ProcessPortKey(unsigned ipVersion, unsigned protocol, uint16_t port)
{
    return (static_cast<uint32_t>(ipVersion) << 24) |
           (static_cast<uint32_t>(protocol) << 16) | port;
}

std::unordered_set<uint32_t> SnapshotProcessPortKeys(unsigned long long* generation)
{
    EnterCriticalSection(&PortSetLock());
    if (generation != NULL) { *generation = g_processPortsGeneration.load(); }
    std::unordered_set<uint32_t> copy(g_processPortKeys);
    LeaveCriticalSection(&PortSetLock());
    return copy;
}

// 只读当前世代号（收包线程的热路径：只判断有没有变化，不需要加锁）
unsigned long long CurrentPortsGeneration()
{
    return g_processPortsGeneration.load(std::memory_order_acquire);
}

std::vector<unsigned long> SnapshotProcessPids()
{
    EnterCriticalSection(&PortSetLock());
    std::vector<unsigned long> copy(g_processPids);
    LeaveCriticalSection(&PortSetLock());
    return copy;
}

// 有变化才写入，并推动世代号；返回是否发生了变化
bool PublishProcessPorts(const std::unordered_set<uint16_t>& ports,
                          const std::unordered_set<uint32_t>& keys,
                          const std::vector<unsigned long>& pids)
{
    bool changed = false;
    EnterCriticalSection(&PortSetLock());
    if (g_processPorts != ports || g_processPortKeys != keys || g_processPids != pids) {
        g_processPorts = ports;
        g_processPortKeys = keys;
        g_processPids  = pids;
        g_processPortsGeneration.fetch_add(1, std::memory_order_release);
        changed = true;
    }
    // 供界面显示“目标进程数 / 命中端口数”（与集合是否变化无关，每次刷新都更新）
    g_statTargetPids.store(pids.size());
    g_statTargetPorts.store(ports.size());
    LeaveCriticalSection(&PortSetLock());
    return changed;
}

void ClearProcessPorts()
{
    EnterCriticalSection(&PortSetLock());
    g_processPorts.clear();
    g_processPortKeys.clear();
    g_processPids.clear();
    g_processPortsGeneration.fetch_add(1, std::memory_order_release);
    g_statTargetPids.store(0);
    g_statTargetPorts.store(0);
    LeaveCriticalSection(&PortSetLock());
}

// ---- 句柄所有权 -------------------------------------------------------------

HANDLE LoadHandle()
{
    return static_cast<HANDLE>(InterlockedCompareExchangePointer(
        reinterpret_cast<PVOID volatile*>(&g_handle), NULL, NULL));
}

HANDLE TakeHandle()
{
    return static_cast<HANDLE>(InterlockedExchangePointer(
        reinterpret_cast<PVOID volatile*>(&g_handle), NULL));
}

void CloseHandleOnce()
{
    HANDLE handle = TakeHandle();
    if (handle != NULL && handle != INVALID_HANDLE_VALUE) {
        DebugLogf("释放 WinDivert 句柄: %p", handle);
#ifdef WEAKNET_TEST_HOOKS
        if (handle == g_testFakeDriverHandle) {
            CloseHandle(handle);
            DebugLogf("测试驱动句柄已释放");
            return;
        }
#endif
        WinDivertClose(handle);
        DebugLogf("WinDivert 句柄已释放");
    }
}

// ---- 停止请求 ---------------------------------------------------------------

bool IsStopRequested()
{
    return InterlockedCompareExchange(const_cast<LONG*>(&g_stopRequested), 0, 0) != 0;
}

StopReason GetStopReasonRaw()
{
    return static_cast<StopReason>(
        InterlockedCompareExchange(const_cast<LONG*>(&g_stopReasonRaw), 0, 0));
}

void RequestStop(StopReason reason)
{
    DebugLogf("请求停止会话：原因=%s", StopReasonText(reason));
    // 保留最先触发的停止原因；工作线程收尾时的再次请求不能覆盖它。
    InterlockedCompareExchange(const_cast<LONG*>(&g_stopReasonRaw),
                               static_cast<LONG>(reason),
                               static_cast<LONG>(StopReason::None));
    InterlockedExchange(const_cast<LONG*>(&g_stopRequested), 1);
    if (g_stopEvent != NULL) {
        SetEvent(g_stopEvent);
    }
}

// 请求进程退出（Ctrl+C / 关闭控制台 / 时长到期）：既停会话，也置退出标志
void RequestExit(StopReason reason)
{
    DebugLogf("请求进程退出：原因=%s", StopReasonText(reason));
    InterlockedExchange(const_cast<LONG*>(&g_exitRequested), 1);
    RequestStop(reason);
}

// =============================================================================
//  控制台事件（Ctrl+C / 关闭窗口）
// =============================================================================

BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType)
{
    switch (ctrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
        RequestExit(StopReason::User);
        return TRUE;

    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        // 这几种情况系统只给几秒钟，等主流程把句柄/驱动处理干净
        RequestExit(StopReason::ConsoleExit);
        if (g_cleanupDoneEvent != NULL) {
            WaitForSingleObject(g_cleanupDoneEvent, 5000);
        }
        return TRUE;

    default:
        return FALSE;
    }
}

void OnSigInt(int)
{
    RequestExit(StopReason::User);
}

// =============================================================================
//  看门狗线程：打断阻塞中的 recv
// =============================================================================

DWORD WINAPI ShutdownWatcherThread(LPVOID)
{
    WaitForSingleObject(g_stopEvent, INFINITE);

    HANDLE handle = LoadHandle();
    if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
        return 0;
    }

#ifdef WEAKNET_TEST_HOOKS
    if (handle == g_testFakeDriverHandle) {
        CloseHandleOnce();
        return 0;
    }
#endif

    // 1) 让“之后”的 recv 直接返回 ERROR_NO_DATA，不再进入阻塞
    if (!WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_BOTH)) {
        const DWORD err = GetLastError();
        if (err != ERROR_INVALID_HANDLE) {
            Emit(LogLevel::Debug, "WinDivertShutdown 返回错误: %lu", static_cast<unsigned long>(err));
        }
    }

    // 2) 尽力取消挂起的重叠 I/O（当前驱动是 WDF 手动队列且无 EvtIoCanceledOnQueue，
    //    对挂起中的请求通常无效，属正常）
    if (!CancelIoEx(handle, NULL)) {
        const DWORD err = GetLastError();
        if (err != ERROR_NOT_FOUND) {
            Emit(LogLevel::Debug, "CancelIoEx 返回错误: %lu", static_cast<unsigned long>(err));
        }
    }

    // 3) 关键一步：关闭句柄 → 驱动文件清理例程 WdfIoQueuePurge(read_queue)
    //    无条件完成挂起的读请求，阻塞中的 recv 立刻以错误返回
    CloseHandleOnce();
    return 0;
}

// =============================================================================
//  --duration 计时线程
// =============================================================================

DWORD WINAPI DurationTimerThread(LPVOID param)
{
    const DWORD seconds = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(param));
    DebugLogf("计时线程启动：将在 %lu 秒后自动停止", static_cast<unsigned long>(seconds));
    if (WaitForSingleObject(g_stopEvent, seconds * 1000UL) == WAIT_TIMEOUT) {
        // 时长到期：既是“停止会话”，也是“进程该结束了”
        DebugLogf("计时线程：运行时长已到期");
        RequestExit(StopReason::Duration);
    } else {
        DebugLogf("计时线程：会话先结束了，计时线程退出");
    }
    return 0;
}

// =============================================================================
//  进程模式：端口集合刷新线程
// =============================================================================
DWORD WINAPI PortRefreshThread(LPVOID param)
{
    const Config* cfg = static_cast<const Config*>(param);
    if (cfg == NULL) {
        return 0;
    }

    unsigned periodMs = cfg->processRefreshMs;
    if (periodMs < kMinProcessRefreshMs) {
        periodMs = kMinProcessRefreshMs;
    }

    // 会话刚开始时进程可能还没建连接（端口集合为空），此时每秒一条“暂无端口”的
    // 提示会刷屏，所以只在“状态发生变化”或“首次成功/失败”时打印。
    bool warnedNoProcess = false;   // 已经提示过“没找到进程”
    bool warnedNoPorts   = false;   // 已经提示过“还没看到端口”
    bool hasSeenPorts    = false;
    unsigned long long scanRound = 0;

    DebugLogf("端口刷新线程启动：目标进程=\"%s\" 刷新周期=%u ms",
              cfg->processName.c_str(), periodMs);

    while (!IsStopRequested()) {
        std::unordered_set<uint16_t> ports;
        std::unordered_set<uint32_t> keys;
        std::vector<unsigned long>   pids;
        std::string errorText;

        ++scanRound;
        const bool resolved = CollectProcessLocalPorts(cfg->processName, ports, pids,
                                                       errorText, &keys);

        // 每一轮扫描都落一行：出问题时能看出“到底有没有在扫、扫到了什么”
        DebugLogf("端口扫描 #%llu: resolved=%d pid数=%llu 端口数=%llu%s%s",
                  scanRound, resolved ? 1 : 0,
                  static_cast<unsigned long long>(pids.size()),
                  static_cast<unsigned long long>(ports.size()),
                  errorText.empty() ? "" : " err=", errorText.c_str());

        if (!resolved) {
            // 进程名解析或连接表查询失败：清空端口集合 = 全部放行（宁可不断网，
            // 也不要误伤别的进程），并按状态变化打印日志。
            if (pids.empty()) {
                if (!warnedNoProcess) {
                    Emit(LogLevel::Warning,
                         "未找到进程 “%s”（%s）。当前所有 TCP/UDP 报文都会被放行，"
                         "请确认程序名是否正确、是否正在运行。",
                         cfg->processName.c_str(), errorText.c_str());
                    warnedNoProcess = true;
                }
            } else if (!warnedNoPorts) {
                Emit(LogLevel::Warning,
                     "进程 “%s”(PID %lu) 的端口表查询失败：%s；当前所有 TCP/UDP 报文都会被放行。",
                     cfg->processName.c_str(), pids[0], errorText.c_str());
                warnedNoPorts = true;
            }
            PublishProcessPorts(std::unordered_set<uint16_t>(),
                                std::unordered_set<uint32_t>(), pids);
        } else {
            warnedNoProcess = false;

            if (ports.empty()) {
                if (!warnedNoPorts) {
                    Emit(LogLevel::Info,
                         "已找到进程 “%s”(PID %lu)，但它当前还没有 TCP/UDP 连接；"
                         "一旦建立连接即开始丢包。",
                         cfg->processName.c_str(), pids.empty() ? 0UL : pids[0]);
                    warnedNoPorts = true;
                }
            } else {
                warnedNoPorts = false;
                if (!hasSeenPorts) {
                    Emit(LogLevel::Info, "进程 “%s” 已识别到 %llu 个本地端口，开始选择性丢包。",
                         cfg->processName.c_str(),
                         static_cast<unsigned long long>(ports.size()));
                    hasSeenPorts = true;
                }
            }

            if (PublishProcessPorts(ports, keys, pids)) {
                Emit(LogLevel::Debug, "端口集合已更新：%llu 个端口 / %llu 个目标进程。",
                     static_cast<unsigned long long>(ports.size()),
                     static_cast<unsigned long long>(pids.size()));
            }
        }

        // 分段等待，停止请求后最多 100ms 就能退出（不拖慢收尾）
        DWORD waited = 0;
        while (waited < periodMs && !IsStopRequested()) {
            const DWORD slice = (periodMs - waited) > 100 ? 100 : (periodMs - waited);
            if (WaitForSingleObject(g_stopEvent, slice) != WAIT_TIMEOUT) {
                break;      // 收到停止信号
            }
            waited += slice;
        }
    }

    ClearProcessPorts();
    return 0;
}

// =============================================================================
//  报文信息解析
// =============================================================================

const char* ProtocolText(UINT8 protocol)
{
    switch (protocol) {
    case 1:  return "ICMP";
    case 6:  return "TCP";
    case 17: return "UDP";
    case 58: return "ICMPv6";
    default: return "IP";
    }
}

void FormatPacketSummary(const unsigned char* packet, UINT packetLen, char* out, size_t outLen)
{
    PWINDIVERT_IPHDR   ipHdr   = NULL;
    PWINDIVERT_IPV6HDR ipv6Hdr = NULL;
    PWINDIVERT_TCPHDR  tcpHdr  = NULL;
    PWINDIVERT_UDPHDR  udpHdr  = NULL;
    UINT8  protocol = 0;
    PVOID  payload = NULL;
    UINT   payloadLen = 0;
    PVOID  next = NULL;
    UINT   nextLen = 0;

    if (!WinDivertHelperParsePacket(packet, packetLen, &ipHdr, &ipv6Hdr, &protocol,
                                    NULL, NULL, &tcpHdr, &udpHdr,
                                    &payload, &payloadLen, &next, &nextLen)) {
        std::snprintf(out, outLen, "无法解析的报文（%u 字节）", packetLen);
        return;
    }

    char srcAddr[64] = { 0 };
    char dstAddr[64] = { 0 };
    if (ipHdr != NULL) {
        WinDivertHelperFormatIPv4Address(ipHdr->SrcAddr, srcAddr, sizeof(srcAddr));
        WinDivertHelperFormatIPv4Address(ipHdr->DstAddr, dstAddr, sizeof(dstAddr));
    } else if (ipv6Hdr != NULL) {
        WinDivertHelperFormatIPv6Address(ipv6Hdr->SrcAddr, srcAddr, sizeof(srcAddr));
        WinDivertHelperFormatIPv6Address(ipv6Hdr->DstAddr, dstAddr, sizeof(dstAddr));
    } else {
        std::snprintf(out, outLen, "%s 非 IPv4/IPv6 报文（%u 字节）", ProtocolText(protocol), packetLen);
        return;
    }

    unsigned srcPort = 0;
    unsigned dstPort = 0;
    char flags[32] = { 0 };

    if (tcpHdr != NULL) {
        srcPort = static_cast<unsigned>(WinDivertHelperNtohs(tcpHdr->SrcPort));
        dstPort = static_cast<unsigned>(WinDivertHelperNtohs(tcpHdr->DstPort));

        std::string flagText;
        if (tcpHdr->Syn) { flagText += "SYN,"; }
        if (tcpHdr->Ack) { flagText += "ACK,"; }
        if (tcpHdr->Fin) { flagText += "FIN,"; }
        if (tcpHdr->Rst) { flagText += "RST,"; }
        if (tcpHdr->Psh) { flagText += "PSH,"; }
        if (flagText.empty()) {
            flagText = "DATA";
        } else {
            flagText.erase(flagText.size() - 1);
        }
        std::snprintf(flags, sizeof(flags), " [%s]", flagText.c_str());
    } else if (udpHdr != NULL) {
        srcPort = static_cast<unsigned>(WinDivertHelperNtohs(udpHdr->SrcPort));
        dstPort = static_cast<unsigned>(WinDivertHelperNtohs(udpHdr->DstPort));
    }

    std::snprintf(out, outLen, "%s %s:%u -> %s:%u%s %uB",
                  ProtocolText(protocol), srcAddr, srcPort, dstAddr, dstPort, flags, packetLen);
}

UINT8 PeekProtocol(const unsigned char* packet, UINT packetLen)
{
    if (packetLen < 20) {
        return 0;
    }
    const UINT8 version = static_cast<UINT8>(packet[0] >> 4);
    if (version == 4) {
        return packet[9];
    }
    if (version == 6 && packetLen >= 40) {
        return packet[6];
    }
    return 0;
}

// 从报文里取出 TCP/UDP 的源端口与目的端口（主机字节序）。
// 返回 false 表示这不是一个能解析端口的 TCP/UDP 报文（例如 IP 分片、其它协议）。
// 注意：分片报文一律返回 false，调用方在进程模式下会直接放行，避免误伤。
bool ExtractTcpUdpPorts(const unsigned char* packet, UINT packetLen, UINT8* protocol,
                        unsigned* srcPort, unsigned* dstPort)
{
    if (packet == NULL || packetLen == 0) {
        return false;
    }

    PWINDIVERT_IPHDR   ipHdr   = NULL;
    PWINDIVERT_IPV6HDR ipv6Hdr = NULL;
    PWINDIVERT_TCPHDR  tcpHdr  = NULL;
    PWINDIVERT_UDPHDR  udpHdr  = NULL;
    UINT8  proto = 0;

    if (!WinDivertHelperParsePacket(packet, packetLen, &ipHdr, &ipv6Hdr, &proto,
                                    NULL, NULL, &tcpHdr, &udpHdr,
                                    NULL, NULL, NULL, NULL)) {
        return false;
    }
    if (protocol != NULL) {
        *protocol = proto;
    }

    if (tcpHdr != NULL) {
        if (srcPort != NULL) { *srcPort = static_cast<unsigned>(WinDivertHelperNtohs(tcpHdr->SrcPort)); }
        if (dstPort != NULL) { *dstPort = static_cast<unsigned>(WinDivertHelperNtohs(tcpHdr->DstPort)); }
        return true;
    }
    if (udpHdr != NULL) {
        if (srcPort != NULL) { *srcPort = static_cast<unsigned>(WinDivertHelperNtohs(udpHdr->SrcPort)); }
        if (dstPort != NULL) { *dstPort = static_cast<unsigned>(WinDivertHelperNtohs(udpHdr->DstPort)); }
        return true;
    }
    return false;
}

// =============================================================================
//  连接标识（五元组）—— v2.0.0 限速的"按连接公平分配"要用
// =============================================================================
//  为什么需要它：v1.5.0 的限速是"一个方向一个 FIFO 队列 + 一个令牌桶"。
//  问题是**一条凶猛的连接能把队列塞满**（比如某个下载线程一口气灌几百个包），
//  同一应用里其它连接的包就只能排在后面，甚至因为队列满而被丢掉 —— 经典的头阻塞。
//  真实瓶颈链路有公平排队，多条连接能比较均匀地分到带宽；这里就按连接分开排队、
//  轮询取包，令牌桶仍然是**一个**（所以总速率上限完全不变）。
struct FlowKey {
    unsigned char  src[16];      // IPv4 只占前 4 字节，其余补 0（保证同一连接键一致）
    unsigned char  dst[16];
    unsigned short srcPort;
    unsigned short dstPort;
    unsigned char  proto;
    unsigned char  isIpv6;

    bool operator<(const FlowKey& o) const
    {
        int c = std::memcmp(src, o.src, sizeof(src));
        if (c != 0) { return c < 0; }
        c = std::memcmp(dst, o.dst, sizeof(dst));
        if (c != 0) { return c < 0; }
        if (srcPort != o.srcPort) { return srcPort < o.srcPort; }
        if (dstPort != o.dstPort) { return dstPort < o.dstPort; }
        if (proto   != o.proto)   { return proto   < o.proto; }
        return isIpv6 < o.isIpv6;
    }
};

// 取五元组。与 ExtractTcpUdpPorts 用同一个解析器，但把地址也带出来。
// 返回 false（ICMP、分片、异常报文）时调用方会用"全零键"当同一个默认流。
bool ExtractFlowKey(const unsigned char* packet, UINT packetLen, FlowKey* out)
{
    if (packet == NULL || packetLen == 0 || out == NULL) {
        return false;
    }

    PWINDIVERT_IPHDR   ipHdr   = NULL;
    PWINDIVERT_IPV6HDR ipv6Hdr = NULL;
    PWINDIVERT_TCPHDR  tcpHdr  = NULL;
    PWINDIVERT_UDPHDR  udpHdr  = NULL;
    UINT8  proto = 0;

    if (!WinDivertHelperParsePacket(packet, packetLen, &ipHdr, &ipv6Hdr, &proto,
                                    NULL, NULL, &tcpHdr, &udpHdr,
                                    NULL, NULL, NULL, NULL)) {
        return false;
    }

    std::memset(out, 0, sizeof(*out));
    out->proto = proto;

    if (ipHdr != NULL) {
        std::memcpy(out->src, &ipHdr->SrcAddr, 4);
        std::memcpy(out->dst, &ipHdr->DstAddr, 4);
    } else if (ipv6Hdr != NULL) {
        out->isIpv6 = 1;
        std::memcpy(out->src, ipv6Hdr->SrcAddr, 16);
        std::memcpy(out->dst, ipv6Hdr->DstAddr, 16);
    } else {
        return false;
    }

    if (tcpHdr != NULL) {
        out->srcPort = WinDivertHelperNtohs(tcpHdr->SrcPort);
        out->dstPort = WinDivertHelperNtohs(tcpHdr->DstPort);
        return true;
    }
    if (udpHdr != NULL) {
        out->srcPort = WinDivertHelperNtohs(udpHdr->SrcPort);
        out->dstPort = WinDivertHelperNtohs(udpHdr->DstPort);
        return true;
    }
    return false;       // ICMP 之类没有端口，无法按连接区分
}

// =============================================================================
//  丢包率用的快速随机数发生器（v1.3.0）
//  为什么不用 rand()：
//    * rand() 内部带锁，在逐包判断的热路径上是瓶颈；
//    * 它的低位随机性差，rand() % 100 会有可见偏斜。
//  这里用 xorshift64*：单条流水线、无锁、周期 2^64-1，做丢包判定绰绰有余。
//  每个工作线程持有自己的实例（本文件里收包线程只有一个，天然无竞争）。
// =============================================================================
struct LossRandom {
    unsigned long long state;

    LossRandom()
    {
        // 多源熵混合种子：时间 + 线程 id + 性能计数器，
        // 避免多次启动（或同一毫秒内重启）拿到同一个序列。
        LARGE_INTEGER qpc;
        std::memset(&qpc, 0, sizeof(qpc));
        QueryPerformanceCounter(&qpc);

        unsigned long long seed = static_cast<unsigned long long>(GetTickCount64());
        seed ^= (static_cast<unsigned long long>(GetCurrentThreadId()) << 32);
        seed ^= static_cast<unsigned long long>(qpc.QuadPart);
        seed ^= 0x9E3779B97F4A7C15ULL;    // 黄金比例常数，顺带避开全零种子
        if (seed == 0) {
            seed = 0x2545F4914F6CDD1DULL;
        }
        state = seed;
    }

    unsigned long long Next()
    {
        unsigned long long x = state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        state = x;
        return x * 0x2545F4914F6CDD1DULL;
    }

    // 返回 [0,100) 的均匀整数。
    // 用“取高 32 位 -> 乘 100 -> 再取高 32 位”的线性映射，
    // 而不是 x % 100：没有取模偏斜，也更快（一次乘法 + 一次移位）。
    unsigned NextPercent()
    {
        const unsigned long long high = Next() >> 32;          // [0, 2^32)
        return static_cast<unsigned>((high * 100ULL) >> 32);   // [0, 100)
    }

    // 以 percent% 的概率返回 true。
    //   percent == 0   -> 恒 false（该方向不接管，正常不会走到这里）
    //   percent >= 100 -> 恒 true（100% 黑洞，不掷随机数）
    bool Hit(unsigned percent)
    {
        if (percent == 0)   { return false; }
        if (percent >= 100) { return true; }
        return NextPercent() < percent;
    }
};

// =============================================================================
//  限速：令牌桶 + 排队 + 独立节流线程（v1.5.0）
// =============================================================================
//  为什么只能在用户态做：WinDivert 的过滤器语言没有"速率"这个概念，只能把报文
//  收到用户态，自己算令牌、自己决定什么时候放回去。
//
//  为什么必须单独一个线程：
//    * 收包线程绝不能被"等令牌够了再发"阻塞 —— 一阻塞就停止 WinDivertRecv，
//      驱动队列很快溢出，丢掉的是**根本没打算丢**的包；
//    * 单独一个发送线程还顺带保证了 WinDivertSend 串行、天然保序。
//
//  为什么必须 timeBeginPeriod(1)：Windows 默认定时器精度约 15.6ms，
//  不抬高精度的话限速会退化成"每 15ms 喷一串"，那就不叫整形了。
//
//  算法（Linux tc 的 TBF / 令牌桶，纯整形、不丢包）：
//     tokens = min(tokens + rate * dt, burst)
//     能发 <=> tokens >= 包长（桶满时也放行，否则比桶还大的包永远发不出去）
//     不能发就排队；队列按字节封顶，排不下才丢（单独统计）
//
//  保序要点：**队列非空时，新包一律排到队尾**，绝不能"令牌刚好够就抢先发"，
//  否则新包会插到还在等令牌的旧包前面 —— 那就是乱序了。
// =============================================================================

namespace {

struct ShapedPacket {
    std::vector<unsigned char> data;
    UINT               len = 0;
    WINDIVERT_ADDRESS  addr;
    unsigned long long enqueueUs = 0;   // 入队时刻，用来判定"等太久了"（见 maxDelayMs）
    size_t             charge = 0;      // 这个包要扣多少令牌（v2.0.4：至少 mpu 字节）
};

// 一条连接的排队队列。
// 单独记 bytes 是为了能对**单条连接**做入队限额：只做"轮询调度"是不够的 ——
// 如果字节预算被所有连接共享，一条凶猛的连接照样能把缓冲占满，
// 别的连接的包在**入队那一刻**就被丢了，那还是饿死。
struct FlowQueue {
    std::deque<ShapedPacket> packets;
    size_t                   bytes = 0;
};

// 连接的排队表：键是五元组，值是这条连接的 FIFO。
// typedef 必须放在这里（ShapedPacket 定义之后、且同在匿名命名空间内），
// 否则会和后面那个匿名的 ShapedPacket 变成两个不同的类型。
typedef std::map<FlowKey, FlowQueue> FlowMap;
typedef FlowMap::iterator FlowIt;

struct ShapeQueue {
    // v2.0.0：按连接分开排队 + 轮询取包（公平排队）。
    // 令牌桶仍然是**一个**，所以"这个方向总共不超 X B/s"的语义完全没变；
    // 变的只是"多条连接之间怎么分配"：从"先来先服务（谁塞得快谁占满）"
    // 改成"轮流各取一个包"，一条凶猛的连接再也饿不死别人。
    std::map<FlowKey, FlowQueue> flows;
    std::deque<FlowKey>  order;                   // 轮询顺序（只放非空连接的键）
    size_t                 queuedBytes = 0;       // 所有连接合计（内存硬上限用）
    size_t                 perFlowLimitBytes = 0; // 单条连接能占的字节上限（公平用）
    size_t                 mpuBytes = 0;          // 最小包单位（对齐 tc tbf 的 mpu，0 = 不限）
    double                 tokens = 0.0;          // 可用令牌（字节）
    unsigned long long     lastRefillUs = 0;
    unsigned long long     rateBytesPerSec = 0;   // 0 = 不限速（直通）
    double                 burstBytes = 0.0;      // 桶容量
    size_t                 limitBytes = 0;        // 队列字节上限（防内存爆）
    unsigned               maxDelayMs = 0;        // 排队时间上限，超了就丢
    std::atomic<unsigned long long> sent{0};      // 经限速放行的报文数
    std::atomic<unsigned long long> sentBytes{0}; // 对应字节数
};

ShapeQueue g_shapeIn;      // 下行（inbound）
ShapeQueue g_shapeOut;     // 上行（outbound）

HANDLE g_shapeEvent  = NULL;   // 自动重置：有新包入队 / 要求退出
HANDLE g_shapeThread = NULL;
bool   g_shapingOn   = false;
bool   g_timerRaised = false;  // 是否已 timeBeginPeriod(1)（退路才用）

// v2.0.0：高精度等待定时器。
// 为什么要它：原来靠 timeBeginPeriod(1) + WaitForSingleObject，只有 1ms 粒度，
// 而且 timeBeginPeriod 是**全局**的（抬高整个系统的定时器精度，费电、影响别的程序）。
// Windows 10 1803+ 的 CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 可以拿到亚毫秒精度，
// 且不需要动全局设置。拿不到时才回退到老办法。
HANDLE g_shapeTimer = NULL;
bool   g_shapeTimerHighRes = false;

// v2.0.3：整形的时间基准 —— 必须用 QueryPerformanceCounter，不能用 GetTickCount64。
//
// 为什么：实测 GetTickCount64() 的分辨率就是**系统时钟节拍 15~16ms**，
// 而且在这台机器上调 timeBeginPeriod(1) **也改善不了它**。
// 后果：令牌按 15.6ms 的整数倍"一坨一坨"补，而桶容量只有 rate/100（10ms 的量），
// 一坨比桶还大 → 每坨都被截断掉一部分令牌 → 限速系统性偏低。
// 算一下就对上了：1MB/s 时桶 10486 字节，15.6ms 本该补 16358 → 只能用 10486，
// 上限约 672KB/s。实测 1M 达成 82%、3M 达成 67%（预测 67%），量级吻合。
//
// 这也解释了为什么仿真测试全准：仿真按精确 1ms 步进推时间，量化误差根本不出现。
// 这是 v2.0.0 引入的回归 —— 当时把 timeBeginPeriod(1) 改成"只有拿不到高精度定时器才调"，
// 睡眠精度上去了，记账精度却丢了。
// 将 QPC tick 换成微秒。先做商和余数，避免长时间开机后 ticks * 1000000 溢出。
unsigned long long QpcTicksToUs(unsigned long long ticks, unsigned long long frequency)
{
    if (frequency == 0) { return 0; }
    const unsigned long long seconds = ticks / frequency;
    const unsigned long long remainder = ticks % frequency;
    if (seconds > ULLONG_MAX / 1000000ULL) { return ULLONG_MAX; }
    // QPC 频率在 Windows 上远小于此界限；额外分支避免异常频率下余数乘法溢出。
    const unsigned long long fraction =
        (remainder <= ULLONG_MAX / 1000000ULL)
        ? (remainder * 1000000ULL) / frequency
        : static_cast<unsigned long long>(
              static_cast<long double>(remainder) * 1000000.0L /
              static_cast<long double>(frequency));
    return seconds * 1000000ULL + fraction;
}

unsigned long long ShapeNowUs()
{
    static const unsigned long long frequency = []() -> unsigned long long {
        LARGE_INTEGER value;
        if (!QueryPerformanceFrequency(&value) || value.QuadPart <= 0) { return 0; }
        return static_cast<unsigned long long>(value.QuadPart);
    }();
    LARGE_INTEGER ticks;
    if (frequency == 0 || !QueryPerformanceCounter(&ticks) || ticks.QuadPart < 0) {
        return GetTickCount64() * 1000ULL;
    }
    return QpcTicksToUs(static_cast<unsigned long long>(ticks.QuadPart), frequency);
}

CRITICAL_SECTION& ShapeLock()
{
    // 与 DebugLock 同样的手法：函数内静态对象保证只初始化一次，且不必关心
    // 全局对象构造顺序。
    static CRITICAL_SECTION cs;
    static const bool initialized = []() -> bool {
        InitializeCriticalSection(&cs);
        return true;
    }();
    (void)initialized;
    return cs;
}

// 一次性发送（不做限速判断）。收包线程与节流线程都用它，错误处理完全一致。
bool SendPacketNow(HANDLE handle, const unsigned char* data, UINT len,
                   const WINDIVERT_ADDRESS& addr)
{
    UINT sendLen = 0;
    const bool apiOk = WinDivertSend(handle, const_cast<unsigned char*>(data), len, &sendLen,
                                    const_cast<WINDIVERT_ADDRESS*>(&addr)) != FALSE;
    const DWORD apiError = apiOk ? ERROR_WRITE_FAULT : GetLastError();
    const bool sent = apiOk && sendLen == len;
    if (!sent) {
        const DWORD sendError = apiError;
        // 停止/收尾过程中句柄已关闭、驱动队列已 purge：属正常路径
        if (sendError != ERROR_NO_DATA && sendError != ERROR_OPERATION_ABORTED &&
            sendError != ERROR_INVALID_HANDLE) {
            g_statSendErrors.fetch_add(1);
            const unsigned long long sendFailures = g_statSendErrors.load();
            if (sendFailures <= kSendErrorBurst || (sendFailures % kSendErrorStep) == 0) {
                Emit(LogLevel::Warning,
                     "WinDivertSend 放行失败（错误码 %lu，累计 %llu 个包未能放行）。",
                     static_cast<unsigned long>(sendError), sendFailures);
            }
        }
    } else {
        g_statForwarded.fetch_add(1);
        g_statForwardedBytes.fetch_add(len);
    }
    return sent;
}

// 按速率给桶里补令牌。必须在持锁状态下调用。
void ShapeRefillLocked(ShapeQueue& q, unsigned long long now)
{
    if (q.rateBytesPerSec == 0) {
        return;
    }
    if (q.lastRefillUs == 0) {
        q.lastRefillUs = now;
        return;
    }
    if (now <= q.lastRefillUs) {
        return;         // 时钟没走（或回绕），这轮不补
    }
    // now / lastRefillUs 都是**微秒**（v2.0.3 起），所以除数从 1000 改成 1000000
    const unsigned long long dtUs = now - q.lastRefillUs;
    q.tokens += static_cast<double>(q.rateBytesPerSec) *
                static_cast<double>(dtUs) / 1000000.0;
    if (q.tokens > q.burstBytes) {
        q.tokens = q.burstBytes;       // 桶满了就不再攒
    }
    q.lastRefillUs = now;
}

// 桶容量 / 队列上限的自动取值（不暴露成参数：用户只需要给一个速率）。
//
// 桶容量为什么不能用固定的 4×MTU：
//   在 300 B/s 这种极低速率下，4×MTU（6000 字节）等于**20 秒**的量 —— 开局
//   （或链路空闲一阵之后）会把这 20 秒的额度一次喷出去，那就完全不是限速了。
//   所以桶容量跟着速率走，但**必须至少有一个满包**：否则比桶还大的报文永远
//   攒不够令牌，那条流会被永久卡死。
void ShapeConfigureQueue(ShapeQueue& q, unsigned long long rateBytesPerSec,
                          unsigned maxDelayMs, size_t mpuBytes)
{
    q.mpuBytes = mpuBytes;
    q.rateBytesPerSec = rateBytesPerSec;
    if (q.rateBytesPerSec == 0) {
        q.burstBytes = 0.0;
        q.limitBytes = 0;
        q.maxDelayMs = 0;
        q.tokens = 0.0;
        q.lastRefillUs = 0;
        q.flows.clear();
        q.order.clear();
        q.queuedBytes = 0;
        return;
    }

    // 桶容量 = rate / HZ（HZ=100），即 10ms 的令牌量。这是 tc tbf 对 burst 的最小值规则。
    //
    // ⚠ v2.0.5：这里**去掉了原来的 1500 字节地板**。
    // 那个 1500 是"以太网 MTU"，当年的理由是"否则比桶还大的包永远攒不够令牌"。
    // 但那个理由后来已经被"赤字放行"取代（见 ShapeCanSend），而地板的害处是实打实的：
    //   995 B/s 时桶 1500 字节 = **1.5 秒的额度** → 桶一满就喷一波包，
    //   然后整整 1.5 秒发不出任何东西。
    //   游戏收到 1.5 秒静默会直接判定掉线（用户实测："连不上、一直转圈"），
    //   而 NetLimiter 是均匀摊开延迟（显示 999 延迟但连接保持）。
    // 现在桶只有 10ms 的量，大包走赤字通道，节奏就均匀了。
    q.burstBytes = static_cast<double>(q.rateBytesPerSec) / 100.0;
    if (q.burstBytes < 1.0) { q.burstBytes = 1.0; }

    // 排队时间上限：0 = 按速率自动算
    q.maxDelayMs = (maxDelayMs > 0) ? maxDelayMs : AutoMaxShapeDelayMs(q.rateBytesPerSec);

    // 队列字节上限：按 tc tbf 的关系 **limit = rate × latency + burst**（v2.0.4）。
    //
    // 原来这里是独立的启发式 `rate/10`（100ms 的量），而延迟上限默认是 200ms ——
    // 两者对不上，后果是：一个需要等 150ms 的包，**延迟检查说"可以等"，
    // 队列检查说"放不下"**，然后被丢掉。这是无谓丢包，不是整形。
    // 改成按 latency 反推队列容量之后，两者自洽：只要在延迟容忍内就装得下。
    // 仍然保留 4MB 硬顶防内存爆（tc 没有上限，但我们是常驻进程，必须封顶）。
    // v2.0.5：队列给一个**与速率无关的下限**。
    //
    // 为什么：低速率下按 rate×latency 算出来的队列太小（995 B/s 时只有 6000 字节），
    // 而游戏的连接握手/登录突发轻松超过这个量 —— 一超就被**丢掉**，
    // TCP 进入重传风暴，游戏自己判定连接失败（"一直转圈"）。
    // NetLimiter 是**延迟而不是丢**，所以它显示 999 延迟但连接保持。
    //
    // 内存代价很小：256KB 的下限在任何速率下都只是 256KB。
    // 速率高的时候按 rate×latency 算出来的本来就更大，不受影响。
    {
        double limit = static_cast<double>(q.rateBytesPerSec) *
                       (static_cast<double>(q.maxDelayMs) / 1000.0) + q.burstBytes;
        const double kMinQueueBytes = 256.0 * 1024.0;
        if (limit < kMinQueueBytes) { limit = kMinQueueBytes; }
        if (limit > 4.0 * 1024.0 * 1024.0) { limit = 4.0 * 1024.0 * 1024.0; }
        if (limit < q.burstBytes) { limit = q.burstBytes; }
        q.limitBytes = static_cast<size_t>(limit);

        // 延迟上限必须与"我们实际提供的缓冲"自洽：
        // 队列能装 limit 字节，就该容忍它对应的排队时间。
        // 不然又回到 v2.0.4 修的那个矛盾（延迟检查说"可以等"、队列检查说"放不下"）。
        const unsigned long long queueDelayMs = static_cast<unsigned long long>(
            static_cast<double>(q.limitBytes) * 1000.0 /
            static_cast<double>(q.rateBytesPerSec));
        if (queueDelayMs > q.maxDelayMs) {
            q.maxDelayMs = (queueDelayMs > 600000ULL)
                         ? 600000U : static_cast<unsigned>(queueDelayMs);
        }
    }

    // 单条连接的排队字节上限：约 1/8 的共享预算，但至少 4 个满包
    // （下限是为了别把正常的小突发给拦掉；1/8 是为了让 8 条左右的连接能同时排队）
    double perFlow = static_cast<double>(q.limitBytes) / 8.0;
    const double fourMtu = 4.0 * 1500.0;
    if (perFlow < fourMtu) { perFlow = fourMtu; }
    if (perFlow > static_cast<double>(q.limitBytes)) { perFlow = static_cast<double>(q.limitBytes); }
    q.perFlowLimitBytes = static_cast<size_t>(perFlow);

    q.tokens = q.burstBytes;    // 开局给满桶（TBF 的标准做法）
    q.lastRefillUs = 0;
}

// 这个包还要等多少毫秒才能真正发出去。
// 注意不能只算自己的令牌缺口 —— 排在前面（同连接内 + 其它连接轮到的）也要先吃令牌，
// 所以要把已排队的字节数一起算进去，否则会严重低估等待时间（延迟上限就失效了）。
size_t ShapeCharge(const ShapeQueue& q, size_t len);   // 见下方定义

long long ShapeWaitMsLocked(const ShapeQueue& q, size_t len)
{
    if (q.rateBytesPerSec == 0) {
        return 0;
    }
    const double pending = static_cast<double>(q.queuedBytes) +
                           static_cast<double>(ShapeCharge(q, len)) - q.tokens;
    if (pending <= 0.0) {
        return 0;
    }
    return static_cast<long long>(pending * 1000.0 /
                                  static_cast<double>(q.rateBytesPerSec) + 0.5);
}

// v2.0.0：每个方向最多跟踪多少条连接。超过之后新连接一律按"队列满"处理（丢弃），
// 避免被大量短连接把内存撑爆（单条连接的包再小也至少几十字节，
// 所以字节上限其实已经间接限住了，这里只是再加一道明确的闸）。
const size_t kMaxShapeFlows = 4096;

// 大包可能来自回环、巨帧或分段卸载。队列容量按实际报文收费上限调整，
// 令牌桶本身保持小容量；大包由 ShapeCanSend 的赤字机制发送。
const size_t kShapeMaxPacket = 65536;   // IP 报文长度上限就是 65535，留 1 字节余量

// v2.0.4：一个包要扣多少令牌 —— 对齐 tc tbf 的 mpu（最小包单位）。
// tc 手册的原话：零字节的包并不占用零带宽；以太网上任何帧都不小于 64 字节。
// mpuBytes = 0 时行为与 tc 默认一致（不设下限），扣费就等于包长。
size_t ShapeCharge(const ShapeQueue& q, size_t len)
{
    return (len < q.mpuBytes) ? q.mpuBytes : len;
}

// v2.0.5：现在能不能发这个包？
//
// 两种情况：
//   a) 令牌够          -> 照常发（正常限速路径）
//   b) 包比桶还大      -> **赤字放行**：只要还有一点令牌就先发出去，允许令牌变负，
//                         欠下的量由后续补充扣回来。
//
// 为什么需要 b)：桶只有 rate/100（995 B/s 时还不到 10 字节），
// 而任何一个真实报文都比它大。如果死等"令牌 >= 包长"，就永远发不出去。
// 原来的做法是把桶**永久撑大**到该包大小 —— 那会让桶一直停在 1500 字节，
// 于是永远在"喷一波 + 静默 1.5 秒"之间循环。改成赤字之后桶保持小，
// 节奏是均匀的，而平均速率照样准（欠的令牌一定会从后续流量里扣回来）。
//
// 注意：只有"包比桶大"才走赤字通道。正常大小的包仍然要求攒够令牌，
// 这样不会在高速率下额外制造突发。
bool ShapeCanSend(const ShapeQueue& q, size_t charge)
{
    if (q.tokens <= 0.0) { return false; }
    if (q.tokens >= static_cast<double>(charge)) { return true; }
    return static_cast<double>(charge) > q.burstBytes;
}

void ShapeEnsurePacketCapacityLocked(ShapeQueue& q, size_t len)
{
    if (q.rateBytesPerSec == 0) { return; }

    size_t want = len;
    if (want > kShapeMaxPacket) { want = kShapeMaxPacket; }
    if (static_cast<double>(want) <= q.burstBytes) { return; }

    // v2.0.5：**不再撑大桶**（桶会被赤字通道兜住），只把队列上限与延迟上限放大，
    // 保证这个大包能排得下、也等得起。撑桶是永久性的，正是"喷一波+静默"的根源。
    if (q.limitBytes < want) { q.limitBytes = want; }
    if (q.perFlowLimitBytes < want) { q.perFlowLimitBytes = want; }

    // 延迟上限也按"3 个包的时间"重算：大包在低速下本来就要攒很久令牌，
    // 拿 1500 字节算出来的上限会把它当"等太久"丢掉 —— 那就不是整形而是丢包了。
    const double needMs = static_cast<double>(want) * 3.0 * 1000.0 /
                          static_cast<double>(q.rateBytesPerSec);
    const unsigned long long cap =
        (needMs > 600000.0) ? 600000ULL : static_cast<unsigned long long>(needMs);
    if (cap > q.maxDelayMs) { q.maxDelayMs = static_cast<unsigned>(cap); }

    if (q.tokens > q.burstBytes) { q.tokens = q.burstBytes; }
}

// 把一个包交给限速器：令牌够且该方向队列为空就当场发；否则按连接排队；
// 排不下或等太久就丢。返回 true 表示"已经处理掉了"（发了 或 丢了）。
bool ShapeSubmit(HANDLE handle, const unsigned char* data, UINT len,
                 const WINDIVERT_ADDRESS& addr, bool outbound, const FlowKey& flow)
{
    ShapeQueue& q = outbound ? g_shapeOut : g_shapeIn;
    const unsigned long long now = ShapeNowUs();

    bool sendNow = false;
    {
        EnterCriticalSection(&ShapeLock());
        ShapeRefillLocked(q, now);
        // 先确保队列能容纳这个包，再判断令牌；桶容量不随包长改变。
        const size_t charge = ShapeCharge(q, len);
        ShapeEnsurePacketCapacityLocked(q, charge);

        const bool tokensEnough = ShapeCanSend(q, charge);

        // 只有"整个方向一条积压都没有"时才允许直接发。
        // 这里必须看 flows 而不是看这条连接自己的队列：否则新包会插到
        // 别的连接还在等令牌的包前面 —— 那就不公平了。
        if (q.flows.empty() && tokensEnough) {
            // v2.0.5：**允许令牌变负**（赤字）。原来这里钳到 0 会把赤字抹掉，
            // 等于白送了这一个包的额度，速率会偏高。
            q.tokens -= static_cast<double>(charge);
            sendNow = true;
        } else {
            // 排队之前先看两件事：
            //   1) 等它真能发出去要多久？超过上限就**别排了，直接丢** ——
            //      排在队列里等几十秒的包送到时对方早就重传过了，纯属白占内存；
            //   2) 队列字节数还放得下吗？
            const long long waitMs = ShapeWaitMsLocked(q, len);
            const bool tooLate = (q.maxDelayMs > 0) &&
                                 (waitMs > static_cast<long long>(q.maxDelayMs));
            FlowIt it = q.flows.find(flow);
            const bool newFlow = (it == q.flows.end());
            const size_t flowBytes = newFlow ? 0 : it->second.bytes;
            const bool queueFull  = (q.queuedBytes + len > q.limitBytes);
            // 单连接限额：防止一条连接把共享预算吃光，让别的连接在入队时就被丢
            const bool flowFull   = (flowBytes + len > q.perFlowLimitBytes);
            const bool tooManyFlows = newFlow && (q.flows.size() >= kMaxShapeFlows);

            if (tooLate || queueFull || flowFull || tooManyFlows) {
                g_statShapeDropped.fetch_add(1);
                g_statShapeLateDropped.fetch_add(tooLate && !queueFull ? 1 : 0);
                LeaveCriticalSection(&ShapeLock());
                return true;                 // 丢了也是"处理掉了"
            }

            ShapedPacket p;
            p.data.assign(data, data + len);
            p.len  = len;
            p.charge = charge;
            p.addr = addr;
            p.enqueueUs = now;

            if (newFlow) {
                it = q.flows.insert(std::make_pair(flow, FlowQueue())).first;
                q.order.push_back(flow);     // 新连接排在轮询队尾
            }
            it->second.packets.push_back(std::move(p));
            it->second.bytes += len;
            q.queuedBytes += len;
        }
        LeaveCriticalSection(&ShapeLock());
    }

    if (sendNow) {
        if (SendPacketNow(handle, data, len, addr)) {
            q.sent.fetch_add(1);
            q.sentBytes.fetch_add(len);
        }
    } else if (g_shapeEvent != NULL) {
        SetEvent(g_shapeEvent);              // 叫醒节流线程
    }
    return true;
}

// 把"现在就能发"的包取出来（在锁内调用，只搬不发送，避免持锁做系统调用）。
//
// v2.0.0：改成**按连接轮询**：每一轮给每条有积压的连接发一个包，发完排到队尾。
// 这样一条塞了几百个包的连接，也只能和别的连接一样"一轮拿一个"，
// 不会再独占队列。令牌桶仍是全局一个，所以总速率上限一点没变。
void ShapeCollectLocked(ShapeQueue& q, unsigned long long now,
                        std::vector<ShapedPacket>& out)
{
    if (q.flows.empty()) {
        q.order.clear();
        return;
    }
    ShapeRefillLocked(q, now);

    // 先清掉"等太久"的包：正常情况下入队时就已经挡掉了，但机器休眠/进程被饿死后
    // 时钟会突然跳一大截，那时所有积压包会瞬间到期、被当成一个巨大突发喷出去。
    // 与其喷一个几分钟攒出来的突发，不如如实丢掉。逐连接检查队头（连接内是 FIFO，
    // 队头就是最老的）。
    if (q.maxDelayMs > 0) {
        for (FlowIt it = q.flows.begin(); it != q.flows.end(); ) {
            FlowQueue& fq = it->second;
            while (!fq.packets.empty() &&
                   (now - fq.packets.front().enqueueUs) >
                       static_cast<unsigned long long>(q.maxDelayMs) * 1000ULL) {
                q.queuedBytes -= fq.packets.front().len;
                fq.bytes      -= fq.packets.front().len;
                fq.packets.pop_front();
                g_statShapeDropped.fetch_add(1);
                g_statShapeLateDropped.fetch_add(1);
            }
            if (fq.packets.empty()) {
                it = q.flows.erase(it);
            } else {
                ++it;
            }
        }
        if (q.flows.empty()) {
            q.order.clear();
            return;
        }
        // 轮询表里可能有已经被清空的键，下面取包时会顺手剔掉。
    }

    // 轮询发送。每一轮把当时存在的连接各看一次，能发就发一个、排到队尾；
    // 一轮下来一个包都没发出去就说明令牌不够了，收工。
    bool progress = true;
    bool waitForTokens = false;
    while (progress && !waitForTokens && !q.flows.empty()) {
        progress = false;
        size_t remaining = q.order.size();
        while (remaining-- > 0 && !q.order.empty()) {
            const FlowKey key = q.order.front();
            q.order.pop_front();

            FlowIt it = q.flows.find(key);
            if (it == q.flows.end() || it->second.packets.empty()) {
                continue;                    // 已被清空：丢掉这个键，不再入队
            }

            ShapedPacket& p = it->second.packets.front();
            // 与直接发送路径共用令牌规则，大包可先记赤字再补回。
            const bool canSend = ShapeCanSend(q, p.charge);
            if (canSend) {
                q.tokens -= static_cast<double>(p.charge);   // 允许变负（赤字）
                q.queuedBytes -= p.len;
                it->second.bytes -= p.len;
                out.push_back(std::move(p));
                it->second.packets.pop_front();
                progress = true;
                if (it->second.packets.empty()) {
                    q.flows.erase(it);
                } else {
                    q.order.push_back(key);  // 这条连接还有包：排到队尾，让别人先走
                }
            } else {
                if (progress) {
                    // 本轮已有连接发过包，下一次必须先轮到当前连接。
                    // 若再放队尾，低速率下每次只够一包时队首连接会一直独占。
                    q.order.push_front(key);
                    waitForTokens = true;
                    break;
                }
                q.order.push_back(key);      // 本轮尚未发送，继续找能发送的小包
            }
        }
    }
}

// 还要等多少**微秒**才有包可发。<0 表示两个队列都空，可以一直等。
// v2.0.0：从"毫秒"改成"微秒" —— 配合高精度定时器，让高速率下的节奏更细。
// 注意速率的长期准确性不依赖这个值（令牌是按真实流逝时间补的，睡多睡少都会自校正），
// 它只影响"包之间的疏密"，也就是毫秒级的突发程度。
long long ShapeNextWaitUsLocked(unsigned long long now)
{
    long long best = -1;
    ShapeQueue* queues[2] = { &g_shapeIn, &g_shapeOut };
    for (int i = 0; i < 2; ++i) {
        ShapeQueue& q = *queues[i];
        if (q.flows.empty() || q.rateBytesPerSec == 0) {
            continue;
        }
        ShapeRefillLocked(q, now);
        // 令牌不足导致本轮停下时，下一次应优先唤醒队首连接。
        // 选全局最短包会在别的流已可发送、队首尚不可发送时空转。
        size_t nextCharge = 0;
        for (size_t j = 0; j < q.order.size(); ++j) {
            FlowIt it = q.flows.find(q.order[j]);
            if (it != q.flows.end() && !it->second.packets.empty()) {
                nextCharge = it->second.packets.front().charge;
                break;
            }
        }
        if (nextCharge == 0) {
            continue;
        }
        // 与 ShapeCanSend 保持同一套规则：包比桶大时只要令牌回正就能发（赤字），
        // 否则要攒够整包。算错这里会导致"要么早发、要么空转"。
        const double need = (static_cast<double>(nextCharge) > q.burstBytes)
                          ? (0.0 - q.tokens)
                          : (static_cast<double>(nextCharge) - q.tokens);
        if (need <= 0.0) {
            return 0;           // 现在就能发，别再睡了
        }
        double us = need * 1000000.0 / static_cast<double>(q.rateBytesPerSec);
        long long w = static_cast<long long>(us + 0.5);
        // 下限 100 微秒：再短就是忙等，白烧 CPU，而且令牌也会在下一圈自然补齐
        if (w < 100) { w = 100; }
        if (best < 0 || w < best) { best = w; }
    }
    return best;
}
// 停止时把两个队列里没来得及发的包全部丢掉，并记账。
// 为什么丢掉而不是发完：这些包已经等了 0~100ms，用户按停止就是要"网络马上恢复正常"；
// 一次性 flush 出去会喷出一个大突发，正好和限速的目的相反。丢几个包 TCP 会重传，无感。
void ShapeDiscardAll(const char* why)
{
    unsigned long long dropped = 0;
    EnterCriticalSection(&ShapeLock());
    ShapeQueue* queues[2] = { &g_shapeIn, &g_shapeOut };
    for (int i = 0; i < 2; ++i) {
        ShapeQueue& q = *queues[i];
        for (FlowIt it = q.flows.begin(); it != q.flows.end(); ++it) {
            dropped += static_cast<unsigned long long>(it->second.packets.size());
        }
        q.flows.clear();
        q.order.clear();
        q.queuedBytes = 0;
    }
    LeaveCriticalSection(&ShapeLock());

    if (dropped > 0) {
        g_statShapeDropped.fetch_add(dropped);
        Emit(LogLevel::Info, "%s：限速队列里还有 %llu 个报文未发出，已丢弃"
                             "（这些包已过期，TCP 会重传）。",
             (why != NULL) ? why : "结束", dropped);
    }
}

// 节流线程：睡到"下一个包可以发"的时刻，醒了把能发的发掉。
DWORD WINAPI ShaperThread(LPVOID param)
{
    (void)param;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
    DebugLogf("节流线程启动：下行 %llu B/s，上行 %llu B/s",
              g_shapeIn.rateBytesPerSec, g_shapeOut.rateBytesPerSec);

    std::vector<ShapedPacket> batchIn;
    std::vector<ShapedPacket> batchOut;

    while (!IsStopRequested()) {
        HANDLE handle = LoadHandle();
        if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
            break;              // 句柄已被看门狗关闭：正常退出路径
        }

        const unsigned long long now = ShapeNowUs();
        batchIn.clear();
        batchOut.clear();
        long long waitUs = -1;

        EnterCriticalSection(&ShapeLock());
        ShapeCollectLocked(g_shapeIn, now, batchIn);
        ShapeCollectLocked(g_shapeOut, now, batchOut);
        waitUs = ShapeNextWaitUsLocked(ShapeNowUs());
        LeaveCriticalSection(&ShapeLock());

        // 发送放在锁外：WinDivertSend 是系统调用，持锁发送会拖住收包线程
        for (size_t i = 0; i < batchIn.size(); ++i) {
            if (IsStopRequested()) { break; }
            if (SendPacketNow(handle, batchIn[i].data.data(), batchIn[i].len, batchIn[i].addr)) {
                g_shapeIn.sent.fetch_add(1);
                g_shapeIn.sentBytes.fetch_add(batchIn[i].len);
            }
        }
        for (size_t i = 0; i < batchOut.size(); ++i) {
            if (IsStopRequested()) { break; }
            if (SendPacketNow(handle, batchOut[i].data.data(), batchOut[i].len, batchOut[i].addr)) {
                g_shapeOut.sent.fetch_add(1);
                g_shapeOut.sentBytes.fetch_add(batchOut[i].len);
            }
        }

        if (IsStopRequested()) {
            break;
        }

        if (waitUs < 0) {
            // 队列空：等新包入队，或等到要求退出（100ms 兜底，防止漏通知）
            WaitForSingleObject(g_shapeEvent, 100);
        } else if (waitUs == 0) {
            // 现在就能发：不再睡，直接转下一圈
        } else if (g_shapeTimer != NULL) {
            // 高精度路径：把定时器设成"相对 waitUs 微秒后到期"，
            // 同时等"事件"（有新包/要退出）与"定时器"（到点了）二者之一。
            // SetWaitableTimerEx 的相对时间单位是 100 纳秒，所以 ×10。
            LARGE_INTEGER due;
            due.QuadPart = -static_cast<LONGLONG>(waitUs) * 10LL;
            if (SetWaitableTimerEx(g_shapeTimer, &due, 0, NULL, NULL, NULL, 0)) {
                HANDLE waits[2] = { g_shapeEvent, g_shapeTimer };
                WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            } else {
                // 设置失败（极少）：退回毫秒级等待，别把线程卡死
                const DWORD ms = static_cast<DWORD>((waitUs + 999) / 1000);
                WaitForSingleObject(g_shapeEvent, ms > 0 ? ms : 1);
            }
        } else {
            // 退路：毫秒级。向上取整，宁可晚一点也别空转
            const DWORD ms = static_cast<DWORD>((waitUs + 999) / 1000);
            WaitForSingleObject(g_shapeEvent, ms > 0 ? ms : 1);
        }
    }

    ShapeDiscardAll("限速停止");
    DebugLogf("节流线程退出");
    return 0;
}

// 拉起节流线程（如果配置里有限速）。事件或线程创建失败时返回 false。
bool ShaperStart(const Config& cfg)
{
    const unsigned long long downBps = cfg.rateDownBytesPerSec;
    const unsigned long long upBps   = cfg.rateUpBytesPerSec;
    if (downBps == 0 && upBps == 0) {
        return true;            // 没开限速，什么都不做
    }

    EnterCriticalSection(&ShapeLock());
    ShapeConfigureQueue(g_shapeIn,  downBps, cfg.rateMaxDelayMs, cfg.mpuBytes);
    ShapeConfigureQueue(g_shapeOut, upBps,   cfg.rateMaxDelayMs, cfg.mpuBytes);
    LeaveCriticalSection(&ShapeLock());

    if (g_shapeEvent == NULL) {
#ifdef WEAKNET_TEST_HOOKS
        if (g_testFailShapeEvent != 0) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            g_shapeEvent = NULL;
        } else
#endif
        g_shapeEvent = CreateEventW(NULL, FALSE, FALSE, NULL);   // 自动重置
        if (g_shapeEvent == NULL) {
            Emit(LogLevel::Warning, "创建限速事件失败（错误码 %lu），限速不生效。",
                 static_cast<unsigned long>(GetLastError()));
            return false;
        }
    }

    // ---- 等待机制：优先高精度定时器，拿不到才抬全局定时器精度 ----------------
    // v2.0.0：先试 CREATE_WAITABLE_TIMER_HIGH_RESOLUTION（Win10 1803+）。
    // 它有两个好处：亚毫秒精度；**不需要** timeBeginPeriod（那个是全局设置，
    // 会抬高整个系统的定时器精度，费电、也会影响别的程序）。
    if (g_shapeTimer == NULL && !g_shapeTimerHighRes) {
        g_shapeTimer = CreateWaitableTimerExW(
            NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
        if (g_shapeTimer != NULL) {
            g_shapeTimerHighRes = true;
        } else {
            DebugLogf("高精度定时器不可用（错误码 %lu），退回毫秒级等待",
                      static_cast<unsigned long>(GetLastError()));
        }
    }

    // 退路：没有高精度定时器时，才去抬全局定时器精度（Windows 默认定时器精度约 15.6ms）
    if (!g_shapeTimerHighRes && !g_timerRaised) {
        if (timeBeginPeriod(1) == TIMERR_NOERROR) {
            g_timerRaised = true;
        } else {
            Emit(LogLevel::Warning,
                 "无法把系统定时器精度提到 1ms，限速的精度会明显变差。");
        }
    }

    g_shapingOn = true;
#ifdef WEAKNET_TEST_HOOKS
    if (g_testFailShapeThread != 0) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        g_shapeThread = NULL;
    } else
#endif
    g_shapeThread = CreateThread(NULL, 0, ShaperThread, NULL, 0, NULL);
    if (g_shapeThread == NULL) {
        Emit(LogLevel::Warning, "创建限速线程失败（错误码 %lu），限速不生效。",
             static_cast<unsigned long>(GetLastError()));
        g_shapingOn = false;
        return false;
    }

    Emit(LogLevel::Info,
         "限速已启用：下行 %s，上行 %s（真正的整形：排队等待，不丢包）。",
         DescribeRate(downBps).c_str(), DescribeRate(upBps).c_str());
    DebugLogf("限速启用：下行 %s（桶 %.0f 字节 / 队列 %llu 字节 / 最多排 %u ms），"
              "上行 %s（桶 %.0f 字节 / 队列 %llu 字节 / 最多排 %u ms）",
              DescribeRate(downBps).c_str(),
              g_shapeIn.burstBytes,
              static_cast<unsigned long long>(g_shapeIn.limitBytes), g_shapeIn.maxDelayMs,
              DescribeRate(upBps).c_str(),
              g_shapeOut.burstBytes,
              static_cast<unsigned long long>(g_shapeOut.limitBytes), g_shapeOut.maxDelayMs);
    return true;
}

// 超时后先关闭拦截句柄，让网络恢复，再给线程一次退出机会。
// 仍不退出时只能结束进程：绝不能释放仍被线程使用的配置/事件并启动下一会话。
void WaitForThreadStopped(HANDLE thread, const char* name, DWORD warningMs)
{
    if (thread == NULL) { return; }
    DWORD wait = WaitForSingleObject(thread, warningMs);
    if (wait == WAIT_OBJECT_0) { return; }
    Emit(LogLevel::Error, "%s 未在 %lu ms 内退出（等待结果 %lu），正在关闭拦截句柄。",
         name, static_cast<unsigned long>(warningMs), static_cast<unsigned long>(wait));
    CloseHandleOnce();
    if (wait == WAIT_TIMEOUT) {
        wait = WaitForSingleObject(thread, 5000);
    }
    if (wait != WAIT_OBJECT_0) {
        DebugLogf("致命：%s 未退出，终止进程以避免旧线程访问新会话资源", name);
        TerminateProcess(GetCurrentProcess(), ERROR_TIMEOUT);
    }
}

// 停掉节流线程并恢复定时器精度。可以重复调用。
void ShaperStop()
{
    if (g_shapeThread != NULL) {
        if (g_shapeEvent != NULL) {
            SetEvent(g_shapeEvent);          // 立刻叫醒它去看退出标志
        }
        WaitForThreadStopped(g_shapeThread, "节流线程", 3000);
        CloseHandle(g_shapeThread);
        g_shapeThread = NULL;
    }
    if (g_shapeEvent != NULL) {
        CloseHandle(g_shapeEvent);
        g_shapeEvent = NULL;
    }
    if (g_shapingOn) {
        ShapeDiscardAll("限速停止");
        g_shapingOn = false;
    }
    if (g_timerRaised) {
        timeEndPeriod(1);
        g_timerRaised = false;
    }
    // 高精度定时器句柄：留给下一次会话复用（只创建一次），进程退出时由系统回收。
    // 不做 CloseHandle —— 反复开关限速时没必要反复创建内核对象。
    EnterCriticalSection(&ShapeLock());
    ShapeConfigureQueue(g_shapeIn, 0, 0, 0);
    ShapeConfigureQueue(g_shapeOut, 0, 0, 0);
    LeaveCriticalSection(&ShapeLock());
}

}  // namespace

// =============================================================================
//  工作线程：收包 / 丢包 / 放行
// =============================================================================
DWORD WINAPI WorkerThread(LPVOID param)
{
    const Config* cfg = static_cast<const Config*>(param);
    const bool verbose = (cfg != NULL) ? cfg->verbose : false;
    const bool processMode = (cfg != NULL) && !cfg->processName.empty();

    // 进程模式：目标端口集合的本地快照 + 它对应的世代号（见 PortRefreshThread）
    std::unordered_set<uint32_t> localPorts;
    unsigned long long localGeneration = 0;

    // 丢包率用的随机数发生器：本线程独占，无锁
    LossRandom rng;

    std::vector<unsigned char> packet(kMaxPacketLen);

    while (!IsStopRequested()) {
        HANDLE handle = LoadHandle();
        if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
            break;
        }

#ifdef WEAKNET_TEST_HOOKS
        if (handle == g_testFakeDriverHandle) {
            WaitForSingleObject(g_stopEvent, INFINITE);
            break;
        }
#endif

        UINT recvLen = 0;
        WINDIVERT_ADDRESS addr;
        std::memset(&addr, 0, sizeof(addr));

        if (!WinDivertRecv(handle, packet.data(), static_cast<UINT>(packet.size()),
                           &recvLen, &addr)) {
            const DWORD err = GetLastError();
            // 句柄被关闭 / 队列被 purge / 已 shutdown：都是优雅退出路径
            if (err == ERROR_NO_DATA || err == ERROR_OPERATION_ABORTED ||
                err == ERROR_INVALID_HANDLE) {
                break;
            }
            Emit(LogLevel::Warning, "WinDivertRecv 失败（错误码 %lu），%lu ms 后重试。",
                 static_cast<unsigned long>(err), static_cast<unsigned long>(kRetryDelayMs));
            Sleep(kRetryDelayMs);
            continue;
        }

        // =============================================================
        //  进程模式：命中目标端口的报文按丢包率处理；未命中的必须 WinDivertSend 放行。
        //  概率丢包（丢包率 1~99）：命中的报文掷随机数，未命中的也要回注放行。
        //  纯 100% 黑洞（旧行为）：命中即丢弃、绝不回注。
        // =============================================================
        // 方向：WINDIVERT_ADDRESS 只有 Outbound 一个方向位，为 0 即入方向。
        const bool outbound = (addr.Outbound != 0);
        const unsigned lossPercent = (cfg != NULL)
                                   ? (outbound ? cfg->lossUpPercent : cfg->lossDownPercent)
                                   : 100;

        const UINT8 protocol = PeekProtocol(packet.data(), recvLen);
        bool hit = true;    // 过滤器模式：收上来的包全部是命中包

        if (processMode) {
            // 端口集合由“端口刷新线程”周期性更新；用世代号判断是否需要重新取快照，
            // 平常每个包只是一次整数比较 + 一次哈希查找。
            const unsigned long long generation = CurrentPortsGeneration();
            if (generation != localGeneration) {
                localPorts = SnapshotProcessPortKeys(&localGeneration);
            }

            unsigned srcPort = 0;
            unsigned dstPort = 0;
            UINT8 parsedProtocol = protocol;
            if (!ExtractTcpUdpPorts(packet.data(), recvLen, &parsedProtocol, &srcPort, &dstPort)) {
                // 解析不出端口（IP 分片、异常报文、非 TCP/UDP）：一律放行，绝不误伤
                hit = false;
            } else {
                // “本机端口”在报文里的位置由方向决定：
                //   出方向(outbound)：本机端口是源端口
                //   入方向(inbound) ：本机端口是目的端口
                const bool useDstPort = !outbound;
                const uint32_t key = ProcessPortKey(packet[0] >> 4, parsedProtocol,
                    static_cast<uint16_t>(useDstPort ? dstPort : srcPort));
                hit = (localPorts.find(key) != localPorts.end());
            }
        }

        // 记“该方向被接管（命中目标）的报文数”，后面用来核对实际丢包比例
        if (hit) {
            if (outbound) { g_statMatchedUp.fetch_add(1); }
            else          { g_statMatchedDown.fetch_add(1); }
        }

        // 命中后是否丢弃：该方向丢包率 100% -> 必丢；1~99 -> 掷随机数；0 -> 不放行规则外（防御性放行）
        const bool shouldDrop = hit && (lossPercent >= 100 || rng.Hit(lossPercent));

        if (!shouldDrop) {
            // ---- 放行：原样回注（WINDIVERT_ADDRESS 必须保持 recv 时不变）--------
            //  非命中包（只有进程模式会有）永远全速直发，不受限速影响；
            //  命中包若该方向设了限速，就交给限速器（令牌够当场发，不够排队）。
            const unsigned long long rateBps = (cfg != NULL)
                                    ? (outbound ? cfg->rateUpBytesPerSec
                                                : cfg->rateDownBytesPerSec)
                                    : 0ULL;
            if (hit && rateBps > 0) {
                // v2.0.0：限速要按连接做公平排队，所以需要五元组。
                // 过滤器模式（按端口）平时一个字节都不解析，这里为了限速才解析一次；
                // 解析不出来（ICMP、分片）就用全零键，它们共用一条"默认流"。
                FlowKey flow;
                if (!ExtractFlowKey(packet.data(), recvLen, &flow)) {
                    std::memset(&flow, 0, sizeof(flow));
                }
                ShapeSubmit(handle, packet.data(), recvLen, addr, outbound, flow);
            } else {
                SendPacketNow(handle, packet.data(), recvLen, addr);
            }
            continue;
        }

        // 记录“该方向真正被丢弃的报文数”
        if (outbound) { g_statDroppedUp.fetch_add(1); }
        else          { g_statDroppedDown.fetch_add(1); }

        // ---- 命中：丢弃（不回注），并计入“已丢弃”统计 --------------------------
        //  协议分布统计的也是“被丢弃的报文”，这样 协议分布 与 已丢弃数据包 对得上；
        //  放行掉的报文另有 forwarded 计数。
        const unsigned long long index = g_statPackets.fetch_add(1) + 1;
        g_statBytes.fetch_add(recvLen);
        if (protocol == 6) {
            g_statTcp.fetch_add(1);
        } else if (protocol == 17) {
            g_statUdp.fetch_add(1);
        } else {
            g_statOther.fetch_add(1);
        }

        if (verbose && (index <= kVerboseBurst || (index % kVerboseStep) == 0)) {
            char summary[256] = { 0 };
            FormatPacketSummary(packet.data(), recvLen, summary, sizeof(summary));
            Emit(LogLevel::Packet, "[丢弃 #%llu] %s", index, summary);
        }
    }

    // ---- 收尾 ----------------------------------------------------------------
    const StopReason reason = GetStopReasonRaw();
    RequestStop(reason == StopReason::None ? StopReason::Error : reason);

    if (g_watcherThread != NULL) {
        WaitForThreadStopped(g_watcherThread, "退出监视线程", 5000);
    }
    CloseHandleOnce();
    if (g_timerThread != NULL) {
        WaitForThreadStopped(g_timerThread, "计时线程", 5000);
    }
    if (g_portThread != NULL) {
        WaitForThreadStopped(g_portThread, "端口刷新线程", 5000);
    }

    g_stopTick = GetTickCount64();

    // 通知控制台关闭回调：可以放心结束了
    if (g_cleanupDoneEvent != NULL) {
        SetEvent(g_cleanupDoneEvent);
    }
    if (g_finishedEvent != NULL) {
        SetEvent(g_finishedEvent);
    }
    return 0;
}

// =============================================================================
//  进程退出信号（对外）
// =============================================================================

bool IsExitRequested()
{
    return InterlockedCompareExchange(const_cast<LONG*>(&g_exitRequested), 0, 0) != 0;
}

// =============================================================================
//  进程名解析与“进程 -> 本地端口”映射（iphlpapi）
// =============================================================================

namespace {

bool EqualsIgnoreCaseAscii(const std::string& a, const char* b)
{
    const size_t n = std::strlen(b);
    if (a.size() != n) {
        return false;
    }
    for (size_t i = 0; i < n; ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') { ca = static_cast<char>(ca - 'A' + 'a'); }
        if (cb >= 'A' && cb <= 'Z') { cb = static_cast<char>(cb - 'A' + 'a'); }
        if (ca != cb) {
            return false;
        }
    }
    return true;
}

// 进程名比较：自动补全 .exe、忽略大小写
bool ProcessNameMatches(const std::string& normalized, const char* candidate)
{
    if (candidate == NULL || *candidate == '\0') {
        return false;
    }
    const std::string candidateName(candidate);
    if (EqualsIgnoreCaseAscii(normalized, candidateName.c_str())) {
        return true;
    }

    // 只写了名字没写扩展名：允许 "chrome" 匹配 "chrome.exe"
    if (candidateName.size() > 4 && normalized.size() == candidateName.size() - 4) {
        const std::string withoutExtension(candidateName, 0, candidateName.size() - 4);
        if (EqualsIgnoreCaseAscii(normalized, withoutExtension.c_str())) {
            return true;
        }
    }
    return false;
}

// 连接表的四种查询请求：IPv4/IPv6 × TCP/UDP
enum class PortTableKind { Tcp4, Tcp6, Udp4, Udp6 };

// 说明：表类常量取自 iphlpapi.h / iptypes.h，这里显式写出枚举值，
// 避免不同版本 SDK 的枚举名差异（TCP_TABLE_OWNER_PID_ALL = 5、UDP_TABLE_OWNER_PID = 1）。
const TCP_TABLE_CLASS kTcpTableOwnerPidAll = static_cast<TCP_TABLE_CLASS>(5);
const UDP_TABLE_CLASS kUdpTableOwnerPid    = static_cast<UDP_TABLE_CLASS>(1);
const ULONG kAddrFamilyIpv4      = AF_INET;
const ULONG kAddrFamilyIpv6      = AF_INET6;

struct PortTableQuery {
    PortTableKind kind;
    const char*   name;      // 日志文案
    ULONG         family;    // AF_INET / AF_INET6
};

const PortTableQuery kPortTableQueries[] = {
    { PortTableKind::Tcp4, "TCP/IPv4", kAddrFamilyIpv4 },
    { PortTableKind::Tcp6, "TCP/IPv6", kAddrFamilyIpv6 },
    { PortTableKind::Udp4, "UDP/IPv4", kAddrFamilyIpv4 },
    { PortTableKind::Udp6, "UDP/IPv6", kAddrFamilyIpv6 }
};

// 目标 PID 集合：用哈希集合 O(1) 判断，避免每条连接都线性扫一遍
typedef std::unordered_set<unsigned long> PidSet;

PidSet MakePidSet(const std::vector<unsigned long>& pids)
{
    PidSet set;
    set.reserve(pids.size() * 2 + 1);
    for (size_t i = 0; i < pids.size(); ++i) {
        if (pids[i] != 0) {
            set.insert(pids[i]);
        }
    }
    return set;
}

bool IsTargetPid(const PidSet& pids, unsigned long pid)
{
    return pid != 0 && pids.find(pid) != pids.end();
}

// 四张表（IPv4/IPv6 × TCP/UDP）的 dwLocalPort 都是“低 16 位 + 网络字节序”，
// 这里统一转成主机字节序的 uint16_t。
uint16_t LocalPortFromDword(DWORD localPortField)
{
    return static_cast<uint16_t>(WinDivertHelperNtohs(
        static_cast<UINT16>(localPortField & 0xFFFFu)));
}

// 拉取一种连接表，把属于目标 PID 的本地端口塞进 ports
bool CollectPortsFromTable(const PortTableQuery& query,
                           const PidSet& pids,
                           std::unordered_set<uint16_t>& ports,
                            std::string& errorText,
                            std::unordered_set<uint32_t>* detailedKeys)
{
    const bool isTcp = (query.kind == PortTableKind::Tcp4 || query.kind == PortTableKind::Tcp6);
    const unsigned ipVersion = (query.family == AF_INET6) ? 6 : 4;
    const unsigned protocol = isTcp ? 6 : 17;

    DWORD size = 0;
    DWORD status = isTcp
        ? GetExtendedTcpTable(NULL, &size, FALSE, query.family, kTcpTableOwnerPidAll, 0)
        : GetExtendedUdpTable(NULL, &size, FALSE, query.family, kUdpTableOwnerPid, 0);

    if (status != ERROR_INSUFFICIENT_BUFFER) {
        // 该协议族不可用（例如系统禁用了 IPv6）：属于正常情况，不算错误
        if (status == ERROR_NOT_SUPPORTED || status == ERROR_INVALID_PARAMETER) {
            return true;
        }
        char buf[192] = { 0 };
        std::snprintf(buf, sizeof(buf), "%s 表长度查询失败（错误码 %lu）", query.name,
                      static_cast<unsigned long>(status));
        errorText = buf;
        return false;
    }
    if (size == 0) {
        return true;    // 表为空
    }

    std::vector<unsigned char> buffer(size);
    DWORD actualSize = size;
    status = isTcp
        ? GetExtendedTcpTable(buffer.data(), &actualSize, FALSE, query.family, kTcpTableOwnerPidAll, 0)
        : GetExtendedUdpTable(buffer.data(), &actualSize, FALSE, query.family, kUdpTableOwnerPid, 0);

    if (status == ERROR_INSUFFICIENT_BUFFER) {
        // 两次调用之间表变大了：本轮跳过，下一次刷新就会补上
        return true;
    }
    if (status != NO_ERROR) {
        char buf[192] = { 0 };
        std::snprintf(buf, sizeof(buf), "%s 表读取失败（错误码 %lu）", query.name,
                      static_cast<unsigned long>(status));
        errorText = buf;
        return false;
    }

    switch (query.kind) {
    case PortTableKind::Tcp4: {
        const MIB_TCPTABLE_OWNER_PID* table =
            reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const MIB_TCPROW_OWNER_PID& row = table->table[i];
            if (IsTargetPid(pids, static_cast<unsigned long>(row.dwOwningPid))) {
                const uint16_t port = LocalPortFromDword(row.dwLocalPort);
                ports.insert(port);
                if (detailedKeys != NULL) { detailedKeys->insert(ProcessPortKey(ipVersion, protocol, port)); }
            }
        }
        break;
    }
    case PortTableKind::Tcp6: {
        const MIB_TCP6TABLE_OWNER_PID* table =
            reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const MIB_TCP6ROW_OWNER_PID& row = table->table[i];
            if (IsTargetPid(pids, static_cast<unsigned long>(row.dwOwningPid))) {
                const uint16_t port = LocalPortFromDword(row.dwLocalPort);
                ports.insert(port);
                if (detailedKeys != NULL) { detailedKeys->insert(ProcessPortKey(ipVersion, protocol, port)); }
            }
        }
        break;
    }
    case PortTableKind::Udp4: {
        const MIB_UDPTABLE_OWNER_PID* table =
            reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const MIB_UDPROW_OWNER_PID& row = table->table[i];
            if (IsTargetPid(pids, static_cast<unsigned long>(row.dwOwningPid))) {
                const uint16_t port = LocalPortFromDword(row.dwLocalPort);
                ports.insert(port);
                if (detailedKeys != NULL) { detailedKeys->insert(ProcessPortKey(ipVersion, protocol, port)); }
            }
        }
        break;
    }
    case PortTableKind::Udp6: {
        const MIB_UDP6TABLE_OWNER_PID* table =
            reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const MIB_UDP6ROW_OWNER_PID& row = table->table[i];
            if (IsTargetPid(pids, static_cast<unsigned long>(row.dwOwningPid))) {
                const uint16_t port = LocalPortFromDword(row.dwLocalPort);
                ports.insert(port);
                if (detailedKeys != NULL) { detailedKeys->insert(ProcessPortKey(ipVersion, protocol, port)); }
            }
        }
        break;
    }
    default:
        break;
    }

    return true;
}

}  // namespace

bool NormalizeProcessName(const std::string& text, std::string& out, std::string& err)
{
    out.clear();

    // 去掉首尾空白
    size_t begin = 0;
    size_t end = text.size();
    while (begin < end && (text[begin] == ' ' || text[begin] == '\t')) { ++begin; }
    while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t')) { --end; }
    std::string trimmed = text.substr(begin, end - begin);

    if (trimmed.empty()) {
        err = "进程名为空";
        return false;
    }
    if (trimmed.size() > 260) {
        err = "进程名过长";
        return false;
    }

    // 只取文件名部分：既支持 "chrome.exe" 也支持完整路径
    size_t slash = trimmed.find_last_of("\\/");
    std::string name = (slash == std::string::npos) ? trimmed : trimmed.substr(slash + 1);
    if (name.empty()) {
        err = "进程名不合法（只有路径分隔符）";
        return false;
    }

    // 统一小写
    for (size_t i = 0; i < name.size(); ++i) {
        if (name[i] >= 'A' && name[i] <= 'Z') {
            name[i] = static_cast<char>(name[i] - 'A' + 'a');
        }
    }
    out = name;
    return true;
}

bool FindProcessIdsByName(const std::string& processName, std::vector<unsigned long>& pids)
{
    pids.clear();
    if (processName.empty()) {
        return false;
    }

    std::string normalized;
    std::string normalizeError;
    if (!NormalizeProcessName(processName, normalized, normalizeError)) {
        return false;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W entry;
    std::memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            // 进程名统一转成小写 UTF-8 再比较（进程名基本都是 ASCII）
            char utf8[512] = { 0 };
            const int written = WideCharToMultiByte(CP_UTF8, 0, entry.szExeFile, -1,
                                                    utf8, sizeof(utf8) - 1, NULL, NULL);
            if (written <= 1) {
                continue;
            }
            std::string candidate(utf8);
            for (size_t i = 0; i < candidate.size(); ++i) {
                if (candidate[i] >= 'A' && candidate[i] <= 'Z') {
                    candidate[i] = static_cast<char>(candidate[i] - 'A' + 'a');
                }
            }
            if (ProcessNameMatches(normalized, candidate.c_str())) {
                pids.push_back(static_cast<unsigned long>(entry.th32ProcessID));
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);

    // 同名多开时保持稳定顺序，便于日志比对
    std::sort(pids.begin(), pids.end());
    pids.erase(std::unique(pids.begin(), pids.end()), pids.end());
    return !pids.empty();
}

bool CollectLocalPortsByPids(const std::vector<unsigned long>& pids,
                             std::unordered_set<uint16_t>& ports,
                              std::string& errorText,
                              std::unordered_set<uint32_t>* detailedKeys)
{
    ports.clear();
    if (detailedKeys != NULL) { detailedKeys->clear(); }
    errorText.clear();

    if (pids.empty()) {
        errorText = "没有可查询的 PID";
        return false;
    }

    bool ok = true;
    const PidSet pidSet = MakePidSet(pids);
    for (size_t i = 0; i < sizeof(kPortTableQueries) / sizeof(kPortTableQueries[0]); ++i) {
        std::string tableError;
        if (!CollectPortsFromTable(kPortTableQueries[i], pidSet, ports, tableError,
                                   detailedKeys)) {
            ok = false;
            if (!tableError.empty()) {
                errorText = tableError;    // 保留最后一个失败原因
            }
        }
    }

    // 防御：端口集合异常膨胀说明查询结果不对（正常进程不可能有这么多端口），
    // 这时宁可放弃丢包，也不要拿一个可疑集合去误伤流量。
    if (ports.size() > kMaxProcessPortCount) {
        ports.clear();
        if (detailedKeys != NULL) { detailedKeys->clear(); }
        errorText = "识别到的端口数量异常偏多，已放弃本次端口集合";
        return false;
    }
    return ok;
}

bool CollectProcessLocalPorts(const std::string& processName,
                              std::unordered_set<uint16_t>& ports,
                              std::vector<unsigned long>& pids,
                               std::string& errorText,
                               std::unordered_set<uint32_t>* detailedKeys)
{
    ports.clear();
    if (detailedKeys != NULL) { detailedKeys->clear(); }
    pids.clear();
    errorText.clear();

    if (!FindProcessIdsByName(processName, pids)) {
        errorText = "没有找到同名进程";
        return false;
    }
    return CollectLocalPortsByPids(pids, ports, errorText, detailedKeys);
}

bool QueryPortTableStats(const std::vector<unsigned long>& pids, PortTableStats& stats)
{
    stats = PortTableStats();
    if (pids.empty()) {
        return false;
    }

    const PidSet pidSet = MakePidSet(pids);
    std::unordered_set<unsigned long> distinctPids;
    std::unordered_set<unsigned long> matched;

    for (size_t q = 0; q < sizeof(kPortTableQueries) / sizeof(kPortTableQueries[0]); ++q) {
        const PortTableQuery& query = kPortTableQueries[q];
        const bool isTcp = (query.kind == PortTableKind::Tcp4 || query.kind == PortTableKind::Tcp6);

        DWORD size = 0;
        DWORD status = isTcp
            ? GetExtendedTcpTable(NULL, &size, FALSE, query.family, kTcpTableOwnerPidAll, 0)
            : GetExtendedUdpTable(NULL, &size, FALSE, query.family, kUdpTableOwnerPid, 0);
        if (status != ERROR_INSUFFICIENT_BUFFER || size == 0) {
            continue;
        }

        std::vector<unsigned char> buffer(size);
        DWORD actualSize = size;
        status = isTcp
            ? GetExtendedTcpTable(buffer.data(), &actualSize, FALSE, query.family,
                                  kTcpTableOwnerPidAll, 0)
            : GetExtendedUdpTable(buffer.data(), &actualSize, FALSE, query.family,
                                  kUdpTableOwnerPid, 0);
        if (status != NO_ERROR) {
            continue;
        }

        if (query.kind == PortTableKind::Tcp4) {
            const MIB_TCPTABLE_OWNER_PID* t =
                reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
            stats.tcp4Entries = t->dwNumEntries;
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const unsigned long pid = static_cast<unsigned long>(t->table[i].dwOwningPid);
                distinctPids.insert(pid);
                if (IsTargetPid(pidSet, pid)) { matched.insert(pid); }
            }
        } else if (query.kind == PortTableKind::Tcp6) {
            const MIB_TCP6TABLE_OWNER_PID* t =
                reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
            stats.tcp6Entries = t->dwNumEntries;
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const unsigned long pid = static_cast<unsigned long>(t->table[i].dwOwningPid);
                distinctPids.insert(pid);
                if (IsTargetPid(pidSet, pid)) { matched.insert(pid); }
            }
        } else if (query.kind == PortTableKind::Udp4) {
            const MIB_UDPTABLE_OWNER_PID* t =
                reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
            stats.udp4Entries = t->dwNumEntries;
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const unsigned long pid = static_cast<unsigned long>(t->table[i].dwOwningPid);
                distinctPids.insert(pid);
                if (IsTargetPid(pidSet, pid)) { matched.insert(pid); }
            }
        } else {
            const MIB_UDP6TABLE_OWNER_PID* t =
                reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buffer.data());
            stats.udp6Entries = t->dwNumEntries;
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const unsigned long pid = static_cast<unsigned long>(t->table[i].dwOwningPid);
                distinctPids.insert(pid);
                if (IsTargetPid(pidSet, pid)) { matched.insert(pid); }
            }
        }
    }

    stats.tablePids   = distinctPids.size();
    stats.matchedPids = matched.size();
    return true;
}

// =============================================================================
//  枚举“正在运行的应用程序”（v1.4.0，供界面里的进程选择器使用）
// =============================================================================

namespace {

// 宽字符串 -> UTF-8。定义在文件后半段（调试日志那一节），这里先声明：
// 两处都在同一个匿名命名空间里，声明在前、定义在后是合法的。
std::string WideToUtf8Log(const wchar_t* text);

// 从 exe 文件的版本信息里取“程序说明”（FileDescription），例如
// "C:\...\chrome.exe" -> "Google Chrome"。取不到就返回空串（不当作错误）。
std::string QueryFileDescription(const std::wstring& exePath)
{
    if (exePath.empty()) {
        return std::string();
    }

    DWORD handle = 0;
    const DWORD size = GetFileVersionInfoSizeW(exePath.c_str(), &handle);
    if (size == 0) {
        return std::string();      // 该文件没有版本信息（很正常）
    }

    std::vector<unsigned char> data(size);
    if (!GetFileVersionInfoW(exePath.c_str(), 0, size, data.data())) {
        return std::string();
    }

    // 先取语言/代码页（Translation），才能拼出 StringFileInfo 的键
    struct Translation { WORD language; WORD codePage; };
    Translation* translation = NULL;
    UINT translationSize = 0;
    if (!VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation",
                        reinterpret_cast<LPVOID*>(&translation), &translationSize) ||
        translation == NULL || translationSize < sizeof(Translation)) {
        return std::string();
    }

    wchar_t subBlock[128] = { 0 };
    std::swprintf(subBlock, sizeof(subBlock) / sizeof(subBlock[0]),
                  L"\\StringFileInfo\\%04x%04x\\FileDescription",
                  translation[0].language, translation[0].codePage);

    wchar_t* value = NULL;
    UINT valueSize = 0;
    if (!VerQueryValueW(data.data(), subBlock,
                        reinterpret_cast<LPVOID*>(&value), &valueSize) ||
        value == NULL || valueSize == 0) {
        return std::string();
    }

    std::string utf8 = WideToUtf8Log(value);
    // 有些程序的说明就是文件名本身，没必要重复显示
    return utf8;
}

// 查一张连接表，按 PID 累加条目数（用于界面上显示“这个程序当前有多少连接”）。
// 表为空、系统不支持该协议族、查询失败都当作正常：连接数只是给用户看的提示，
// 不该因为它失败就让整个列表出不来。
void CountConnectionsFromTable(const PortTableQuery& query,
                               std::unordered_map<unsigned long, unsigned long>& counts)
{
    const bool isTcp = (query.kind == PortTableKind::Tcp4 || query.kind == PortTableKind::Tcp6);

    DWORD size = 0;
    DWORD status = isTcp
        ? GetExtendedTcpTable(NULL, &size, FALSE, query.family, kTcpTableOwnerPidAll, 0)
        : GetExtendedUdpTable(NULL, &size, FALSE, query.family, kUdpTableOwnerPid, 0);
    if (status != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        return;
    }

    std::vector<unsigned char> buffer(size);
    DWORD actualSize = size;
    status = isTcp
        ? GetExtendedTcpTable(buffer.data(), &actualSize, FALSE, query.family,
                              kTcpTableOwnerPidAll, 0)
        : GetExtendedUdpTable(buffer.data(), &actualSize, FALSE, query.family,
                              kUdpTableOwnerPid, 0);
    if (status != NO_ERROR) {
        return;
    }

    switch (query.kind) {
    case PortTableKind::Tcp4: {
        const MIB_TCPTABLE_OWNER_PID* t =
            reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            ++counts[static_cast<unsigned long>(t->table[i].dwOwningPid)];
        }
        break;
    }
    case PortTableKind::Tcp6: {
        const MIB_TCP6TABLE_OWNER_PID* t =
            reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            ++counts[static_cast<unsigned long>(t->table[i].dwOwningPid)];
        }
        break;
    }
    case PortTableKind::Udp4: {
        const MIB_UDPTABLE_OWNER_PID* t =
            reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            ++counts[static_cast<unsigned long>(t->table[i].dwOwningPid)];
        }
        break;
    }
    default: {
        const MIB_UDP6TABLE_OWNER_PID* t =
            reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            ++counts[static_cast<unsigned long>(t->table[i].dwOwningPid)];
        }
        break;
    }
    }
}

// 枚举进程表：pid -> exe 名（小写）与 exe 全路径
struct ProcessEntryLite {
    unsigned long pid = 0;
    std::string   exeName;       // 小写，如 "chrome.exe"
    std::wstring  exePath;       // 可能为空（取不到时）
};

// 收集所有有可见标题窗口的 PID -> 主窗口标题（只保留第一个遇到的）
BOOL CALLBACK EnumWindowsCollect(HWND hwnd, LPARAM param)
{
    std::unordered_map<unsigned long, std::wstring>* titles =
        reinterpret_cast<std::unordered_map<unsigned long, std::wstring>*>(param);
    if (titles == NULL) {
        return TRUE;
    }

    if (!IsWindowVisible(hwnd)) {
        return TRUE;    // 隐藏窗口不算“打开的应用”
    }
    const int titleLen = GetWindowTextLengthW(hwnd);
    if (titleLen <= 0) {
        return TRUE;    // 没标题的（多为工具窗口）也跳过
    }
    // 只要顶层窗口：有 owner 的通常是对话框/工具窗
    if (GetWindow(hwnd, GW_OWNER) != NULL) {
        return TRUE;
    }

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == 0) {
        return TRUE;
    }
    if (titles->find(pid) != titles->end()) {
        return TRUE;    // 同一个进程已经有窗口了，保留第一个
    }

    std::wstring title(static_cast<size_t>(titleLen) + 1, L'\0');
    GetWindowTextW(hwnd, &title[0], titleLen + 1);
    title.resize(static_cast<size_t>(titleLen));
    (*titles)[pid] = title;
    return TRUE;
}

}  // namespace

bool ListRunningApps(std::vector<RunningApp>& out, std::string& errorText)
{
    out.clear();
    errorText.clear();

    // ---- 1. 进程表 -----------------------------------------------------------
    std::vector<ProcessEntryLite> processes;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            errorText = "无法枚举进程（CreateToolhelp32Snapshot 失败）";
            return false;
        }
        PROCESSENTRY32W entry;
        std::memset(&entry, 0, sizeof(entry));
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snap, &entry)) {
            do {
                ProcessEntryLite item;
                item.pid = static_cast<unsigned long>(entry.th32ProcessID);

                std::string name = WideToUtf8Log(entry.szExeFile);
                for (size_t i = 0; i < name.size(); ++i) {
                    if (name[i] >= 'A' && name[i] <= 'Z') {
                        name[i] = static_cast<char>(name[i] - 'A' + 'a');
                    }
                }
                item.exeName = name;

                // 取 exe 全路径：PROCESS_QUERY_LIMITED_INFORMATION 是权限要求最低的方式，
                // 受保护进程取不到也属正常，留空即可（只影响“说明”列）。
                HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                          static_cast<DWORD>(item.pid));
                if (proc != NULL) {
                    wchar_t path[MAX_PATH * 2] = { 0 };
                    DWORD pathLen = static_cast<DWORD>(sizeof(path) / sizeof(path[0]));
                    if (QueryFullProcessImageNameW(proc, 0, path, &pathLen)) {
                        item.exePath.assign(path, pathLen);
                    }
                    CloseHandle(proc);
                }

                processes.push_back(item);
            } while (Process32NextW(snap, &entry));
        }
        CloseHandle(snap);
    }

    if (processes.empty()) {
        errorText = "没有枚举到任何进程";
        return false;
    }

    // ---- 2. 有可见窗口的 PID -> 窗口标题 -------------------------------------
    std::unordered_map<unsigned long, std::wstring> windowTitles;
    EnumWindows(EnumWindowsCollect, reinterpret_cast<LPARAM>(&windowTitles));

    // ---- 3. 按 PID 统计连接数（TCP4/6 + UDP4/6）-----------------------------
    std::unordered_map<unsigned long, unsigned long> connectionCounts;
    for (size_t q = 0; q < sizeof(kPortTableQueries) / sizeof(kPortTableQueries[0]); ++q) {
        CountConnectionsFromTable(kPortTableQueries[q], connectionCounts);
    }

    // ---- 4. 组装 + 取“程序说明”（按 exe 路径缓存，同名进程只读一次文件）------
    std::unordered_map<std::wstring, std::string> descriptionCache;
    out.reserve(processes.size());

    for (size_t i = 0; i < processes.size(); ++i) {
        const ProcessEntryLite& p = processes[i];
        if (p.pid == 0 || p.exeName.empty()) {
            continue;
        }

        RunningApp app;
        app.pid     = p.pid;
        app.exeName = p.exeName;

        const std::unordered_map<unsigned long, std::wstring>::const_iterator w =
            windowTitles.find(p.pid);
        if (w != windowTitles.end()) {
            app.hasWindow   = true;
            app.windowTitle = WideToUtf8Log(w->second.c_str());
        }

        const std::unordered_map<unsigned long, unsigned long>::const_iterator c =
            connectionCounts.find(p.pid);
        if (c != connectionCounts.end()) {
            app.connectionCount = c->second;
        }

        if (!p.exePath.empty()) {
            const std::unordered_map<std::wstring, std::string>::const_iterator cached =
                descriptionCache.find(p.exePath);
            if (cached != descriptionCache.end()) {
                app.displayName = cached->second;
            } else {
                app.displayName = QueryFileDescription(p.exePath);
                descriptionCache[p.exePath] = app.displayName;
            }
        }

        app.isUwpHost = (app.exeName == "applicationframehost.exe");

        out.push_back(app);
    }

    // ---- 5. 排序：有窗口的在前 -> 连接数多的在前 -> 名字升序 ------------------
    std::sort(out.begin(), out.end(), [](const RunningApp& a, const RunningApp& b) {
        if (a.hasWindow != b.hasWindow) { return a.hasWindow; }
        if (a.connectionCount != b.connectionCount) {
            return a.connectionCount > b.connectionCount;
        }
        return a.exeName < b.exeName;
    });

    return true;
}

// =============================================================================
//  参数解析（CLI 与 GUI 共用）
// =============================================================================

bool ParsePortList(const std::string& text, std::vector<unsigned short>& out, std::string& err)
{
    // 支持 “8080,8443” / “8080 8443” / “8080;8443”：非数字即视为分隔符
    std::vector<unsigned long> tokens;
    unsigned long current = 0;
    bool hasDigits = false;

    for (size_t i = 0; i <= text.size(); ++i) {
        const char ch = (i < text.size()) ? text[i] : '\0';
        if (ch >= '0' && ch <= '9') {
            current = current * 10 + static_cast<unsigned long>(ch - '0');
            hasDigits = true;
            if (current > 100000UL) {
                err = "端口号超出合法范围（1-65535）";
                return false;
            }
        } else {
            if (hasDigits) {
                tokens.push_back(current);
                current = 0;
                hasDigits = false;
            } else if (ch != ',' && ch != ';' && ch != ' ' && ch != '\t' && ch != '\0') {
                err = std::string("端口列表中出现了非法字符 '") + ch + "'";
                return false;
            }
        }
    }

    if (tokens.empty()) {
        err = "端口列表为空";
        return false;
    }

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == 0 || tokens[i] > 65535UL) {
            char buf[96] = { 0 };
            std::snprintf(buf, sizeof(buf), "端口 %lu 非法（有效范围 1-65535）", tokens[i]);
            err = buf;
            return false;
        }
        out.push_back(static_cast<unsigned short>(tokens[i]));
    }

    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());

    if (out.size() > kMaxPortCount) {
        char buf[128] = { 0 };
        std::snprintf(buf, sizeof(buf), "端口数量 %llu 过多（上限 %llu 个），过滤器会过长",
                      static_cast<unsigned long long>(out.size()),
                      static_cast<unsigned long long>(kMaxPortCount));
        err = buf;
        return false;
    }
    return true;
}

bool ParseDurationSeconds(const std::string& text, long& seconds, std::string& err)
{
    // 允许空串：表示不限时
    if (text.empty()) {
        seconds = 0;
        return true;
    }

    char* end = NULL;
    const long value = std::strtol(text.c_str(), &end, 10);
    if (end == text.c_str() || (end != NULL && *end != '\0') || value < 0) {
        err = "运行时长需要一个不小于 0 的整数（单位：秒，0 = 不限时）";
        return false;
    }
    if (value > 86400L) {
        err = "运行时长过大（上限 86400 秒 = 24 小时）";
        return false;
    }
    seconds = value;
    return true;
}

// -----------------------------------------------------------------------------
//  方向接管的判定（丢包率 + 限速共用的语义核心，只在这一个地方定义）
// -----------------------------------------------------------------------------
// “接管”= 该方向的报文会被收进用户态，进入丢弃 / 排队放行的逐包判断。
//
//   * 丢包率为 0 **且** 该方向没限速 -> 不接管
//     （过滤器里根本不含这个方向，流量原样通过、零开销）
//   * 丢包率为 0 但该方向**有限速** -> 仍然接管
//     v1.7.1 修正：v1.5.0 加限速时漏了这一条 —— 限速只能作用于被接管的流量，
//     如果“丢包率 0”直接让方向不接管，那“只限速、不丢包”就永远配不出来：
//     要么不接管（限速失效），要么必须掺 1%~100% 的丢包。
//   * 进程模式          -> dir 按历史行为被忽略，只看丢包率/限速
//                          （默认 100/100 -> 两个方向都接管，与 v1.2.x 完全一致）
//   * 端口 / 全部端口模式 -> 还必须落在 dir 内

bool DirectionIntercepted(const Config& cfg, bool outbound)
{
    const unsigned loss = outbound ? cfg.lossUpPercent : cfg.lossDownPercent;
    const unsigned long long rate = outbound ? cfg.rateUpBytesPerSec
                                             : cfg.rateDownBytesPerSec;

    if (loss == 0 && rate == 0) {
        return false;                       // 既不丢包也不限速 -> 该方向不接管
    }
    if (!cfg.processName.empty()) {
        return true;                        // 进程模式忽略 dir（见头文件说明）
    }
    if (outbound) {
        return (cfg.dir == Direction::Outbound || cfg.dir == Direction::Both);
    }
    return (cfg.dir == Direction::Inbound || cfg.dir == Direction::Both);
}

bool ParseLossPercent(const std::string& text, unsigned& out, std::string& err)
{
    // 去掉首尾空白（GUI 输入框里很容易带空格）
    size_t begin = 0;
    size_t end   = text.size();
    while (begin < end && (text[begin] == ' ' || text[begin] == '\t')) { ++begin; }
    while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t')) { --end; }
    const std::string trimmed = text.substr(begin, end - begin);

    if (trimmed.empty()) {
        err = "丢包率不能为空（请填 0~100 的整数，100 = 全部丢弃）";
        return false;
    }

    char* stop = NULL;
    const long value = std::strtol(trimmed.c_str(), &stop, 10);
    if (stop == trimmed.c_str() || (stop != NULL && *stop != '\0')) {
        err = "丢包率需要一个 0~100 的整数（如 30 表示丢 30%）";
        return false;
    }
    if (value < 0 || value > 100) {
        err = "丢包率必须在 0~100 之间（0 = 不丢，100 = 全部丢弃）";
        return false;
    }
    out = static_cast<unsigned>(value);
    return true;
}

bool ParseRate(const std::string& text, unsigned long long& out, std::string& err)
{
    size_t begin = 0;
    size_t end   = text.size();
    while (begin < end && (text[begin] == ' ' || text[begin] == '\t')) { ++begin; }
    while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t')) { --end; }
    std::string trimmed = text.substr(begin, end - begin);

    if (trimmed.empty()) {
        err = "限速值不能为空（如 300B = 300 字节/秒，200K = 200KB/s，0 = 不限速）";
        return false;
    }

    // 把后缀全部转成小写，方便比较
    for (size_t i = 0; i < trimmed.size(); ++i) {
        if (trimmed[i] >= 'A' && trimmed[i] <= 'Z') {
            trimmed[i] = static_cast<char>(trimmed[i] - 'A' + 'a');
        }
    }

    // 乘数：裸数字按 KB/s（与 v1.5.0 兼容）
    unsigned long long multiplier = 1024ULL;

    // 先剥掉可能出现的 "ps" / "/s"（例如 300bps、300b/s）
    if (trimmed.size() >= 3 && trimmed.compare(trimmed.size() - 3, 3, "b/s") == 0) {
        trimmed.erase(trimmed.size() - 3);
    } else if (trimmed.size() >= 2 && trimmed.compare(trimmed.size() - 2, 2, "ps") == 0) {
        trimmed.erase(trimmed.size() - 2);
    }

    // 再看单位后缀
    if (!trimmed.empty()) {
        const char last = trimmed[trimmed.size() - 1];
        if (last == 'b') {
            multiplier = 1ULL;
            trimmed.erase(trimmed.size() - 1);
            // "kb" / "mb"
            if (!trimmed.empty() && trimmed[trimmed.size() - 1] == 'k') {
                multiplier = 1024ULL;
                trimmed.erase(trimmed.size() - 1);
            } else if (!trimmed.empty() && trimmed[trimmed.size() - 1] == 'm') {
                multiplier = 1024ULL * 1024ULL;
                trimmed.erase(trimmed.size() - 1);
            }
        } else if (last == 'k') {
            multiplier = 1024ULL;
            trimmed.erase(trimmed.size() - 1);
        } else if (last == 'm') {
            multiplier = 1024ULL * 1024ULL;
            trimmed.erase(trimmed.size() - 1);
        }
    }

    if (trimmed.empty()) {
        err = "限速值缺少数字（如 300B、200K、2M）";
        return false;
    }

    // v2.0.8：数字部分允许小数（1.2K / 0.5M / 2.5MB）。
    // 原来用 strtoll 只认整数，用户想输 "1.2K" 会直接吃一个格式错误。
    char* stop = NULL;
    const double value = std::strtod(trimmed.c_str(), &stop);
    if (stop == trimmed.c_str() || (stop != NULL && *stop != '\0')) {
        err = "限速值格式不对：数字后面只能跟 B / K / KB / M / MB，"
              "数字可以带小数（如 300B、200K、1.2K、0.5M、2M；不写单位按 KB/s 算）";
        return false;
    }
    // 负数、NaN、大到没边的值一起挡掉。
    // 注意 NaN：它和任何数比较都是假，所以必须用 !(value >= 0.0) 这种写法，
    // 否则 `value < 0` 对 NaN 不成立、会被漏过去。
    if (!(value >= 0.0) || value > 1.0e15) {
        err = "限速值必须是 0 或正数（0 = 不限速）";
        return false;
    }

    const unsigned long long kMaxRateBytesPerSec = 1024ULL * 1024ULL * 1024ULL;  // 1 GiB/s
    // 四舍五入到整字节/秒：1.2K = 1228.8 -> 1229 B/s。
    // 先拿 double 比上限，再转整数 —— 直接转可能溢出到未定义行为。
    const double scaled = value * static_cast<double>(multiplier);
    if (scaled > static_cast<double>(kMaxRateBytesPerSec)) {
        err = "限速值不能超过 1GB/s（再高就该用别的手段了）";
        return false;
    }
    out = static_cast<unsigned long long>(scaled + 0.5);
    return true;
}

std::string FormatCount(unsigned long long value)
{
    char raw[32] = { 0 };
    std::snprintf(raw, sizeof(raw), "%llu", value);

    std::string out;
    const size_t len = std::strlen(raw);
    for (size_t i = 0; i < len; ++i) {
        if (i > 0 && ((len - i) % 3) == 0) {
            out.push_back(',');
        }
        out.push_back(raw[i]);
    }
    return out;
}

std::string DescribeRate(unsigned long long bytesPerSec)
{
    char buf[64] = { 0 };
    if (bytesPerSec == 0) {
        return "不限";
    }
    // v2.0.8：不是整单位时保留一位小数。
    // 为什么：输入现在支持小数（1.2K = 1229 B/s），如果显示还是取整成 "1 KB/s"，
    // 用户根本看不出小数有没有生效，还会以为被截断了。
    // 整数时仍然显示整数（1024 B/s -> "1 KB/s"，不是 "1.0 KB/s"）。
    const double kb = 1024.0;
    const double mb = 1024.0 * 1024.0;
    if (bytesPerSec < 1024ULL) {
        std::snprintf(buf, sizeof(buf), "%llu B/s", bytesPerSec);
    } else if (bytesPerSec < 1024ULL * 1024ULL) {
        const double v = static_cast<double>(bytesPerSec) / kb;
        if (bytesPerSec % 1024ULL == 0) {
            std::snprintf(buf, sizeof(buf), "%.0f KB/s", v);
        } else {
            std::snprintf(buf, sizeof(buf), "%.1f KB/s", v);
        }
    } else {
        const double v = static_cast<double>(bytesPerSec) / mb;
        if (bytesPerSec % (1024ULL * 1024ULL) == 0) {
            std::snprintf(buf, sizeof(buf), "%.0f MB/s", v);
        } else {
            std::snprintf(buf, sizeof(buf), "%.2f MB/s", v);
        }
    }
    return buf;
}

unsigned AutoMaxShapeDelayMs(unsigned long long rateBytesPerSec)
{
    if (rateBytesPerSec == 0) {
        return 0;
    }
    // 约 3 个满包（1500 字节）的排队时间：
    //   * 低速率的物理事实是一个满包就要攒很久令牌（300 B/s -> 5 秒），
    //     所以下限必须跟着速率走，否则限速会直接变成"全丢"（0 字节/秒）；
    //   * 上限 10 分钟，避免速率极低时队列变成一台"时光机"。
    double ms = 3.0 * 1500.0 * 1000.0 / static_cast<double>(rateBytesPerSec);
    if (ms < 200.0)     { ms = 200.0; }
    if (ms > 600000.0)  { ms = 600000.0; }
    return static_cast<unsigned>(ms + 0.5);
}

bool IsShapingEnabled(const Config& cfg)
{
    return cfg.rateDownBytesPerSec > 0 || cfg.rateUpBytesPerSec > 0;
}

bool IsProbabilisticLoss(const Config& cfg)
{
    // 只看“会被接管”的方向：0 表示不接管，100 表示全丢，两者都不需要掷随机数
    const bool inboundHandled  = DirectionIntercepted(cfg, false);
    const bool outboundHandled = DirectionIntercepted(cfg, true);
    if (inboundHandled &&
        cfg.lossDownPercent > 0 && cfg.lossDownPercent < 100) {
        return true;
    }
    if (outboundHandled &&
        cfg.lossUpPercent > 0 && cfg.lossUpPercent < 100) {
        return true;
    }
    return false;
}

bool ValidateConfig(const Config& cfg, std::string& errorText)
{
    errorText.clear();

    const bool inboundHandled  = DirectionIntercepted(cfg, false);
    const bool outboundHandled = DirectionIntercepted(cfg, true);

    // ---- 1. 至少得有一个方向会被接管，否则等于什么都没做 ---------------------
    if (!inboundHandled && !outboundHandled) {
        if (!cfg.processName.empty()) {
            errorText = "上行与下行的丢包率都是 0、也都没设限速，没有任何流量会被处理。"
                        "请至少把其中一个方向设为 1~100，或给它设一个限速值。";
        } else {
            errorText = "按当前的方向 / 丢包率 / 限速设置，没有任何流量会被处理。\n"
                        "  * 丢包率为 0 表示“该方向不接管”（除非该方向设了限速）；\n"
                        "  * 两个方向都是 0 且都没限速，就等于什么都没做。\n"
                        "请至少把一个方向的丢包率设为 1~100，"
                        "或给它设一个限速值（如 --rate-up 300B），"
                        "或用 --dir 选择需要接管的方向。";
        }
        return false;
    }

    // ---- 2. 端口模式：丢包率与 --dir 不能自相矛盾 -----------------------------
    // 例：--dir inbound 却设了 --loss-up 30 —— 上行根本不在接管范围内，
    // 这个 30% 永远不会生效。与其静默忽略，不如直接告诉用户。
    //
    // 注意判定边界（这里踩过一次）：
    //   * 0（不接管）与“方向不在 dir 内”语义一致 -> 不算矛盾；
    //   * 100 是默认值，且 --dir inbound + lossUp=100 正是 v1.2.x 的默认组合，
    //     必须保持合法，否则老命令行会全部报错；
    //   * 只有 1~99（用户明确想按比例丢）却不在 dir 内，才是真矛盾。
    if (cfg.processName.empty()) {
        const bool dirHasInbound  = (cfg.dir == Direction::Inbound  || cfg.dir == Direction::Both);
        const bool dirHasOutbound = (cfg.dir == Direction::Outbound || cfg.dir == Direction::Both);

        const bool downWantsPartial = (cfg.lossDownPercent >= 1 && cfg.lossDownPercent <= 99);
        const bool upWantsPartial   = (cfg.lossUpPercent   >= 1 && cfg.lossUpPercent   <= 99);

        if (!dirHasInbound && downWantsPartial) {
            char buf[512] = { 0 };
            std::snprintf(buf, sizeof(buf),
                          "配置矛盾：下行丢包率被设为 %u%%，但拦截方向（%s）不包含下行，"
                          "该设置不会生效。\n"
                          "请把方向改成 both / inbound，或把下行丢包率改回 100。",
                          cfg.lossDownPercent, DirectionLabel(cfg.dir));
            errorText = buf;
            return false;
        }
        if (!dirHasOutbound && upWantsPartial) {
            char buf[512] = { 0 };
            std::snprintf(buf, sizeof(buf),
                          "配置矛盾：上行丢包率被设为 %u%%，但拦截方向（%s）不包含上行，"
                          "该设置不会生效。\n"
                          "请把方向改成 both / outbound，或把上行丢包率改回 100。",
                          cfg.lossUpPercent, DirectionLabel(cfg.dir));
            errorText = buf;
            return false;
        }
    }

    // ---- 3. 限速被 100% 丢包架空：不报错，但调用方应该提醒 --------------------
    // 见 RateLossConflictWarning()：这里只做校验，不做输出 ——
    // ValidateConfig 在界面上是**每次按键都会调用**的，在这里打日志会刷屏。
    return true;
}

std::string RateLossConflictWarning(const Config& cfg)
{
    // 丢包率的判断在限速之前：100% 丢包会把报文全部拦下，限速器一个包都收不到，
    // 于是"限速"白设。这不是非法配置（确实就是在断网），但用户多半是写错了。
    const bool downConflict = (cfg.rateDownBytesPerSec > 0 && cfg.lossDownPercent >= 100);
    const bool upConflict   = (cfg.rateUpBytesPerSec   > 0 && cfg.lossUpPercent   >= 100);
    if (!downConflict && !upConflict) {
        return std::string();
    }

    std::string text;
    if (downConflict && upConflict) {
        text = "下行与上行都同时设了「丢包率 100%」和「限速」：";
    } else if (downConflict) {
        text = "下行同时设了「丢包率 100%」和「限速 " +
               DescribeRate(cfg.rateDownBytesPerSec) + "」：";
    } else {
        text = "上行同时设了「丢包率 100%」和「限速 " +
               DescribeRate(cfg.rateUpBytesPerSec) + "」：";
    }
    text += "报文会先被 100% 丢包全部拦下，限速器收不到任何报文，限速无从生效。"
            "只想限速不丢包的话，请把对应方向的丢包率设为 0。";
    return text;
}

// =============================================================================
//  每应用实时速率：ETW 监控（v2.0.0）
// =============================================================================
//  为什么用 ETW 而不是自己抓包：
//    * WinDivert 在 NETWORK 层**拿不到进程 ID**（官方文档明说），只能自己用五元组
//      去关联 FLOW/SOCKET 层，短连接容易漏；
//    * Microsoft-Windows-Kernel-Network 提供程序**原生就带
//      PID + 字节数 + 收发方向**，这正是任务管理器"应用网络使用"用的那一套；
//    * 纯用户态、不抓包、不用额外驱动、TCP 与 UDP 全覆盖。
//  代价：**ETW 会话需要管理员权限**。
//
//  事件前缀布局（v2.0.0 已用真实抓包 + 原始 hex 逐字节核对，不是猜的）：
//      offset 0        u32  PID
//      offset 4        u32  size（字节数）
//      offset 8        daddr（IPv4 = 4 字节，IPv6 = 16 字节）
//      8 + aLen        saddr
//      8 + 2*aLen      u16  dport
//      8 + 2*aLen + 2  u16  sport
//  做"每应用速率"只需要 PID + size + 方向（方向由事件 ID 决定），
//  也就是**前 8 个字节**，非常不容易出错。
//
//  事件 ID：10/26 = TCP 发送，11/27 = TCP 接收，42/58 = UDP 发送，43/59 = UDP 接收。
//  ⚠ 18（TCPCOPY）与 11 的 size/PID/端口完全一样，是副本，**必须排除**，
//    否则字节数会翻倍（实测确认）。
// =============================================================================

namespace {

// {7DD42A49-5329-4832-8DFD-43D979153A88}
const GUID kKernelNetworkGuid = {
    0x7dd42a49, 0x5329, 0x4832,
    { 0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88 }
};

const wchar_t* const kAppRateSessionName = L"WeakNetToolAppRate";
const ULONGLONG      kKernelNetworkKeywords = 0x30;    // IPv4(0x10) | IPv6(0x20)

struct PidCounters {
    unsigned long long tx = 0;      // 累计发出字节
    unsigned long long rx = 0;      // 累计收到字节
    std::string        exeName;     // 解析一次后缓存
    std::string        exePath;     // 完整路径（没解析出来就是空）
};

CRITICAL_SECTION& AppRateLock()
{
    static CRITICAL_SECTION cs;
    static const bool initialized = []() -> bool {
        InitializeCriticalSection(&cs);
        return true;
    }();
    (void)initialized;
    return cs;
}

std::map<unsigned long, PidCounters> g_appCounters;      // 累计值（ETW 线程写）
std::map<unsigned long, PidCounters> g_appPrev;          // 上次采样（GetAppRates 里用）
unsigned long long g_appPrevTick = 0;

TRACEHANDLE g_appSession  = INVALID_PROCESSTRACE_HANDLE;
TRACEHANDLE g_appTrace    = INVALID_PROCESSTRACE_HANDLE;
HANDLE      g_appThread   = NULL;
HANDLE      g_appOpened   = NULL;      // OpenTrace 成功的事件
volatile LONG g_appRunning = 0;
volatile LONG g_appOpenStatus = 0;   // 0=等待、1=OpenTrace 成功、-1=失败
volatile LONG g_appOpenError = 0;
volatile LONG g_appEventCount = 0;     // 收到的事件总数（诊断"有没有在工作"）

// 事件 ID → (是否统计, 是否出方向)
bool ClassifyEventId(unsigned id, bool* outbound)
{
    switch (id) {
    case 10: case 26: *outbound = true;  return true;   // TCP 发送
    case 11: case 27: *outbound = false; return true;   // TCP 接收
    case 42: case 58: *outbound = true;  return true;   // UDP 发送
    case 43: case 59: *outbound = false; return true;   // UDP 接收
    default: return false;                              // 含 18=TCPCOPY（副本，必须排除）
    }
}

// ETW 回调：跑在 ProcessTrace 的消费线程上，必须快。
VOID WINAPI AppRateEventCallback(PEVENT_RECORD rec)
{
    InterlockedIncrement(&g_appEventCount);

    const unsigned id = rec->EventHeader.EventDescriptor.Id;
    bool outbound = false;
    if (!ClassifyEventId(id, &outbound)) {
        return;
    }

    const unsigned char* p = static_cast<const unsigned char*>(rec->UserData);
    if (p == NULL || rec->UserDataLength < 8) {
        return;                     // 至少要能读到 PID + size
    }

    unsigned long pid = 0;
    unsigned size = 0;
    std::memcpy(&pid, p, 4);
    std::memcpy(&size, p + 4, 4);
    if (pid == 0 || size == 0) {
        return;
    }

    EnterCriticalSection(&AppRateLock());
    PidCounters& c = g_appCounters[pid];
    if (outbound) { c.tx += size; } else { c.rx += size; }
    LeaveCriticalSection(&AppRateLock());
}

DWORD WINAPI AppRateConsumeThread(LPVOID)
{
    EVENT_TRACE_LOGFILEW log;
    std::memset(&log, 0, sizeof(log));
    log.LoggerName          = const_cast<LPWSTR>(kAppRateSessionName);
    log.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = AppRateEventCallback;

    TRACEHANDLE h = OpenTraceW(&log);
    if (h == INVALID_PROCESSTRACE_HANDLE) {
        const DWORD error = GetLastError();
        DebugLogf("每应用速率：OpenTrace 失败（错误码 %lu）", error);
        InterlockedExchange(&g_appOpenError, static_cast<LONG>(error));
        InterlockedExchange(&g_appOpenStatus, -1);
        SetEvent(g_appOpened);
        return 1;
    }
    g_appTrace = h;
    InterlockedExchange(&g_appOpenStatus, 1);
    SetEvent(g_appOpened);

    // ProcessTrace 会一直阻塞，直到会话被 ControlTrace(STOP) 结束
    const ULONG rc = ProcessTrace(&h, 1, NULL, NULL);
    if (rc != ERROR_SUCCESS && rc != ERROR_CANCELLED) {
        DebugLogf("每应用速率：ProcessTrace 返回 %lu", rc);
    }
    CloseTrace(h);
    g_appTrace = INVALID_PROCESSTRACE_HANDLE;
    return 0;
}

// 判断进程是否还活着（用于回收已经退出的 PID 条目）
bool ProcessExists(unsigned long pid)
{
    if (pid == 0 || pid == 4) { return true; }
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (proc == NULL) {
        return false;
    }
    DWORD code = 0;
    const bool alive = GetExitCodeProcess(proc, &code) && (code == STILL_ACTIVE);
    CloseHandle(proc);
    return alive;
}

// 给一个 PID 解析 exe 名（小写）与完整路径。受保护进程会失败，这时退回 "pid:NNNN"。
std::string ResolveProcessName(unsigned long pid, std::string* fullPathOut)
{
    if (fullPathOut != NULL) { fullPathOut->clear(); }
    if (pid == 0) { return "System Idle Process"; }
    if (pid == 4) { return "System"; }

    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (proc != NULL) {
        wchar_t path[MAX_PATH * 2] = { 0 };
        DWORD len = static_cast<DWORD>(sizeof(path) / sizeof(path[0]));
        if (QueryFullProcessImageNameW(proc, 0, path, &len) && len > 0) {
            CloseHandle(proc);
            std::wstring full(path, len);
            const size_t slash = full.find_last_of(L"\\/");
            std::wstring base = (slash == std::wstring::npos) ? full : full.substr(slash + 1);
            std::string utf8 = WideToUtf8Log(base.c_str());
            for (size_t i = 0; i < utf8.size(); ++i) {
                if (utf8[i] >= 'A' && utf8[i] <= 'Z') { utf8[i] = static_cast<char>(utf8[i] - 'A' + 'a'); }
            }
            if (fullPathOut != NULL) {
                *fullPathOut = WideToUtf8Log(full.c_str());   // 保留原始大小写：取图标要用真实路径
            }
            return utf8;
        }
        CloseHandle(proc);
    }
    char buf[48] = { 0 };
    std::snprintf(buf, sizeof(buf), "pid:%lu", pid);
    return buf;
}

}  // namespace

bool StartAppRateMonitor(std::string& errorText)
{
    errorText.clear();
    if (InterlockedCompareExchange(&g_appRunning, 0, 0) != 0) {
        if (g_appThread != NULL && WaitForSingleObject(g_appThread, 0) != WAIT_OBJECT_0) {
            return true;
        }
        StopAppRateMonitor();        // 消费线程已退出，清掉旧会话后重试
    }

    const size_t propsSize =
        sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(kAppRateSessionName) + 1) * sizeof(wchar_t);
    std::vector<unsigned char> propsBuf(propsSize, 0);
    EVENT_TRACE_PROPERTIES* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propsBuf.data());
    props->Wnode.BufferSize    = static_cast<ULONG>(propsSize);
    props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;                    // QPC 时间戳
    props->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);
    props->BufferSize          = 64;
    props->MinimumBuffers      = 4;
    props->MaximumBuffers      = 64;

    // 清掉可能残留的同名会话（上次异常退出留下的）
#ifdef WEAKNET_TEST_HOOKS
    ULONG rc = ERROR_ACCESS_DENIED;
    if (g_testFailEtwStart == 0) {
        ControlTraceW(0, kAppRateSessionName, props, EVENT_TRACE_CONTROL_STOP);
        rc = StartTraceW(&g_appSession, kAppRateSessionName, props);
    }
#else
    ControlTraceW(0, kAppRateSessionName, props, EVENT_TRACE_CONTROL_STOP);
    ULONG rc = StartTraceW(&g_appSession, kAppRateSessionName, props);
#endif
    if (rc != ERROR_SUCCESS) {
        if (rc == ERROR_ACCESS_DENIED) {
            errorText = "启动 ETW 会话被拒绝：每应用速率监控需要管理员权限。";
        } else {
            char buf[192] = { 0 };
            std::snprintf(buf, sizeof(buf), "启动 ETW 会话失败（错误码 %lu）。", rc);
            errorText = buf;
        }
        return false;
    }

    rc = EnableTraceEx2(g_appSession, &kKernelNetworkGuid,
                        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        TRACE_LEVEL_VERBOSE, kKernelNetworkKeywords, 0, 0, NULL);
    if (rc != ERROR_SUCCESS) {
        ControlTraceW(g_appSession, kAppRateSessionName, props, EVENT_TRACE_CONTROL_STOP);
        g_appSession = INVALID_PROCESSTRACE_HANDLE;
        char buf[192] = { 0 };
        std::snprintf(buf, sizeof(buf),
                      "启用网络事件提供程序失败（错误码 %lu）。", rc);
        errorText = buf;
        return false;
    }

    {
        EnterCriticalSection(&AppRateLock());
        g_appCounters.clear();
        g_appPrev.clear();
        g_appPrevTick = 0;
        LeaveCriticalSection(&AppRateLock());
    }

    g_appOpened = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_appOpened == NULL) {
        const DWORD error = GetLastError();
        ControlTraceW(g_appSession, kAppRateSessionName, props, EVENT_TRACE_CONTROL_STOP);
        g_appSession = INVALID_PROCESSTRACE_HANDLE;
        char buf[128] = { 0 };
        std::snprintf(buf, sizeof(buf), "创建 ETW 就绪事件失败（错误码 %lu）。", error);
        errorText = buf;
        return false;
    }
    InterlockedExchange(&g_appOpenStatus, 0);
    InterlockedExchange(&g_appOpenError, 0);
    g_appThread = CreateThread(NULL, 0, AppRateConsumeThread, NULL, 0, NULL);
    if (g_appThread == NULL) {
        ControlTraceW(g_appSession, kAppRateSessionName, props, EVENT_TRACE_CONTROL_STOP);
        g_appSession = INVALID_PROCESSTRACE_HANDLE;
        CloseHandle(g_appOpened);
        g_appOpened = NULL;
        errorText = "创建 ETW 消费线程失败。";
        return false;
    }

    // 等 OpenTrace 就绪，避免调用方立刻取快照时还没开始收
    const DWORD openWait = WaitForSingleObject(g_appOpened, 3000);
    if (openWait != WAIT_OBJECT_0 ||
        InterlockedCompareExchange(&g_appOpenStatus, 0, 0) != 1 ||
        WaitForSingleObject(g_appThread, 0) == WAIT_OBJECT_0) {
        const LONG openError = InterlockedCompareExchange(&g_appOpenError, 0, 0);
        char buf[160] = { 0 };
        std::snprintf(buf, sizeof(buf),
                      "ETW 消费线程未就绪（等待结果 %lu，OpenTrace 错误码 %ld）。",
                      static_cast<unsigned long>(openWait), static_cast<long>(openError));
        errorText = buf;
        StopAppRateMonitor();
        return false;
    }
    InterlockedExchange(&g_appRunning, 1);
    DebugLogf("每应用速率监控已启动（ETW 会话 %ls，关键字 0x%llx）",
              kAppRateSessionName, kKernelNetworkKeywords);
    return true;
}

void StopAppRateMonitor()
{
    if (InterlockedCompareExchange(&g_appRunning, 0, 0) == 0 && g_appThread == NULL) {
        return;
    }

    // 停会话 -> ProcessTrace 返回 -> 消费线程退出
    const size_t propsSize =
        sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(kAppRateSessionName) + 1) * sizeof(wchar_t);
    std::vector<unsigned char> propsBuf(propsSize, 0);
    EVENT_TRACE_PROPERTIES* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propsBuf.data());
    props->Wnode.BufferSize = static_cast<ULONG>(propsSize);
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    if (g_appSession != INVALID_PROCESSTRACE_HANDLE) {
        ControlTraceW(g_appSession, kAppRateSessionName, props, EVENT_TRACE_CONTROL_STOP);
        g_appSession = INVALID_PROCESSTRACE_HANDLE;
    }

    if (g_appThread != NULL) {
        const DWORD wait = WaitForSingleObject(g_appThread, 5000);
        if (wait != WAIT_OBJECT_0) {
            DebugLogf("ETW 消费线程未及时退出（等待结果 %lu），继续等待以避免释放其资源。",
                      static_cast<unsigned long>(wait));
            if (WaitForSingleObject(g_appThread, INFINITE) != WAIT_OBJECT_0) {
                TerminateProcess(GetCurrentProcess(), ERROR_TIMEOUT);
            }
        }
        CloseHandle(g_appThread);
        g_appThread = NULL;
    }
    if (g_appOpened != NULL) {
        CloseHandle(g_appOpened);
        g_appOpened = NULL;
    }

    InterlockedExchange(&g_appRunning, 0);
    EnterCriticalSection(&AppRateLock());
    g_appCounters.clear();
    g_appPrev.clear();
    g_appPrevTick = 0;
    LeaveCriticalSection(&AppRateLock());
    DebugLogf("每应用速率监控已停止");
}

bool IsAppRateMonitorRunning()
{
    return InterlockedCompareExchange(&g_appRunning, 0, 0) != 0 &&
           g_appThread != NULL && WaitForSingleObject(g_appThread, 0) != WAIT_OBJECT_0;
}

unsigned long long GetAppRateEventCount()
{
    return static_cast<unsigned long long>(
        InterlockedCompareExchange(&g_appEventCount, 0, 0));
}

std::vector<AppRate> GetAppRates(bool includeIdle)
{
    std::vector<AppRate> out;

    const unsigned long long now = GetTickCount64();
    EnterCriticalSection(&AppRateLock());

    // 采样区间：距上次调用的实际时间。这样调用间隔不精确也不影响速率正确性。
    unsigned long long dtMs = 0;
    if (g_appPrevTick != 0 && now > g_appPrevTick) {
        dtMs = now - g_appPrevTick;
    }
    g_appPrevTick = now;

    for (std::map<unsigned long, PidCounters>::iterator it = g_appCounters.begin();
         it != g_appCounters.end(); ++it) {
        AppRate a;
        a.pid      = it->first;
        a.txTotal  = it->second.tx;
        a.rxTotal  = it->second.rx;

        // 进程名/路径解析一次就缓存（进程退出后条目会被清掉，不会无限增长）
        if (it->second.exeName.empty()) {
            it->second.exeName = ResolveProcessName(it->first, &it->second.exePath);
        }
        a.exeName = it->second.exeName;
        a.exePath = it->second.exePath;

        const std::map<unsigned long, PidCounters>::iterator prev = g_appPrev.find(it->first);
        if (dtMs > 0) {
            // 上次采样里没有这个 PID 时，把"上次值"当 0 处理：
            // 它的累计量必然是**本区间内**产生的（上一次采样时它还不存在），
            // 所以 rate = total / dt 是对的。
            // （第一版这里要求 prev 必须存在，导致新出现的进程速率恒为 0 —— 真 bug。）
            const unsigned long long prevTx =
                (prev != g_appPrev.end()) ? prev->second.tx : 0ULL;
            const unsigned long long prevRx =
                (prev != g_appPrev.end()) ? prev->second.rx : 0ULL;
            // 计数器只会增长；万一 PID 被复用导致变小，就当 0 处理，别报个巨大负数
            const unsigned long long dtx = (it->second.tx >= prevTx) ? (it->second.tx - prevTx) : 0;
            const unsigned long long drx = (it->second.rx >= prevRx) ? (it->second.rx - prevRx) : 0;
            a.txBps = dtx * 1000ULL / dtMs;
            a.rxBps = drx * 1000ULL / dtMs;
        }

        if (includeIdle || a.txBps > 0 || a.rxBps > 0) {
            out.push_back(a);
        }
    }

    // 记录本次采样值供下次比较
    g_appPrev = g_appCounters;

    // 清理：把"速率为 0 且进程已经退出"的条目丢掉。
    // 为什么 includeIdle=false 时不这么做：那样表格一空闲就被清空，看着像坏了；
    // 保留"本次监控内用过网络的进程"才是稳定的列表（NetLimiter 也是这样）。
    // 但也不能无限攒着，所以顺手回收已经死掉的 PID。
    if (includeIdle) {
        for (std::map<unsigned long, PidCounters>::iterator it = g_appCounters.begin();
             it != g_appCounters.end(); ) {
            const std::map<unsigned long, PidCounters>::iterator pv = g_appPrev.find(it->first);
            const bool idle = (pv != g_appPrev.end() && pv->second.tx == it->second.tx &&
                               pv->second.rx == it->second.rx);
            if (idle && !ProcessExists(it->first)) {
                g_appPrev.erase(it->first);
                it = g_appCounters.erase(it);
            } else {
                ++it;
            }
        }
    }
    LeaveCriticalSection(&AppRateLock());

    std::sort(out.begin(), out.end(), [](const AppRate& a, const AppRate& b) {
        const unsigned long long sa = a.txBps + a.rxBps;
        const unsigned long long sb = b.txBps + b.rxBps;
        if (sa != sb) { return sa > sb; }
        return a.exeName < b.exeName;
    });
    return out;
}

// =============================================================================
//  过滤器
// =============================================================================

std::string BuildFilter(const Config& cfg)
{
    // =========================================================================
    //  构造步骤：先算“匹配什么”（target，不含方向），再按“接管哪些方向”加前缀。
    //
    //  对默认的 100%/100%（纯黑洞）来说，这样算出来的字符串与 v1.2.x 完全一致
    //  —— 差别被测试逐条盯住了（见 tests：BuildFilter 兼容性用例）。
    // =========================================================================

    // ---- 1. target：匹配什么（不含方向）----------------------------------------
    std::string target;      // 空串 = 不限定（即所有 IP 报文）

    if (!cfg.processName.empty()) {
        // 进程模式：无法用过滤器表达“哪个进程”，只能先全量旁路监听 TCP/UDP，
        // 再由收包循环按“进程 -> 本地端口集合”逐包判断。
        if (cfg.proto == Protocol::Tcp)      { target = "tcp"; }
        else if (cfg.proto == Protocol::Udp) { target = "udp"; }
        else                                 { target = "(tcp or udp)"; }
    } else if (cfg.allPorts || cfg.ports.empty()) {
        // 全部端口（整体断网）：只可能按协议限定；proto=Both 时 target 留空
        if (cfg.proto == Protocol::Tcp)      { target = "tcp"; }
        else if (cfg.proto == Protocol::Udp) { target = "udp"; }
    } else {
        // 指定端口
        const char* const portField = (cfg.side == PortSide::Src) ? "SrcPort" : "DstPort";
        std::string portsExpr;
        for (size_t i = 0; i < cfg.ports.size(); ++i) {
            char clause[96] = { 0 };

            if (cfg.proto == Protocol::Tcp || cfg.proto == Protocol::Both) {
                std::snprintf(clause, sizeof(clause), "tcp.%s == %u", portField,
                              static_cast<unsigned>(cfg.ports[i]));
                if (!portsExpr.empty()) { portsExpr += " or "; }
                portsExpr += clause;
            }
            if (cfg.proto == Protocol::Udp || cfg.proto == Protocol::Both) {
                std::snprintf(clause, sizeof(clause), "udp.%s == %u", portField,
                              static_cast<unsigned>(cfg.ports[i]));
                if (!portsExpr.empty()) { portsExpr += " or "; }
                portsExpr += clause;
            }
        }
        target = "(" + portsExpr + ")";
    }

    // ---- 2. 接管哪些方向（丢包率 0 的方向不接管；进程模式忽略 dir）-------------
    const bool handledIn  = DirectionIntercepted(cfg, false);
    const bool handledOut = DirectionIntercepted(cfg, true);

    // 两个方向都不接管：用 "false" —— WinDivert 支持的无匹配过滤器，
    // 语义正好是“一条都不拦”。（正常路径下 ValidateConfig 已经先拦下这种配置。）
    if (!handledIn && !handledOut) {
        return "false";
    }

    // ---- 3. 组装 ---------------------------------------------------------------
    if (handledIn && handledOut) {
        // 两个方向都要接管：不需要方向前缀
        return target.empty() ? "(ip or ipv6)" : target;
    }

    const char* const dirWord = handledIn ? "inbound" : "outbound";
    if (target.empty()) {
        return dirWord;
    }
    return std::string(dirWord) + " and " + target;
}

bool ValidateFilter(const std::string& filter, std::string& errorText)
{
    std::vector<char> compiled(kFilterBufLen, 0);
    const char* filterError = NULL;
    UINT filterErrorPos = 0;

    if (WinDivertHelperCompileFilter(filter.c_str(), WINDIVERT_LAYER_NETWORK,
                                     compiled.data(), static_cast<UINT>(compiled.size()),
                                     &filterError, &filterErrorPos)) {
        return true;
    }

    char buf[512] = { 0 };
    if (filterError != NULL) {
        std::snprintf(buf, sizeof(buf), "过滤器无法编译：位置 %u：%s", filterErrorPos, filterError);
    } else {
        std::snprintf(buf, sizeof(buf), "过滤器无法编译（可能是过滤器过长或语法错误）");
    }
    errorText = buf;
    return false;
}

// =============================================================================
//  全局快捷键（断网 / 联网切换）
// =============================================================================
namespace {

struct KeyName {
    const char* name;
    unsigned    vk;
};

const KeyName kKeyNames[] = {
    { "Backspace",   VK_BACK       }, { "Tab",         VK_TAB        },
    { "Enter",       VK_RETURN     }, { "Esc",         VK_ESCAPE     },
    { "Escape",      VK_ESCAPE     }, { "Space",       VK_SPACE      },
    { "PageUp",      VK_PRIOR      }, { "PageDown",    VK_NEXT       },
    { "End",         VK_END        }, { "Home",        VK_HOME       },
    { "Left",        VK_LEFT       }, { "Up",          VK_UP         },
    { "Right",       VK_RIGHT      }, { "Down",        VK_DOWN       },
    { "Insert",      VK_INSERT     }, { "Delete",      VK_DELETE     },
    { "Pause",       VK_PAUSE      }, { "PrintScreen", VK_SNAPSHOT   },
    { "Num0",        VK_NUMPAD0    }, { "Num1",        VK_NUMPAD1    },
    { "Num2",        VK_NUMPAD2    }, { "Num3",        VK_NUMPAD3    },
    { "Num4",        VK_NUMPAD4    }, { "Num5",        VK_NUMPAD5    },
    { "Num6",        VK_NUMPAD6    }, { "Num7",        VK_NUMPAD7    },
    { "Num8",        VK_NUMPAD8    }, { "Num9",        VK_NUMPAD9    },
    { "NumMultiply", VK_MULTIPLY   }, { "NumAdd",      VK_ADD        },
    { "NumSub",      VK_SUBTRACT   }, { "NumDecimal",  VK_DECIMAL    },
    { "NumDivide",   VK_DIVIDE     },
    { "OEMPlus",     VK_OEM_PLUS   }, { "OEMMinus",    VK_OEM_MINUS  },
    { "OEMComma",    VK_OEM_COMMA  }, { "OEMPeriod",   VK_OEM_PERIOD },
    { "Minus",       VK_OEM_MINUS  }, { "Equal",       VK_OEM_PLUS   },
    { "Comma",       VK_OEM_COMMA  }, { "Period",      VK_OEM_PERIOD },
    { "Slash",       VK_OEM_2      }, { "Backslash",   VK_OEM_5      },
    { "Semicolon",   VK_OEM_1      }, { "Quote",       VK_OEM_7      },
    { "BracketLeft", VK_OEM_4      }, { "BracketRight",VK_OEM_6      },
    { "Tilde",       VK_OEM_3      },
    // 鼠标侧键的“文字名”（真正的按键值见 MouseHotkeyName / LookupMouseHotkeyByName）
    { "X1",          kHotkeyMouseX1 }, { "X2",         kHotkeyMouseX2  }
};

// 鼠标侧键的中文别名（这些名字在 KeyNameFromVk 里会输出成“鼠标侧键N”）
struct MouseKeyAlias {
    const char* name;
    unsigned    vk;
};

const MouseKeyAlias kMouseKeyAliases[] = {
    { "鼠标侧键1", kHotkeyMouseX1 }, { "鼠标侧键2", kHotkeyMouseX2 },
    { "侧键1",     kHotkeyMouseX1 }, { "侧键2",     kHotkeyMouseX2 },
    { "鼠标4",     kHotkeyMouseX1 }, { "鼠标5",     kHotkeyMouseX2 },
    { "鼠标键4",   kHotkeyMouseX1 }, { "鼠标键5",   kHotkeyMouseX2 },
    { "XButton1",  kHotkeyMouseX1 }, { "XButton2",  kHotkeyMouseX2 },
    { "XBUTTON1",  kHotkeyMouseX1 }, { "XBUTTON2",  kHotkeyMouseX2 }
};

bool EqualsIgnoreCase(const std::string& a, const char* b)
{
    const size_t n = std::strlen(b);
    if (a.size() != n) {
        return false;
    }
    for (size_t i = 0; i < n; ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') { ca = static_cast<char>(ca - 'A' + 'a'); }
        if (cb >= 'A' && cb <= 'Z') { cb = static_cast<char>(cb - 'A' + 'a'); }
        if (ca != cb) {
            return false;
        }
    }
    return true;
}

bool IsModifierOnlyKey(unsigned vk)
{
    return vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL ||
           vk == VK_MENU    || vk == VK_LMENU    || vk == VK_RMENU    ||
           vk == VK_SHIFT   || vk == VK_LSHIFT   || vk == VK_RSHIFT   ||
           vk == VK_LWIN    || vk == VK_RWIN;
}

bool IsFunctionKey(unsigned vk)
{
    return vk >= VK_F1 && vk <= VK_F24;
}

bool IsMouseKey(unsigned vk)
{
    return vk == VK_XBUTTON1 || vk == VK_XBUTTON2;
}

const char* MouseKeyDisplayName(unsigned vk)
{
    if (vk == VK_XBUTTON1) { return "鼠标侧键1"; }
    if (vk == VK_XBUTTON2) { return "鼠标侧键2"; }
    return NULL;
}

bool LookupMouseKeyByName(const std::string& token, unsigned& vk)
{
    for (size_t i = 0; i < sizeof(kMouseKeyAliases) / sizeof(kMouseKeyAliases[0]); ++i) {
        if (EqualsIgnoreCase(token, kMouseKeyAliases[i].name)) {
            vk = kMouseKeyAliases[i].vk;
            return true;
        }
    }
    return false;
}

bool LookupKeyByName(const std::string& token, unsigned& vk)
{
    // 鼠标侧键优先：别名里有中文，也有 X1 / XButton1 之类的英文写法
    if (LookupMouseKeyByName(token, vk)) {
        return true;
    }

    if (token.size() == 1) {
        const char c = token[0];
        if (c >= 'a' && c <= 'z') { vk = static_cast<unsigned>(c - 'a' + 'A'); return true; }
        if (c >= 'A' && c <= 'Z') { vk = static_cast<unsigned>(c); return true; }
        if (c >= '0' && c <= '9') { vk = static_cast<unsigned>(c); return true; }
        return false;
    }

    // F1 ~ F24
    if (token.size() >= 2 && (token[0] == 'F' || token[0] == 'f')) {
        bool digits = true;
        for (size_t i = 1; i < token.size(); ++i) {
            if (token[i] < '0' || token[i] > '9') { digits = false; break; }
        }
        if (digits) {
            const int index = std::atoi(token.c_str() + 1);
            if (index >= 1 && index <= 24) {
                vk = static_cast<unsigned>(VK_F1 + index - 1);
                return true;
            }
            return false;
        }
    }

    for (size_t i = 0; i < sizeof(kKeyNames) / sizeof(kKeyNames[0]); ++i) {
        if (EqualsIgnoreCase(token, kKeyNames[i].name)) {
            vk = kKeyNames[i].vk;
            return true;
        }
    }
    return false;
}

std::string KeyNameFromVk(unsigned vk)
{
    const char* mouseName = MouseKeyDisplayName(vk);
    if (mouseName != NULL) { return mouseName; }

    if (vk >= 'A' && vk <= 'Z') { return std::string(1, static_cast<char>(vk)); }
    if (vk >= '0' && vk <= '9') { return std::string(1, static_cast<char>(vk)); }
    if (IsFunctionKey(vk)) {
        char buf[8] = { 0 };
        std::snprintf(buf, sizeof(buf), "F%u", vk - VK_F1 + 1);
        return buf;
    }
    for (size_t i = 0; i < sizeof(kKeyNames) / sizeof(kKeyNames[0]); ++i) {
        if (kKeyNames[i].vk == vk) {
            return kKeyNames[i].name;
        }
    }
    char buf[16] = { 0 };
    std::snprintf(buf, sizeof(buf), "0x%02X", vk);
    return buf;
}

}  // namespace

bool ParseHotkey(const std::string& text, HotkeySpec& out, std::string& err)
{
    out.modifiers = 0;
    out.vk = 0;

    // 按 '+' 切分（顺带去掉空白），最后一段是主键，前面的都必须是修饰键
    std::vector<std::string> tokens;
    std::string current;
    for (size_t i = 0; i <= text.size(); ++i) {
        const char ch = (i < text.size()) ? text[i] : '+';
        if (ch == '+') {
            if (!current.empty()) { tokens.push_back(current); current.clear(); }
        } else if (ch != ' ' && ch != '\t') {
            current.push_back(ch);
        }
    }

    if (tokens.empty()) {
        err = "快捷键为空";
        return false;
    }

    for (size_t i = 0; i + 1 < tokens.size(); ++i) {
        if (EqualsIgnoreCase(tokens[i], "ctrl") || EqualsIgnoreCase(tokens[i], "control")) {
            out.modifiers |= kHotkeyCtrl;
        } else if (EqualsIgnoreCase(tokens[i], "alt")) {
            out.modifiers |= kHotkeyAlt;
        } else if (EqualsIgnoreCase(tokens[i], "shift")) {
            out.modifiers |= kHotkeyShift;
        } else if (EqualsIgnoreCase(tokens[i], "win") || EqualsIgnoreCase(tokens[i], "windows") ||
                   EqualsIgnoreCase(tokens[i], "cmd") || EqualsIgnoreCase(tokens[i], "super")) {
            out.modifiers |= kHotkeyWin;
        } else {
            err = std::string("无法识别的修饰键: ") + tokens[i] +
                  "（支持 Ctrl / Alt / Shift / Win）";
            return false;
        }
    }

    const std::string& keyToken = tokens.back();
    if (EqualsIgnoreCase(keyToken, "ctrl") || EqualsIgnoreCase(keyToken, "control") ||
        EqualsIgnoreCase(keyToken, "alt") || EqualsIgnoreCase(keyToken, "shift") ||
        EqualsIgnoreCase(keyToken, "win") || EqualsIgnoreCase(keyToken, "windows")) {
        err = "快捷键缺少主键：修饰键本身不能单独做快捷键。"
              "可以写成组合键（例如 Ctrl+Alt+B），或直接写一个单键（例如 F8、B）。";
        return false;
    }

    unsigned vk = 0;
    if (!LookupKeyByName(keyToken, vk)) {
        err = std::string("无法识别的按键: ") + keyToken +
              "（支持 A-Z、0-9、F1-F24、Space、Enter、Esc、方向键，"
              "以及鼠标侧键 X1/X2/Mouse4/Mouse5/侧键1/侧键2）";
        return false;
    }
    out.vk = vk;
    return IsHotkeyAcceptable(out, err);
}

std::string FormatHotkey(const HotkeySpec& spec)
{
    if (spec.empty()) {
        return "（未设置）";
    }
    std::string text;
    if (spec.modifiers & kHotkeyCtrl)  { text += "Ctrl+"; }
    if (spec.modifiers & kHotkeyAlt)   { text += "Alt+"; }
    if (spec.modifiers & kHotkeyShift) { text += "Shift+"; }
    if (spec.modifiers & kHotkeyWin)   { text += "Win+"; }
    text += KeyNameFromVk(spec.vk);
    return text;
}

// 单独按下会带来麻烦、不适合做全局热键的键。
// 说明：这些键一旦被 RegisterHotKey 抢走，会影响系统本身的正常操作
// （Ctrl+Alt+Del 是安全注意序列，Windows 键会顶掉开始菜单等），
// 所以即便用户想绑也直接拒绝，并在提示里说清原因。
bool IsReservedSingleKey(unsigned vk)
{
    switch (vk) {
    case VK_LBUTTON:
    case VK_RBUTTON:
    case VK_MBUTTON:
    case VK_CANCEL:
    case VK_CLEAR:
    case VK_PAUSE:
    case VK_NUMLOCK:
    case VK_SCROLL:
    case VK_CAPITAL:
    case VK_SNAPSHOT:
    case VK_APPS:
    case VK_SLEEP:
    case VK_LWIN:
    case VK_RWIN:
        return true;
    default:
        return false;
    }
}

bool IsHotkeyAcceptable(const HotkeySpec& spec, std::string& err)
{
    if (spec.vk == 0 || IsModifierOnlyKey(spec.vk)) {
        err = "快捷键缺少主键（例如 Ctrl+Alt+B）。"
              "修饰键（Ctrl / Alt / Shift / Win）本身不能单独做快捷键，"
              "请再按一个主键，或直接按鼠标侧键。";
        return false;
    }

    // 单独按键（不带修饰键）：v1.2.3 起允许。
    // 代价是它会从整个系统里被本程序独占，所以给个明确提示。
    if (spec.modifiers == 0) {
        if (IsReservedSingleKey(spec.vk)) {
            err = "这个键被 Windows 保留（如 Win 键、CapsLock、Pause、"
                  "PrintScreen、鼠标左/中/右键），不能单独做全局快捷键。"
                  "请改按其它键，或加上 Ctrl / Alt / Shift 组合使用。";
            return false;
        }
        return true;    // 单键放行
    }
    return true;
}

bool RegisterGlobalHotkey(void* windowHandle, int id, const HotkeySpec& spec,
                          unsigned long& errorCode)
{
    errorCode = 0;
    if (spec.empty()) {
        errorCode = ERROR_INVALID_PARAMETER;
        return false;
    }
    // 鼠标侧键：部分系统上 RegisterHotKey 会返回成功但永不投递消息，因此这里
    // 不把它当主通道（主通道是 WH_MOUSE_LL 钩子，见 SetMouseHotkeyListener）。
    // 仍然尝试注册：成功了就能跟键盘热键走同一套 WM_HOTKEY / WM_XBUTTON 分发。
    if (!RegisterHotKey(static_cast<HWND>(windowHandle), id, spec.modifiers, spec.vk)) {
        errorCode = static_cast<unsigned long>(GetLastError());
        return false;
    }
    return true;
}

void UnregisterGlobalHotkey(void* windowHandle, int id)
{
    UnregisterHotKey(static_cast<HWND>(windowHandle), id);
}

bool PollHotkeyMessage(unsigned long& hotkeyId)
{
    MSG msg;
    if (PeekMessageW(&msg, NULL, WM_HOTKEY, WM_HOTKEY, PM_REMOVE)) {
        hotkeyId = static_cast<unsigned long>(msg.wParam);
        return true;
    }
    return false;
}

unsigned MouseButtonFromWMXButtonParam(unsigned long long wParam)
{
    switch (HIWORD(static_cast<DWORD>(wParam))) {
    case XBUTTON1: return VK_XBUTTON1;
    case XBUTTON2: return VK_XBUTTON2;
    default:       return 0;
    }
}

// =============================================================================
//  鼠标侧键的全局监听（WH_MOUSE_LL）
//  为什么需要它：
//    * RegisterHotKey 对 VK_XBUTTON1/2 的支持并不可靠（有的系统返回成功但从不投递）；
//    * GUI 的“请按键…”捕获要能收到侧键，并且把它的“后退/前进”动作吃掉。
//  线程要求：钩子回调由安装它的线程的消息循环驱动，因此安装线程必须有消息循环
//           （GUI 主线程有；CLI 的 PeekMessage 轮询也算）。
// =============================================================================

namespace {

HHOOK           g_mouseHook           = NULL;
volatile LONG   g_mouseCaptureOn      = 0;   // 捕获模式：吃掉侧键并记录
volatile LONG   g_mouseHotkeyPending  = 0;   // 待取的侧键（VK_XBUTTON1/2，0 = 无）
volatile LONG   g_mouseHookSuppressed = 0;   // 处于“已按下未抬起”状态，避免按住连发
MouseHotkeyFn   g_mouseHotkeyFn       = NULL; // 立即通知回调（可为空）
void*           g_mouseHotkeyUser     = NULL;

// 钩子回调里**绝不能**直接调用上层代码。
// 原因（实测踩坑）：上层收到通知后往往会去卸载/重装钩子（换绑快捷键时就会），
// 而从 WH_MOUSE_LL 自己的回调里 UnhookWindowsHookEx / SetWindowsHookExW，
// 会把整个系统的鼠标输入卡死。所以这里只 PostMessage 一个自定义消息：
//   钩子回调 -> PostMessage(HWND, WM_APP_MOUSE_HOTKEY, vk, 0) -> 消息循环 -> 上层
// 上层在自己的消息处理里想怎么装卸钩子都安全。
const UINT kMouseHotkeyPostedMessage = WM_APP + 0x51;

// 通知目标窗口：由上层通过 SetMouseHotkeyNotifyWindow 指定（没有就退回轮询）。
HWND g_mouseHotkeyWindow = NULL;

bool IsSideButtonMessage(WPARAM wParam)
{
    return wParam == WM_XBUTTONDOWN || wParam == WM_XBUTTONUP ||
           wParam == WM_NCXBUTTONDOWN || wParam == WM_NCXBUTTONUP;
}

// 为了向后兼容保留：只有拿到“窗口消息形态”的 lParam 时才有意义。
// WH_MOUSE_LL 的 lParam 是 MSLLHOOKSTRUCT*，不是这个。见下面的取值逻辑。
LRESULT CALLBACK MouseHotkeyProc(int code, WPARAM wParam, LPARAM lParam)
{
    if (code == HC_ACTION && IsSideButtonMessage(wParam)) {
        const bool isDown = (wParam == WM_XBUTTONDOWN || wParam == WM_NCXBUTTONDOWN);

        // WH_MOUSE_LL：lParam 指向 MSLLHOOKSTRUCT，侧键编号在它的 mouseData 里
        // （high word 是 XBUTTON1/XBUTTON2），**不是** MSG::lParam。
        // 之前误取 msg->lParam（对低级钩子那是鼠标坐标），导致拿到的是垃圾值。
        unsigned vk = 0;
        const MSLLHOOKSTRUCT* info = reinterpret_cast<const MSLLHOOKSTRUCT*>(lParam);
        if (info != NULL) {
            vk = MouseButtonFromWMXButtonParam(
                static_cast<unsigned long long>(info->mouseData));
        }

        if (vk != 0 && isDown) {
            const bool capturing = (InterlockedCompareExchange(
                const_cast<LONG*>(&g_mouseCaptureOn), 0, 0) != 0);
            const LONG alreadyDown = InterlockedCompareExchange(
                const_cast<LONG*>(&g_mouseHookSuppressed), 1, 0);
            if (alreadyDown == 0) {
                // 只在“按下”的那一次登记，避免按住不放时连发
                // 有窗口时消息队列是主通道；只有投递失败才留给轮询兜底。
                // 两条通道同时登记会让同一侧键被处理两次（同键切换立即恢复）。
                const HWND target = g_mouseHotkeyWindow;
                if (target == NULL ||
                    !PostMessageW(target, kMouseHotkeyPostedMessage,
                                  static_cast<WPARAM>(vk), 0)) {
                    InterlockedExchange(const_cast<LONG*>(&g_mouseHotkeyPending),
                                        static_cast<LONG>(vk));
                }
            }
            if (capturing) {
                // 捕获模式下把侧键吃掉：否则浏览器会同时执行“后退/前进”
                return 1;
            }
        } else if (!isDown) {
            InterlockedExchange(const_cast<LONG*>(&g_mouseHookSuppressed), 0);
            if (InterlockedCompareExchange(const_cast<LONG*>(&g_mouseCaptureOn), 0, 0) != 0) {
                return 1;   // 松开也一起吃掉，避免前台程序只收到半个点击
            }
        }
    }
    return CallNextHookEx(g_mouseHook, code, wParam, lParam);
}

}  // namespace

bool IsMouseHotkeyListenerInstalled()
{
    return g_mouseHook != NULL;
}

bool SetMouseHotkeyListener(bool enable)
{
    if (!enable) {
        SetMouseHotkeyCapture(false);
        if (g_mouseHook != NULL) {
            // 注意：这个函数**不能**从鼠标钩子回调里调用（会把系统鼠标卡死）。
            // 钩子回调现在只 PostMessage，所以正常路径不会踩到。
            UnhookWindowsHookEx(g_mouseHook);
            g_mouseHook = NULL;
        }
        InterlockedExchange(const_cast<LONG*>(&g_mouseHotkeyPending), 0);
        InterlockedExchange(const_cast<LONG*>(&g_mouseHookSuppressed), 0);
        g_mouseHotkeyFn     = NULL;
        g_mouseHotkeyUser   = NULL;
        g_mouseHotkeyWindow = NULL;
        return true;
    }

    if (g_mouseHook != NULL) {
        return true;    // 已经装过了
    }
    g_mouseHook = SetWindowsHookExW(WH_MOUSE_LL, MouseHotkeyProc, GetModuleHandleW(NULL), 0);
    if (g_mouseHook == NULL) {
        Emit(LogLevel::Warning, "安装鼠标侧键监听失败（错误码 %lu）。",
             static_cast<unsigned long>(GetLastError()));
        return false;
    }
    Emit(LogLevel::Debug, "鼠标侧键监听已安装（WH_MOUSE_LL）。");
    return true;
}

void SetMouseHotkeyCallback(MouseHotkeyFn fn, void* user)
{
    g_mouseHotkeyUser = user;
    g_mouseHotkeyFn   = fn;
}

// 指定接收侧键通知的窗口：钩子回调只 PostMessage 给它，绝不同步调用上层。
// （PostMessage 是异步的，所以上层在自己的消息处理里卸载/重装钩子绝对安全。）
void SetMouseHotkeyNotifyWindow(void* hwnd)
{
    g_mouseHotkeyWindow = reinterpret_cast<HWND>(hwnd);
}

// 上层收到的自定义消息号，用它来判断“这是侧键通知”
unsigned MouseHotkeyNotifyMessage()
{
    return kMouseHotkeyPostedMessage;
}

void SetMouseHotkeyCapture(bool enable)
{
    InterlockedExchange(const_cast<LONG*>(&g_mouseCaptureOn), enable ? 1 : 0);
    if (enable) {
        // 进入捕获时清掉可能残留的待取值，免得刚点“设置”就立刻被上次的侧键触发
        InterlockedExchange(const_cast<LONG*>(&g_mouseHotkeyPending), 0);
        InterlockedExchange(const_cast<LONG*>(&g_mouseHookSuppressed), 0);
    }
}

bool IsMouseHotkeyCapturing()
{
    return InterlockedCompareExchange(const_cast<LONG*>(&g_mouseCaptureOn), 0, 0) != 0;
}

bool PollMouseHotkey(unsigned& vk)
{
    const LONG pending = InterlockedExchange(
        const_cast<LONG*>(&g_mouseHotkeyPending), 0);
    if (pending == 0) {
        return false;
    }
    vk = static_cast<unsigned>(pending);
    return true;
}

// 以下两个是对外暴露的包装，供界面层判断/显示鼠标侧键
bool IsMouseHotkey(unsigned vk)
{
    return IsMouseKey(vk);
}

// 供界面层判断“这个键能不能做单键热键”（与 IsHotkeyAcceptable 同一套规则）
bool IsReservedHotkeyKey(unsigned vk)
{
    return IsReservedSingleKey(vk);
}

const char* MouseHotkeyName(unsigned vk)
{
    return MouseKeyDisplayName(vk);
}

// =============================================================================
//  管理员权限检测
// =============================================================================
namespace {

bool HasEnabledAdministratorsSid()
{
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminSid = NULL;

    if (!AllocateAndInitializeSid(&ntAuthority, 2,
                                  SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0, &adminSid)) {
        return false;
    }

    BOOL isMember = FALSE;
    if (!CheckTokenMembership(NULL, adminSid, &isMember)) {
        isMember = FALSE;
    }
    FreeSid(adminSid);
    return (isMember != FALSE);
}

}  // namespace

Elevation QueryElevation()
{
    if (HasEnabledAdministratorsSid()) {
        return Elevation::Elevated;
    }

    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION_TYPE type = TokenElevationTypeDefault;
        DWORD returned = 0;
        const BOOL ok = GetTokenInformation(token, TokenElevationType, &type,
                                            sizeof(type), &returned);
        CloseHandle(token);
        if (ok && type == TokenElevationTypeLimited) {
            return Elevation::AdminNotElevated;
        }
    }
    return Elevation::StandardUser;
}

bool IsElevated()
{
    return QueryElevation() == Elevation::Elevated;
}

std::string ElevationAdvice(Elevation state)
{
    if (state == Elevation::Elevated) {
        return "已以管理员权限运行。";
    }
    if (state == Elevation::AdminNotElevated) {
        return "当前账号属于 Administrators 组，但进程未提权（UAC 过滤令牌）。\n"
               "请右键程序 -> “以管理员身份运行”，或在管理员终端/以管理员身份启动。";
    }
    return "当前账号不在 Administrators 组内。\n"
           "请改用管理员账号，或让管理员以提升权限的方式启动本程序。";
}

// =============================================================================
//  Session
// =============================================================================

namespace {

// 判断 WinDivertOpen 失败原因并生成中文提示
std::string DescribeOpenError(DWORD err)
{
    std::string text;
    char buf[1024] = { 0 };

    switch (err) {
    case ERROR_ACCESS_DENIED:
        text = "权限不足：WinDivert 需要管理员权限才能安装/加载驱动。";
        break;
    case ERROR_FILE_NOT_FOUND:
        // 2：目录在，但里面没有 WinDivert64.sys / WinDivert.dll
        text = "同一目录里缺少 WinDivert.dll 或 WinDivert64.sys。\n"
               "请确认这两个文件与 WeakNetTool.exe 放在一起（解压时要整个文件夹一起解压）。";
        break;
    case ERROR_PATH_NOT_FOUND:
        // 3：**整个路径都不存在**。最常见的真实原因是：以前从别的目录运行过，
        // WinDivert 驱动服务被注册成指向那个旧路径，后来那个目录被删/改名了。
        // 而 WinDivert 对“已存在的服务”是**直接复用、不会改路径**的，
        // 于是它去启动一个指向不存在路径的服务 -> 报 3。
        // 注意：这条和“文件没放在一起”无关，别让用户去翻同目录。
        text = "WinDivert 驱动服务指向的**旧路径已经不存在**了。\n"
               "原因：以前从别的目录运行过本程序，驱动服务被登记成指向那个目录，\n"
               "      之后那个目录被删除 / 改名 / 移动（比如把程序从 C 盘挪到 D 盘）。\n"
               "      WinDivert 对已存在的服务只会复用、不会自动改路径，所以一直找旧文件。\n"
               "处理（管理员执行其一即可）：\n"
               "  1) 本程序会先尝试自动修复；若仍失败，手动重建服务：\n"
               "       sc stop WinDivert\n"
               "       sc delete WinDivert\n"
               "     然后重新运行本程序（它会用当前目录的驱动重新注册）；\n"
               "  2) 或者重启电脑后重新运行。";
        break;
    case ERROR_SERVICE_DOES_NOT_EXIST:
        text = "WinDivert 驱动未安装且不允许自动安装（可能被安全软件或系统策略拦截）。";
        break;
    case ERROR_INVALID_PARAMETER:
        text = "过滤器语法或参数不合法。";
        break;
    case ERROR_INVALID_IMAGE_HASH:
        text = "驱动数字签名校验失败，可能被系统策略或杀软阻止。";
        break;
    case ERROR_DRIVER_BLOCKED:          // 1275
        text = "驱动被系统阻止加载。常见原因：\n"
               "  1) 安全软件 / 杀毒软件把 WinDivert 驱动拦了；\n"
               "  2) 在虚拟机或某些受策略限制的环境里，系统不允许加载这类驱动；\n"
               "  3) 32/64 位驱动装错了（本程序用的是 x64 版）。\n"
               "处理：把本程序目录加入杀软白名单后重试。";
        break;
    case ERROR_DRIVER_FAILED_PRIOR_UNLOAD:   // 654
        text = "内存里还残留着**另一个版本**的 WinDivert 驱动（版本不兼容）。\n"
               "处理：注销或重启一次，让旧驱动卸载干净；\n"
               "并确认机器上没有别的程序（加速器 / 代理 / 抓包工具）也带着 WinDivert。";
        break;
    case 1753:   // EPT_S_NOT_REGISTERED
        text = "系统的「基础筛选引擎 (BFE)」服务被禁用了，WinDivert 依赖它。\n"
               "处理：把服务 Base Filtering Engine 的启动类型改回「自动」并启动它：\n"
               "  sc config BFE start= auto && sc start BFE";
        break;
    case 1450:   // ERROR_NO_SYSTEM_RESOURCES
        // 注意：这个错误码**不在 WinDivert 官方文档的错误表里**，
        // 它是内核/WDF 层在“资源不够”时抛出来的（分页/非分页池耗尽、
        // 或系统里累积了太多筛选器/句柄），不是过滤器语法或权限问题。
        text = "系统资源不足（内核资源耗尽），无法创建 WinDivert 句柄。\n"
               "这不是本程序的参数问题，按顺序试：\n"
               "  1) 关掉本程序**所有**正在运行的实例（包括托盘里的旧实例、任务管理器里的残留进程），\n"
               "     重复启动很容易累积出这个问题；再重新打开一次；\n"
               "  2) 注销或重启电脑 —— 内核池的占用只有重启才能彻底清干净，这是最有效的一步；\n"
               "  3) 排查是不是有别的程序也在用 WinDivert（加速器、代理、抓包、某些游戏工具），\n"
               "     它们和本程序会抢同一份内核资源；\n"
               "  4) 临时关掉杀软/防火墙的实时防护再试（它们会在内核里挂大量筛选器）；\n"
               "  5) 看任务管理器「性能 → 内存」，确认「已提交」没被占满、物理内存也没吃光。\n"
               "如果重启后立刻就报 1450，基本可以确定是第 3 条（有别的程序在抢）。";
        break;
    case 193:   // ERROR_BAD_EXE_FORMAT
        text = "驱动映像不是合法的可执行文件。常见原因：机器上残留了别的 WinDivert 应用\n"
               "留下的旧驱动服务（指向已被破坏的 C:\\Windows\\System32\\drivers\\WinDivert.sys）。\n"
               "处理办法（管理员执行）：sc stop WinDivert / sc delete WinDivert /\n"
               "del /f \"C:\\Windows\\System32\\drivers\\WinDivert.sys\"，然后重新运行本程序。";
        break;
    default:
        text = "打开 WinDivert 句柄失败。";
        break;
    }

    std::snprintf(buf, sizeof(buf), "%s（错误码 %lu）", text.c_str(),
                  static_cast<unsigned long>(err));
    return buf;
}

// 宽字符串 -> UTF-8。注意 DebugLogf 内部用的是窄字符 vsnprintf，
// 它**不支持 %ls**（MSVC 的窄 printf 不会把 wchar_t* 转成本地编码，
// 结果是打出空串或乱码）。所以凡是宽字符串都要先经过这个函数再 %s。
std::string WideToUtf8Log(const wchar_t* text)
{
    if (text == NULL || *text == L'\0') {
        return std::string();
    }
    const int needed = WideCharToMultiByte(CP_UTF8, 0, text, -1, NULL, 0, NULL, NULL);
    if (needed <= 1) {
        return std::string();
    }
    std::string out(static_cast<size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, &out[0], needed, NULL, NULL);
    return out;
}

// 检查 WinDivert 驱动服务的注册路径是否还指向“当前这份程序所在目录”。
// 如果指向的是别处（而且那个路径已经不在了），就删掉服务，让 WinDivert
// 用当前目录重新注册。返回 true 表示做了修复动作。
//
// 为什么要修：WinDivert.dll 对**已存在的服务**只 OpenService 复用、不改路径。
// 用户把程序从 A 目录挪到 B 目录（或删掉 A）之后，服务还指着 A，
// 于是启动驱动时报 ERROR_PATH_NOT_FOUND(3)，而文件明明就在 B 里躺得好好的。
bool RepairStaleDriverService()
{
    // 本程序期望的驱动路径 = exe 目录 + \WinDivert64.sys
    wchar_t exePath[MAX_PATH] = { 0 };
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) <= 0) {
        return false;
    }
    std::wstring wantDir(exePath);
    const size_t slash = wantDir.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return false;
    }
    wantDir.resize(slash);
    const std::wstring wantSys = wantDir + L"\\WinDivert64.sys";

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL,
                                   SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (scm == NULL) {
        DebugLogf("预处理：无法打开服务管理器（错误码 %lu），跳过驱动服务自检",
                  static_cast<unsigned long>(GetLastError()));
        return false;
    }

    bool repaired = false;
    SC_HANDLE svc = OpenServiceW(scm, L"WinDivert",
                                 SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS |
                                 DELETE | SERVICE_STOP);
    if (svc != NULL) {
        // 取出当前注册的驱动路径
        DWORD cfgSize = 0;
        QueryServiceConfigW(svc, NULL, 0, &cfgSize);
        std::wstring registered;
        if (cfgSize > 0) {
            std::vector<unsigned char> raw(cfgSize);
            if (QueryServiceConfigW(svc,
                                    reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(raw.data()),
                                    cfgSize, &cfgSize)) {
                const LPQUERY_SERVICE_CONFIGW cfg =
                    reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(raw.data());
                if (cfg->lpBinaryPathName != NULL) {
                    registered = cfg->lpBinaryPathName;
                }
            }
        }

        // 已经是当前目录的驱动 -> 不用管
        const bool pointsHere =
            !registered.empty() && registered.find(wantSys) != std::wstring::npos;

        if (!pointsHere && !registered.empty()) {
            // 去掉 \??\ 前缀，判断那个路径是否真的不存在
            std::wstring plain = registered;
            if (plain.compare(0, 4, L"\\??\\") == 0) {
                plain = plain.substr(4);
            }
            const bool targetMissing = (GetFileAttributesW(plain.c_str()) == INVALID_FILE_ATTRIBUTES);

            DebugLogf("预处理：驱动服务指向 %s（该路径%s）",
                      WideToUtf8Log(registered.c_str()).c_str(),
                      targetMissing ? "已不存在" : "仍存在");

            if (targetMissing) {
                // 先尽力停掉服务，再删除注册，让 WinDivert 重新按当前目录注册
                SERVICE_STATUS status;
                std::memset(&status, 0, sizeof(status));
                ControlService(svc, SERVICE_CONTROL_STOP, &status);
                if (DeleteService(svc)) {
                    DebugLogf("预处理：已删除指向旧路径的 WinDivert 服务，"
                              "接下来会用当前目录的驱动重新注册");
                    repaired = true;
                } else {
                    DebugLogf("预处理：删除服务失败（错误码 %lu），"
                              "请手动执行 sc stop WinDivert 与 sc delete WinDivert",
                              static_cast<unsigned long>(GetLastError()));
                }
            } else {
                // 路径还在（可能是另一个程序正在用）—— 不动它，避免影响别人
                DebugLogf("预处理：旧路径仍然存在，保持原样不动（可能别的程序正在用）");
            }
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return repaired;
}

// 打开句柄失败时记一份“现场”：内存 / 提交量 / 本进程句柄数 / 同名进程数 /
// WinDivert 服务状态。别人机器上报错时，这份记录能直接判断是资源耗尽、
// 重复启动，还是有别的程序在抢 WinDivert。
void LogSystemResourceSnapshot(DWORD err)
{
    MEMORYSTATUSEX mem;
    std::memset(&mem, 0, sizeof(mem));
    mem.dwLength = sizeof(mem);
    if (GlobalMemoryStatusEx(&mem)) {
        DebugLogf("  内存: 物理 %llu MB / 可用 %llu MB；提交 %llu MB / 上限 %llu MB（负载 %lu%%）",
                  static_cast<unsigned long long>(mem.ullTotalPhys / (1024 * 1024)),
                  static_cast<unsigned long long>(mem.ullAvailPhys / (1024 * 1024)),
                  static_cast<unsigned long long>(mem.ullTotalPageFile / (1024 * 1024)),
                  static_cast<unsigned long long>(mem.ullTotalVirtual / (1024 * 1024)),
                  static_cast<unsigned long>(mem.dwMemoryLoad));
    }

    // 本进程句柄数 / 线程数
    DWORD handleCount = 0;
    if (GetProcessHandleCount(GetCurrentProcess(), &handleCount)) {
        DebugLogf("  本进程句柄数: %lu", static_cast<unsigned long>(handleCount));
    }

    // 同名进程数（自己重复启动是最常见的“资源被占”来源）
    unsigned selfCount = 0;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W entry;
            std::memset(&entry, 0, sizeof(entry));
            entry.dwSize = sizeof(entry);
            const DWORD selfPid = GetCurrentProcessId();
            if (Process32FirstW(snap, &entry)) {
                do {
                    if (_wcsicmp(entry.szExeFile, L"WeakNetTool.exe") == 0 ||
                        _wcsicmp(entry.szExeFile, L"WeakNetToolGUI.exe") == 0) {
                        ++selfCount;
                        DebugLogf("  发现本程序实例: pid=%lu 名字=%s%s",
                                  static_cast<unsigned long>(entry.th32ProcessID),
                                  WideToUtf8Log(entry.szExeFile).c_str(),
                                  (entry.th32ProcessID == selfPid) ? "（就是自己）" : "");
                    }
                } while (Process32NextW(snap, &entry));
            }
            CloseHandle(snap);
        }
    }
    if (selfCount > 1) {
        DebugLogf("  ⚠ 当前有 %u 个本程序实例在运行 —— 重复启动会累积内核资源，"
                  "把多余的全部关掉再试", selfCount);
    }

    // WinDivert 驱动服务状态（1450/654 这类问题经常能从服务状态看出来）
    {
        SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
        if (scm != NULL) {
            SC_HANDLE svc = OpenServiceW(scm, L"WinDivert",
                                         SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
            if (svc != NULL) {
                SERVICE_STATUS_PROCESS ssp;
                DWORD needed = 0;
                std::memset(&ssp, 0, sizeof(ssp));
                if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                         reinterpret_cast<LPBYTE>(&ssp),
                                         sizeof(ssp), &needed)) {
                    DebugLogf("  WinDivert 服务: state=%lu（4=RUNNING） exitCode=%lu",
                              static_cast<unsigned long>(ssp.dwCurrentState),
                              static_cast<unsigned long>(ssp.dwWin32ExitCode));
                } else {
                    DebugLogf("  WinDivert 服务: 查询状态失败 错误码=%lu",
                              static_cast<unsigned long>(GetLastError()));
                }

                // 把服务注册的驱动路径也记下来：如果它指向的是**别的目录**
                // （比如之前解压到别处、或旧版本留下的），就能立刻看出问题 ——
                // 用户多次解压到不同目录并各跑过一次时特别容易踩到。
                DWORD cfgSize = 0;
                QueryServiceConfigW(svc, NULL, 0, &cfgSize);
                if (cfgSize > 0) {
                    std::vector<unsigned char> raw(cfgSize);
                    if (QueryServiceConfigW(svc,
                                            reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(raw.data()),
                                            cfgSize, &cfgSize)) {
                        const LPQUERY_SERVICE_CONFIGW cfg =
                            reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(raw.data());
                        DebugLogf("  WinDivert 驱动路径（服务注册）: %s",
                                  WideToUtf8Log(cfg->lpBinaryPathName).c_str());

                        // 和本进程所在目录比对，不同就明确提示
                        wchar_t exePath[MAX_PATH] = { 0 };
                        if (GetModuleFileNameW(NULL, exePath, MAX_PATH) > 0) {
                            std::wstring selfDir(exePath);
                            const size_t slash = selfDir.find_last_of(L"\\/");
                            if (slash != std::wstring::npos) { selfDir.resize(slash); }
                            const std::wstring registered =
                                (cfg->lpBinaryPathName != NULL) ? cfg->lpBinaryPathName : L"";
                            const bool sameDir =
                                !registered.empty() &&
                                registered.find(selfDir) != std::wstring::npos;
                            if (!sameDir) {
                                DebugLogf("  ⚠ 驱动已从**另一个目录**注册/加载（本程序在 %s）。"
                                          "如果之前把程序解压到别处运行过，请重启电脑后只用一份，"
                                          "否则旧驱动会一直占着资源。",
                                          WideToUtf8Log(selfDir.c_str()).c_str());
                            }
                        }
                    }
                }
                CloseServiceHandle(svc);
            } else {
                DebugLogf("  WinDivert 服务: 不存在或无法查询（错误码 %lu）",
                          static_cast<unsigned long>(GetLastError()));
            }
            CloseServiceHandle(scm);
        }
    }

    if (err == 1450) {
        DebugLogf("  ⚠ 1450 = ERROR_NO_SYSTEM_RESOURCES：内核资源不足。"
                  "优先怀疑重复启动 / 重启后仍报则怀疑有别的程序在抢 WinDivert。");
    }
}

Stats SnapshotStatsRaw()
{
    Stats stats;
    stats.packets = g_statPackets.load();
    stats.bytes = g_statBytes.load();
    stats.tcp = g_statTcp.load();
    stats.udp = g_statUdp.load();
    stats.other = g_statOther.load();
    stats.forwarded = g_statForwarded.load();
    stats.forwardedBytes = g_statForwardedBytes.load();
    stats.processCount = g_statTargetPids.load();
    stats.portCount = g_statTargetPorts.load();
    stats.matchedDown = g_statMatchedDown.load();
    stats.matchedUp = g_statMatchedUp.load();
    stats.droppedDown = g_statDroppedDown.load();
    stats.droppedUp = g_statDroppedUp.load();
    stats.shapedDown = g_shapeIn.sent.load();
    stats.shapedUp = g_shapeOut.sent.load();
    stats.shapedBytesDown = g_shapeIn.sentBytes.load();
    stats.shapedBytesUp = g_shapeOut.sentBytes.load();
    stats.shapeDropped = g_statShapeDropped.load();
    stats.shapeLateDropped = g_statShapeLateDropped.load();
    return stats;
}

// 会话收尾：确认全部线程退出后，先取最终统计，再关闭共享资源并清空状态。
void TeardownSession(Stats* finalStats = NULL)
{
    // 限速线程要先停：它还在用 WinDivert 句柄发限速队列里的包，
    // 必须等它退出（并把队列丢弃掉）之后，才轮到其他线程收尾。
    ShaperStop();

    if (g_workerThread != NULL) {
        WaitForThreadStopped(g_workerThread, "收包线程", 5000);
        CloseHandle(g_workerThread);
        g_workerThread = NULL;
    }
    if (g_watcherThread != NULL) {
        WaitForThreadStopped(g_watcherThread, "退出监视线程", 5000);
        CloseHandle(g_watcherThread);
        g_watcherThread = NULL;
    }
    if (g_timerThread != NULL) {
        WaitForThreadStopped(g_timerThread, "计时线程", 5000);
        CloseHandle(g_timerThread);
        g_timerThread = NULL;
    }
    // 端口刷新线程必须在 cfg_ 被复用/销毁之前退出（它持有 &cfg_）
    if (g_portThread != NULL) {
        WaitForThreadStopped(g_portThread, "端口刷新线程", 5000);
        CloseHandle(g_portThread);
        g_portThread = NULL;
    }
    if (finalStats != NULL) { *finalStats = SnapshotStatsRaw(); }
    if (g_stopEvent != NULL) {
        CloseHandle(g_stopEvent);
        g_stopEvent = NULL;
    }
    if (g_cleanupDoneEvent != NULL) {
        CloseHandle(g_cleanupDoneEvent);
        g_cleanupDoneEvent = NULL;
    }
    if (g_finishedEvent != NULL) {
        CloseHandle(g_finishedEvent);
        g_finishedEvent = NULL;
    }

    g_statPackets.store(0);
    g_statBytes.store(0);
    g_statTcp.store(0);
    g_statUdp.store(0);
    g_statOther.store(0);
    g_statForwarded.store(0);
    g_statForwardedBytes.store(0);
    g_statSendErrors.store(0);
    g_statMatchedDown.store(0);
    g_statMatchedUp.store(0);
    g_statDroppedDown.store(0);
    g_statDroppedUp.store(0);
    g_statShapeDropped.store(0);
    g_statShapeLateDropped.store(0);
    g_shapeIn.sent.store(0);
    g_shapeOut.sent.store(0);
    g_shapeIn.sentBytes.store(0);
    g_shapeOut.sentBytes.store(0);
    ClearProcessPorts();
    InterlockedExchange(const_cast<LONG*>(&g_stopRequested), 0);
    InterlockedExchange(const_cast<LONG*>(&g_stopReasonRaw), static_cast<LONG>(StopReason::None));
    g_startTick = 0;
    g_stopTick = 0;
}

}  // namespace

Session::~Session()
{
    if (owns_ && IsRunning()) {
        Stop();
    }
}

StartResult Session::Start(const Config& cfg, LogFn logFn, void* logUser)
{
    StartResult result;
    result.ok = false;

    if (g_workerThread != NULL) {
        result.message = "已经有一个会话在运行中（同一进程只支持一个会话）。";
        return result;
    }

    // 进程模式：规范化进程名（大小写 / 路径 / 空串都在这里挡住）
    Config effective = cfg;
    if (!effective.processName.empty()) {
        std::string normalizedName;
        std::string nameError;
        if (!NormalizeProcessName(effective.processName, normalizedName, nameError)) {
            result.message = "进程名不合法：" + nameError;
            return result;
        }
        effective.processName = normalizedName;
        if (effective.processRefreshMs < kMinProcessRefreshMs) {
            effective.processRefreshMs = kMinProcessRefreshMs;
        }
    } else if (effective.ports.empty() && !effective.allPorts) {
        result.message = "没有指定任何端口（也未启用“全部端口”模式或进程名模式）。";
        return result;
    }

    // 丢包率与方向的语义检查（0/0 无意义、丢包率与 --dir 自相矛盾等）
    {
        std::string configError;
        if (!ValidateConfig(effective, configError)) {
            result.message = configError;
            return result;
        }
    }

    g_logFn   = logFn;
    g_logUser = logUser;

    cfg_         = effective;
    processMode_ = !cfg_.processName.empty();
    ClearProcessPorts();
    filter_ = BuildFilter(cfg_);

    // 自相矛盾的组合（丢包率 100% + 限速）在这里提醒一次。
    // 放在这里而不是 ValidateConfig：那里是界面每次按键都调的，会刷屏。
    {
        const std::string conflict = RateLossConflictWarning(cfg_);
        if (!conflict.empty()) {
            Emit(LogLevel::Warning, "%s", conflict.c_str());
            DebugLogf("配置警告：%s", conflict.c_str());
        }
    }

    // 先校验过滤器（需要管理员权限才能打开句柄，但语法错误更该先报）
    std::string filterError;
    if (!ValidateFilter(filter_, filterError)) {
        result.message = filterError;
        return result;
    }

    // ---- 1. 打开句柄 ---------------------------------------------------------
    // 打开前先记一行“第几次尝试 + exe 目录”：别人报 1450 时，
    // 「是不是首次打开就失败」「exe 放在哪个目录」这两点最能定位问题。
    {
        static volatile LONG s_openAttempts = 0;
        const LONG attempt = InterlockedIncrement(const_cast<LONG*>(&s_openAttempts));
        wchar_t exePath[MAX_PATH] = { 0 };
        if (GetModuleFileNameW(NULL, exePath, MAX_PATH) > 0) {
            DebugLogf("准备打开 WinDivert 句柄：第 %ld 次尝试，exe=%s",
                      static_cast<long>(attempt), WideToUtf8Log(exePath).c_str());
        }
    }

    // ---- 1.5 预处理：清掉“指向旧目录”的驱动服务注册 --------------------------
    // WinDivert.dll 找驱动的方式是：拿【DLL 自身所在目录】+ "\WinDivert64.sys"
    // 组成绝对路径，然后 CreateService 注册。但它对**已经存在的服务**只会
    // OpenService 直接复用，**不会改路径**。
    // 于是：用户先把程序放在 A 目录跑过一次 -> 服务指向 A；之后把 A 删掉换成 B
    // -> 服务仍指向已不存在的 A -> StartService 报 ERROR_PATH_NOT_FOUND(3)。
    // 这里在打开前检测这种情况并删除旧服务，让 WinDivert 用当前目录重新注册。
#ifdef WEAKNET_TEST_HOOKS
    if (g_testFakeDriver == 0) { RepairStaleDriverService(); }
    HANDLE handle = INVALID_HANDLE_VALUE;
    if (g_testFakeDriver != 0) {
        if (g_testFailDriverOpen != 0) {
            SetLastError(ERROR_ACCESS_DENIED);
        } else {
            handle = CreateEventW(NULL, TRUE, FALSE, NULL);
            g_testFakeDriverHandle = handle;
        }
    } else {
        handle = WinDivertOpen(filter_.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    }
#else
    RepairStaleDriverService();
    HANDLE handle = WinDivertOpen(filter_.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
#endif
    if (handle == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        result.errorCode = err;
        result.message = DescribeOpenError(err);

        // 打开失败时把现场信息写进调试日志：这类问题是别人机器上的，
        // 光有一个错误码很难判断，把内存/句柄/服务状态一起记下来才好远程定位。
        DebugLogf("WinDivertOpen 失败：错误码=%lu 过滤器=\"%s\"",
                  static_cast<unsigned long>(err), filter_.c_str());
        LogSystemResourceSnapshot(err);
        return result;
    }
    g_handle = handle;      // 交给全局，后续由看门狗/工作线程原子访问

    // ---- 2. 事件对象 ---------------------------------------------------------
    if (g_stopEvent == NULL)        { g_stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL); }
    if (g_cleanupDoneEvent == NULL) { g_cleanupDoneEvent = CreateEventW(NULL, TRUE, FALSE, NULL); }
    if (g_finishedEvent == NULL)    { g_finishedEvent = CreateEventW(NULL, TRUE, FALSE, NULL); }

    if (g_stopEvent == NULL || g_cleanupDoneEvent == NULL || g_finishedEvent == NULL) {
        result.errorCode = GetLastError();
        result.message = "创建事件对象失败。";
        CloseHandleOnce();
        TeardownSession();
        return result;
    }

    // ---- 3. 控制台事件处理（CLI 需要） --------------------------------------
    if (cfg_.installConsoleHandler && !g_consoleHandlerInstalled) {
        signal(SIGINT, OnSigInt);
        if (SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
            g_consoleHandlerInstalled = true;
        }
    }

    // ---- 4. 驱动版本 & 队列调优 ---------------------------------------------
    UINT64 driverMajor = 0;
    UINT64 driverMinor = 0;
#ifdef WEAKNET_TEST_HOOKS
    if (handle != g_testFakeDriverHandle &&
#else
    if (
#endif
        WinDivertGetParam(handle, WINDIVERT_PARAM_VERSION_MAJOR, &driverMajor) &&
        WinDivertGetParam(handle, WINDIVERT_PARAM_VERSION_MINOR, &driverMinor)) {
        Emit(LogLevel::Info, "WinDivert 驱动版本: %llu.%llu",
             static_cast<unsigned long long>(driverMajor),
             static_cast<unsigned long long>(driverMinor));
        if (driverMajor != kDriverMajor || driverMinor < kDriverMinor) {
            Emit(LogLevel::Warning,
                 "驱动版本与随程序发布的 DLL 版本(2.2)不一致，建议统一使用同一发行包。");
        }
    }
#ifdef WEAKNET_TEST_HOOKS
    if (handle != g_testFakeDriverHandle &&
#else
    if (
#endif
        !WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH,
                           WINDIVERT_PARAM_QUEUE_LENGTH_MAX)) {
        Emit(LogLevel::Debug, "设置队列长度失败（错误码 %lu），继续使用默认值。",
             static_cast<unsigned long>(GetLastError()));
    }

    // ---- 5. 启动看门狗与计时线程，再启动工作线程 ----------------------------
    g_startTick = GetTickCount64();
    g_stopTick  = 0;

    g_watcherThread = CreateThread(NULL, 0, ShutdownWatcherThread, NULL, 0, NULL);
    if (g_watcherThread == NULL) {
        result.errorCode = GetLastError();
        result.message = "创建退出监视线程失败。";
        CloseHandleOnce();
        TeardownSession();
        return result;
    }

    if (cfg_.durationSec > 0) {
        g_timerThread = CreateThread(NULL, 0, DurationTimerThread,
                                     reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(cfg_.durationSec)),
                                     0, NULL);
        if (g_timerThread == NULL) {
            result.errorCode = GetLastError();
            result.message = "创建计时线程失败，已取消拦截。";
            RequestStop(StopReason::Error);
            TeardownSession();
            return result;
        }
    }

    // ---- 5.5 进程模式：先解析一次进程名，再启动端口刷新线程 -------------------
    //  先同步解析一次有两个好处：
    //    * 进程名写错时立即给出明确提示（而不是静默地全部放行）；
    //    * 收包线程启动时端口集合已经就绪，避免开局漏丢几百毫秒的报文。
    if (processMode_) {
        std::unordered_set<uint16_t> initialPorts;
        std::unordered_set<uint32_t> initialKeys;
        std::vector<unsigned long>   initialPids;
        std::string                  resolveError;
        bool initialResolved = false;

        // 进程可能刚好在启动，连接表也许还没来得及建立：短时间重试几次
        for (int attempt = 0; attempt < 5; ++attempt) {
            initialResolved = CollectProcessLocalPorts(cfg_.processName, initialPorts,
                                                       initialPids, resolveError, &initialKeys);
            if (initialResolved) {
                break;
            }
            initialPorts.clear();
            initialKeys.clear();
            Sleep(150);
        }

        if (!initialResolved) {
            Emit(LogLevel::Warning,
                 "进程 “%s” 的端口尚未就绪（%s）。会话会继续运行并每秒重试一次，"
                 "在成功查询之前所有 TCP/UDP 报文都会被放行。",
                 cfg_.processName.c_str(), resolveError.c_str());
        } else {
            Emit(LogLevel::Info, "进程 “%s” 命中 %llu 个实例（PID %lu%s），当前 %llu 个本地端口。",
                 cfg_.processName.c_str(),
                 static_cast<unsigned long long>(initialPids.size()),
                 initialPids[0],
                 initialPids.size() > 1 ? " 等" : "",
                 static_cast<unsigned long long>(initialPorts.size()));
        }
        PublishProcessPorts(initialPorts, initialKeys, initialPids);

        g_portThread = CreateThread(NULL, 0, PortRefreshThread, &cfg_, 0, NULL);
        if (g_portThread == NULL) {
            result.errorCode = GetLastError();
            result.message = "创建端口刷新线程失败，已取消拦截。";
            RequestStop(StopReason::Error);
            TeardownSession();
            return result;
        }
    }

    // ---- 5.8 限速：先拉起节流线程，再启动收包线程 ---------------------------
    //  顺序很重要：收包线程一开跑就会往限速队列里塞包，节流线程必须先就绪，
    //  否则开局那批包只能堆在队列里等着（虽然也不会丢，但没必要）。
    if (!ShaperStart(cfg_)) {
        result.errorCode = 0;
        result.message = "限速组件启动失败，已取消拦截并恢复网络。";
        RequestStop(StopReason::Error);
        TeardownSession();
        return result;
    }

#ifdef WEAKNET_TEST_HOOKS
    if (g_testFailWorkerThread != 0) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        g_workerThread = NULL;
    } else
#endif
    g_workerThread = CreateThread(NULL, 0, WorkerThread, &cfg_, 0, NULL);
    if (g_workerThread == NULL) {
        result.errorCode = GetLastError();
        result.message = "创建收包线程失败。";
        RequestStop(StopReason::Error);
        TeardownSession();
        return result;
    }

    owns_ = true;
    result.ok = true;
    return result;
}

void Session::Stop()
{
    if (!owns_) {
        return;
    }
    RequestStop(StopReason::User);
    WaitForStop();
}

bool Session::WaitForStop(unsigned long timeoutMs)
{
    if (g_finishedEvent == NULL) {
        return true;    // 没有会话
    }
    if (WaitForSingleObject(g_finishedEvent, timeoutMs) != WAIT_OBJECT_0) {
        return false;   // 超时（还在运行）
    }

    lastReason_     = GetStopReasonRaw();
    lastElapsedMs_  = ElapsedMs();
    TeardownSession(&lastStats_);
    hasSnapshot_    = true;
    owns_ = false;
    return true;
}

bool Session::HasFinished() const
{
    if (g_finishedEvent == NULL) {
        return true;
    }
    return WaitForSingleObject(g_finishedEvent, 0) == WAIT_OBJECT_0;
}

bool Session::IsRunning() const
{
    return g_workerThread != NULL;
}

Stats Session::GetStats() const
{
    if (!IsRunning() && hasSnapshot_) {
        return lastStats_;
    }
    return SnapshotStatsRaw();
}

std::vector<unsigned long> Session::CurrentProcessIds() const
{
    return SnapshotProcessPids();
}

std::unordered_set<uint16_t> Session::CurrentPorts() const
{
    return SnapshotProcessPorts(NULL);
}

StopReason Session::GetStopReason() const
{
    if (!IsRunning() && hasSnapshot_) {
        return lastReason_;
    }
    return GetStopReasonRaw();
}

unsigned long long Session::ElapsedMs() const
{
    if (!IsRunning() && hasSnapshot_) {
        return lastElapsedMs_;
    }
    if (g_startTick == 0) {
        return 0;
    }
    const ULONGLONG end = (g_stopTick != 0) ? g_stopTick : GetTickCount64();
    return end - g_startTick;
}

}  // namespace weaknet
