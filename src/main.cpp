// =============================================================================
//  WeakNetTool —— Windows 平台弱网测试小工具（命令行版）
// -----------------------------------------------------------------------------
//  作用：把指定端口的下行（入站）数据包在内核里直接丢弃，形成 100% 丢包黑洞，
//        用于验证程序的超时 / 重试 / 断线重连 / 降级等弱网逻辑。
//
//  实现要点：WinDivert 在网络层把匹配过滤器的报文“截走”，只有再调用
//        WinDivertSend() 才会重新注入网络栈；本工具收到包后什么都不做，
//        于是报文在内核里被彻底丢弃 —— 这才是真正的 100% 丢包。
//
//  界面层职责：参数解析、控制台彩色输出、权限提示、运行总结。
//  真正的引擎（过滤器、收包循环、优雅停止）在 weaknet_core.cpp，与 GUI 共用。
//
//  编译见项目根目录 README.md。
// =============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#  define _CRT_SECURE_NO_WARNINGS
#endif

#include <windows.h>

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <io.h>

#include <algorithm>
#include <stdint.h>
#include <string>
#include <unordered_set>
#include <vector>

#include "weaknet_core.h"

namespace {

using weaknet::Config;
using weaknet::Direction;
using weaknet::Elevation;
using weaknet::FormatCount;
using weaknet::LogLevel;
using weaknet::PortSide;
using weaknet::Protocol;
using weaknet::Session;
using weaknet::Stats;

// 进程退出码（方便脚本判断失败原因）
enum ExitCode {
    kExitOk      = 0,   // 正常结束（Ctrl+C / 到期自动停止）
    kExitRuntime = 1,   // 运行期错误（打不开 WinDivert 等）
    kExitUsage   = 2,   // 命令行参数错误
    kExitNoAdmin = 3    // 未以管理员身份运行
};

const DWORD kPollIntervalMs = 1000;    // 统计刷新间隔

// =============================================================================
//  控制台输出（彩色 + 中文对齐）
// =============================================================================

HANDLE g_stdout       = INVALID_HANDLE_VALUE;
bool   g_colorEnabled = false;
bool   g_stdoutIsTty  = false;

enum class Color { Default, Gray, Red, Green, Yellow, Cyan, White };

WORD ColorToAttr(Color color)
{
    switch (color) {
    case Color::Gray:   return FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_BLUE;
    case Color::Red:    return FOREGROUND_RED   | FOREGROUND_INTENSITY;
    case Color::Green:  return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    case Color::Yellow: return FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    case Color::Cyan:   return FOREGROUND_GREEN | FOREGROUND_BLUE  | FOREGROUND_INTENSITY;
    case Color::White:  return FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    case Color::Default:
    default:            return FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_BLUE;
    }
}

void SetColor(Color color)
{
    if (g_colorEnabled && g_stdout != INVALID_HANDLE_VALUE) {
        SetConsoleTextAttribute(g_stdout, ColorToAttr(color));
    }
}

// 初始化控制台：UTF-8 代码页 + 彩色支持探测 + 标题
void InitConsole()
{
    // 源码是 UTF-8（CMake 里加了 /utf-8），这里把控制台输出代码页也切成 UTF-8，
    // 中文字符串才能正确显示而不会变成乱码。
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    g_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    g_stdoutIsTty = (_isatty(_fileno(stdout)) != 0);

    DWORD mode = 0;
    g_colorEnabled = (g_stdout != INVALID_HANDLE_VALUE && g_stdout != NULL &&
                      GetConsoleMode(g_stdout, &mode) != 0);

    SetConsoleTitleW(L"WeakNetTool - Windows 弱网测试工具 (下行丢包)");
}

void Print(Color color, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    SetColor(color);
    vfprintf(stdout, fmt, ap);
    fflush(stdout);
    SetColor(Color::Default);
    va_end(ap);
}

// UTF-8 字符串在控制台上的“显示宽度”（中日韩字符占 2 列，但 UTF-8 编码是 3 字节）
size_t VisualWidth(const char* text)
{
    size_t width = 0;
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(text); *p != '\0'; ++p) {
        if ((*p & 0xC0) == 0x80) {
            continue;
        }
        width += (*p >= 0xE0) ? 2 : 1;
    }
    return width;
}

// 引擎日志回调：把引擎内部线程产生的日志按等级上色后打印
void ConsoleLog(LogLevel level, const char* text, void* user)
{
    (void)user;
    switch (level) {
    case LogLevel::Error:   Print(Color::Red,    "[错误] %s\n", text); break;
    case LogLevel::Warning: Print(Color::Yellow, "[警告] %s\n", text); break;
    case LogLevel::Debug:   Print(Color::Gray,   "[调试] %s\n", text); break;
    case LogLevel::Packet:  Print(Color::Gray,   "  %s\n", text); break;
    case LogLevel::Info:
    default:                Print(Color::Default,"%s\n", text); break;
    }
}

// =============================================================================
//  帮助
// =============================================================================

void PrintUsage(const char* exeName)
{
    Print(Color::Cyan, "%s v%s —— Windows 弱网测试工具（把指定端口的下行报文丢进黑洞）\n",
          weaknet::kToolName, weaknet::kToolVersion);
    Print(Color::Default, "\n用法:\n");
    Print(Color::White,   "  %s --port <端口[,端口...]> [选项]\n\n", exeName);

    Print(Color::Default, "必填参数（三选一）:\n");
    Print(Color::White,   "  -p, --port <列表>       要丢包的端口，多个端口用逗号分隔，例如 --port 8080,8443\n");
    Print(Color::Gray,    "                          也可以写 --port all 表示“全部端口”（整体断网）\n");
    Print(Color::White,   "      --process <进程名>   只丢指定进程的报文，例如 --process chrome.exe\n");
    Print(Color::Gray,    "                          进程名大小写不敏感，可省略 .exe，也可直接粘贴完整路径\n");
    Print(Color::Gray,    "                          原理：按进程名找到 PID，再周期性查询该 PID 占用的本地端口，\n");
    Print(Color::Gray,    "                          命中这些端口的报文丢弃，其余报文原样放行\n\n");

    Print(Color::Default, "可选参数:\n");
    Print(Color::White,   "      --all-ports         不限定端口：丢所有入站报文（整体断网）\n");
    Print(Color::Gray,    "      --process-refresh <毫秒>\n");
    Print(Color::Gray,    "                          进程模式下的端口集合刷新周期，默认 1000ms，最小 100ms\n");
    Print(Color::White,   "      --dir <inbound|outbound|both>\n");
    Print(Color::Gray,    "                          拦截方向，默认 inbound（本机收包，即下行丢包）\n");
    Print(Color::White,   "      --match <src|dst>   端口匹配哪一端，默认 src（对端服务端口）\n");
    Print(Color::Gray,    "                          src：丢“来自 8080 端口”的包（远端服务响应）\n");
    Print(Color::Gray,    "                          dst：丢“发往 8080 端口”的包（本机监听服务）\n");
    Print(Color::White,   "      --proto <tcp|udp|both>\n");
    Print(Color::Gray,    "                          协议范围，默认 both\n");
    Print(Color::White,   "      --loss <0-100>      丢包率：作用于“会被接管的方向”\n");
    Print(Color::Gray,    "                          默认方向是 inbound，所以 --loss 30 = 只丢下行 30%；\n");
    Print(Color::Gray,    "                          想上下行都按同一比例丢，加 --dir both\n");
    Print(Color::White,   "      --loss-down <0-100> 只设下行（本机收包）丢包率，默认 100\n");
    Print(Color::White,   "      --loss-up <0-100>   只设上行（本机发包）丢包率，默认 100\n");
    Print(Color::Gray,    "                          0   = 不丢包（该方向同时也没限速 → 完全不接管，零开销）\n");
    Print(Color::Gray,    "                          1-99= 逐包按概率丢弃，没被丢中的原样回注放行\n");
    Print(Color::Gray,    "                          100 = 全部丢弃（旧版的“黑洞”行为）\n");
    Print(Color::Gray,    "                          例：--dir both --loss-up 30 --loss-down 50\n");
    Print(Color::White,   "      --rate <速率>      限速：作用于“会被接管的方向”（v1.5.0 新增）\n");
    Print(Color::Gray,    "                          默认方向是 inbound，所以 --rate 200K = 只限下行；\n");
    Print(Color::Gray,    "                          想上下行都限，加 --dir both\n");
    Print(Color::White,   "      --rate-down <速率>  只限下行（本机收包），0 = 不限（默认）\n");
    Print(Color::White,   "      --rate-up <速率>    只限上行（本机发包），0 = 不限（默认）\n");
    Print(Color::Gray,    "                          速率可以带单位：300B = 300 字节/秒（v1.6.0 新增）、\n");
    Print(Color::Gray,    "                          200K = 200KB/s、2M = 2MB/s；不写单位按 KB/s 算。\n");
    Print(Color::Gray,    "                          这是**真正的整形**：超速的报文排队等一会儿再放行，\n");
    Print(Color::Gray,    "                          不丢包也能降速（和丢包率是两回事，可以叠加）。\n");
    Print(Color::Gray,    "                          v1.7.1：只给限速、没提丢包率时，该方向丢包率自动按 0 处理\n");
    Print(Color::Gray,    "                          （即“只限速不丢包”），所以下面这条就够了：\n");
    Print(Color::Gray,    "                          例：--dir outbound --rate-up 300B   ← 上行限 300 字节/秒\n");
    Print(Color::Gray,    "                          例：--dir both --rate-up 300B --rate-down 1M\n");
    Print(Color::White,   "      --rate-latency <ms> 队列里最多排多久，超过就丢（v1.6.0 新增，0 = 自动）\n");
    Print(Color::White,   "      --mpu <字节>        最小包单位：每包至少按这么多字节扣令牌（v2.0.4，0 = 不限）\n");
    Print(Color::Gray,    "                          对齐 tc tbf 的 mpu。以太网任何帧都不小于 64 字节，\n");
    Print(Color::Gray,    "                          设 64 可让 ACK 密集的流量更贴近真实链路。\n");
    Print(Color::Gray,    "                          低速率的物理事实是“一个满包要攒很久令牌”（300 B/s 要 5 秒），\n");
    Print(Color::Gray,    "                          所以自动值会跟着速率走（约 3 个满包的时间），不要随便调小，\n");
    Print(Color::Gray,    "                          调太小会让限速直接退化成 0 字节/秒。\n");
    Print(Color::White,   "  -d, --duration <秒>     运行指定秒数后自动优雅退出（默认一直运行到 Ctrl+C）\n");
    Print(Color::White,   "  -v, --verbose           打印被丢弃报文的信息（仅前若干个，避免刷屏）\n");
    Print(Color::White,   "  -q, --quiet             不打印周期性统计\n");
    Print(Color::White,   "      --hotkey-block <快捷键>\n");
    Print(Color::Gray,    "                          全局快捷键：按下即“断网”（开始丢包）\n");
    Print(Color::White,   "      --hotkey-unblock <快捷键>\n");
    Print(Color::Gray,    "                          全局快捷键：按下即“联网”（停止丢包，进程继续待命）\n");
    Print(Color::Gray,    "                          写法如 Ctrl+Alt+B、Ctrl+Shift+F9；\n");
    Print(Color::Gray,    "                          **也支持单独一个键**（v1.2.3 起）：--hotkey-block F8、--hotkey-block B\n");
    Print(Color::Gray,    "                            注意：单键会被本程序全局独占，该键在别的程序里不再产生输入，\n");
    Print(Color::Gray,    "                            建议用 F1~F24 这类不常用的键；Win/CapsLock 等系统保留键不可用。\n");
    Print(Color::Gray,    "                          鼠标侧键：\n");
    Print(Color::Gray,    "                            --hotkey-block X1      鼠标侧键1（鼠标 4 号键）\n");
    Print(Color::Gray,    "                            --hotkey-block 侧键2   鼠标侧键2（鼠标 5 号键）\n");
    Print(Color::Gray,    "                          **两个键写成同一个**就是“切换键”：按一下断网、再按一下联网，\n");
    Print(Color::Gray,    "                          例如 --hotkey-block X1 --hotkey-unblock X1\n");
    Print(Color::Gray,    "                          给了热键参数就进入交互模式，可以反复切换，Ctrl+C 或 --duration 到期才退出\n");
    Print(Color::White,   "      --dry-run           只构造并校验过滤器后退出，不需要管理员权限\n");
    Print(Color::White,   "      --debug-log[=路径]  记录调试日志（默认 exe 同目录 weaknet_debug.log，每行立即落盘）\n");
    Print(Color::White,   "      --no-debug-log      不写调试日志\n");
    Print(Color::White,   "  -h, --help              显示本帮助\n");
    Print(Color::White,   "      --version           显示版本信息\n\n");

    Print(Color::Default, "示例:\n");
    Print(Color::Gray,    "  %s --port 8080\n", exeName);
    Print(Color::Gray,    "        丢掉所有“源端口是 8080”的入站报文（模拟远端服务 8080 完全不可达）\n");
    Print(Color::Gray,    "  %s --port 8080 --match dst\n", exeName);
    Print(Color::Gray,    "        丢掉所有“目的端口是 8080”的入站报文（模拟本机 8080 服务只进不出）\n");
    Print(Color::Gray,    "  %s --port 53 --proto udp --dir both -v\n", exeName);
    Print(Color::Gray,    "        丢掉双向 UDP 53 端口报文，并打印被丢弃的报文信息\n");
    Print(Color::Gray,    "  %s --port 8080 --duration 30 -q\n", exeName);
    Print(Color::Gray,    "        静默丢弃 30 秒后自动恢复网络\n");
    Print(Color::Gray,    "  %s --port all --hotkey-block Ctrl+Alt+B --hotkey-unblock Ctrl+Alt+R\n", exeName);
    Print(Color::Gray,    "        整体断网 + 全局快捷键：按 Ctrl+Alt+B 断网、Ctrl+Alt+R 联网，Ctrl+C 退出\n");
    Print(Color::Gray,    "  %s --process chrome.exe -v\n", exeName);
    Print(Color::Gray,    "        只丢 chrome.exe 的流量（TCP+UDP，IPv4+IPv6 全覆盖），其余进程不受影响\n");
    Print(Color::Gray,    "  %s --hotkey-block X1 --hotkey-unblock X1 --port all\n", exeName);
    Print(Color::Gray,    "        鼠标侧键1 当切换键：按一下整体断网、再按一下恢复联网\n\n");

    Print(Color::Default, "退出码:\n");
    Print(Color::Gray,    "  0=正常结束  1=运行期错误  2=命令行参数错误  3=未以管理员身份运行\n\n");

    Print(Color::Yellow, "注意:\n");
    Print(Color::Gray,    "  * 本工具只“丢包”，不放行、不改包；丢掉的包不会到达任何本机进程。\n");
    Print(Color::Gray,    "  * Windows 把“本机 -> 本机”的流量一律视为 loopback，且只在 outbound\n");
    Print(Color::Gray,    "    方向被 WinDivert 捕获。因此在本机同时跑客户端+服务端做自测时，\n");
    Print(Color::Gray,    "    请用 --dir outbound --match src 来丢“服务端响应”，效果等同下行丢包。\n");
    Print(Color::Gray,    "  * 需要 WinDivert.dll 与 WinDivert64.sys 与本程序在同一目录（见 README.md）。\n");
    Print(Color::Gray,    "  * 不想敲命令行？同目录下的 WeakNetToolGUI.exe 是同一引擎的图形界面。\n\n");
}

// =============================================================================
//  命令行解析
// =============================================================================

struct Options {
    Config cfg;
    bool   verbose   = false;   // 已并入 cfg.verbose，这里保留一份便于打印参数
    bool   quiet     = false;
    bool   dryRun    = false;
    bool   showHelp  = false;
    bool   showVersion = false;

    // 调试日志：默认写到 exe 同目录的 weaknet_debug.log；
    // --debug-log=路径 可指定位置，--no-debug-log 完全关闭。
    bool        debugLog = true;
    std::string debugLogPath;

    // 用户是否显式给过丢包率参数（v1.3.0）。
    // 用途：进程模式下 dir 按历史行为被忽略，如果用户既给了 --process 又给了 --dir，
    //       提示他 --dir 不生效；只有用户真给过 loss 参数时才做这类提示。
    bool        lossSet = false;

    // --loss <N> 的“双向统一设置”先生效、但要等 --dir / --loss-up / --loss-down
    // 都解析完才能决定落到哪些方向，所以先记下来，解析循环结束后再套用。
    // （否则 `--loss 25 --dir both` 与 `--dir both --loss 25` 的行为会不一样。）
    bool        lossBothSet   = false;
    unsigned    lossBothValue = 100;
    bool        lossDownSet   = false;   // --loss-down 显式给过
    bool        lossUpSet     = false;   // --loss-up 显式给过

    // 限速（v1.5.0）：同样先记下来，等 --dir 解析完再决定落到哪些方向
    bool               rateBothSet   = false;
    unsigned long long rateBothValue = 0;   // 字节/秒
    bool               rateDownSet   = false;   // --rate-down 显式给过
    bool               rateUpSet     = false;   // --rate-up 显式给过
    bool               rateLatencySet = false;
    unsigned           rateLatencyMs  = 0;
    // ③ 判定用：用户是否真的提过某个方向的丢包率（--loss 写进去的也算）
    bool               lossGivenIn  = false;
    // v2.0.7：用户有没有**显式**写过 --dir。
    // 为什么需要它：--dir 缺省值是 inbound，但"没写"和"写了 inbound"必须区分开 ——
    // 下面那条"方向是权威的"规则只对"显式写了 --dir"生效，
    // 否则 `--process chrome.exe`（不写 --dir，历史语义=整个进程断网）会被改成只断下行。
    bool               dirGiven     = false;
    // 下面两个只是给 dry-run / 启动提示用：告诉用户"另一个方向因为你选了单一方向而被自动忽略"
    bool               dirImpliedIdleDown = false;
    bool               dirImpliedIdleUp   = false;
    bool               lossGivenOut = false;
    // 记录"限速隐含把该方向丢包率置 0"这件事，好给用户一句明确说明
    bool               rateImpliedZeroLossIn  = false;
    bool               rateImpliedZeroLossOut = false;

    // 全局快捷键（可选）：按键后切换“断网 / 联网”，进程保持待命
    weaknet::HotkeySpec blockHotkey;
    weaknet::HotkeySpec unblockHotkey;
};

// 热键 id：引擎里只用 id 来区分是哪个键触发的
const int kHotkeyIdBlock   = 1;
const int kHotkeyIdUnblock = 2;
const int kHotkeyIdToggle  = 3;   // 断网/联网绑成同一个键时的切换键

bool ParseArgs(const std::vector<std::string>& args, Options& opt, std::string& err)
{
    for (size_t i = 0; i < args.size(); ++i) {
        std::string arg = args[i];
        std::string inlineValue;
        bool hasInlineValue = false;

        // 支持 --port=8080 这种等号写法
        if (arg.size() > 2 && arg[0] == '-' && arg.find('=') != std::string::npos) {
            const size_t eq = arg.find('=');
            inlineValue = arg.substr(eq + 1);
            hasInlineValue = true;
            arg = arg.substr(0, eq);
        }

        // 取选项值：优先等号后的内容，否则吃掉下一个参数
        const auto takeValue = [&](const char* name, std::string& value) -> bool {
            if (hasInlineValue) {
                value = inlineValue;
                return true;
            }
            if (i + 1 >= args.size()) {
                err = std::string("选项 ") + name + " 后面缺少取值";
                return false;
            }
            value = args[++i];
            return true;
        };

        std::string value;

        if (arg == "-h" || arg == "--help") {
            opt.showHelp = true;
        } else if (arg == "--version") {
            opt.showVersion = true;
        } else if (arg == "-p" || arg == "--port") {
            if (!takeValue("--port", value)) { return false; }
            if (value == "all" || value == "*" || value == "全部") {
                opt.cfg.allPorts = true;          // --port all：不限定端口（整体断网）
            } else {
                opt.cfg.allPorts = false;
                if (!weaknet::ParsePortList(value, opt.cfg.ports, err)) { return false; }
            }
        } else if (arg == "--all-ports") {
            opt.cfg.allPorts = true;
        } else if (arg == "--process" || arg == "--process-name") {
            if (!takeValue("--process", value)) { return false; }
            std::string normalized;
            std::string nameError;
            if (!weaknet::NormalizeProcessName(value, normalized, nameError)) {
                err = "进程名无效：" + nameError;
                return false;
            }
            opt.cfg.processName = normalized;
        } else if (arg == "--process-refresh") {
            if (!takeValue("--process-refresh", value)) { return false; }
            char* end = NULL;
            const long ms = std::strtol(value.c_str(), &end, 10);
            if (end == value.c_str() || (end != NULL && *end != '\0') || ms <= 0) {
                err = "选项 --process-refresh 需要一个大于 0 的整数（单位：毫秒）";
                return false;
            }
            if (ms < static_cast<long>(weaknet::kMinProcessRefreshMs)) {
                char buf[160] = { 0 };
                std::snprintf(buf, sizeof(buf), "刷新周期过小（最小 %u 毫秒）",
                              weaknet::kMinProcessRefreshMs);
                err = buf;
                return false;
            }
            opt.cfg.processRefreshMs = static_cast<unsigned>(ms);
        } else if (arg == "--hotkey-block") {
            if (!takeValue("--hotkey-block", value)) { return false; }
            if (!weaknet::ParseHotkey(value, opt.blockHotkey, err)) {
                err = "断网快捷键无效：" + err;
                return false;
            }
        } else if (arg == "--hotkey-unblock") {
            if (!takeValue("--hotkey-unblock", value)) { return false; }
            if (!weaknet::ParseHotkey(value, opt.unblockHotkey, err)) {
                err = "联网快捷键无效：" + err;
                return false;
            }
        } else if (arg == "--dir") {
            if (!takeValue("--dir", value)) { return false; }
            if (value == "inbound" || value == "in") {
                opt.cfg.dir = Direction::Inbound;
            } else if (value == "outbound" || value == "out") {
                opt.cfg.dir = Direction::Outbound;
            } else if (value == "both") {
                opt.cfg.dir = Direction::Both;
            } else {
                err = "选项 --dir 的取值只能是 inbound / outbound / both";
                return false;
            }
            opt.dirGiven = true;      // 显式写了 --dir（与"缺省 inbound"区分开，见 Options 注释）
        } else if (arg == "--match") {
            if (!takeValue("--match", value)) { return false; }
            if (value == "src" || value == "source") {
                opt.cfg.side = PortSide::Src;
            } else if (value == "dst" || value == "dest" || value == "destination") {
                opt.cfg.side = PortSide::Dst;
            } else {
                err = "选项 --match 的取值只能是 src / dst";
                return false;
            }
        } else if (arg == "--proto") {
            if (!takeValue("--proto", value)) { return false; }
            if (value == "tcp") {
                opt.cfg.proto = Protocol::Tcp;
            } else if (value == "udp") {
                opt.cfg.proto = Protocol::Udp;
            } else if (value == "both" || value == "all") {
                opt.cfg.proto = Protocol::Both;
            } else {
                err = "选项 --proto 的取值只能是 tcp / udp / both";
                return false;
            }
        } else if (arg == "-d" || arg == "--duration") {
            if (!takeValue("--duration", value)) { return false; }
            if (!weaknet::ParseDurationSeconds(value, opt.cfg.durationSec, err)) {
                return false;
            }
            if (opt.cfg.durationSec == 0) {
                err = "选项 --duration 需要一个大于 0 的整数（单位：秒）";
                return false;
            }
        } else if (arg == "--loss") {
            // 上下行统一设置：落到哪些方向要等 --dir 解析完才知道，
            // 所以先记下来（见循环结束后的套用逻辑）。
            if (!takeValue("--loss", value)) { return false; }
            unsigned percent = 100;
            if (!weaknet::ParseLossPercent(value, percent, err)) {
                err = std::string("--loss: ") + err;
                return false;
            }
            opt.lossBothSet   = true;
            opt.lossBothValue = percent;
            opt.lossSet       = true;
        } else if (arg == "--loss-down") {
            if (!takeValue("--loss-down", value)) { return false; }
            unsigned percent = 100;
            if (!weaknet::ParseLossPercent(value, percent, err)) {
                err = std::string("--loss-down: ") + err;
                return false;
            }
            opt.cfg.lossDownPercent = percent;
            opt.lossDownSet = true;
            opt.lossSet = true;
        } else if (arg == "--loss-up") {
            if (!takeValue("--loss-up", value)) { return false; }
            unsigned percent = 100;
            if (!weaknet::ParseLossPercent(value, percent, err)) {
                err = std::string("--loss-up: ") + err;
                return false;
            }
            opt.cfg.lossUpPercent = percent;
            opt.lossUpSet = true;
            opt.lossSet = true;
        } else if (arg == "--rate") {
            // 上下行同一个限速值；落到哪些方向要等 --dir 解析完才知道
            if (!takeValue("--rate", value)) { return false; }
            unsigned long long bps = 0;
            if (!weaknet::ParseRate(value, bps, err)) {
                err = std::string("--rate: ") + err;
                return false;
            }
            opt.rateBothSet   = true;
            opt.rateBothValue = bps;
        } else if (arg == "--rate-down") {
            if (!takeValue("--rate-down", value)) { return false; }
            unsigned long long bps = 0;
            if (!weaknet::ParseRate(value, bps, err)) {
                err = std::string("--rate-down: ") + err;
                return false;
            }
            opt.cfg.rateDownBytesPerSec = bps;
            opt.rateDownSet = true;
        } else if (arg == "--rate-up") {
            if (!takeValue("--rate-up", value)) { return false; }
            unsigned long long bps = 0;
            if (!weaknet::ParseRate(value, bps, err)) {
                err = std::string("--rate-up: ") + err;
                return false;
            }
            opt.cfg.rateUpBytesPerSec = bps;
            opt.rateUpSet = true;
        } else if (arg == "--rate-latency") {
            // 队列里最多允许多久（毫秒）；不写就按速率自动算
            if (!takeValue("--rate-latency", value)) { return false; }
            char* stop = NULL;
            const long ms = std::strtol(value.c_str(), &stop, 10);
            if (stop == value.c_str() || (stop != NULL && *stop != '\0') || ms < 0) {
                err = "--rate-latency 需要一个非负整数（毫秒，如 500）；0 = 自动";
                return false;
            }
            if (ms > 3600000L) {
                err = "--rate-latency 最大 3600000（1 小时），再大就没意义了";
                return false;
            }
            opt.rateLatencySet = true;
            opt.rateLatencyMs  = static_cast<unsigned>(ms);
        } else if (arg == "--mpu") {
            // v2.0.4：最小包单位（对齐 tc tbf 的 mpu）。0 = 不设下限。
            if (!takeValue("--mpu", value)) { return false; }
            char* stop = NULL;
            const long mpu = std::strtol(value.c_str(), &stop, 10);
            if (stop == value.c_str() || (stop != NULL && *stop != '\0') || mpu < 0) {
                err = "--mpu 需要一个非负整数（字节，如 64）；0 = 不设下限";
                return false;
            }
            if (mpu > 65535L) {
                err = "--mpu 最大 65535（再大就超过一个 IP 报文了）";
                return false;
            }
            opt.cfg.mpuBytes = static_cast<unsigned>(mpu);
        } else if (arg == "-v" || arg == "--verbose") {
            opt.verbose = true;
            opt.cfg.verbose = true;
        } else if (arg == "-q" || arg == "--quiet") {
            opt.quiet = true;
        } else if (arg == "--dry-run") {
            opt.dryRun = true;
        } else if (arg == "--debug-log" || arg == "--debug-log-file") {
            // 可选：--debug-log=路径；不带取值时用默认位置
            if (hasInlineValue) {
                opt.debugLogPath = inlineValue;
            }
        } else if (arg == "--no-debug-log") {
            opt.debugLog = false;
        } else {
            err = "无法识别的参数: " + args[i];
            return false;
        }
    }

    // ---- --loss <N> 的落地方向（必须在 --dir 解析完之后再决定）----------------
    // 规则：--loss 只作用于“会被接管的方向”：
    //   进程模式            -> dir 被忽略，两个方向都设
    //   端口模式 dir=inbound  -> 只设下行（另加 --dir both 才会连上行一起设）
    // 另外，显式给出的 --loss-up / --loss-down 优先级更高，不会被 --loss 覆盖。
    if (opt.lossBothSet) {
        const bool processMode = !opt.cfg.processName.empty();
        const bool dirHasIn  = processMode ||
                               opt.cfg.dir == Direction::Inbound  ||
                               opt.cfg.dir == Direction::Both;
        const bool dirHasOut = processMode ||
                               opt.cfg.dir == Direction::Outbound ||
                               opt.cfg.dir == Direction::Both;
        if (dirHasIn && !opt.lossDownSet)  { opt.cfg.lossDownPercent = opt.lossBothValue; }
        if (dirHasOut && !opt.lossUpSet)   { opt.cfg.lossUpPercent   = opt.lossBothValue; }
        // 记下 --loss 到底写进了哪些方向：下面第 ③ 条要靠它判断
        // "用户是不是真的没提过这个方向的丢包率"
        if (dirHasIn && !opt.lossDownSet)  { opt.lossGivenIn  = true; }
        if (dirHasOut && !opt.lossUpSet)   { opt.lossGivenOut = true; }
    }

    // ---- --rate <N> 的落地方向：与 --loss 完全同一套规则 ----------------------
    if (opt.rateBothSet) {
        const bool processMode = !opt.cfg.processName.empty();
        const bool dirHasIn  = processMode ||
                               opt.cfg.dir == Direction::Inbound  ||
                               opt.cfg.dir == Direction::Both;
        const bool dirHasOut = processMode ||
                               opt.cfg.dir == Direction::Outbound ||
                               opt.cfg.dir == Direction::Both;
        if (dirHasIn && !opt.rateDownSet)  { opt.cfg.rateDownBytesPerSec = opt.rateBothValue; }
        if (dirHasOut && !opt.rateUpSet)   { opt.cfg.rateUpBytesPerSec   = opt.rateBothValue; }
    }
    if (opt.rateLatencySet) {
        opt.cfg.rateMaxDelayMs = opt.rateLatencyMs;
    }

    // ---- ③ 限速隐含"这个方向不丢包" ------------------------------------------
    // 语义：用户给某个方向设了限速、又完全没提过这个方向的丢包率，
    // 那就认为他只想限速、不想丢包 —— 把该方向丢包率置 0（接管但不丢）。
    // 不这么做的话，`--rate-up 300B` 会落在"丢包率 100% + 限速"这个死组合上：
    // 报文被 100% 丢包全部拦下，限速器一个包都收不到，限速白设。
    //
    // 只对"用户完全没提过丢包率"的方向生效；显式写过 --loss / --loss-up /
    // --loss-down 的方向一律尊重用户的值（那种情况下 100% + 限速由
    // RateLossConflictWarning 去提醒）。
    if (opt.cfg.rateDownBytesPerSec > 0 && !opt.lossGivenIn && !opt.lossDownSet) {
        opt.cfg.lossDownPercent = 0;
        opt.rateImpliedZeroLossIn = true;
    }
    if (opt.cfg.rateUpBytesPerSec > 0 && !opt.lossGivenOut && !opt.lossUpSet) {
        opt.cfg.lossUpPercent = 0;
        opt.rateImpliedZeroLossOut = true;
    }

    // ---- ④ 方向是权威的（v2.0.7）---------------------------------------------
    // 用户反馈："我选择上行，但默认的下行 100 的丢包率没改成 0，那么下行也会丢。"
    //
    // 原因：**进程模式下引擎会忽略 dir**（为了保住"断网"时两方向都杀），
    // 所以"方向=上行 + 上行限速"实际会变成上行限速、**下行按默认 100% 全丢**。
    // 界面已经按同一规则处理了；这里把命令行补齐，两边语义一致。
    //
    // 只对"用户**显式**写了 --dir"生效，而且只动**用户没有显式配置过**的那个方向：
    //   * 不写 --dir          -> 不动（`--process X` 保持历史语义：整个进程断网）
    //   * 显式 --dir outbound -> 若用户没提过下行 -> 下行按"不接管"处理
    //   * 显式 --dir inbound  -> 若用户没提过上行 -> 上行按"不接管"处理
    if (opt.dirGiven) {
        if (opt.cfg.dir == weaknet::Direction::Outbound) {
            if (!opt.lossGivenIn && !opt.lossDownSet && !opt.rateDownSet && !opt.rateBothSet) {
                opt.cfg.lossDownPercent     = 0;
                opt.cfg.rateDownBytesPerSec = 0;
                opt.dirImpliedIdleDown = true;
            }
        } else if (opt.cfg.dir == weaknet::Direction::Inbound) {
            if (!opt.lossGivenOut && !opt.lossUpSet && !opt.rateUpSet && !opt.rateBothSet) {
                opt.cfg.lossUpPercent     = 0;
                opt.cfg.rateUpBytesPerSec = 0;
                opt.dirImpliedIdleUp = true;
            }
        }
    }
    if (!opt.showHelp && !opt.showVersion && opt.cfg.ports.empty() && !opt.cfg.allPorts &&
        opt.cfg.processName.empty()) {
        err = "缺少必填参数 --port（要丢包的端口；整体断网可用 --port all，"
              "按进程选择性丢包可用 --process chrome.exe）";
        return false;
    }

    // 丢包率 / 方向的语义检查（与 GUI 共用同一套规则，避免两边不一致）
    if (!opt.showHelp && !opt.showVersion) {
        std::string configError;
        if (!weaknet::ValidateConfig(opt.cfg, configError)) {
            err = configError;
            return false;
        }
    }
    return true;
}

// 把宽字符（UTF-16）转换成 UTF-8：MSVC 的 main() 会用 ANSI 代码页转换命令行，
// 路径含中文就会乱码；改用 wmain() 拿宽字符再自行转换。
std::string WideToUtf8(const wchar_t* text)
{
    if (text == NULL || *text == L'\0') {
        return std::string();
    }
    const int needed = WideCharToMultiByte(CP_UTF8, 0, text, -1, NULL, 0, NULL, NULL);
    if (needed <= 1) {
        return std::string();
    }
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, &out[0], needed, NULL, NULL);
    out.resize(static_cast<size_t>(needed - 1));
    return out;
}

// =============================================================================
//  权限检查
// =============================================================================

bool EnsureAdministrator()
{
    const Elevation state = weaknet::QueryElevation();
    if (state == Elevation::Elevated) {
        return true;
    }

    Print(Color::Red, "\n");
    Print(Color::Red, "############################################################\n");
    Print(Color::Red, "#                    !! 权限不足，无法运行 !!                 #\n");
    Print(Color::Red, "############################################################\n");
    Print(Color::Yellow, "\n  WinDivert 需要在内核里安装/加载过滤驱动，必须以管理员权限运行。\n\n");

    const std::string advice = weaknet::ElevationAdvice(state);
    Print(Color::White, "  %s\n", advice.c_str());

    Print(Color::Gray, "\n  提示：只想检查命令行与过滤器是否正确？可以用免管理员的诊断模式：\n");
    Print(Color::Gray, "        %s --port 8080 --dry-run\n\n", weaknet::kToolName);
    return false;
}

// =============================================================================
//  主流程
// =============================================================================

// 打印一次运行总结（热键模式下每次“联网”都会打一份）
void PrintSummary(const Session& session)
{
    const Stats stats = session.GetStats();
    const double totalSec = static_cast<double>(session.ElapsedMs()) / 1000.0;

    Print(Color::Default, "\n\n");
    Print(Color::Cyan, "======================== 运行总结 ========================\n");
    Print(Color::Default, "  运行时长     : %.1f s\n", totalSec);
    Print(Color::Default, "  已丢弃数据包 : %s 个\n", FormatCount(stats.packets).c_str());
    Print(Color::Default, "  已丢弃字节   : %.2f MiB\n",
          static_cast<double>(stats.bytes) / (1024.0 * 1024.0));
    Print(Color::Default, "  协议分布     : TCP %s / UDP %s / 其它 %s\n",
          FormatCount(stats.tcp).c_str(), FormatCount(stats.udp).c_str(),
          FormatCount(stats.other).c_str());
    if (session.IsProcessMode() || stats.forwarded > 0) {
        Print(Color::Default, "  已放行数据包 : %s 个 / %.2f MiB（命中但未被丢中，或未命中目标）\n",
              FormatCount(stats.forwarded).c_str(),
              static_cast<double>(stats.forwardedBytes) / (1024.0 * 1024.0));
    }

    // ---- 丢包率核对（v1.3.0）--------------------------------------------------
    // 只有当确实发生了“概率丢包”时才显示：否则会误导成“设置了丢包率”。
    // 展示 matched/dropped 两个数，用户自己除一下就能看出实际比例是否符合设置。
    if (stats.matchedDown > 0 || stats.matchedUp > 0) {
        const weaknet::Config cfg = session.GetConfig();
        if (weaknet::IsProbabilisticLoss(cfg)) {
            Print(Color::Cyan, "  ---- 实际丢包率核对（设置值 vs 实测）----\n");
            if (stats.matchedDown > 0) {
                const double actual =
                    100.0 * static_cast<double>(stats.droppedDown) /
                    static_cast<double>(stats.matchedDown);
                Print(Color::Default,
                      "  下行：设置 %u%%   实测 %.1f%%（命中 %s / 丢弃 %s）\n",
                      cfg.lossDownPercent, actual,
                      FormatCount(stats.matchedDown).c_str(),
                      FormatCount(stats.droppedDown).c_str());
            }
            if (stats.matchedUp > 0) {
                const double actual =
                    100.0 * static_cast<double>(stats.droppedUp) /
                    static_cast<double>(stats.matchedUp);
                Print(Color::Default,
                      "  上行：设置 %u%%   实测 %.1f%%（命中 %s / 丢弃 %s）\n",
                      cfg.lossUpPercent, actual,
                      FormatCount(stats.matchedUp).c_str(),
                      FormatCount(stats.droppedUp).c_str());
            }
            Print(Color::Gray,
                  "  说明：报文越多越接近设置值；样本太少时偏差大是正常的。\n");
        }
    }

    // ---- 限速核对（v1.5.0）----------------------------------------------------
    // 展示"设置值 vs 实测值（按总字节/总时长算）"，让用户能自己确认限速生效没有。
    if (stats.shapedDown > 0 || stats.shapedUp > 0) {
        const weaknet::Config cfg = session.GetConfig();
        Print(Color::Cyan, "  ---- 限速核对（设置值 vs 实测均值）----\n");

        const double downBps = (totalSec > 0.0)
            ? (static_cast<double>(stats.shapedBytesDown) / totalSec) : 0.0;
        const double upBps = (totalSec > 0.0)
            ? (static_cast<double>(stats.shapedBytesUp) / totalSec) : 0.0;

        if (stats.shapedDown > 0) {
            Print(Color::Default, "  下行：设置 %s   实测均值 %s（%s 个包 / %.2f MiB）\n",
                  weaknet::DescribeRate(cfg.rateDownBytesPerSec).c_str(),
                  weaknet::DescribeRate(static_cast<unsigned long long>(downBps + 0.5)).c_str(),
                  FormatCount(stats.shapedDown).c_str(),
                  static_cast<double>(stats.shapedBytesDown) / (1024.0 * 1024.0));
        }
        if (stats.shapedUp > 0) {
            Print(Color::Default, "  上行：设置 %s   实测均值 %s（%s 个包 / %.2f MiB）\n",
                  weaknet::DescribeRate(cfg.rateUpBytesPerSec).c_str(),
                  weaknet::DescribeRate(static_cast<unsigned long long>(upBps + 0.5)).c_str(),
                  FormatCount(stats.shapedUp).c_str(),
                  static_cast<double>(stats.shapedBytesUp) / (1024.0 * 1024.0));
        }
        Print(Color::Gray,
              "  说明：实测均值会低于设置值——只有当流量足够大、把令牌用满时才会顶到上限；\n");
        Print(Color::Gray,
              "        流量本来就比上限小的话，限速器根本不需要拦，这是正常的。\n");
    }
    if (stats.shapeDropped > 0) {
        Print(Color::Yellow,
              "  限速丢弃     : %s 个（限速队列排满或停止时清队列 —— 与丢包率无关）\n",
              FormatCount(stats.shapeDropped).c_str());
        if (stats.shapeLateDropped > 0) {
            Print(Color::Yellow,
                  "                 其中 %s 个是因为“排队会等太久”而主动丢的；\n",
                  FormatCount(stats.shapeLateDropped).c_str());
            Print(Color::Gray,
                  "                 速率越低这个比例越高（一个满包要攒几秒令牌），属正常现象。\n");
        }
    }

    if (totalSec > 0.0) {
        Print(Color::Default, "  平均速率     : %.1f pps\n",
              static_cast<double>(stats.packets) / totalSec);
    }
    Print(Color::Default, "  退出原因     : %s\n", weaknet::StopReasonText(session.GetStopReason()));
    Print(Color::Green, "  WinDivert    : 句柄已关闭，不再拦截任何报文，网络已恢复正常。\n");
    if (stats.packets == 0) {
        if (session.IsProcessMode()) {
            Print(Color::Yellow,
                  "  [提示] 本次运行没有丢弃任何报文。进程模式下常见原因：\n");
            Print(Color::Yellow, "         目标进程当时没有网络连接（端口集合为空 → 全部放行）；\n");
            Print(Color::Yellow, "         目标进程名写错（用任务管理器核对一下 .exe 名字）。\n");
        } else {
            Print(Color::Yellow,
                  "  [提示] 本次运行没有匹配到任何报文，请确认方向 / 匹配端 / 端口与实际流量一致：\n");
            Print(Color::Yellow, "         想丢“远端服务器 8080 的响应”用默认的 --match src；\n");
            Print(Color::Yellow, "         想丢“发往本机 8080 服务的请求”请加 --match dst；\n");
            Print(Color::Yellow, "         本机回环（同机跑客户端和服务端）只在出方向可见，需加 --dir outbound；\n");
            Print(Color::Yellow, "         想整体断网用 --port all（或 GUI 里勾选“全部端口”）。\n");
        }
    }
    Print(Color::Cyan, "==========================================================\n");
}

// 启动一次拦截并打印参数；失败返回 false
bool StartSession(Session& session, const Options& opt)
{
    const weaknet::StartResult started = session.Start(opt.cfg, ConsoleLog, NULL);
    if (!started.ok) {
        Print(Color::Red, "\n[错误] 启动失败：%s\n", started.message.c_str());
        Print(Color::Gray, "       可用 “%s --port <端口> --dry-run” 先校验过滤器本身是否正确。\n",
              weaknet::kToolName);
        return false;
    }

    Print(Color::Green, "\n[断网] 已进入黑洞模式，开始拦截。\n");
    Print(Color::Default, "  过滤器   : ");
    Print(Color::Cyan, "%s\n", session.FilterText().c_str());
    if (session.IsProcessMode()) {
        Print(Color::Default, "  目标进程 : %s\n", session.ProcessName().c_str());
        Print(Color::Default, "  端口刷新 : 每 %u ms 重新查询该进程占用的本地端口\n",
              opt.cfg.processRefreshMs);
    } else {
        Print(Color::Default, "  方向     : %s\n", weaknet::DirectionLabel(opt.cfg.dir));
        if (!opt.cfg.allPorts) {
            Print(Color::Default, "  端口匹配 : %s\n", weaknet::SideLabel(opt.cfg.side));
        } else {
            Print(Color::Default, "  端口范围 : 全部端口（整体断网）\n");
        }
    }
    Print(Color::Default, "  协议     : %s\n", weaknet::ProtocolLabel(opt.cfg.proto));
    if (opt.cfg.durationSec > 0) {
        Print(Color::Default, "  运行时长 : %ld 秒后自动停止\n", opt.cfg.durationSec);
    } else {
        Print(Color::Default, "  运行时长 : 不限制（按 Ctrl+C 优雅停止并恢复网络）\n");
    }
    if (session.IsProcessMode()) {
        Print(Color::Gray, "\n  命中目标进程端口的报文会被内核直接丢弃；\n");
        Print(Color::Gray, "  其余报文一律 WinDivertSend 原样放行，不影响其它进程上网。\n");
        Print(Color::Gray, "  停止本程序后网络立即恢复正常。\n\n");
    } else {
        Print(Color::Gray, "\n  命中过滤器的报文会被内核直接丢弃（既不回注也不转发）；\n");
        Print(Color::Gray, "  停止本程序后网络立即恢复正常。\n\n");
    }
    return true;
}

// 每秒刷新一次统计（即使一个包都没命中也能看出程序在跑）
void PrintStatsLine(const Session& session, ULONGLONG& lastTick, unsigned long long& lastPackets)
{
    const Stats stats = session.GetStats();
    const ULONGLONG now = GetTickCount64();

    const double elapsedSec = static_cast<double>(session.ElapsedMs()) / 1000.0;
    const double deltaSec   = static_cast<double>(now - lastTick) / 1000.0;
    const double instantPps = (deltaSec > 0.0)
                            ? (static_cast<double>(stats.packets - lastPackets) / deltaSec) : 0.0;

    char line[320] = { 0 };
    if (session.IsProcessMode()) {
        std::snprintf(line, sizeof(line),
                      "[统计] 运行 %6.1fs | 已丢弃 %s 包 / %.2f MiB | 已放行 %s 包 | 目标端口 %llu 个 | "
                      "当前 %8.1f pps",
                      elapsedSec, FormatCount(stats.packets).c_str(),
                      static_cast<double>(stats.bytes) / (1024.0 * 1024.0),
                      FormatCount(stats.forwarded).c_str(),
                      static_cast<unsigned long long>(stats.portCount), instantPps);
    } else {
        std::snprintf(line, sizeof(line),
                      "[统计] 运行 %6.1fs | 已丢弃 %s 包 / %.2f MiB | 当前 %8.1f pps | TCP %s / UDP %s",
                      elapsedSec, FormatCount(stats.packets).c_str(),
                      static_cast<double>(stats.bytes) / (1024.0 * 1024.0), instantPps,
                      FormatCount(stats.tcp).c_str(), FormatCount(stats.udp).c_str());
    }

    if (g_stdoutIsTty) {
        // 单行原地刷新：按显示宽度补齐空格，避免中文字符导致的残影
        std::string padded(line);
        const size_t width = VisualWidth(line);
        if (width < 110) {
            padded.append(110 - width, ' ');
        }
        Print(Color::Cyan, "\r%s", padded.c_str());
    } else {
        Print(Color::Cyan, "%s\n", line);
    }

    lastTick = now;
    lastPackets = stats.packets;
}

int RunTool(const Options& opt)
{
    Session session;
    const bool hotkeyMode = !opt.blockHotkey.empty() || !opt.unblockHotkey.empty();

    // 断网键与联网键完全相同 => 切换语义（第一下断网、第二下联网）
    const bool toggleMode = hotkeyMode && !opt.blockHotkey.empty() &&
                            opt.blockHotkey.vk == opt.unblockHotkey.vk &&
                            opt.blockHotkey.modifiers == opt.unblockHotkey.modifiers;

    // 是否用到了鼠标侧键（侧键在部分系统上 RegisterHotKey 无效，靠钩子通道）
    const bool usesMouseKey = hotkeyMode &&
        (weaknet::IsMouseHotkey(opt.blockHotkey.vk) ||
         weaknet::IsMouseHotkey(opt.unblockHotkey.vk));
    bool mouseHookReady = false;

    // ---- 注册全局快捷键（可选）------------------------------------------------
    if (hotkeyMode) {
        weaknet::DebugLogf("快捷键模式：toggle=%s 用到侧键=%s",
                           toggleMode ? "是（同一个键）" : "否",
                           usesMouseKey ? "是" : "否");
        Print(Color::Default, "\n[快捷键] 全局快捷键（进程运行期间一直有效，无需窗口在前台）：\n");

        // 鼠标侧键：只要用到就装上低级鼠标钩子（这条通道对侧键更可靠）
        if (usesMouseKey) {
            mouseHookReady = weaknet::SetMouseHotkeyListener(true);
            weaknet::DebugLogf("鼠标侧键钩子安装：%s", mouseHookReady ? "成功" : "失败");
            if (!mouseHookReady) {
                Print(Color::Red, "[错误] 鼠标侧键监听安装失败，无法把侧键当作快捷键。\n");
                return kExitRuntime;
            }
        }

        unsigned long errorCode = 0;
        bool blockOk = true;
        bool unblockOk = true;
        if (toggleMode) {
            // 两个键一样：只需要注册一个
            blockOk = weaknet::RegisterGlobalHotkey(NULL, kHotkeyIdToggle, opt.blockHotkey, errorCode);
            if (!blockOk && !weaknet::IsMouseHotkey(opt.blockHotkey.vk)) {
                Print(Color::Red, "[错误] 注册切换键 %s 失败（错误码 %lu）。\n",
                      weaknet::FormatHotkey(opt.blockHotkey).c_str(), errorCode);
                Print(Color::Gray, "       该组合可能已被别的程序占用，换一个再试。\n");
                return kExitRuntime;
            }
            Print(Color::Default, "  切换键   : ");
            Print(Color::White, "%s\n", weaknet::FormatHotkey(opt.blockHotkey).c_str());
            Print(Color::Gray, "             （断网与联网是同一个键：按一下断网、再按一下联网）\n");
        } else {
            if (!opt.blockHotkey.empty()) {
                blockOk = weaknet::RegisterGlobalHotkey(NULL, kHotkeyIdBlock, opt.blockHotkey, errorCode);
                if (!blockOk && !weaknet::IsMouseHotkey(opt.blockHotkey.vk)) {
                    Print(Color::Red, "[错误] 注册断网快捷键 %s 失败（错误码 %lu）。\n",
                          weaknet::FormatHotkey(opt.blockHotkey).c_str(), errorCode);
                    Print(Color::Gray, "       该组合可能已被别的程序占用，换一个再试。\n");
                    weaknet::SetMouseHotkeyListener(false);
                    return kExitRuntime;
                }
                Print(Color::Default, "  断网键   : ");
                Print(Color::White, "%s\n", weaknet::FormatHotkey(opt.blockHotkey).c_str());
            }
            if (!opt.unblockHotkey.empty()) {
                unblockOk = weaknet::RegisterGlobalHotkey(NULL, kHotkeyIdUnblock, opt.unblockHotkey, errorCode);
                if (!unblockOk && !weaknet::IsMouseHotkey(opt.unblockHotkey.vk)) {
                    Print(Color::Red, "[错误] 注册联网快捷键 %s 失败（错误码 %lu）。\n",
                          weaknet::FormatHotkey(opt.unblockHotkey).c_str(), errorCode);
                    if (!opt.blockHotkey.empty()) {
                        weaknet::UnregisterGlobalHotkey(NULL, kHotkeyIdBlock);
                    }
                    weaknet::SetMouseHotkeyListener(false);
                    return kExitRuntime;
                }
                Print(Color::Default, "  联网键   : ");
                Print(Color::White, "%s\n", weaknet::FormatHotkey(opt.unblockHotkey).c_str());
            }
        }

        if (usesMouseKey && (!blockOk || !unblockOk)) {
            Print(Color::Gray, "  说明     : 侧键交给鼠标钩子监听（系统热键对侧键支持不稳定），功能不受影响。\n");
        }
        Print(Color::Gray, "  提示：可以反复按快捷键切换断网/联网；Ctrl+C 退出程序。\n");
    }

    // ---- 启动第一次拦截 -------------------------------------------------------
    if (!StartSession(session, opt)) {
        if (hotkeyMode) {
            weaknet::UnregisterGlobalHotkey(NULL, kHotkeyIdBlock);
            weaknet::UnregisterGlobalHotkey(NULL, kHotkeyIdUnblock);
            weaknet::UnregisterGlobalHotkey(NULL, kHotkeyIdToggle);
            weaknet::SetMouseHotkeyListener(false);
        }
        return kExitRuntime;
    }

    bool dropping = true;
    ULONGLONG lastTick = GetTickCount64();
    unsigned long long lastPackets = 0;

    while (!weaknet::IsExitRequested()) {
        // ---- 收集本次要处理的热键 id（键盘消息 + 鼠标侧键钩子）----
        unsigned long hotkeyIds[8] = { 0 };
        size_t hotkeyCount = 0;
        unsigned long hotkeyId = 0;
        while (weaknet::PollHotkeyMessage(hotkeyId) && hotkeyCount < 8) {
            hotkeyIds[hotkeyCount++] = hotkeyId;
        }
        unsigned mouseVk = 0;
        while (weaknet::PollMouseHotkey(mouseVk) && hotkeyCount < 8) {
            if (toggleMode && mouseVk == opt.blockHotkey.vk) {
                hotkeyIds[hotkeyCount++] = static_cast<unsigned long>(kHotkeyIdToggle);
            } else if (mouseVk == opt.blockHotkey.vk) {
                hotkeyIds[hotkeyCount++] = static_cast<unsigned long>(kHotkeyIdBlock);
            } else if (mouseVk == opt.unblockHotkey.vk) {
                hotkeyIds[hotkeyCount++] = static_cast<unsigned long>(kHotkeyIdUnblock);
            }
        }

        for (size_t i = 0; i < hotkeyCount; ++i) {
            const unsigned long id = hotkeyIds[i];
            if (id == static_cast<unsigned long>(kHotkeyIdToggle)) {
                // 切换键：按当前状态取反
                if (dropping) {
                    weaknet::DebugLogf("切换键：第一下 -> 停止拦截（恢复联网）");
                    Print(Color::Yellow, "\n[联网] 切换键：正在停止拦截并恢复网络…\n");
                    session.Stop();
                    dropping = false;
                    PrintSummary(session);
                    Print(Color::Green, "  已恢复联网。再按一下切换键即可断网…（Ctrl+C 退出）\n");
                } else if (StartSession(session, opt)) {
                    weaknet::DebugLogf("切换键：第二下 -> 重新开始拦截（断网）");
                    dropping = true;
                    lastTick = GetTickCount64();
                    lastPackets = 0;
                }
                continue;
            }
            if (id == static_cast<unsigned long>(kHotkeyIdBlock)) {
                if (!dropping) {
                    weaknet::DebugLogf("收到断网快捷键 -> 开始拦截");
                    if (StartSession(session, opt)) {
                        dropping = true;
                        lastTick = GetTickCount64();
                        lastPackets = 0;
                    }
                }
            } else if (id == static_cast<unsigned long>(kHotkeyIdUnblock)) {
                if (dropping) {
                    weaknet::DebugLogf("收到联网快捷键 -> 停止拦截");
                    Print(Color::Yellow, "\n[联网] 收到快捷键，正在停止拦截并恢复网络…\n");
                    session.Stop();
                    dropping = false;
                    PrintSummary(session);
                    if (hotkeyMode) {
                        Print(Color::Green, "  已恢复联网。等待下一次断网快捷键…（Ctrl+C 退出）\n");
                    }
                }
            }
        }

        if (!dropping) {
            Sleep(150);                     // 待命状态：等快捷键
            continue;
        }

        // ---- 运行中：等 1 秒打印统计；会话结束则处理 ----
        if (session.WaitForStop(kPollIntervalMs)) {
            dropping = false;
            PrintSummary(session);
            if (!hotkeyMode || weaknet::IsExitRequested() ||
                session.GetStopReason() == weaknet::StopReason::Duration) {
                break;
            }
            Print(Color::Green, "  已停止拦截。等待下一次断网快捷键…（Ctrl+C 退出）\n");
            continue;
        }
        if (!opt.quiet) {
            PrintStatsLine(session, lastTick, lastPackets);
        }
    }

    if (dropping) {
        session.Stop();
        PrintSummary(session);
    }
    if (hotkeyMode) {
        weaknet::UnregisterGlobalHotkey(NULL, kHotkeyIdBlock);
        weaknet::UnregisterGlobalHotkey(NULL, kHotkeyIdUnblock);
        weaknet::UnregisterGlobalHotkey(NULL, kHotkeyIdToggle);
        weaknet::SetMouseHotkeyListener(false);
        weaknet::DebugLogf("已注销全局快捷键与鼠标侧键监听");
        Print(Color::Gray, "\n[快捷键] 已注销全局快捷键与鼠标侧键监听。\n");
    }
    return kExitOk;
}

}  // namespace

// =============================================================================
//  main
// =============================================================================

int wmain(int argc, wchar_t** argv)
{
    InitConsole();

    // 把宽字符命令行统一转成 UTF-8（args[0] 是程序路径，用于 Usage 回显）
    std::vector<std::string> args;
    std::string exePath = weaknet::kToolName;
    for (int i = 0; i < argc; ++i) {
        const std::string utf8 = WideToUtf8(argv[i]);
        if (i == 0) {
            if (!utf8.empty()) {
                exePath = utf8;
            }
            continue;
        }
        args.push_back(utf8);
    }

    // ---- 1. 解析命令行 -------------------------------------------------------
    Options opt;
    std::string err;
    if (!ParseArgs(args, opt, err)) {
        Print(Color::Red, "[参数错误] %s\n\n", err.c_str());
        PrintUsage(exePath.c_str());
        return kExitUsage;
    }

    // ---- 1.5 打开调试日志 ----------------------------------------------------
    // 尽早打开：后面每一步（过滤器校验、提权、开句柄、装钩子）出错或崩溃，
    // 都能在 weaknet_debug.log 里查到原因。默认开启，--no-debug-log 可关闭。
    if (opt.debugLog) {
        std::string logPath = opt.debugLogPath;
        if (logPath.empty()) {
            // 默认放在 exe 同目录，方便用户直接找到
            const size_t slash = exePath.find_last_of("\\/");
            logPath = (slash == std::string::npos)
                    ? std::string("weaknet_debug.log")
                    : exePath.substr(0, slash + 1) + "weaknet_debug.log";
        }
        std::string logError;
        if (weaknet::InitDebugLog(logPath.c_str(), true, logError)) {
            if (!opt.quiet) {
                Print(Color::Gray, "[调试日志] %s\n", weaknet::DebugLogPath().c_str());
            }
        } else {
            opt.debugLog = false;   // 打不开就静默降级，不能因为日志拦住主流程
            Print(Color::Yellow, "[调试日志] 无法启用：%s\n", logError.c_str());
        }
    }
    if (opt.debugLog) {
        weaknet::DebugLogf("命令行：%s", exePath.c_str());
        for (size_t i = 0; i < args.size(); ++i) {
            weaknet::DebugLogf("  参数[%llu] = %s",
                               static_cast<unsigned long long>(i), args[i].c_str());
        }
    }
    if (opt.showHelp) {
        PrintUsage(exePath.c_str());
        weaknet::ShutdownDebugLog();
        return kExitOk;
    }
    if (opt.showVersion) {
        Print(Color::Default, "%s v%s（WinDivert %llu.%llu）\n", weaknet::kToolName,
              weaknet::kToolVersion,
              static_cast<unsigned long long>(weaknet::kDriverMajor),
              static_cast<unsigned long long>(weaknet::kDriverMinor));
        weaknet::ShutdownDebugLog();
        return kExitOk;
    }

    // ---- 2. 构造并校验过滤器 -------------------------------------------------
    const std::string filter = weaknet::BuildFilter(opt.cfg);
    weaknet::DebugLogf("过滤器：%s", filter.c_str());
    std::string filterError;
    if (!weaknet::ValidateFilter(filter, filterError)) {
        weaknet::DebugLogf("过滤器校验失败：%s", filterError.c_str());
        Print(Color::Red, "[错误] %s\n", filterError.c_str());
        Print(Color::Red, "        过滤器: %s\n", filter.c_str());
        weaknet::ShutdownDebugLog();
        return kExitUsage;
    }
    weaknet::DebugLogf("过滤器校验通过");

    if (opt.dryRun) {
        Print(Color::Cyan, "[诊断模式] 过滤器已通过编译校验（未真正开始拦截）。\n");
        Print(Color::Default, "  过滤器 : ");
        Print(Color::White, "%s\n", filter.c_str());
        if (!opt.cfg.processName.empty()) {
            // 进程模式：顺手做一次“进程名 -> PID -> 端口集合”的解析演示（免管理员）
            Print(Color::Default, "  进程   : %s\n", opt.cfg.processName.c_str());
            Print(Color::Default, "  刷新   : 每 %u ms\n", opt.cfg.processRefreshMs);

            std::unordered_set<uint16_t> ports;
            std::vector<unsigned long>   pids;
            std::string                  resolveError;
            weaknet::CollectProcessLocalPorts(opt.cfg.processName, ports, pids, resolveError);
            if (pids.empty()) {
                Print(Color::Yellow, "  解析   : 没有找到该进程（%s）\n", resolveError.c_str());
            } else {
                std::string pidText;
                for (size_t i = 0; i < pids.size(); ++i) {
                    char buf[32] = { 0 };
                    std::snprintf(buf, sizeof(buf), "%s%lu", (i == 0 ? "" : ", "), pids[i]);
                    pidText += buf;
                }
                Print(Color::Default, "  PID    : %s\n", pidText.c_str());
                Print(Color::Default, "  端口   : %llu 个\n",
                      static_cast<unsigned long long>(ports.size()));

                std::vector<unsigned short> sortedPorts(ports.begin(), ports.end());
                std::sort(sortedPorts.begin(), sortedPorts.end());
                std::string portText;
                for (size_t i = 0; i < sortedPorts.size() && i < 32; ++i) {
                    char buf[16] = { 0 };
                    std::snprintf(buf, sizeof(buf), "%s%u", (i == 0 ? "" : ", "),
                                  static_cast<unsigned>(sortedPorts[i]));
                    portText += buf;
                }
                if (sortedPorts.size() > 32) { portText += ", ..."; }
                if (!portText.empty()) {
                    Print(Color::Gray, "           %s\n", portText.c_str());
                } else {
                    Print(Color::Yellow,
                          "           （该进程当前没有 TCP/UDP 连接 → 暂时不会丢任何包）\n");
                }

                weaknet::PortTableStats tableStats;
                if (weaknet::QueryPortTableStats(pids, tableStats)) {
                    Print(Color::Gray,
                          "           连接表：TCP4 %llu / TCP6 %llu / UDP4 %llu / UDP6 %llu 条，"
                          "其中命中目标 PID %llu 个\n",
                          tableStats.tcp4Entries, tableStats.tcp6Entries,
                          tableStats.udp4Entries, tableStats.udp6Entries,
                          tableStats.matchedPids);
                }
            }
        } else {
            Print(Color::Default, "  方向   : %s\n", weaknet::DirectionLabel(opt.cfg.dir));
            Print(Color::Default, "  端口   : %s\n", weaknet::SideLabel(opt.cfg.side));
        }
        Print(Color::Default, "  协议   : %s\n", weaknet::ProtocolLabel(opt.cfg.proto));

        // ---- 丢包率（v1.3.0）--------------------------------------------------
        //  这里必须把“设置值”和“是否真的生效”分开显示：某个方向若不在 --dir 里，
        //  它的丢包率是不会生效的（ValidateConfig 已挡住主要矛盾，这里再讲清实际行为）。
        {
            const bool processMode = !opt.cfg.processName.empty();

            char line[256] = { 0 };
            if (processMode) {
                std::snprintf(line, sizeof(line),
                              "  丢包率 : 下行 %u%% / 上行 %u%%"
                              "（进程模式下 --dir 不参与判断，只看丢包率是否为 0）",
                              opt.cfg.lossDownPercent, opt.cfg.lossUpPercent);
            } else {
                std::snprintf(line, sizeof(line),
                              "  丢包率 : 下行 %u%% / 上行 %u%%",
                              opt.cfg.lossDownPercent, opt.cfg.lossUpPercent);
            }
            Print(Color::Default, "%s\n", line);

            // 分别说明两个方向最终会不会被接管。
            // 这里必须调引擎里的那一份判断（DirectionIntercepted）——
            // v1.7.1 之前 main.cpp 自己又写了一遍"丢包率!=0 就算接管"，
            // 加了限速之后两边就会对不上。
            Print(Color::Gray, "           下行：%s    上行：%s\n",
                  weaknet::DirectionIntercepted(opt.cfg, false)
                      ? "接管" : "不接管（原样通过）",
                  weaknet::DirectionIntercepted(opt.cfg, true)
                      ? "接管" : "不接管（原样通过）");

            if (weaknet::IsProbabilisticLoss(opt.cfg)) {
                Print(Color::Yellow,
                      "           注意：概率丢包需要把命中的报文逐一回注，"
                      "高带宽下 CPU 占用会明显上升。\n");
            }
        }

        // ---- 限速（v1.5.0）----------------------------------------------------
        {
            const bool processMode = !opt.cfg.processName.empty();
            const bool dirIn  = (opt.cfg.dir == weaknet::Direction::Inbound  ||
                                 opt.cfg.dir == weaknet::Direction::Both);
            const bool dirOut = (opt.cfg.dir == weaknet::Direction::Outbound ||
                                 opt.cfg.dir == weaknet::Direction::Both);

            Print(Color::Default, "  限速   : 下行 %s / 上行 %s\n",
                  weaknet::DescribeRate(opt.cfg.rateDownBytesPerSec).c_str(),
                  weaknet::DescribeRate(opt.cfg.rateUpBytesPerSec).c_str());

            if (weaknet::IsShapingEnabled(opt.cfg)) {
                const bool inHandled  = processMode || dirIn;
                const bool outHandled = processMode || dirOut;
                if ((opt.cfg.rateDownBytesPerSec > 0 && !inHandled) ||
                    (opt.cfg.rateUpBytesPerSec > 0 && !outHandled)) {
                    Print(Color::Yellow,
                          "           注意：有方向的限速值设了、但该方向不被 --dir 覆盖，"
                          "不会生效。\n");
                }

                // ③ 说明"限速顺带把该方向丢包率置 0 了"，免得用户以为是程序改了配置
                // v2.0.7：显式选了单一方向 -> 另一个方向被自动忽略，必须告诉用户，
    // 否则他会以为"我设的下行丢包率生效了"。
    if (opt.dirImpliedIdleDown) {
        Print(Color::Gray, "  提示：方向选了 outbound（上行），且你没配过下行 —— "
                           "下行已按「不接管」处理（丢包率/限速都置 0）。\n");
        Print(Color::Gray, "        要同时影响下行请用 --dir both。\n");
    }
    if (opt.dirImpliedIdleUp) {
        Print(Color::Gray, "  提示：方向选了 inbound（下行），且你没配过上行 —— "
                           "上行已按「不接管」处理（丢包率/限速都置 0）。\n");
        Print(Color::Gray, "        要同时影响上行请用 --dir both。\n");
    }

    if (opt.rateImpliedZeroLossIn || opt.rateImpliedZeroLossOut) {
                    Print(Color::Gray,
                          "           说明：你只给了限速、没提丢包率，已把%s的丢包率按 0 处理\n",
                          (opt.rateImpliedZeroLossIn && opt.rateImpliedZeroLossOut)
                              ? "上下行"
                              : (opt.rateImpliedZeroLossIn ? "下行" : "上行"));
                    Print(Color::Gray,
                          "                 （接管但不丢包 = 纯限速）；要叠加丢包请显式写 --loss-*。\n");
                }

                // 「--dir both 却只限了一个方向」这个坑：另一个方向会按**默认的
                // 100% 丢包**处理，也就是把那个方向直接黑洞掉 —— 不说一声很容易懵。
                // 只在"那个方向的丢包率是用户没提过、走了默认值"时才提醒：
                // 如果用户显式写了 --loss-down 100，那是他自己的选择，不该再唠叨。
                if (dirIn && dirOut) {
                    const bool downNotAsked = !opt.lossGivenIn && !opt.lossDownSet;
                    const bool upNotAsked   = !opt.lossGivenOut && !opt.lossUpSet;
                    const bool downSilentBlackhole =
                        (downNotAsked && opt.cfg.rateDownBytesPerSec == 0 &&
                         opt.cfg.lossDownPercent >= 100);
                    const bool upSilentBlackhole =
                        (upNotAsked && opt.cfg.rateUpBytesPerSec == 0 &&
                         opt.cfg.lossUpPercent >= 100);
                    if (downSilentBlackhole && opt.cfg.rateUpBytesPerSec > 0) {
                        Print(Color::Yellow,
                              "           注意：--dir both 下你只限了上行，下行仍按默认的"
                              "「丢包率 100%%」处理 ——\n");
                        Print(Color::Yellow,
                              "                 也就是**下载会被完全断掉**。只限上行请用 "
                              "--dir outbound，\n");
                        Print(Color::Yellow,
                              "                 或显式写 --loss-down 0 表示下行不丢包。\n");
                    } else if (upSilentBlackhole && opt.cfg.rateDownBytesPerSec > 0) {
                        Print(Color::Yellow,
                              "           注意：--dir both 下你只限了下行，上行仍按默认的"
                              "「丢包率 100%%」处理 ——\n");
                        Print(Color::Yellow,
                              "                 也就是**上传会被完全断掉**。只限下行请用 "
                              "--dir inbound，\n");
                        Print(Color::Yellow,
                              "                 或显式写 --loss-up 0 表示上行不丢包。\n");
                    }
                }

                // 「丢包率 100% + 限速」自相矛盾（除非上面已经提示过同类问题）
                {
                    const std::string conflict = weaknet::RateLossConflictWarning(opt.cfg);
                    if (!conflict.empty()) {
                        Print(Color::Yellow, "           注意：%s\n", conflict.c_str());
                    }
                }

                // 把自动算出来的排队上限摊开给用户看：这是低速率最容易踩的坑
                if (opt.cfg.rateDownBytesPerSec > 0) {
                    const unsigned effMs = (opt.cfg.rateMaxDelayMs > 0)
                        ? opt.cfg.rateMaxDelayMs
                        : weaknet::AutoMaxShapeDelayMs(opt.cfg.rateDownBytesPerSec);
                    Print(Color::Gray,
                          "           下行队列：最多排 %u ms（%s）\n",
                          effMs,
                          opt.cfg.rateMaxDelayMs > 0
                              ? "手动指定"
                              : "自动，按速率算，约 3 个满包的时间");
                }
                if (opt.cfg.rateUpBytesPerSec > 0) {
                    const unsigned effMs = (opt.cfg.rateMaxDelayMs > 0)
                        ? opt.cfg.rateMaxDelayMs
                        : weaknet::AutoMaxShapeDelayMs(opt.cfg.rateUpBytesPerSec);
                    Print(Color::Gray,
                          "           上行队列：最多排 %u ms（%s）\n",
                          effMs,
                          opt.cfg.rateMaxDelayMs > 0
                              ? "手动指定"
                              : "自动，按速率算，约 3 个满包的时间");
                }
                Print(Color::Gray,
                      "           提示：低速率下“一个满包要攒很久令牌”（300 B/s 要 5 秒），\n");
                Print(Color::Gray,
                      "                 TCP 的重传超时只有秒级——所以低速限速会让 TCP 连接卡死甚至断开，\n");
                Print(Color::Gray,
                      "                 这是物理事实而非工具缺陷；UDP 或小包交互型流量不受此限。\n");
            }
        }

        Print(Color::Gray, "\n  去掉 --dry-run 即可在管理员权限下真正开始丢包。\n");
        weaknet::DebugLogf("诊断模式结束（未真正拦截）");
        weaknet::ShutdownDebugLog();
        return kExitOk;
    }

    // ---- 3. 权限检查 ---------------------------------------------------------
    if (!EnsureAdministrator()) {
        weaknet::DebugLogf("权限检查未通过：当前进程没有管理员权限");
        weaknet::ShutdownDebugLog();
        return kExitNoAdmin;
    }
    weaknet::DebugLogf("权限检查通过：已是管理员");

    // ---- 4. 运行 -------------------------------------------------------------
    const int exitCode = RunTool(opt);
    weaknet::DebugLogf("进程退出：exitCode=%d", exitCode);
    weaknet::ShutdownDebugLog();
    return exitCode;
}
