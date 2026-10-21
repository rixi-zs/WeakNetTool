// =============================================================================
//  WeakNetTool GUI —— 同一引擎的图形界面（Win32 原生控件，无第三方依赖）
// -----------------------------------------------------------------------------
//  设计原则：
//    * 界面只负责“取参数 / 显示状态 / 显示日志 / 响应快捷键”，真正的丢包逻辑全部在
//      weaknet_core.cpp 里，与命令行版共用同一份实现（包括那个很关键的
//      “关句柄唤醒阻塞 recv”的优雅停止机制）。
//    * 引擎通过 LogFn 回调把日志丢进来，回调可能来自引擎线程，因此这里只把它塞进
//      一个带锁的队列；由 UI 定时器（400ms）取走并显示，绝不跨线程直接操作控件。
//    * 全局快捷键：断网 / 联网各一个，可自定义、可关闭，配置写在与 exe 同目录的
//      WeakNetTool.ini 里；用 RegisterHotKey 注册，所以窗口不在前台也有效。
//    * exe 通过清单请求管理员权限（CMake 里 /MANIFESTUAC:requireAdministrator），
//      另外保留一个运行期自检 + “以管理员身份重新启动”的兜底。
// =============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <commctrl.h>      // ListView / InitCommonControlsEx（v1.4.0 进程选择器）
#include <shellapi.h>

#include <cstdio>
#include <cstring>
#include <cwchar>
#include <map>
#include <algorithm>
#include <string>
#include <unordered_set>
#include <vector>

#include "weaknet_core.h"

namespace {

#ifdef WEAKNET_GUI_TEST_HOOKS
std::wstring g_testIniPath;
#endif

using weaknet::Config;
using weaknet::Direction;
using weaknet::FormatCount;
using weaknet::HotkeySpec;
using weaknet::LogLevel;
using weaknet::PortSide;
using weaknet::Protocol;
using weaknet::Session;
using weaknet::Stats;

// -----------------------------------------------------------------------------
//  控件 ID
// -----------------------------------------------------------------------------
enum ControlId {
    IDC_LBL_PORT = 1000, IDC_EDIT_PORT, IDC_CHK_ALLPORTS, IDC_LBL_DURATION, IDC_EDIT_DURATION,
    IDC_CHK_VERBOSE,
    // v1.2.0：第一种“丢什么”的目标 —— 按进程名（与 端口 / 全部端口 三选一）
    IDC_RADIO_BYPROCESS, IDC_LBL_PROCESS, IDC_EDIT_PROCESS, IDC_LBL_PROCESS_HINT, IDC_LBL_PROCESS_STATE,
    // v1.7.0：把“按端口”也做成显式单选项（原来靠“另外两个都没勾”隐含表达，很难懂）
    IDC_RADIO_BYPORT,
    // v1.4.0：从正在运行的程序里挑一个，省得手输进程名
    IDC_BTN_BROWSE_PROCESS,
    IDC_LBL_DIR, IDC_COMBO_DIR, IDC_LBL_MATCH, IDC_COMBO_MATCH,
    IDC_LBL_PROTO, IDC_COMBO_PROTO,
    // v1.3.0：按方向分别设置的丢包率；v1.5.0：按方向分别设置的限速（同一行）
    IDC_LBL_LOSS, IDC_EDIT_LOSS_DOWN, IDC_EDIT_LOSS_UP, IDC_LBL_LOSS_HINT,
    IDC_LBL_RATE, IDC_EDIT_RATE_DOWN, IDC_EDIT_RATE_UP,
    // v2.0.11：速率单位下拉（B/s / KB/s / MB/s）—— 不用再手敲 K / MB
    IDC_COMBO_RATE_UNIT_DOWN, IDC_COMBO_RATE_UNIT_UP,
    IDC_LBL_FILTER, IDC_EDIT_FILTER, IDC_LBL_SHAPE_WARN,
    IDC_GRP_HOTKEY, IDC_CHK_HOTKEY, IDC_LBL_HOTKEY_BLOCK, IDC_HOTKEY_BLOCK, IDC_BTN_SET_BLOCK,
    IDC_LBL_HOTKEY_UNBLOCK, IDC_HOTKEY_UNBLOCK, IDC_BTN_SET_UNBLOCK, IDC_LBL_HOTKEY_HINT,
    IDC_LBL_HOTKEY_STATUS,
    IDC_BTN_START, IDC_BTN_STOP, IDC_LBL_STATUS, IDC_LBL_STATS,
    IDC_LBL_TOGGLE_HINT,
    IDC_EDIT_LOG, IDC_LBL_HINT,
    // v1.7.0：仿 NetLimiter 的排版 —— 标签页 / 状态栏 / 菜单
    IDC_TABS, IDC_STATUS_BAR,
    // v2.0.0：活动页（仿 NetLimiter 主视图）
    IDC_LIST_APPRATE, IDC_LBL_APPRATE_STATUS, IDC_LBL_APPRATE_HINT,
    IDC_CHK_ACTIVITY_FILTER, IDC_EDIT_ACTIVITY_SEARCH, IDC_COMBO_ACTIVITY_UNIT,
    IDC_LBL_INFO_CAPTION, IDC_LBL_INFO_PATH, IDC_LIST_INFO_PROPS, IDC_LIST_INFO_RULES
};

// 菜单命令 ID（v1.7.0）
enum MenuId {
    IDM_EXIT = 40001,
    IDM_OPEN_LOG,
    IDM_OPEN_FOLDER,
    IDM_HELP_README,
    IDM_HELP_ABOUT
};

// “丢什么”的三种目标（三选一）
enum class TargetMode {
    ByPort = 0,      // 按端口列表
    AllPorts = 1,    // 全部端口（整体断网）
    ByProcess = 2    // 按进程名（v1.2.0）
};

const UINT_PTR kTimerId = 1;
const UINT     kTimerIntervalMs = 400;

const int kHotkeyIdBlock   = 1;     // 断网
const int kHotkeyIdUnblock = 2;     // 联网
const int kHotkeyIdToggle  = 3;     // 断网/联网绑成同一个键时的切换键

// -----------------------------------------------------------------------------
//  全局状态
// -----------------------------------------------------------------------------
HINSTANCE g_instance = NULL;
// 客户区目标尺寸（逻辑像素）。**只有这一份来源**：布局计算和窗口创建都用它。
const int kClientW = 1100;   // v2.0.0：左右分栏要更宽（按当前屏幕工作区 1707x1019 实测收的）
const int kClientH = 610;

HWND      g_mainWindow = NULL;
HWND      g_hPort = NULL, g_hAllPorts = NULL, g_hDuration = NULL, g_hVerbose = NULL;
// v1.2.0：按进程名丢包（与 g_hPort / g_hAllPorts 三选一）
HWND      g_hRadioByProcess = NULL, g_hProcess = NULL, g_hProcessState = NULL;
// v1.7.0：三个目标改成同一组单选按钮，"按端口"也需要自己的句柄
HWND      g_hRadioByPort = NULL;
// v1.4.0：进程选择器按钮
HWND      g_hBrowseProcess = NULL;
HWND      g_hDir = NULL, g_hMatch = NULL, g_hProto = NULL;
// v1.3.0：丢包率（上行 / 下行分别设置）
HWND      g_hLossDown = NULL, g_hLossUp = NULL, g_hLossHint = NULL;
// v1.5.0：限速（上行 / 下行分别设置，KB/s，0 = 不限）
HWND      g_hRateUnitDown = NULL, g_hRateUnitUp = NULL;   // v2.0.11 速率单位下拉
HWND      g_hRateDown = NULL, g_hRateUp = NULL;
HWND      g_hFilter = NULL;
// v1.7.1：过滤器预览下方的"配置矛盾"提示行（正常时为空）
HWND      g_hShapeWarn = NULL;
HWND      g_hHotkeyEnabled = NULL, g_hHotkeyBlock = NULL, g_hHotkeyUnblock = NULL;
HWND      g_hBtnSetBlock = NULL, g_hBtnSetUnblock = NULL;
HWND      g_hHotkeyStatus = NULL;     // 热键区的状态自检文本（“当前/捕获中”）
HWND      g_hStart = NULL, g_hStop = NULL;
HWND      g_hStatus = NULL, g_hStats = NULL, g_hLog = NULL;
HFONT     g_font = NULL;

// ---- v1.7.0：仿 NetLimiter 的骨架（标签页 + 状态栏 + 菜单）--------------------
// 为什么改成标签页：原来所有东西挤在一列，客户区高达 650（150% DPI 下窗口 1031px），
// 在 1080p 屏幕上根本放不下，而且日志框空着也占 240px。改成标签页后客户区降到 570。
HWND      g_hTabs = NULL;             // 标签控件
HWND      g_hStatusBar = NULL;        // 底部状态栏（原生 STATUSCLASSNAME）
bool      g_tabPagesReady = false;    // 三个页面的控件是否都已建好

// 每个标签页的控件列表：切页时按页显示/隐藏。
// 用固定 3 个 vector（不引 std::array，保持和项目其它地方一致的写法）。
std::vector<HWND> g_pageControls[4];   // v2.0.0：新增「应用速率」页
int       g_buildingPage = 0;         // 正在建哪个页面的控件（TabCtl 会往这里记）
int       g_tabOriginX = 0;           // 标签页内容区左上角（父窗口坐标）
int       g_tabOriginY = 0;

// 状态栏两格：左格放状态文本，右格放统计
const int kStatusPaneCount = 2;

// v2.0.0：活动页（仿 NetLimiter 主视图）
HWND      g_hAppRateList = NULL;      // 左侧应用列表
HWND      g_hAppRateStatus = NULL;    // 监控状态/错误提示
HWND      g_hActivityFilter = NULL;   // 只显示有流量的
HWND      g_hActivitySearch = NULL;   // 搜索框
HWND      g_hActivityUnit = NULL;     // 单位（自动/B/s/KB/s/MB/s）
HWND      g_hInfoPath = NULL;         // 右侧：选中应用的完整路径
HWND      g_hInfoProps = NULL;        // 右侧：应用属性表
HWND      g_hInfoRules = NULL;        // 右侧：规则表
HIMAGELIST g_appIconList = NULL;      // 应用图标（从 exe 提取）
std::map<std::string, int> g_exeIconIndex;   // exe 路径 -> 图标索引（同一程序共用一个图标）
unsigned long long g_appRateLastRefresh = 0;   // 上次刷新时间（限制到 ~1 秒一次）

// 活动页排序（v2.0.1）
// 为什么要有这个：速率每秒都在变，**按速率排序会让行到处跳，根本点不中**。
// 所以默认按名称排（顺序完全稳定），用户点列头才按那一列排；
// 而且按速率列排序时，"重排"节流到 3 秒一次 —— 数字照常每秒更新，只是不换位置。
int  g_activitySortColumn = 0;      // 0=名称 1=下载速度 2=上传速度 3=累计下行 4=累计上行
bool g_activitySortDesc   = false;
unsigned long long g_activityLastResort = 0;
std::vector<unsigned long> g_activityOrder;   // 上次显示顺序（PID），不重排时按它保持原位
bool g_activityResortNow = false;             // 用户刚点了列头：下次刷新强制重排

Session   g_session;
bool      g_running = false;
int       g_dpi = 96;                 // 用于按 DPI 缩放布局

// 用户最后一次选择的“丢什么”目标。用来实现三选一：切换目标时把另一方的
// 输入框内容清掉，避免出现“勾了全部端口但端口框里还留着 8080”这种歧义状态。
TargetMode g_targetMode = TargetMode::AllPorts;

// 本次（或最近一次）会话生效的端口刷新周期，仅用于状态行显示
unsigned g_sessionRefreshMs = weaknet::kDefaultProcessRefreshMs;

// 程序化改写控件内容（加载配置、切换目标模式时清空另一方）期间置 true，
// 用来屏蔽由此产生的 EN_CHANGE/BN_CLICKED 副作用，避免“设置值 -> 触发事件 ->
// 又反过来改设置值”的回环。
bool g_uiSyncing = false;

// 调试日志开关：默认打开（写 exe 同目录的 weaknet_debug.log）。
// 崩溃 / 卡死时这是唯一能事后查原因的线索，所以界面上默认就开。
bool g_debugLogWanted = true;

void UpdateProcessStateLabel();

HotkeySpec g_blockHotkey;             // 断网快捷键
HotkeySpec g_unblockHotkey;           // 联网快捷键
bool       g_hotkeyEnabled = true;
int        g_capturing = 0;           // 0=未捕获；1=正在设置断网键；2=正在设置联网键
bool       g_captureBusy = false;     // 防重入闸门：正在处理一个捕获到的按键
int        g_captureRejects = 0;      // 本次捕获里被拒绝的按键次数（仅用于提示/自检）
int        g_captureLastReject = -1;  // 上次被拒的 vk（按住不放时只提示一次）
// 捕获期间是否把全局热键临时注销了（见 StartCapture 的说明）。
// 注销是为了让按键能作为 WM_KEYDOWN 到达窗口；捕获结束后必须恢复注册。
bool       g_hotkeysSuspended = false;
// 每个热键 id 的注册方式：0=未注册，1=RegisterHotKey 成功（走 WM_HOTKEY/WM_XBUTTON），
// 2=只装上了鼠标钩子（走 PollMouseHotkey）。
// 侧键的去重就靠它：同一个侧键只允许一条通道处理，否则“切换键”会被按一下当成两下。
int        g_hotkeyRegistered[4] = { 0, 0, 0, 0 };

const int kHotkeyViaNone = 0;
const int kHotkeyViaRegister = 1;
const int kHotkeyViaHook = 2;

// 引擎日志队列（引擎线程写、UI 线程读）
CRITICAL_SECTION         g_logLock;
bool                     g_logLockReady = false;
std::vector<std::string> g_pendingLog;
const size_t             kMaxPendingLog = 4000;

// -----------------------------------------------------------------------------
//  调试日志：weaknet_debug.log（引擎与界面共用同一套落盘函数）
// -----------------------------------------------------------------------------

void GuiLog(LogLevel level, const char* text, void* user);   // 前置声明，见下方定义

// 日志文件放在 exe 同目录，方便用户直接找到并发给我们排查。
// 返回 UTF-8 编码的完整路径；取不到时退回相对文件名。
// 注意用宽字符接口：程序放在中文目录（如“桌面\弱网工具”）下时，
// GetModuleFileNameA 会因 ANSI 代码页拿到乱码，日志就打不开了。
std::string DebugLogFilePath()
{
    wchar_t widePath[MAX_PATH] = { 0 };
    const DWORD written = GetModuleFileNameW(NULL, widePath, MAX_PATH);
    if (written == 0 || written >= MAX_PATH) {
        return std::string("weaknet_debug.log");
    }

    char utf8Path[MAX_PATH * 4] = { 0 };
    if (WideCharToMultiByte(CP_UTF8, 0, widePath, -1, utf8Path,
                            sizeof(utf8Path) - 1, NULL, NULL) <= 0) {
        return std::string("weaknet_debug.log");
    }

    std::string path(utf8Path);
    const size_t slash = path.find_last_of("\\/");
    if (slash == std::string::npos) {
        return std::string("weaknet_debug.log");
    }
    return path.substr(0, slash + 1) + "weaknet_debug.log";
}

// 启动日志。失败不弹窗（写不了日志不该拦住用户用工具），只在界面日志里提示。
void StartDebugLog()
{
    if (!g_debugLogWanted) {
        return;
    }
    std::string error;
    if (weaknet::InitDebugLog(DebugLogFilePath().c_str(), true, error)) {
        GuiLog(LogLevel::Info, ("调试日志：" + weaknet::DebugLogPath()).c_str(), NULL);
    } else {
        GuiLog(LogLevel::Warning, ("调试日志无法启用：" + error).c_str(), NULL);
    }
}

// -----------------------------------------------------------------------------
//  小工具
// -----------------------------------------------------------------------------
int S(int value)     // 按当前 DPI 缩放一个像素值
{
    return MulDiv(value, g_dpi, 96);
}

std::wstring Utf8ToWide(const char* text)
{
    if (text == NULL || *text == '\0') {
        return std::wstring();
    }
    const int needed = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
    if (needed <= 1) {
        return std::wstring();
    }
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text, -1, &out[0], needed);
    out.resize(static_cast<size_t>(needed - 1));
    return out;
}

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

std::wstring GetWideText(HWND control)
{
    const int len = GetWindowTextLengthW(control);
    if (len <= 0) {
        return std::wstring();
    }
    std::wstring text(static_cast<size_t>(len) + 1, L'\0');
    GetWindowTextW(control, &text[0], len + 1);
    text.resize(static_cast<size_t>(len));
    return text;
}

std::string GetUtf8Text(HWND control)
{
    return WideToUtf8(GetWideText(control).c_str());
}

bool IsChecked(HWND control)
{
    return SendMessageW(control, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

void SetChecked(HWND control, bool checked)
{
    SendMessageW(control, BM_SETCHECK, checked ? BST_CHECKED : BST_UNCHECKED, 0);
}

// -----------------------------------------------------------------------------
//  配置文件（与 exe 同目录的 WeakNetTool.ini）
// -----------------------------------------------------------------------------
std::wstring IniPath()
{
#ifdef WEAKNET_GUI_TEST_HOOKS
    if (!g_testIniPath.empty()) { return g_testIniPath; }
#endif
    wchar_t exePath[MAX_PATH] = { 0 };
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) {
        return L"WeakNetTool.ini";
    }
    std::wstring path(exePath);
    const size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return L"WeakNetTool.ini";
    }
    return path.substr(0, pos + 1) + L"WeakNetTool.ini";
}

int IniReadInt(const wchar_t* section, const wchar_t* key, int defaultValue)
{
    return static_cast<int>(GetPrivateProfileIntW(section, key, defaultValue, IniPath().c_str()));
}

std::wstring IniReadString(const wchar_t* section, const wchar_t* key, const wchar_t* defaultValue)
{
    wchar_t buffer[256] = { 0 };
    GetPrivateProfileStringW(section, key, defaultValue, buffer,
                             static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])),
                             IniPath().c_str());
    return buffer;
}

void IniWriteInt(const wchar_t* section, const wchar_t* key, int value)
{
    wchar_t buffer[32] = { 0 };
    _snwprintf_s(buffer, sizeof(buffer) / sizeof(buffer[0]), _TRUNCATE, L"%d", value);
    WritePrivateProfileStringW(section, key, buffer, IniPath().c_str());
}

void IniWriteString(const wchar_t* section, const wchar_t* key, const std::wstring& value)
{
    WritePrivateProfileStringW(section, key, value.c_str(), IniPath().c_str());
}

// -----------------------------------------------------------------------------
//  控件创建
// -----------------------------------------------------------------------------
// 直接按**物理像素**建控件，不做 DPI 缩放。
// 标签页内容需要一个"混合"坐标：原点已经是物理像素（TCM_ADJUSTRECT 量出来的），
// 页内偏移才是逻辑值。若把两者相加后再交给 MakeControlIn，原点会被二次缩放。
HWND MakeControlPx(HWND parent, const wchar_t* className, const wchar_t* text,
                   DWORD style, int px, int py, int pw, int ph, int id)
{
    HWND control = CreateWindowExW(
        0, className, text,
        WS_CHILD | WS_VISIBLE | style,
        px, py, pw, ph,
        parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        g_instance, NULL);
    if (control != NULL && g_font != NULL) {
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g_font), TRUE);
    }
    return control;
}

// 在指定父窗口下建控件。MakeControl() 是它的常用包装（父窗口固定为主窗口）；
// 进程选择器需要把控件建在自己的弹出窗口里，所以单独要这一个版本。
HWND MakeControlIn(HWND parent, const wchar_t* className, const wchar_t* text,
                   DWORD style, int x, int y, int w, int h, int id)
{
    return MakeControlPx(parent, className, text, style,
                         S(x), S(y), S(w), S(h), id);
}

HWND MakeControl(const wchar_t* className, const wchar_t* text, DWORD style,
                 int x, int y, int w, int h, int id)
{
    return MakeControlIn(g_mainWindow, className, text, style, x, y, w, h, id);
}

// -----------------------------------------------------------------------------
//  v1.7.0：标签页骨架的辅助函数
// -----------------------------------------------------------------------------
// 标签页里的控件坐标是相对"内容区"写的（逻辑像素），这里把物理原点加上缩放后的
// 偏移，并且把控件登记到当前页，切页时才知道该显示谁。
HWND TabCtl(const wchar_t* className, const wchar_t* text, DWORD style,
            int x, int y, int w, int h, int id)
{
    HWND control = MakeControlPx(g_mainWindow, className, text, style,
                                 g_tabOriginX + S(x), g_tabOriginY + S(y),
                                 S(w), S(h), id);
    if (control != NULL && g_buildingPage >= 0 && g_buildingPage < 4) {
        g_pageControls[g_buildingPage].push_back(control);
    }
    return control;
}

// 页内 ListView：坐标和 TabCtl 一样写逻辑值，额外处理字体/扩展样式/登记。
HWND TabListView(int id, int x, int y, int w, int h)
{
    HWND list = CreateWindowExW(
        WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        g_tabOriginX + S(x), g_tabOriginY + S(y), S(w), S(h),
        g_mainWindow, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), g_instance, NULL);
    if (list != NULL) {
        if (g_buildingPage >= 0 && g_buildingPage < 4) {
            g_pageControls[g_buildingPage].push_back(list);
        }
        if (g_font != NULL) {
            SendMessageW(list, WM_SETFONT, reinterpret_cast<WPARAM>(g_font), TRUE);
        }
        ListView_SetExtendedListViewStyle(list,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    }
    return list;
}

// 给 ListView 加一列（宽度按逻辑值缩放）
void ListViewAddColumn(HWND list, int index, const wchar_t* title, int width)
{
    if (list == NULL) { return; }
    LVCOLUMNW col;
    std::memset(&col, 0, sizeof(col));
    col.mask     = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    col.iSubItem = index;
    col.cx       = S(width);
    col.pszText  = const_cast<LPWSTR>(title);
    SendMessageW(list, LVM_INSERTCOLUMNW, static_cast<WPARAM>(index),
                 reinterpret_cast<LPARAM>(&col));
}

// 切换标签页：只显示当前页的控件。
// 注意日志框即使在别的页也要继续接收文字，所以只是 ShowWindow(SW_HIDE)，
// 绝不销毁、也不停止写入。
void ShowTabPage(int index)
{
    if (index < 0 || index > 3) {
        return;
    }
    for (int page = 0; page < 4; ++page) {
        const int show = (page == index) ? SW_SHOW : SW_HIDE;
        for (size_t i = 0; i < g_pageControls[page].size(); ++i) {
            ShowWindow(g_pageControls[page][i], show);
        }
    }
    if (index == 2 && g_hLog != NULL) {
        // 切到日志页时滚到最底，直接看到最新一条
        SendMessageW(g_hLog, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
        SendMessageW(g_hLog, EM_SCROLLCARET, 0, 0);
    }
}

// 状态栏是原生控件，文本要按"格"写，不能再 SetWindowTextW 整条设置。
void SetStatusText(const std::wstring& text)
{
    if (g_hStatusBar != NULL) {
        SendMessageW(g_hStatusBar, SB_SETTEXTW, 0, reinterpret_cast<LPARAM>(text.c_str()));
    }
}

void SetStatsText(const std::wstring& text)
{
    if (g_hStatusBar != NULL) {
        SendMessageW(g_hStatusBar, SB_SETTEXTW, 1, reinterpret_cast<LPARAM>(text.c_str()));
    }
}

// 建菜单栏（v1.7.0）。菜单是仿 NetLimiter 那套：顶部一条，分文件/工具/帮助。
HMENU BuildAppMenu()
{
    HMENU menu = CreateMenu();

    HMENU fileMenu = CreatePopupMenu();
    AppendMenuW(fileMenu, MF_STRING, IDM_OPEN_FOLDER, L"打开程序所在文件夹(&O)");
    AppendMenuW(fileMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(fileMenu, MF_STRING, IDM_EXIT, L"退出(&X)");
    AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), L"文件(&F)");

    HMENU toolMenu = CreatePopupMenu();
    AppendMenuW(toolMenu, MF_STRING, IDM_OPEN_LOG, L"查看调试日志(&L)");
    AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(toolMenu), L"工具(&T)");

    HMENU helpMenu = CreatePopupMenu();
    AppendMenuW(helpMenu, MF_STRING, IDM_HELP_README, L"使用说明(&R)");
    AppendMenuW(helpMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(helpMenu, MF_STRING, IDM_HELP_ABOUT, L"关于(&A)");
    AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(helpMenu), L"帮助(&H)");

    return menu;
}

// 把多行文本追加到只读日志框（控件过大时先清空，避免长时间运行后臃肿）
void AppendLog(const std::wstring& text)
{
    if (g_hLog == NULL || text.empty()) {
        return;
    }
    if (GetWindowTextLengthW(g_hLog) > 200000) {
        SetWindowTextW(g_hLog, L"[日志过长，已自动清空]\r\n");
    }
    SendMessageW(g_hLog, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
    SendMessageW(g_hLog, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(text.c_str()));
}

// -----------------------------------------------------------------------------
//  引擎日志回调（可能来自引擎线程）：只入队，不碰控件
// -----------------------------------------------------------------------------
void GuiLog(LogLevel level, const char* text, void* user)
{
    (void)user;
    const char* tag = "";
    switch (level) {
    case LogLevel::Error:   tag = "[错误] "; break;
    case LogLevel::Warning: tag = "[警告] "; break;
    case LogLevel::Debug:   tag = "[调试] "; break;
    case LogLevel::Packet:  tag = "  ";      break;
    case LogLevel::Info:
    default:                                 break;
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    char line[1200] = { 0 };
    std::snprintf(line, sizeof(line), "[%02d:%02d:%02d] %s%s",
                  static_cast<int>(st.wHour), static_cast<int>(st.wMinute),
                  static_cast<int>(st.wSecond), tag, text);

    if (g_logLockReady) {
        EnterCriticalSection(&g_logLock);
    }
    if (g_pendingLog.size() < kMaxPendingLog) {
        g_pendingLog.push_back(line);
    }
    if (g_logLockReady) {
        LeaveCriticalSection(&g_logLock);
    }
}

// UI 线程：把队列里的日志搬到控件上
void DrainLog()
{
    if (g_hLog == NULL) {
        return;
    }
    std::vector<std::string> lines;
    if (g_logLockReady) {
        EnterCriticalSection(&g_logLock);
    }
    lines.swap(g_pendingLog);
    if (g_logLockReady) {
        LeaveCriticalSection(&g_logLock);
    }
    if (lines.empty()) {
        return;
    }

    std::wstring text;
    for (size_t i = 0; i < lines.size(); ++i) {
        text += Utf8ToWide(lines[i].c_str());
        text += L"\r\n";
    }
    AppendLog(text);
}

// -----------------------------------------------------------------------------
//  界面参数 <-> 引擎配置
// -----------------------------------------------------------------------------
Direction ComboToDirection()
{
    switch (SendMessageW(g_hDir, CB_GETCURSEL, 0, 0)) {
    case 1:  return Direction::Outbound;
    case 2:  return Direction::Both;
    default: return Direction::Inbound;
    }
}

// v2.0.11：把「数字框 + 单位下拉」拼成 ParseRate 认识的一串。
// 用户可能顺手在数字框里也敲了单位（"1.2K"），这里**以右侧下拉为准**：
// 先把尾部的空白/字母/斜杠去掉，再补上下拉选中的单位。
std::string RateFieldText(HWND edit, HWND combo)
{
    std::string num = GetUtf8Text(edit);
    while (!num.empty()) {
        const char c = num[num.size() - 1];
        const bool tail = (c == ' ' || c == '\t' || c == '/' ||
                           (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));
        if (!tail) { break; }
        num.erase(num.size() - 1);
    }
    static const char* const kUnitSuffix[3] = { "B", "KB", "MB" };
    int idx = (combo != NULL)
            ? static_cast<int>(SendMessageW(combo, CB_GETCURSEL, 0, 0))
            : 1;
    if (idx < 0 || idx > 2) { idx = 1; }
    return num + kUnitSuffix[idx];
}

PortSide ComboToSide()
{
    return (SendMessageW(g_hMatch, CB_GETCURSEL, 0, 0) == 1) ? PortSide::Dst : PortSide::Src;
}

Protocol ComboToProtocol()
{
    switch (SendMessageW(g_hProto, CB_GETCURSEL, 0, 0)) {
    case 1:  return Protocol::Udp;
    case 2:  return Protocol::Both;
    default: return Protocol::Tcp;
    }
}

// -----------------------------------------------------------------------------
//  “丢什么”的三选一：按进程名 / 按端口 / 全部端口
// -----------------------------------------------------------------------------
bool IsProcessModeSelected()
{
    return g_hRadioByProcess != NULL && IsChecked(g_hRadioByProcess);
}

// 规范化进程名（失败时返回空串，原因写进 message）
std::string NormalizedProcessName(std::string& message)
{
    if (g_hProcess == NULL) {
        return std::string();
    }
    const std::string raw = GetUtf8Text(g_hProcess);
    std::string normalized;
    std::string error;
    if (!weaknet::NormalizeProcessName(raw, normalized, error)) {
        // 输入框为空时不当作错误，交由 ReadConfigFromUi 统一提示
        if (!raw.empty()) {
            message = error;
        }
        return std::string();
    }
    return normalized;
}

// 切换目标模式：清掉另一方的输入，保证任何时候只有一个模式携带有效参数
void ApplyTargetMode(TargetMode mode, bool clearOthers)
{
    g_targetMode = mode;

    if (g_hRadioByProcess != NULL) {
        SetChecked(g_hRadioByProcess, mode == TargetMode::ByProcess);
    }
    if (g_hRadioByPort != NULL) {
        SetChecked(g_hRadioByPort, mode == TargetMode::ByPort);
    }
    if (g_hAllPorts != NULL) {
        SetChecked(g_hAllPorts, mode == TargetMode::AllPorts);
    }

    if (!clearOthers) {
        return;
    }
    // 清空另一方的输入框时屏蔽 EN_CHANGE，避免触发“自动切模式”的回环
    const bool savedSyncing = g_uiSyncing;
    g_uiSyncing = true;
    if (mode == TargetMode::ByProcess && g_hPort != NULL) {
        SetWindowTextW(g_hPort, L"");
    } else if (mode == TargetMode::ByPort && g_hProcess != NULL) {
        SetWindowTextW(g_hProcess, L"");
    }
    g_uiSyncing = savedSyncing;
}

// 从界面读取配置；失败时通过 message 返回中文原因
bool ReadConfigFromUi(Config& cfg, std::string& message)
{
    cfg.ports.clear();
    cfg.allPorts = false;
    cfg.processName.clear();

    const TargetMode mode = g_targetMode;

    if (mode == TargetMode::AllPorts) {
        cfg.allPorts = true;                        // 不限定端口：整体断网
    } else if (mode == TargetMode::ByProcess) {
        std::string error;
        const std::string name = NormalizedProcessName(error);
        if (name.empty()) {
            message = error.empty()
                    ? "已选择“按进程名丢包”，请填写进程名（例如 chrome.exe）。"
                    : ("进程名无效：" + error);
            return false;
        }
        cfg.processName = name;                     // 交给引擎做“进程 -> 本地端口”映射
    } else {
        if (!weaknet::ParsePortList(GetUtf8Text(g_hPort), cfg.ports, message)) {
            return false;
        }
    }

    if (!weaknet::ParseDurationSeconds(GetUtf8Text(g_hDuration), cfg.durationSec, message)) {
        return false;
    }
    cfg.dir     = ComboToDirection();
    cfg.side    = ComboToSide();
    cfg.proto   = ComboToProtocol();
    cfg.verbose = IsChecked(g_hVerbose);
    cfg.installConsoleHandler = false;      // GUI 不需要接管 Ctrl+C

    // ---- 丢包率（v1.3.0）------------------------------------------------------
    if (!weaknet::ParseLossPercent(GetUtf8Text(g_hLossDown), cfg.lossDownPercent, message)) {
        message = std::string("下行丢包率：") + message;
        return false;
    }
    if (!weaknet::ParseLossPercent(GetUtf8Text(g_hLossUp), cfg.lossUpPercent, message)) {
        message = std::string("上行丢包率：") + message;
        return false;
    }

    // ---- 限速（v1.5.0，v1.6.0 起支持 300B / 200K / 2M 这类单位后缀）----------
    // v2.0.11：速率 = 数字框 + 单位下拉，所以这里要把两半拼起来再解析
    if (!weaknet::ParseRate(RateFieldText(g_hRateDown, g_hRateUnitDown),
                            cfg.rateDownBytesPerSec, message)) {
        message = std::string("下行限速：") + message;
        return false;
    }
    if (!weaknet::ParseRate(RateFieldText(g_hRateUp, g_hRateUnitUp),
                            cfg.rateUpBytesPerSec, message)) {
        message = std::string("上行限速：") + message;
        return false;
    }
    // 进程模式的引擎不依赖 dir；GUI 在解析完两方向输入后清零未选方向，
    // 保证单向设置不会被输入框里保存的另一方向参数覆盖。
    if (cfg.dir == weaknet::Direction::Outbound) {
        cfg.lossDownPercent     = 0;
        cfg.rateDownBytesPerSec = 0;
    } else if (cfg.dir == weaknet::Direction::Inbound) {
        cfg.lossUpPercent     = 0;
        cfg.rateUpBytesPerSec = 0;
    }

    // 与 CLI 共用同一套语义检查（0/0 无意义、丢包率与方向自相矛盾等），
    // 保证界面和命令行不会出现两种规则。
    if (!weaknet::ValidateConfig(cfg, message)) {
        return false;
    }
    return true;
}

// 刷新“将要使用的过滤器”预览，并按当前目标模式启用/禁用相关控件。
// 规则：按进程名时，端口输入框与“端口匹配”自动置灰。
void UpdateFilterPreview()
{
    const TargetMode mode = g_targetMode;
    const bool byProcess = (mode == TargetMode::ByProcess);
    const bool editable  = !g_running;

    EnableWindow(g_hRadioByProcess, editable);
    EnableWindow(g_hRadioByPort, editable);
    EnableWindow(g_hAllPorts, editable);
    EnableWindow(g_hPort, editable && mode == TargetMode::ByPort);
    EnableWindow(g_hMatch, editable && mode == TargetMode::ByPort);
    // 进程模式下的“端口匹配”不参与判断（引擎按报文方向自动取本机那一端），
    // 因此和端口输入框一起置灰，避免误以为它还有作用。
    EnableWindow(g_hProcess, editable && byProcess);

    // 丢包率输入框：运行中不可改；方向由 --dir / 组合框决定，
    // 若某方向不在拦截方向内，它的丢包率不会生效（ValidateConfig 会报错）。
    EnableWindow(g_hLossDown, editable);
    EnableWindow(g_hLossUp, editable);
    EnableWindow(g_hRateDown, editable);
    EnableWindow(g_hRateUp, editable);
    EnableWindow(g_hRateUnitDown, editable);
    EnableWindow(g_hRateUnitUp, editable);

    Config cfg;
    std::string message;
    std::wstring text;

    if (ReadConfigFromUi(cfg, message)) {
        text = Utf8ToWide(weaknet::BuildFilter(cfg).c_str());

        // 把丢包率也写在预览里：过滤器字符串本身看不出丢包率，
        // 但“到底会不会丢、丢多少”才是使用者最关心的信息。
        // v1.7.0：预览框改成了多行，这里用真正的换行，比原来堆空格清楚得多。
        wchar_t lossNote[256] = { 0 };
        _snwprintf_s(lossNote, sizeof(lossNote) / sizeof(lossNote[0]), _TRUNCATE,
                     L"\r\n丢包率：下行 %u%% / 上行 %u%%",
                     cfg.lossDownPercent, cfg.lossUpPercent);
        text += lossNote;

        // 限速同理：过滤器里看不出速率
        if (weaknet::IsShapingEnabled(cfg)) {
            const std::wstring downText =
                Utf8ToWide(weaknet::DescribeRate(cfg.rateDownBytesPerSec).c_str());
            const std::wstring upText =
                Utf8ToWide(weaknet::DescribeRate(cfg.rateUpBytesPerSec).c_str());
            wchar_t rateNote[320] = { 0 };
            _snwprintf_s(rateNote, sizeof(rateNote) / sizeof(rateNote[0]), _TRUNCATE,
                         L"\r\n限速：下行 %s / 上行 %s（整形，不丢包）",
                         downText.c_str(), upText.c_str());
            text += rateNote;
        }
        // 「丢包率 100% + 限速」是自相矛盾的：报文先被 100% 丢包拦下，
        // 限速器一个包都收不到，限速白设。写在预览框下面单独一行，
        // 不等运行就看得见（预览框只有三行，塞进去会被裁掉）。
        if (g_hShapeWarn != NULL) {
            std::wstring warn;
            const bool downConflict = (cfg.rateDownBytesPerSec > 0 &&
                                       cfg.lossDownPercent >= 100);
            const bool upConflict   = (cfg.rateUpBytesPerSec > 0 &&
                                       cfg.lossUpPercent >= 100);
            if (downConflict || upConflict) {
                warn = L"⚠ ";
                warn += (downConflict && upConflict) ? L"上下行"
                                                      : (downConflict ? L"下行" : L"上行");
                warn += L"同时设了「丢包率 100%」和「限速」：报文会先被全部拦下，"
                        L"限速无从生效（只想限速请把丢包率设为 0）";
            }
            SetWindowTextW(g_hShapeWarn, warn.c_str());
        }

        if (byProcess) {
            // 进程模式刻意不限定方向，这里补一句说明，避免使用者以为方向没生效
            text += L"      ← 进程模式：全量旁听 TCP/UDP，命中该进程本地端口的按丢包率处理";
        }
    } else {
        text = L"（参数不完整：" + Utf8ToWide(message.c_str()) + L"）";
        // 配置不合法时清掉"矛盾提示"：留着上一次的内容会误导
        // （比如刚把丢包率改成 0，旧警告还挂在下面）。
        if (g_hShapeWarn != NULL) {
            SetWindowTextW(g_hShapeWarn, L"");
        }
    }
    SetWindowTextW(g_hFilter, text.c_str());

    UpdateProcessStateLabel();
}

// 进程模式的状态行：显示“要丢的是谁”以及（运行中）实际识别到的 PID / 端口。
// 运行前只做一次纯查询（不依赖 WinDivert），让用户在点“开始拦截”之前就能确认
// 进程名写对了 —— 这和命令行版 --dry-run 的体验一致。
void UpdateProcessStateLabel()
{
    if (g_hProcessState == NULL) {
        return;
    }
    if (g_targetMode != TargetMode::ByProcess) {
        // v1.7.0：不再留空。空着一行会让"丢什么"分组框底部看起来是一块无意义的空白，
        // 这里改成一句说明，既填满空间又提示了这条路径怎么用。
        SetWindowTextW(g_hProcessState,
                       L"提示：按进程名丢包时，这里会显示命中的实例数与它占用的本地端口；"
                       L"也可以直接点「浏览…」从正在运行的程序里选。");
        return;
    }

    std::wstring text;
    char buffer[512] = { 0 };

    if (g_running && g_session.IsProcessMode()) {
        const std::vector<unsigned long> pids = g_session.CurrentProcessIds();
        const std::unordered_set<uint16_t> ports = g_session.CurrentPorts();

        std::string pidText;
        for (size_t i = 0; i < pids.size() && i < 5; ++i) {
            char one[32] = { 0 };
            std::snprintf(one, sizeof(one), "%s%lu", (i == 0 ? "" : ", "), pids[i]);
            pidText += one;
        }
        if (pids.size() > 5) { pidText += ", ..."; }
        if (pidText.empty()) { pidText = "（无）"; }

        std::snprintf(buffer, sizeof(buffer),
                      "进程模式运行中：PID %s | 命中端口 %llu 个 | 端口集合每 %u ms 重算",
                      pidText.c_str(), static_cast<unsigned long long>(ports.size()),
                      g_sessionRefreshMs);
        text = Utf8ToWide(buffer);
    } else {
        std::string error;
        const std::string name = NormalizedProcessName(error);
        if (name.empty()) {
            text = L"请填写进程名，例如 chrome.exe（可省略 .exe，也可粘贴完整路径）";
        } else {
            std::unordered_set<uint16_t> ports;
            std::vector<unsigned long>   pids;
            std::string                  resolveError;
            weaknet::CollectProcessLocalPorts(name, ports, pids, resolveError);

            if (pids.empty()) {
                // 说明文案刻意精简：这是单行控件，太长会被省略号截掉
                std::snprintf(buffer, sizeof(buffer),
                              "进程 “%s”：未找到（%s）。运行后每秒重试，找到前全部放行。",
                              name.c_str(), resolveError.c_str());
            } else {
                std::snprintf(buffer, sizeof(buffer),
                              "进程 “%s”：命中 %llu 个实例，占用 %llu 个本地端口"
                              "（端口为空时全部放行）。",
                              name.c_str(),
                              static_cast<unsigned long long>(pids.size()),
                              static_cast<unsigned long long>(ports.size()));
            }
            text = Utf8ToWide(buffer);
        }
    }
    SetWindowTextW(g_hProcessState, text.c_str());
}

// =============================================================================
//  进程选择器（v1.4.0）：从正在运行的程序里挑一个，代替手输进程名
//  设计要点：
//    * 默认只列出「有可见窗口的程序」—— 不加这个筛会混进几百个系统进程；
//    * 「显示所有进程」勾上后连无窗口/系统进程一起列，并标出 UWP 宿主；
//    * 连接数一列很重要：0 连接的目标即使丢包也没有流量可丢；
//    * 选中后交给引擎的仍然是**进程名**（exeName），不是 PID，
//      所以目标进程重启后依然有效，Chrome/Edge 这类多进程应用也能全覆盖。
// =============================================================================

namespace {

const int kPickerListId      = 2001;
const int kPickerSearchId    = 2002;
const int kPickerOnlyConnId  = 2003;
const int kPickerShowAllId   = 2004;
const int kPickerRefreshId   = 2005;
const int kPickerOkId        = 2006;
const int kPickerCancelId    = 2007;
const int kPickerCountId     = 2008;

struct ProcessPicker {
    HWND window = NULL;
    HWND list = NULL;
    HWND search = NULL;
    HWND onlyConnected = NULL;
    HWND showAll = NULL;
    HWND countLabel = NULL;
    std::vector<weaknet::RunningApp> apps;   // 全部（已由 core 排好序）
    std::vector<size_t> visible;             // 过滤后要显示的下标
    std::string chosenExeName;               // 用户选中的进程名（UTF-8）
    bool done = false;
};

// 忽略大小写的“包含”（只处理 ASCII 大小写；中文按字节比较，够用）
bool ContainsNoCase(const std::string& haystack, const std::string& needle)
{
    if (needle.empty()) { return true; }
    if (needle.size() > haystack.size()) { return false; }
    for (size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            char a = haystack[i + j];
            char b = needle[j];
            if (a >= 'A' && a <= 'Z') { a = static_cast<char>(a - 'A' + 'a'); }
            if (b >= 'A' && b <= 'Z') { b = static_cast<char>(b - 'A' + 'a'); }
            if (a != b) { match = false; break; }
        }
        if (match) { return true; }
    }
    return false;
}

void PickerReload(ProcessPicker* st);      // 重新枚举
void PickerRepopulate(ProcessPicker* st);  // 按当前筛选重建列表

void PickerRepopulate(ProcessPicker* st)
{
    if (st->list == NULL) {
        return;
    }
    SendMessageW(st->list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(st->list);
    st->visible.clear();

    const std::string filter = WideToUtf8(GetWideText(st->search).c_str());
    const bool onlyConnected = IsChecked(st->onlyConnected);
    const bool showAll       = IsChecked(st->showAll);

    for (size_t i = 0; i < st->apps.size(); ++i) {
        const weaknet::RunningApp& a = st->apps[i];

        if (!showAll) {
            if (!a.hasWindow) { continue; }     // 只列“打开的应用”
            if (a.isUwpHost)  { continue; }     // 商店应用宿主名字对不上，默认藏起来
        }
        if (onlyConnected && a.connectionCount == 0) {
            continue;
        }
        if (!filter.empty() &&
            !ContainsNoCase(a.exeName, filter) &&
            !ContainsNoCase(a.displayName, filter) &&
            !ContainsNoCase(a.windowTitle, filter)) {
            continue;
        }
        st->visible.push_back(i);
    }

    int row = 0;
    for (size_t r = 0; r < st->visible.size(); ++r) {
        const weaknet::RunningApp& a = st->apps[st->visible[r]];

        std::wstring desc = Utf8ToWide(a.displayName.c_str());
        if (desc.empty()) {
            desc = Utf8ToWide(a.windowTitle.c_str());
        }
        if (desc.empty()) {
            desc = L"(无说明)";
        }
        if (a.isUwpHost) {
            desc += L"（商店应用宿主）";
        }

        wchar_t pidText[32] = { 0 };
        _snwprintf_s(pidText, sizeof(pidText) / sizeof(pidText[0]), _TRUNCATE,
                     L"%lu", a.pid);
        wchar_t connText[32] = { 0 };
        _snwprintf_s(connText, sizeof(connText) / sizeof(connText[0]), _TRUNCATE,
                     L"%lu", a.connectionCount);

        LVITEMW item;
        std::memset(&item, 0, sizeof(item));
        item.mask     = LVIF_TEXT | LVIF_PARAM;
        item.iItem    = row;
        item.iSubItem = 0;
        item.pszText  = const_cast<LPWSTR>(Utf8ToWide(a.exeName.c_str()).c_str());
        item.lParam   = static_cast<LPARAM>(st->visible[r]);
        const int inserted = static_cast<int>(
            SendMessageW(st->list, LVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&item)));
        if (inserted < 0) {
            ++row;
            continue;
        }

        // 其余列（LVM_SETITEMTEXTW 直接写子项）
        LVITEMW sub;
        std::memset(&sub, 0, sizeof(sub));
        sub.mask = LVIF_TEXT;

        sub.iItem = inserted; sub.iSubItem = 1;
        sub.pszText = const_cast<LPWSTR>(desc.c_str());
        SendMessageW(st->list, LVM_SETITEMW, 0, reinterpret_cast<LPARAM>(&sub));

        sub.iItem = inserted; sub.iSubItem = 2; sub.pszText = pidText;
        SendMessageW(st->list, LVM_SETITEMW, 0, reinterpret_cast<LPARAM>(&sub));

        sub.iItem = inserted; sub.iSubItem = 3; sub.pszText = connText;
        SendMessageW(st->list, LVM_SETITEMW, 0, reinterpret_cast<LPARAM>(&sub));

        ++row;
    }

    SendMessageW(st->list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(st->list, NULL, TRUE);

    // 选中第一行，方便直接回车确认
    if (!st->visible.empty()) {
        ListView_SetItemState(st->list, 0, LVIS_SELECTED | LVIS_FOCUSED,
                              LVIS_SELECTED | LVIS_FOCUSED);
    }

    if (st->countLabel != NULL) {
        wchar_t buf[256] = { 0 };
        if (showAll) {
            _snwprintf_s(buf, sizeof(buf) / sizeof(buf[0]), _TRUNCATE,
                         L"显示 %d / %d 个进程（含无窗口与系统进程）",
                         static_cast<int>(st->visible.size()),
                         static_cast<int>(st->apps.size()));
        } else {
            _snwprintf_s(buf, sizeof(buf) / sizeof(buf[0]), _TRUNCATE,
                         L"显示 %d 个正在运行的程序（勾选“显示所有进程”可看到全部 %d 个）",
                         static_cast<int>(st->visible.size()),
                         static_cast<int>(st->apps.size()));
        }
        SetWindowTextW(st->countLabel, buf);
    }
}

void PickerReload(ProcessPicker* st)
{
    std::vector<weaknet::RunningApp> apps;
    std::string err;
    if (!weaknet::ListRunningApps(apps, err)) {
        MessageBoxW(st->window,
                    (L"枚举正在运行的程序失败：\n" + Utf8ToWide(err.c_str())).c_str(),
                    L"进程选择器", MB_OK | MB_ICONWARNING);
        return;
    }
    st->apps.swap(apps);
    PickerRepopulate(st);
}

// 取当前选中行的进程名；没有选中返回 false
bool PickerTakeSelection(ProcessPicker* st, std::string& out)
{
    const int sel = ListView_GetNextItem(st->list, -1, LVNI_SELECTED);
    if (sel < 0) {
        return false;
    }
    LVITEMW item;
    std::memset(&item, 0, sizeof(item));
    item.mask    = LVIF_PARAM;
    item.iItem   = sel;
    if (!SendMessageW(st->list, LVM_GETITEMW, 0, reinterpret_cast<LPARAM>(&item))) {
        return false;
    }
    const size_t index = static_cast<size_t>(item.lParam);
    if (index >= st->apps.size()) {
        return false;
    }
    out = st->apps[index].exeName;
    return true;
}

LRESULT CALLBACK PickerProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
{
    ProcessPicker* st = reinterpret_cast<ProcessPicker*>(GetWindowLongPtrW(window, GWLP_USERDATA));

    switch (message) {
    case WM_CREATE: {
        CREATESTRUCTW* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        st = reinterpret_cast<ProcessPicker*>(cs->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(st));
        st->window = window;

        const DWORD labelStyle = SS_LEFT | SS_CENTERIMAGE;

        MakeControlIn(window, L"STATIC", L"搜索", labelStyle, 12, 12, 36, 22, 0);
        st->search = MakeControlIn(window, L"EDIT", L"",
                                   ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP,
                                   50, 10, 240, 24, kPickerSearchId);
        st->onlyConnected = MakeControlIn(window, L"BUTTON", L"只显示有网络连接的程序",
                                          BS_AUTOCHECKBOX | WS_TABSTOP,
                                          304, 11, 220, 22, kPickerOnlyConnId);
        st->showAll = MakeControlIn(window, L"BUTTON", L"显示所有进程（含无窗口、系统进程）",
                                    BS_AUTOCHECKBOX | WS_TABSTOP,
                                    304, 35, 260, 22, kPickerShowAllId);
        MakeControlIn(window, L"BUTTON", L"刷新", BS_PUSHBUTTON | WS_TABSTOP,
                      600, 34, 108, 24, kPickerRefreshId);

        st->list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                                   LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                   S(12), S(66), S(696), S(326),
                                   window,
                                   reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPickerListId)),
                                   g_instance, NULL);
        if (st->list != NULL) {
            ListView_SetExtendedListViewStyle(st->list,
                LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
            SendMessageW(st->list, WM_SETFONT,
                         reinterpret_cast<WPARAM>(g_font), TRUE);

            struct Column { const wchar_t* title; int width; };
            const Column columns[] = {
                { L"进程名", 200 }, { L"说明 / 窗口标题", 320 },
                { L"PID", 80 },    { L"连接", 70 }
            };
            for (int c = 0; c < 4; ++c) {
                LVCOLUMNW col;
                std::memset(&col, 0, sizeof(col));
                col.mask     = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
                col.iSubItem = c;
                col.cx       = S(columns[c].width);
                col.pszText  = const_cast<LPWSTR>(columns[c].title);
                SendMessageW(st->list, LVM_INSERTCOLUMNW, static_cast<WPARAM>(c),
                             reinterpret_cast<LPARAM>(&col));
            }
        }

        st->countLabel = MakeControlIn(window, L"STATIC", L"", SS_LEFT | SS_ENDELLIPSIS,
                                       12, 398, 500, 20, kPickerCountId);

        MakeControlIn(window, L"BUTTON", L"确定", BS_DEFPUSHBUTTON | WS_TABSTOP,
                      530, 420, 88, 28, kPickerOkId);
        MakeControlIn(window, L"BUTTON", L"取消", BS_PUSHBUTTON | WS_TABSTOP,
                      626, 420, 82, 28, kPickerCancelId);

        PickerReload(st);

        SetFocus(st->search);
        return 0;
    }

    case WM_COMMAND: {
        const int id = LOWORD(wParam);
        const int notify = HIWORD(wParam);
        if (st == NULL) { break; }

        if (id == kPickerSearchId && notify == EN_CHANGE) {
            PickerRepopulate(st);
            return 0;
        }
        if ((id == kPickerOnlyConnId || id == kPickerShowAllId) && notify == BN_CLICKED) {
            PickerRepopulate(st);
            return 0;
        }
        if (id == kPickerRefreshId && notify == BN_CLICKED) {
            PickerReload(st);
            return 0;
        }
        if (id == kPickerOkId && notify == BN_CLICKED) {
            std::string picked;
            if (!PickerTakeSelection(st, picked)) {
                MessageBoxW(window, L"请先在上面的列表里选中一个程序。",
                            L"进程选择器", MB_OK | MB_ICONINFORMATION);
                return 0;
            }
            st->chosenExeName = picked;
            st->done = true;
            return 0;
        }
        if (id == kPickerCancelId && notify == BN_CLICKED) {
            st->done = true;      // chosenExeName 保持空 = 取消
            return 0;
        }
        break;
    }

    case WM_NOTIFY: {
        NMHDR* hdr = reinterpret_cast<NMHDR*>(lParam);
        if (st != NULL && hdr != NULL && hdr->idFrom == kPickerListId &&
            hdr->code == NM_DBLCLK) {
            std::string picked;
            if (PickerTakeSelection(st, picked)) {
                st->chosenExeName = picked;
                st->done = true;
            }
            return 0;
        }
        break;
    }

    case WM_KEYDOWN:
        if (wParam == VK_ESCAPE && st != NULL) {
            st->done = true;      // 取消
            return 0;
        }
        if (wParam == VK_RETURN && st != NULL) {
            std::string picked;
            if (PickerTakeSelection(st, picked)) {
                st->chosenExeName = picked;
                st->done = true;
            }
            return 0;
        }
        break;

    case WM_CLOSE:
        if (st != NULL) { st->done = true; }
        return 0;

    default:
        break;
    }
    return DefWindowProcW(window, message, wParam, lParam);
}

}  // namespace

// 打开进程选择器。返回 true 表示用户选中了一个程序，结果写入 outExeName（UTF-8）。
bool ChooseProcessFromRunning(std::string& outExeName)
{
    outExeName.clear();

    // 注册窗口类（只注册一次）
    static bool registered = false;
    const wchar_t* const kClass = L"WeakNetProcessPicker";
    if (!registered) {
        WNDCLASSEXW wc;
        std::memset(&wc, 0, sizeof(wc));
        wc.cbSize        = sizeof(wc);
        wc.lpfnWndProc   = PickerProc;
        wc.hInstance     = g_instance;
        wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_3DFACE + 1);
        wc.lpszClassName = kClass;
        if (RegisterClassExW(&wc) == 0) {
            return false;
        }
        registered = true;
    }

    ProcessPicker st;

    RECT rect = { 0, 0, S(720), S(460) };
    AdjustWindowRect(&rect, WS_POPUPWINDOW | WS_CAPTION, FALSE);

    // 居中到主窗口
    RECT ownerRect;
    GetWindowRect(g_mainWindow, &ownerRect);
    const int w = rect.right - rect.left;
    const int h = rect.bottom - rect.top;
    int x = ownerRect.left + ((ownerRect.right - ownerRect.left) - w) / 2;
    int y = ownerRect.top + ((ownerRect.bottom - ownerRect.top) - h) / 2;
    if (x < 0) { x = 0; }
    if (y < 0) { y = 0; }

    HWND window = CreateWindowExW(WS_EX_DLGMODALFRAME, kClass, L"选择要丢包的应用程序",
                                  WS_POPUPWINDOW | WS_CAPTION | WS_VISIBLE,
                                  x, y, w, h,
                                  g_mainWindow, NULL, g_instance, &st);
    if (window == NULL) {
        return false;
    }

    // 模态：禁用主窗口，自己泵消息
    EnableWindow(g_mainWindow, FALSE);
    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);

    MSG msg;
    while (!st.done && GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (!IsDialogMessageW(window, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    EnableWindow(g_mainWindow, TRUE);
    DestroyWindow(window);
    SetActiveWindow(g_mainWindow);

    if (st.chosenExeName.empty()) {
        return false;    // 取消
    }
    outExeName = st.chosenExeName;
    return true;
}

// 刷新热键区状态文本的函数定义在快捷键那一节（依赖 IsToggleHotkey）
// =============================================================================
//  应用速率页（v2.0.0）
// =============================================================================
//  监控按需启动：第一次切到本页时才拉起 ETW 会话（不切就不占资源）。
//  刷新频率限制到约 1 秒一次 —— ETW 实时投递本身就有秒级延迟，
   //  刷得再快也只会显示同样的数字，还白白闪屏。
// 单位选择（工具栏那个下拉）—— 0=自动 1=B/s 2=KB/s 3=MB/s
int g_activityUnitMode = 0;

void FormatRateCell(unsigned long long bps, wchar_t* out, size_t outCount)
{
    const int mode = g_activityUnitMode;
    if (mode == 1) { _snwprintf_s(out, outCount, _TRUNCATE, L"%llu B/s", bps); return; }
    if (mode == 2) { _snwprintf_s(out, outCount, _TRUNCATE, L"%.2f KB/s", bps / 1024.0); return; }
    if (mode == 3) { _snwprintf_s(out, outCount, _TRUNCATE, L"%.2f MB/s", bps / (1024.0 * 1024.0)); return; }
    // 自动
    if (bps == 0) {
        wcsncpy_s(out, outCount, L"0 B/s", _TRUNCATE);
    } else if (bps < 1024ULL) {
        _snwprintf_s(out, outCount, _TRUNCATE, L"%llu B/s", bps);
    } else if (bps < 1024ULL * 1024ULL) {
        _snwprintf_s(out, outCount, _TRUNCATE, L"%.1f KB/s", bps / 1024.0);
    } else {
        _snwprintf_s(out, outCount, _TRUNCATE, L"%.2f MB/s", bps / (1024.0 * 1024.0));
    }
}

void FormatBytesCell(unsigned long long bytes, wchar_t* out, size_t outCount)
{
    if (bytes < 1024ULL) {
        _snwprintf_s(out, outCount, _TRUNCATE, L"%llu B", bytes);
    } else if (bytes < 1024ULL * 1024ULL) {
        _snwprintf_s(out, outCount, _TRUNCATE, L"%.1f KB", bytes / 1024.0);
    } else if (bytes < 1024ULL * 1024ULL * 1024ULL) {
        _snwprintf_s(out, outCount, _TRUNCATE, L"%.2f MB", bytes / (1024.0 * 1024.0));
    } else {
        _snwprintf_s(out, outCount, _TRUNCATE, L"%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }
}

// 确保监控已启动；把成功/失败写进状态行
void EnsureAppRateMonitor()
{
    if (g_hAppRateStatus == NULL) {
        return;
    }
    if (weaknet::IsAppRateMonitorRunning()) {
        return;
    }
    std::string error;
    if (weaknet::StartAppRateMonitor(error)) {
        SetWindowTextW(g_hAppRateStatus,
                       L"监控中：每约 1 秒刷新一次。首次切换过来时会有一两秒才出数据"
                       L"（ETW 实时投递本身有延迟）。");
    } else {
        SetWindowTextW(g_hAppRateStatus,
                       (L"无法启动监控：" + Utf8ToWide(error.c_str())).c_str());
    }
}

// 应用图标：从 exe 里取真实图标，同一路径只取一次。
// 这是"像 NetLimiter"里性价比最高的一步 —— 列表里每行都有程序自己的图标。
int GetExeIconIndex(const std::string& exePath)
{
    if (exePath.empty() || g_appIconList == NULL) {
        return -1;
    }
    const std::map<std::string, int>::iterator cached = g_exeIconIndex.find(exePath);
    if (cached != g_exeIconIndex.end()) {
        return cached->second;
    }

    int index = -1;
    const std::wstring wide = Utf8ToWide(exePath.c_str());
    SHFILEINFOW sfi;
    std::memset(&sfi, 0, sizeof(sfi));
    // SHGFI_SMALLICON 给 16x16；高 DPI 下取大图标再让 ImageList 缩放会更清楚
    if (SHGetFileInfoW(wide.c_str(), 0, &sfi, sizeof(sfi),
                       SHGFI_ICON | SHGFI_SMALLICON) && sfi.hIcon != NULL) {
        index = ImageList_AddIcon(g_appIconList, sfi.hIcon);
        DestroyIcon(sfi.hIcon);
    }
    // 取不到（受保护进程/路径无效）就记 -1，避免每次都重试
    g_exeIconIndex[exePath] = index;
    return index;
}

// 右侧「信息视图」：把选中应用的路径、属性、当前规则填进去
void UpdateInfoPanel(const weaknet::AppRate* a)
{
    if (g_hInfoPath != NULL) {
        if (a == NULL) {
            SetWindowTextW(g_hInfoPath, L"（未选中应用）");
        } else {
            const std::wstring line = (a->exePath.empty()
                                       ? Utf8ToWide(a->exeName.c_str())
                                       : Utf8ToWide(a->exePath.c_str()));
            SetWindowTextW(g_hInfoPath, line.c_str());
        }
    }

    if (g_hInfoProps != NULL) {
        SendMessageW(g_hInfoProps, WM_SETREDRAW, FALSE, 0);
        ListView_DeleteAllItems(g_hInfoProps);
        if (a != NULL) {
            struct Row { const wchar_t* key; std::wstring value; };
            std::vector<Row> rows;
            Row r;
            r.key = L"名称";   r.value = Utf8ToWide(a->exeName.c_str()); rows.push_back(r);
            r.key = L"PID";    { wchar_t b[32]; _snwprintf_s(b, 32, _TRUNCATE, L"%lu", a->pid); r.value = b; } rows.push_back(r);
            r.key = L"路径";   r.value = Utf8ToWide(a->exePath.c_str()); rows.push_back(r);
            r.key = L"本次下行"; { wchar_t b[32]; FormatBytesCell(a->rxTotal, b, 32); r.value = b; } rows.push_back(r);
            r.key = L"本次上行"; { wchar_t b[32]; FormatBytesCell(a->txTotal, b, 32); r.value = b; } rows.push_back(r);

            for (size_t i = 0; i < rows.size(); ++i) {
                LVITEMW item;
                std::memset(&item, 0, sizeof(item));
                item.mask = LVIF_TEXT;
                item.iItem = static_cast<int>(i);
                item.pszText = const_cast<LPWSTR>(rows[i].key);
                const int at = static_cast<int>(SendMessageW(
                    g_hInfoProps, LVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&item)));
                if (at < 0) { continue; }
                LVITEMW sub;
                std::memset(&sub, 0, sizeof(sub));
                sub.mask = LVIF_TEXT;
                sub.iItem = at;
                sub.iSubItem = 1;
                sub.pszText = const_cast<LPWSTR>(rows[i].value.c_str());
                SendMessageW(g_hInfoProps, LVM_SETITEMW, 0, reinterpret_cast<LPARAM>(&sub));
            }
        }
        SendMessageW(g_hInfoProps, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(g_hInfoProps, NULL, TRUE);
    }

    if (g_hInfoRules != NULL) {
        SendMessageW(g_hInfoRules, WM_SETREDRAW, FALSE, 0);
        ListView_DeleteAllItems(g_hInfoRules);
        // NetLimiter 的"类型 × 下载/上传"四行。我们目前一次只能对一个目标生效，
        // 所以除"限制"外都显示"未设置"，避免给用户错的印象。
        const wchar_t* const types[] = { L"拦截", L"限制", L"优先级", L"配额" };
        for (int i = 0; i < 4; ++i) {
            LVITEMW item;
            std::memset(&item, 0, sizeof(item));
            item.mask = LVIF_TEXT;
            item.iItem = i;
            item.pszText = const_cast<LPWSTR>(types[i]);
            const int at = static_cast<int>(SendMessageW(
                g_hInfoRules, LVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&item)));
            if (at < 0) { continue; }
            for (int c = 1; c <= 2; ++c) {
                LVITEMW sub;
                std::memset(&sub, 0, sizeof(sub));
                sub.mask = LVIF_TEXT;
                sub.iItem = at;
                sub.iSubItem = c;
                sub.pszText = const_cast<LPWSTR>(L"未设置");
                SendMessageW(g_hInfoRules, LVM_SETITEMW, 0, reinterpret_cast<LPARAM>(&sub));
            }
        }
        SendMessageW(g_hInfoRules, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(g_hInfoRules, NULL, TRUE);
    }
}

// 从列表里取出当前选中的那一行（返回索引，-1 表示没选中）
int GetSelectedAppRow()
{
    if (g_hAppRateList == NULL) { return -1; }
    return static_cast<int>(SendMessageW(g_hAppRateList, LVM_GETNEXTITEM,
                                         static_cast<WPARAM>(-1), LVNI_SELECTED));
}

// 列头上的排序箭头（让"可以点列头排序"这件事看得见）
void UpdateSortIndicator()
{
    if (g_hAppRateList == NULL) { return; }
    HWND header = ListView_GetHeader(g_hAppRateList);
    if (header == NULL) { return; }
    const int count = Header_GetItemCount(header);
    for (int i = 0; i < count; ++i) {
        HDITEMW item;
        std::memset(&item, 0, sizeof(item));
        item.mask = HDI_FORMAT;
        if (!Header_GetItem(header, i, &item)) { continue; }
        item.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
        if (i == g_activitySortColumn) {
            item.fmt |= (g_activitySortDesc ? HDF_SORTDOWN : HDF_SORTUP);
        }
        Header_SetItem(header, i, &item);
    }
}

// 按当前排序方式给列表排序。
// 关键点：按"速率"列排序时不要每次刷新都重排（那样行会跳），
// 只在不重排时按**上次的显示顺序**摆放，新出现的进程排到末尾。
void SortAppRates(std::vector<weaknet::AppRate>& rates, bool forceNow)
{
    const unsigned long long now = GetTickCount64();
    const bool isNameSort = (g_activitySortColumn == 0);

    bool doResort = forceNow || g_activityResortNow || isNameSort ||
                    (now - g_activityLastResort >= 3000);
    g_activityResortNow = false;

    if (doResort) {
        struct Cmp {
            int col; bool desc;
            bool operator()(const weaknet::AppRate& a, const weaknet::AppRate& b) const {
                unsigned long long va = 0, vb = 0;
                switch (col) {
                case 1: va = a.rxBps;   vb = b.rxBps;   break;
                case 2: va = a.txBps;   vb = b.txBps;   break;
                case 3: va = a.rxTotal; vb = b.rxTotal; break;
                case 4: va = a.txTotal; vb = b.txTotal; break;
                default: break;
                }
                if (col == 0) {
                    const int c = a.exeName.compare(b.exeName);
                    if (c != 0) { return desc ? (c > 0) : (c < 0); }
                    return a.pid < b.pid;
                }
                if (va != vb) { return desc ? (va > vb) : (va < vb); }
                return a.exeName < b.exeName;      // 并列时按名字，保证顺序确定
            }
        };
        Cmp cmp;
        cmp.col = g_activitySortColumn;
        cmp.desc = g_activitySortDesc;
        std::sort(rates.begin(), rates.end(), cmp);

        g_activityLastResort = now;
        g_activityOrder.clear();
        for (size_t i = 0; i < rates.size(); ++i) {
            g_activityOrder.push_back(rates[i].pid);
        }
        return;
    }

    // 不重排：按上次的显示顺序摆放，新进程放末尾（保持稳定，行不会跳）
    std::map<unsigned long, size_t> rank;
    for (size_t i = 0; i < g_activityOrder.size(); ++i) {
        rank[g_activityOrder[i]] = i;
    }
    struct StableCmp {
        std::map<unsigned long, size_t>* rank;
        bool operator()(const weaknet::AppRate& a, const weaknet::AppRate& b) const {
            const std::map<unsigned long, size_t>::iterator ia = rank->find(a.pid);
            const std::map<unsigned long, size_t>::iterator ib = rank->find(b.pid);
            const size_t ra = (ia != rank->end()) ? ia->second : (rank->size() + a.pid);
            const size_t rb = (ib != rank->end()) ? ib->second : (rank->size() + b.pid);
            return ra < rb;
        }
    };
    StableCmp sc;
    sc.rank = &rank;
    std::stable_sort(rates.begin(), rates.end(), sc);

    g_activityOrder.clear();
    for (size_t i = 0; i < rates.size(); ++i) {
        g_activityOrder.push_back(rates[i].pid);
    }
}

void UpdateAppRateList(bool force)
{
    if (g_hAppRateList == NULL) {
        return;
    }

    // 限流到约 1 秒
    const unsigned long long now = GetTickCount64();
    if (!force && g_appRateLastRefresh != 0 && (now - g_appRateLastRefresh) < 900) {
        return;
    }
    g_appRateLastRefresh = now;

    if (!weaknet::IsAppRateMonitorRunning()) {
        return;
    }

    // includeIdle=true：保留本次监控内用过网络的进程（速率为 0 也显示），
    // 这样表格是稳定的、不会一空闲就整个空掉。核心会顺手回收已退出的进程。
    const std::vector<weaknet::AppRate> all = weaknet::GetAppRates(true);

    // 过滤：搜索关键字 + "只显示有流量的"
    wchar_t searchBuf[64] = { 0 };
    if (g_hActivitySearch != NULL) {
        GetWindowTextW(g_hActivitySearch, searchBuf, 64);
    }
    std::wstring search(searchBuf);
    for (size_t i = 0; i < search.size(); ++i) {
        if (search[i] >= L'A' && search[i] <= L'Z') { search[i] = search[i] - L'A' + L'a'; }
    }
    const bool onlyActive = (g_hActivityFilter != NULL) &&
        (SendMessageW(g_hActivityFilter, BM_GETCHECK, 0, 0) == BST_CHECKED);

    std::vector<weaknet::AppRate> rates;
    for (size_t i = 0; i < all.size(); ++i) {
        if (onlyActive && all[i].rxBps == 0 && all[i].txBps == 0) { continue; }
        if (!search.empty()) {
            const std::wstring name = Utf8ToWide(all[i].exeName.c_str());
            if (name.find(search) == std::wstring::npos) { continue; }
        }
        rates.push_back(all[i]);
    }

    SortAppRates(rates, force);

    // 记住当前选中的进程名，重建之后尽量还原选中行（否则每秒闪一下很烦）
    const int prevSel = GetSelectedAppRow();
    std::wstring prevName;
    if (prevSel >= 0) {
        wchar_t buf[260] = { 0 };
        LVITEMW it;
        std::memset(&it, 0, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = prevSel;
        it.iSubItem = 0;
        it.pszText = buf;
        it.cchTextMax = 260;
        SendMessageW(g_hAppRateList, LVM_GETITEMTEXTW, static_cast<WPARAM>(prevSel),
                     reinterpret_cast<LPARAM>(&it));
        prevName = buf;
    }

    // v2.0.9：重建列表前，记住"当前最上面那一行是哪个进程"。
    // 为什么：DeleteAllItems + 重新插入会把滚动位置重置回顶部。
    // 按速率排序时每 3 秒重排一次，于是用户"每三秒就得往下划一次"（用户反馈）。
    // 做法：锚定顶部那一行的 PID，重建后把它滚回顶部 —— 你正在看的位置就不会跳。
    int anchorPid = -1;
    {
        const int topIndex = static_cast<int>(
            SendMessageW(g_hAppRateList, LVM_GETTOPINDEX, 0, 0));
        if (topIndex >= 0) {
            LVITEMW it;
            std::memset(&it, 0, sizeof(it));
            it.mask  = LVIF_PARAM;
            it.iItem = topIndex;
            if (SendMessageW(g_hAppRateList, LVM_GETITEMW, 0,
                             reinterpret_cast<LPARAM>(&it))) {
                anchorPid = static_cast<int>(it.lParam);
            }
        }
    }

    SendMessageW(g_hAppRateList, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_hAppRateList);

    int row = 0;
    int restoreSel = -1;
    int anchorRow = -1;
    for (size_t i = 0; i < rates.size(); ++i) {
        const weaknet::AppRate& a = rates[i];
        const std::wstring name = Utf8ToWide(a.exeName.c_str());

        LVITEMW item;
        std::memset(&item, 0, sizeof(item));
        item.mask     = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
        item.iItem    = row;
        item.iSubItem = 0;
        item.pszText  = const_cast<LPWSTR>(name.c_str());
        item.iImage   = GetExeIconIndex(a.exePath);   // -1 = 无图标，正常显示
        item.lParam   = static_cast<LPARAM>(a.pid);
        const int inserted = static_cast<int>(
            SendMessageW(g_hAppRateList, LVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&item)));
        if (inserted < 0) { ++row; continue; }

        if (!prevName.empty() && name == prevName) { restoreSel = inserted; }
        if (anchorPid >= 0 && static_cast<int>(a.pid) == anchorPid) { anchorRow = inserted; }

        wchar_t cells[4][48];
        FormatRateCell(a.rxBps, cells[0], 48);
        FormatRateCell(a.txBps, cells[1], 48);
        FormatBytesCell(a.rxTotal, cells[2], 48);
        FormatBytesCell(a.txTotal, cells[3], 48);

        LVITEMW sub;
        std::memset(&sub, 0, sizeof(sub));
        sub.mask = LVIF_TEXT;
        for (int c = 0; c < 4; ++c) {
            sub.iItem = inserted;
            sub.iSubItem = c + 1;
            sub.pszText = cells[c];
            SendMessageW(g_hAppRateList, LVM_SETITEMW, 0, reinterpret_cast<LPARAM>(&sub));
        }
        ++row;
    }

    if (restoreSel >= 0) {
        LVITEMW sel;
        std::memset(&sel, 0, sizeof(sel));
        sel.mask = LVIF_STATE;
        sel.state = LVIS_SELECTED | LVIS_FOCUSED;
        sel.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
        SendMessageW(g_hAppRateList, LVM_SETITEMSTATE, static_cast<WPARAM>(restoreSel),
                     reinterpret_cast<LPARAM>(&sel));
    } else if (GetSelectedAppRow() < 0 && !rates.empty()) {
        // 首次进来时自动选第一行，右侧面板才有内容
        LVITEMW sel;
        std::memset(&sel, 0, sizeof(sel));
        sel.mask = LVIF_STATE;
        sel.state = LVIS_SELECTED | LVIS_FOCUSED;
        sel.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
        SendMessageW(g_hAppRateList, LVM_SETITEMSTATE, 0, reinterpret_cast<LPARAM>(&sel));
        restoreSel = 0;
    }

    SendMessageW(g_hAppRateList, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hAppRateList, NULL, TRUE);

    // v2.0.9：把锚点行滚回顶部（>0 才需要；第一行本来就在顶上）
    if (anchorRow > 0) {
        RECT rc;
        rc.left = LVIR_BOUNDS;
        if (SendMessageW(g_hAppRateList, LVM_GETITEMRECT,
                         static_cast<WPARAM>(anchorRow),
                         reinterpret_cast<LPARAM>(&rc))) {
            SendMessageW(g_hAppRateList, LVM_SCROLL, 0, rc.top);
        }
    }

    // 右侧面板跟着选中行刷新
    const int sel = GetSelectedAppRow();
    const weaknet::AppRate* pick = NULL;
    for (size_t i = 0, r = 0; i < rates.size(); ++i) {
        if (onlyActive && rates[i].rxBps == 0 && rates[i].txBps == 0) { continue; }
        if (static_cast<int>(r) == sel) { pick = &rates[i]; break; }
        ++r;
    }
    UpdateInfoPanel(pick);
}

void UpdateHotkeyStatusText();

void UpdateHotkeyEdits()
{
    SetWindowTextW(g_hHotkeyBlock, Utf8ToWide(weaknet::FormatHotkey(g_blockHotkey).c_str()).c_str());
    SetWindowTextW(g_hHotkeyUnblock, Utf8ToWide(weaknet::FormatHotkey(g_unblockHotkey).c_str()).c_str());
    UpdateHotkeyStatusText();
}

void UpdateButtons()
{
    EnableWindow(g_hStart, !g_running);
    EnableWindow(g_hStop, g_running);
    EnableWindow(g_hDuration, !g_running);
    EnableWindow(g_hDir, !g_running);
    EnableWindow(g_hProto, !g_running);
    EnableWindow(g_hVerbose, !g_running);
    EnableWindow(g_hHotkeyEnabled, !g_running);
    EnableWindow(g_hBtnSetBlock, !g_running && g_hotkeyEnabled);
    EnableWindow(g_hBtnSetUnblock, !g_running && g_hotkeyEnabled);

    // “丢什么”的三选一：运行中全部置灰，未运行时按模式决定端口框/进程框是否可编辑
    const bool editable = !g_running;
    const bool byProcess = (g_targetMode == TargetMode::ByProcess);
    const bool byPort    = (g_targetMode == TargetMode::ByPort);

    EnableWindow(g_hRadioByProcess, editable);
    EnableWindow(g_hRadioByPort, editable);
    EnableWindow(g_hAllPorts, editable);
    EnableWindow(g_hPort, editable && byPort);
    EnableWindow(g_hProcess, editable && byProcess);
    // 进程模式下“端口匹配”不起作用（引擎按报文方向自动取本机端口），一并置灰
    EnableWindow(g_hMatch, editable && byPort);
}

void UpdateStatsDisplay()
{
    const Stats stats = g_session.GetStats();
    const double seconds = static_cast<double>(g_session.ElapsedMs()) / 1000.0;

    // 概率丢包模式下，把“设置的丢包率”和“实测丢包率”一起显示 ——
    // 否则用户没法确认设置是否真的生效（这是这个功能最容易踩的疑问）。
    const weaknet::Config cfg = g_session.GetConfig();
    const bool probabilistic = weaknet::IsProbabilisticLoss(cfg);
    std::string lossText;
    if (probabilistic) {
        char loss[160] = { 0 };
        // 只在有样本的方向上算实测值，避免 0/0
        char downPart[64] = { 0 };
        char upPart[64]   = { 0 };
        if (stats.matchedDown > 0) {
            std::snprintf(downPart, sizeof(downPart), "%.0f",
                          100.0 * static_cast<double>(stats.droppedDown) /
                          static_cast<double>(stats.matchedDown));
        } else {
            std::snprintf(downPart, sizeof(downPart), "--");
        }
        if (stats.matchedUp > 0) {
            std::snprintf(upPart, sizeof(upPart), "%.0f",
                          100.0 * static_cast<double>(stats.droppedUp) /
                          static_cast<double>(stats.matchedUp));
        } else {
            std::snprintf(upPart, sizeof(upPart), "--");
        }
        std::snprintf(loss, sizeof(loss),
                      "  |  丢包率 下行 %u%%→%s%% / 上行 %u%%→%s%%",
                      cfg.lossDownPercent, downPart, cfg.lossUpPercent, upPart);
        lossText = loss;
    }

    char narrow[1024] = { 0 };
    if (g_running && g_session.IsProcessMode()) {
        // 进程模式：把“放行了多少”也显示出来，否则只看丢弃数会以为程序没在工作。
        // 这一行是**单行**控件，字段刻意精简（不放“其它”），确保常见数值下不超宽；
        // 极端数值仍有 SS_ENDELLIPSIS 兜底，绝不会画到控件外。
        std::snprintf(narrow, sizeof(narrow),
                      "丢弃 %s 包 / %.2f MiB  |  放行 %s 包  |  目标端口 %llu 个  |  "
                      "TCP %s / UDP %s  |  %.1f pps%s",
                      FormatCount(stats.packets).c_str(),
                      static_cast<double>(stats.bytes) / (1024.0 * 1024.0),
                      FormatCount(stats.forwarded).c_str(),
                      static_cast<unsigned long long>(stats.portCount),
                      FormatCount(stats.tcp).c_str(), FormatCount(stats.udp).c_str(),
                      (seconds > 0.0) ? (static_cast<double>(stats.packets) / seconds) : 0.0,
                      lossText.c_str());
    } else {
        std::snprintf(narrow, sizeof(narrow),
                      "丢弃 %s 包 / %.2f MiB  |  TCP %s / UDP %s / 其它 %s  |  %.1f pps%s",
                      FormatCount(stats.packets).c_str(),
                      static_cast<double>(stats.bytes) / (1024.0 * 1024.0),
                      FormatCount(stats.tcp).c_str(), FormatCount(stats.udp).c_str(),
                      FormatCount(stats.other).c_str(),
                      (seconds > 0.0) ? (static_cast<double>(stats.packets) / seconds) : 0.0,
                      lossText.c_str());
    }
    SetStatsText(Utf8ToWide(narrow));

    wchar_t status[640] = { 0 };
    if (g_running) {
        // 刻意不在这里重复过滤器字符串：上面「过滤器」那一行已经完整显示了，
        // 而过滤器可以很长（进程模式是 "(tcp or udp)"，端口模式能列很多端口），
        // 塞进这条单行状态栏会超宽。这里只留“状态 + 运行时长”。
        char narrowStatus[640] = { 0 };
        std::snprintf(narrowStatus, sizeof(narrowStatus),
                      "断网中（拦截中）…  已运行 %.1f 秒",
                      seconds);
        wcsncpy_s(status, Utf8ToWide(narrowStatus).c_str(), _TRUNCATE);
    } else if (stats.packets > 0 || seconds > 0.0) {
        // 退出原因用**短文案**：StopReasonText() 的完整说明是给命令行用的，
        // 塞进这条 426px 的单行状态栏会超宽被截断，这里只取关键几个字。
        const char* shortReason = "未知";
        switch (g_session.GetStopReason()) {
        case weaknet::StopReason::User:        shortReason = "手动停止"; break;
        case weaknet::StopReason::Duration:    shortReason = "时长到期"; break;
        case weaknet::StopReason::ConsoleExit: shortReason = "控制台关闭"; break;
        case weaknet::StopReason::Error:       shortReason = "异常结束"; break;
        case weaknet::StopReason::None:
        default:                               shortReason = "未知"; break;
        }
        char narrowStatus[640] = { 0 };
        std::snprintf(narrowStatus, sizeof(narrowStatus),
                      "已联网（已停止）  运行 %.1f 秒  原因：%s",
                      seconds, shortReason);
        wcsncpy_s(status, Utf8ToWide(narrowStatus).c_str(), _TRUNCATE);
    } else {
        wcsncpy_s(status, L"未运行（联网状态）。设置好参数后点“开始拦截”，或用快捷键断网。", _TRUNCATE);
    }
    SetStatusText(status);
}

// -----------------------------------------------------------------------------
//  全局快捷键：注册 / 注销 / 捕获
// -----------------------------------------------------------------------------

// 两个快捷键是否是同一个键（修饰键 + 主键都相同）
bool SameHotkey(const HotkeySpec& a, const HotkeySpec& b)
{
    return !a.empty() && !b.empty() && a.vk == b.vk && a.modifiers == b.modifiers;
}

// 断网与联网绑成同一个键 => 切换语义（第一下断网、第二下联网）
bool IsToggleHotkey()
{
    return SameHotkey(g_blockHotkey, g_unblockHotkey);
}

void UnregisterHotkeys()
{
    if (g_hotkeyRegistered[kHotkeyIdToggle] != kHotkeyViaNone) {
        weaknet::UnregisterGlobalHotkey(g_mainWindow, kHotkeyIdToggle);
        g_hotkeyRegistered[kHotkeyIdToggle] = kHotkeyViaNone;
    }
    if (g_hotkeyRegistered[kHotkeyIdBlock] != kHotkeyViaNone) {
        weaknet::UnregisterGlobalHotkey(g_mainWindow, kHotkeyIdBlock);
        g_hotkeyRegistered[kHotkeyIdBlock] = kHotkeyViaNone;
    }
    if (g_hotkeyRegistered[kHotkeyIdUnblock] != kHotkeyViaNone) {
        weaknet::UnregisterGlobalHotkey(g_mainWindow, kHotkeyIdUnblock);
        g_hotkeyRegistered[kHotkeyIdUnblock] = kHotkeyViaNone;
    }
}

// 鼠标侧键的立即派发：定义在 StartDrop/StopDrop 之后
void DispatchMouseHotkey(unsigned vk);

// 结束快捷键捕获（定义在 StartCapture 之后）
void FinishCapture(unsigned vk);

// 统一的“按下快捷键”处理：断网键 / 联网键 / 切换键都走这里，
// 这样鼠标侧键（钩子通道）与键盘热键（WM_HOTKEY 通道）行为完全一致。
// 实现放在 StartDrop/StopDrop 之后（它们在这之前还没定义）。
void HandleHotkeyPressed(int id, const char* how);

// 把一个“已经确认被按下的侧键”派发出去（捕获中则用于录入）。
// 调用来源有两个，都是**异步**的，所以在这里装卸钩子是安全的：
//   1) 钩子 PostMessage 过来的 MouseHotkeyNotifyMessage（主通道）；
//   2) WM_TIMER 里的 PollMouseHotkey（兜底，防止消息因故丢失）。
void DispatchMouseHotkey(unsigned vk)
{
    if (g_captureBusy) {
        // 正在处理上一个按键（可能在 CancelCapture 里重装钩子）：
        // 这里必须挡住，否则会重入
        return;
    }
    if (g_capturing != 0) {
        FinishCapture(vk);
        return;
    }
    if (!g_hotkeyEnabled) {
        return;
    }
    if (IsToggleHotkey() && vk == g_blockHotkey.vk) {
        if (g_hotkeyRegistered[kHotkeyIdToggle] == kHotkeyViaHook) {
            HandleHotkeyPressed(kHotkeyIdToggle, "侧键");
        }
    } else if (vk == g_blockHotkey.vk) {
        if (g_hotkeyRegistered[kHotkeyIdBlock] == kHotkeyViaHook) {
            HandleHotkeyPressed(kHotkeyIdBlock, "侧键");
        }
    } else if (vk == g_unblockHotkey.vk) {
        if (g_hotkeyRegistered[kHotkeyIdUnblock] == kHotkeyViaHook) {
            HandleHotkeyPressed(kHotkeyIdUnblock, "侧键");
        }
    }
}

// 鼠标侧键：优先尝试 RegisterHotKey（成功就走 WM_HOTKEY/WM_XBUTTON）；
// 失败也不打紧 —— 钩子通道已经在跑，记成 kHotkeyViaHook 让它接管。
bool RegisterOneHotkey(int id, const HotkeySpec& spec, const char* what)
{
    unsigned long errorCode = 0;
    if (weaknet::RegisterGlobalHotkey(g_mainWindow, id, spec, errorCode)) {
        g_hotkeyRegistered[id] = kHotkeyViaRegister;
        weaknet::DebugLogf("热键注册成功：id=%d %s = %s（系统 RegisterHotKey 通道）",
                           id, what, weaknet::FormatHotkey(spec).c_str());
        return true;
    }

    if (weaknet::IsMouseHotkey(spec.vk)) {
        // 侧键注册失败是常见情况：钩子通道照样能收到，功能不受影响
        g_hotkeyRegistered[id] = kHotkeyViaHook;
        weaknet::DebugLogf("热键注册失败但属鼠标侧键：id=%d %s = %s（错误码 %lu）"
                           "-> 改用鼠标钩子通道",
                           id, what, weaknet::FormatHotkey(spec).c_str(), errorCode);
        char buffer[256] = { 0 };
        std::snprintf(buffer, sizeof(buffer),
                      "%s %s 未能交给系统热键（错误码 %lu），已改用鼠标钩子监听，功能不受影响。",
                      what, weaknet::FormatHotkey(spec).c_str(), errorCode);
        GuiLog(LogLevel::Info, buffer, NULL);
        return true;
    }

    g_hotkeyRegistered[id] = kHotkeyViaNone;
    weaknet::DebugLogf("热键注册失败：id=%d %s = %s（错误码 %lu），可能已被其他程序占用",
                       id, what, weaknet::FormatHotkey(spec).c_str(), errorCode);
    char buffer[280] = { 0 };
    std::snprintf(buffer, sizeof(buffer),
                  "%s %s 注册失败（错误码 %lu），可能已被其他程序占用。",
                  what, weaknet::FormatHotkey(spec).c_str(), errorCode);
    GuiLog(LogLevel::Warning, buffer, NULL);
    return false;
}

void RegisterHotkeys()
{
    UnregisterHotkeys();

    if (!g_hotkeyEnabled) {
        GuiLog(LogLevel::Info, "全局快捷键已关闭（可在界面上重新勾选）。", NULL);
        weaknet::SetMouseHotkeyListener(false);
        UpdateHotkeyStatusText();     // 状态行要说明“已关闭”，别让人以为还能按
        return;
    }

    // 鼠标侧键的监听通道：只要启用了快捷键就常开，这样侧键一定能收到
    if (weaknet::SetMouseHotkeyListener(true)) {
        // 侧键按下 -> 钩子只 PostMessage（异步）-> 我们自己的消息处理。
        // 绝不在钩子回调里同步回调本函数：这里会 Unhook/SetHook，
        // 从钩子自己的回调里装卸钩子会把系统鼠标卡死（v1.2.3 修的就是这个）。
        weaknet::SetMouseHotkeyNotifyWindow(g_mainWindow);
    }

    if (IsToggleHotkey()) {
        // 断网与联网是同一个键：注册一个，按一下断、再按一下连
        if (RegisterOneHotkey(kHotkeyIdToggle, g_blockHotkey, "切换键")) {
            char buffer[320] = { 0 };
            std::snprintf(buffer, sizeof(buffer),
                          "切换键已生效：%s（断网与联网绑成同一个键，按一下断网、再按一下联网）",
                          weaknet::FormatHotkey(g_blockHotkey).c_str());
            GuiLog(LogLevel::Info, buffer, NULL);
        }
        // 注册结果会体现在状态行上（失败时明确提示，不再假装成功）
        UpdateHotkeyStatusText();
        return;
    }

    if (!g_blockHotkey.empty()) {
        if (RegisterOneHotkey(kHotkeyIdBlock, g_blockHotkey, "断网快捷键")) {
            GuiLog(LogLevel::Info,
                   ("断网快捷键已生效：" + weaknet::FormatHotkey(g_blockHotkey)).c_str(), NULL);
        }
    }

    if (!g_unblockHotkey.empty()) {
        if (RegisterOneHotkey(kHotkeyIdUnblock, g_unblockHotkey, "联网快捷键")) {
            GuiLog(LogLevel::Info,
                   ("联网快捷键已生效：" + weaknet::FormatHotkey(g_unblockHotkey)).c_str(), NULL);
        }
    }
    UpdateHotkeyStatusText();
}

bool IsModifierKey(unsigned vk)
{
    return vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL ||
           vk == VK_MENU    || vk == VK_LMENU    || vk == VK_RMENU    ||
           vk == VK_SHIFT   || vk == VK_LSHIFT   || vk == VK_RSHIFT   ||
           vk == VK_LWIN    || vk == VK_RWIN;
}

// 刷新热键区的自检文本：把“当前用的是哪个键 / 是否正在捕获”写在界面上。
// 做成可见文本（而不是只写日志）有两个好处：用户一眼能看清状态，尤其是
// “以为还在等按键、其实已经结束了”；自动化测试也可以直接读它做断言。
void UpdateHotkeyStatusText()
{
    if (g_hHotkeyStatus == NULL) {
        return;
    }
    char buffer[512] = { 0 };
    if (g_capturing != 0) {
        std::snprintf(buffer, sizeof(buffer),
                      "%s捕获中：按一个按键（单键或组合键都行）或鼠标侧键，Esc 取消；"
                      "按键不合法时会提示并继续等待（已拒绝 %d 次）",
                      (g_capturing == 1) ? "设置断网键 - " : "设置联网键 - ",
                      g_captureRejects);
    } else if (!g_hotkeyEnabled) {
        // 这一支必须排在“注册结果”判断之前：热键功能被关掉时本来就什么都没注册，
        // 如果先去判断“注册成功没有”，会误报成“未能注册、可能被占用”。
        std::snprintf(buffer, sizeof(buffer),
                      "全局快捷键已关闭（勾选“启用全局快捷键”后生效）");
    } else if (IsToggleHotkey()) {
        // 关键：这里必须反映**真实注册结果**，不能只看配置值。
        // 否则注册失败（例如键被别的程序、或另一个 WeakNetTool 实例占用）时，
        // 界面照样显示“切换键 K”，看起来设置成功了，但按键其实没反应 ——
        // 这是最容易让人以为“设置不了”的一种情况。
        const bool registered = (g_hotkeyRegistered[kHotkeyIdToggle] != kHotkeyViaNone);
        if (registered) {
            std::snprintf(buffer, sizeof(buffer),
                          "当前：切换键 %s（按一下断网、再按一下联网）",
                          weaknet::FormatHotkey(g_blockHotkey).c_str());
        } else {
            std::snprintf(buffer, sizeof(buffer),
                          "当前：切换键 %s —— ⚠ 未能注册（可能被别的程序或另一个 "
                          "WeakNetTool 实例占用），按下不会有反应；详见下方日志",
                          weaknet::FormatHotkey(g_blockHotkey).c_str());
        }
    } else {
        std::snprintf(buffer, sizeof(buffer), "当前：断网 %s ／ 联网 %s",
                      weaknet::FormatHotkey(g_blockHotkey).c_str(),
                      weaknet::FormatHotkey(g_unblockHotkey).c_str());
    }
    SetWindowTextW(g_hHotkeyStatus, Utf8ToWide(buffer).c_str());
}

// 丢掉消息队列里已经排队的键盘消息。
// 用途：进入捕获前把上一次的残留键（尤其是按住不放的自动重复）清干净，
// 否则它们会在捕获开始后立刻被消费，表现成“刚点设置就自己结束了”。
void FlushPendingKeyMessages()
{
    MSG msg;
    // PM_NOYIELD 避免把另一个线程正等待的消息抢走
    while (PeekMessageW(&msg, NULL, WM_KEYFIRST, WM_KEYLAST, PM_REMOVE | PM_NOYIELD)) {
        // 丢弃
    }
    while (PeekMessageW(&msg, NULL, WM_SYSKEYDOWN, WM_SYSKEYDOWN, PM_REMOVE | PM_NOYIELD)) {
        // 丢弃
    }
    while (PeekMessageW(&msg, NULL, WM_SYSKEYUP, WM_SYSKEYUP, PM_REMOVE | PM_NOYIELD)) {
        // 丢弃
    }
    while (PeekMessageW(&msg, NULL, WM_SYSCHAR, WM_SYSCHAR, PM_REMOVE | PM_NOYIELD)) {
        // 丢弃
    }
    while (PeekMessageW(&msg, NULL, WM_SYSDEADCHAR, WM_SYSDEADCHAR, PM_REMOVE | PM_NOYIELD)) {
        // 丢弃
    }
}

void StartCapture(int which)
{
    g_capturing = which;
    g_captureRejects = 0;
    g_captureLastReject = 0;
    weaknet::DebugLogf("开始捕获快捷键：目标=%s（Esc 取消）",
                       (which == 1) ? "断网键" : "联网键");
    if (which == 1) {
        SetWindowTextW(g_hBtnSetBlock, L"请按键…");
    } else {
        SetWindowTextW(g_hBtnSetUnblock, L"请按键…");
    }
    // 把焦点给主窗口：这样接下来的按键会作为 WM_KEYDOWN/WM_SYSKEYDOWN
    // 直接送到主窗口过程（不依赖消息循环拦截，行为更可预期）。
    SetFocus(g_mainWindow);

    // 丢掉上一次遗留的键盘消息。否则：按住 Esc 不放时，其自动重复产生的
    // 一串 WM_KEYDOWN 会堆在队列里，一点“设置”就立刻被它们消费掉，
    // 表现成“刚点设置就自己结束了”。
    FlushPendingKeyMessages();

    // ---- 关键：捕获期间必须把已注册的全局热键**全部注销** --------------------
    // 原因（这是“想把两个快捷键设成同一个键却设不上”的真正原因）：
    //   RegisterHotKey 注册过的键会被 Windows **吃掉**，系统只投递 WM_HOTKEY，
    //   **不再投递 WM_KEYDOWN**。于是想按 F10 把联网键设成和断网键一样时：
    //     按下 F10 -> 走 WM_HOTKEY -> 直接触发“断网”，捕获根本收不到这个键。
    //   注销之后按键恢复成普通键盘消息（WM_KEYDOWN），就能正常录入了。
    // 捕获结束时（取消/提交）会在 CancelCapture 里重新注册。
    UnregisterHotkeys();
    g_hotkeysSuspended = true;

    // 鼠标侧键：开启钩子的“捕获模式”，这样点侧键能被录入，
    // 同时把它在前台程序（浏览器后退/前进）里的动作吃掉
    weaknet::SetMouseHotkeyListener(true);
    weaknet::SetMouseHotkeyCapture(true);
    UpdateHotkeyStatusText();

    GuiLog(LogLevel::Info,
           (which == 1) ? "正在设置“断网”快捷键：按一个按键（单键如 F8、或组合键如 Ctrl+Alt+B），"
                          "也可以点一下鼠标侧键。（Esc 取消）"
                        : "正在设置“联网”快捷键：按一个按键（单键如 F8、或组合键如 Ctrl+Alt+B），"
                          "也可以点一下鼠标侧键。（Esc 取消）", NULL);
    GuiLog(LogLevel::Info,
           "提示：按下的键不合法时会提示并继续等待，不会结束设置；"
           "单键会把该键从整个系统里独占，建议用 F1~F24 这类不常用的键；"
           "断网与联网设成同一个键就是切换键（按一下断、再按一下连）。", NULL);
    DrainLog();
}

// 取消捕获（按钮文字复原、关掉钩子捕获态、恢复热键注册）
void CancelCapture()
{
    const bool wasSuspended = g_hotkeysSuspended;
    g_capturing = 0;
    g_captureRejects = 0;
    g_hotkeysSuspended = false;
    SetWindowTextW(g_hBtnSetBlock, L"设置");
    SetWindowTextW(g_hBtnSetUnblock, L"设置");
    weaknet::SetMouseHotkeyCapture(false);
    weaknet::DebugLogf("快捷键捕获已取消（Esc / 主动取消）");

    // 把捕获期间注销掉的全局热键恢复回来。
    // 注意：CommitCapture 是先改 g_blockHotkey/g_unblockHotkey 再调用本函数的，
    // 所以这里注册的就是**新值**；它的调用方随后还会再注册一次（幂等，无害）。
    // 热键功能本来就关着时不必恢复（也没东西可恢复），免得白写一条日志。
    if (wasSuspended && g_hotkeyEnabled) {
        RegisterHotkeys();
    }
    UpdateHotkeyStatusText();
}

// 拿到一个合法按键 / 侧键，写入配置并生效
void CommitCapture(int id, const HotkeySpec& spec)
{
    const bool which = (id == kHotkeyIdBlock);
    const HotkeySpec other = which ? g_unblockHotkey : g_blockHotkey;
    const bool willBecomeToggle =
        (other.vk == spec.vk && other.modifiers == spec.modifiers && !other.empty());

    if (which) {
        g_blockHotkey = spec;
    } else {
        g_unblockHotkey = spec;
    }

    CancelCapture();
    UpdateHotkeyEdits();

    weaknet::DebugLogf("快捷键已提交：%s = %s（%s）",
                       which ? "断网键" : "联网键",
                       weaknet::FormatHotkey(spec).c_str(),
                       willBecomeToggle ? "与另一键相同 -> 切换键" : "独立键");

    char buffer[320] = { 0 };
    std::snprintf(buffer, sizeof(buffer), "%s 已设置为：%s",
                  which ? "断网快捷键" : "联网快捷键",
                  weaknet::FormatHotkey(spec).c_str());
    GuiLog(LogLevel::Info, buffer, NULL);

    // 单键（无修饰键）会把该键从整个系统里独占：明确提示一次，
    // 免得用户绑了字母键之后发现打字打不出来了。
    if (spec.modifiers == 0 && !weaknet::IsMouseHotkey(spec.vk)) {
        GuiLog(LogLevel::Warning,
               ("注意：这是单键绑定，该键已被本程序全局独占，"
                "在其他程序里将不再产生输入。想恢复请重新设置成组合键。"
                "（当前：" + weaknet::FormatHotkey(spec) + "）").c_str(), NULL);
    }

    // 记到 ini 并立即重新注册
    IniWriteString(L"Hotkey", L"Block", Utf8ToWide(weaknet::FormatHotkey(g_blockHotkey).c_str()));
    IniWriteString(L"Hotkey", L"Restore", Utf8ToWide(weaknet::FormatHotkey(g_unblockHotkey).c_str()));
    RegisterHotkeys();

    if (willBecomeToggle || IsToggleHotkey()) {
        std::snprintf(buffer, sizeof(buffer),
                      "断网与联网已绑定为同一个键（%s）：按一下断网、再按一下联网。",
                      weaknet::FormatHotkey(g_blockHotkey).c_str());
        GuiLog(LogLevel::Info, buffer, NULL);
    }
    DrainLog();
}

// 结束捕获（键盘按键或鼠标侧键都会走到这里）。
// 约定：**这里绝不弹模态对话框**。捕获期间弹模态框会：
//   1) 让“Esc 取消”看起来失效（模态框挡住了按键处理）；
//   2) 和 WH_MOUSE_LL 钩子回调互相重入（钩子回调在本线程 -> MessageBox 又泵消息
//      -> 钩子再次回调……），把本线程乃至全系统的鼠标输入拖死。
// 因此不合法时只记日志并**继续等待**，直到拿到合法键或用户按 Esc。
void FinishCapture(unsigned vk)
{
    if (g_capturing == 0) {
        return;                       // 没在捕获
    }
    if (g_captureBusy) {
        return;                       // 防重入：正在处理上一个按键
    }
    if (IsModifierKey(vk)) {
        return;                       // 只按了修饰键：继续等待主键，不算结束
    }

    g_captureBusy = true;
    const int which = g_capturing;

    if (vk == VK_ESCAPE) {
        CancelCapture();
        g_captureBusy = false;
        GuiLog(LogLevel::Info, "已取消快捷键设置（快捷键保持不变）。", NULL);
        DrainLog();
        return;
    }

    HotkeySpec spec;
    spec.vk = vk;
    // 鼠标侧键不吃键盘修饰键（按侧键时手上可能有别的键按着，不该混进来）
    if (!weaknet::IsMouseHotkey(vk)) {
        if (GetKeyState(VK_CONTROL) & 0x8000) { spec.modifiers |= weaknet::kHotkeyCtrl; }
        if (GetKeyState(VK_MENU)    & 0x8000) { spec.modifiers |= weaknet::kHotkeyAlt; }
        if (GetKeyState(VK_SHIFT)   & 0x8000) { spec.modifiers |= weaknet::kHotkeyShift; }
        if ((GetKeyState(VK_LWIN) | GetKeyState(VK_RWIN)) & 0x8000) {
            spec.modifiers |= weaknet::kHotkeyWin;
        }
    }

    std::string err;
    if (!weaknet::IsHotkeyAcceptable(spec, err)) {
        // 不结束捕获，只提示。同一个键按住不放时只提示一次（去掉自动重复的刷屏）
        ++g_captureRejects;
        // 用一个简单标记避免重复日志：把上次被拒的按键记在 g_captureLastReject
        const bool firstTime = (g_captureLastReject != static_cast<int>(vk));
        g_captureLastReject = static_cast<int>(vk);
        if (firstTime) {
            char buffer[420] = { 0 };
            std::snprintf(buffer, sizeof(buffer),
                          "这个键不能单独做快捷键：%s（继续等待，或按 Esc 取消）",
                          err.c_str());
            GuiLog(LogLevel::Warning, buffer, NULL);
        }
        UpdateHotkeyStatusText();
        g_captureBusy = false;
        DrainLog();
        return;
    }

    g_captureRejects = 0;
    g_captureLastReject = 0;
    CommitCapture(which, spec);
    g_captureBusy = false;
}

// -----------------------------------------------------------------------------
//  配置读写（界面状态 + 快捷键）
// -----------------------------------------------------------------------------
// v2.0.11：把某个 EDIT 的文本原样存进 ini（用于"数字 + 单位"里的数字部分）。
// 不能只存算出来的字节数：加载时把 204800 这种数字填回输入框，
// 而输入框里的裸数字按 KB/s 解析 —— 每次重启速率都会膨胀 1024 倍。
void SaveEditText(const wchar_t* key, HWND edit)
{
    if (edit == NULL) { return; }
    IniWriteString(L"Main", key, GetWideText(edit));
}

// v2.0.11：恢复"速率 = 数字 + 单位"。
// 优先用存下来的数字原文 + 单位下标；老配置没有这两个键时，
// 再把字节/秒折算成**能整除的最大单位**（同样不能把字节数直接当数字填回去）。
void RestoreRateField(const wchar_t* textKey, const wchar_t* unitKey,
                       HWND edit, HWND combo, unsigned long long bpsFallback)
{
    const std::wstring saved = IniReadString(L"Main", textKey, L"");
    if (!saved.empty()) {
        SetWindowTextW(edit, saved.c_str());
        int unit = IniReadInt(L"Main", unitKey, 1);
        if (unit < 0 || unit > 2) { unit = 1; }
        SendMessageW(combo, CB_SETCURSEL, static_cast<WPARAM>(unit), 0);
        return;
    }
    unsigned long long value = bpsFallback;   // 0 = 不限
    int unit = 1;                                      // 默认 KB/s（与历史行为一致）
    if (value > 0) {
        if (value % (1024 * 1024) == 0) { value /= (1024 * 1024); unit = 2; }
        else if (value % 1024 == 0)     { value /= 1024;          unit = 1; }
        else                            { unit = 0; }
    }
    wchar_t buffer[32] = { 0 };
    _snwprintf_s(buffer, sizeof(buffer) / sizeof(buffer[0]), _TRUNCATE, L"%llu", value);
    SetWindowTextW(edit, buffer);
    SendMessageW(combo, CB_SETCURSEL, static_cast<WPARAM>(unit), 0);
}

unsigned long long ReadLegacyRateBps(const wchar_t* bpsKey, const wchar_t* kbKey)
{
    const std::wstring saved = IniReadString(L"Main", bpsKey, L"");
    if (!saved.empty()) {
        wchar_t* end = NULL;
        const unsigned long long value = _wcstoui64(saved.c_str(), &end, 10);
        return (end != saved.c_str() && *end == L'\0' && saved[0] != L'-') ? value : 0;
    }
    const int oldKb = IniReadInt(L"Main", kbKey, 0);
    return (oldKb > 0) ? static_cast<unsigned long long>(oldKb) * 1024ULL : 0;
}

bool SaveSettings()
{
    Config cfg;
    std::string error;
    if (!ReadConfigFromUi(cfg, error)) {
        weaknet::DebugLogf("配置未保存（输入无效）：%s", error.c_str());
        IniWriteInt(L"Hotkey", L"Enabled", g_hotkeyEnabled ? 1 : 0);
        IniWriteString(L"Hotkey", L"Block", Utf8ToWide(weaknet::FormatHotkey(g_blockHotkey).c_str()));
        IniWriteString(L"Hotkey", L"Restore", Utf8ToWide(weaknet::FormatHotkey(g_unblockHotkey).c_str()));
        return false;
    }
    unsigned long long rateDown = 0, rateUp = 0;
    if (!weaknet::ParseRate(RateFieldText(g_hRateDown, g_hRateUnitDown), rateDown, error) ||
        !weaknet::ParseRate(RateFieldText(g_hRateUp, g_hRateUnitUp), rateUp, error)) {
        return false;
    }
    IniWriteInt(L"Main", L"Mode", static_cast<int>(g_targetMode));
    IniWriteInt(L"Main", L"AllPorts", (g_targetMode == TargetMode::AllPorts) ? 1 : 0);
    IniWriteString(L"Main", L"Port", GetWideText(g_hPort));
    IniWriteString(L"Main", L"Process", GetWideText(g_hProcess));
    IniWriteString(L"Main", L"Duration", GetWideText(g_hDuration));
    IniWriteInt(L"Main", L"Dir", static_cast<int>(SendMessageW(g_hDir, CB_GETCURSEL, 0, 0)));
    IniWriteInt(L"Main", L"Match", static_cast<int>(SendMessageW(g_hMatch, CB_GETCURSEL, 0, 0)));
    IniWriteInt(L"Main", L"Proto", static_cast<int>(SendMessageW(g_hProto, CB_GETCURSEL, 0, 0)));
    IniWriteInt(L"Main", L"Verbose", IsChecked(g_hVerbose) ? 1 : 0);
    // 输入已整体校验；保存输入框原值，单向运行时另一方向的设置仍可恢复。
    {
        unsigned down = 0, up = 0;
        std::string parseError;
        weaknet::ParseLossPercent(GetUtf8Text(g_hLossDown), down, parseError);
        weaknet::ParseLossPercent(GetUtf8Text(g_hLossUp), up, parseError);
        IniWriteInt(L"Main", L"LossDown", static_cast<int>(down));
        IniWriteInt(L"Main", L"LossUp", static_cast<int>(up));
    }
    // v1.5.0：限速（v1.6.0 起按字节/秒存储，用新键名 Bps 以免和旧的 KB/s 混淆）
    {
        IniWriteString(L"Main", L"RateDownBps", std::to_wstring(rateDown));
        // v2.0.11：单位下拉也一起记住（0=B/s 1=KB/s 2=MB/s）
        IniWriteInt(L"Main", L"RateUnitDown",
                    static_cast<int>(SendMessageW(g_hRateUnitDown, CB_GETCURSEL, 0, 0)));
        IniWriteInt(L"Main", L"RateUnitUp",
                    static_cast<int>(SendMessageW(g_hRateUnitUp, CB_GETCURSEL, 0, 0)));
        // ⚠ 光存字节/秒是不够的：加载时把 204800 这种数字填回输入框，
        // 而输入框里的裸数字按 KB/s 解析 —— 每次重启速率都会**膨胀 1024 倍**。
        // （这是个一直存在的 bug，v2.0.11 换成"数字+单位"结构后正好根治。）
        // 所以把用户实际填的**数字原文**也存下来，加载时优先用它 + 单位下标。
        SaveEditText(L"RateDownText", g_hRateDown);
        SaveEditText(L"RateUpText",   g_hRateUp);
        IniWriteString(L"Main", L"RateUpBps", std::to_wstring(rateUp));
    }

    IniWriteInt(L"Hotkey", L"Enabled", g_hotkeyEnabled ? 1 : 0);
    IniWriteString(L"Hotkey", L"Block", Utf8ToWide(weaknet::FormatHotkey(g_blockHotkey).c_str()));
    IniWriteString(L"Hotkey", L"Restore", Utf8ToWide(weaknet::FormatHotkey(g_unblockHotkey).c_str()));
    return true;
}

void LoadSettings()
{
    // 以下全是程序化改写控件：期间屏蔽 EN_CHANGE/BN_CLICKED 的联动副作用
    g_uiSyncing = true;

    // ---- 快捷键 ----
    g_hotkeyEnabled = IniReadInt(L"Hotkey", L"Enabled", 1) != 0;

    HotkeySpec spec;
    std::string err;
    const std::wstring blockText = IniReadString(L"Hotkey", L"Block", L"Ctrl+Alt+B");
    if (weaknet::ParseHotkey(WideToUtf8(blockText.c_str()), spec, err)) {
        g_blockHotkey = spec;
    } else {
        weaknet::ParseHotkey("Ctrl+Alt+B", g_blockHotkey, err);
    }
    const std::wstring restoreText = IniReadString(L"Hotkey", L"Restore", L"Ctrl+Alt+R");
    if (weaknet::ParseHotkey(WideToUtf8(restoreText.c_str()), spec, err)) {
        g_unblockHotkey = spec;
    } else {
        weaknet::ParseHotkey("Ctrl+Alt+R", g_unblockHotkey, err);
    }

    // ---- 界面状态（默认值刻意选择“贴合断网/联网场景”：默认全部端口） ----
    SetWindowTextW(g_hPort, IniReadString(L"Main", L"Port", L"8080").c_str());
    SetWindowTextW(g_hProcess, IniReadString(L"Main", L"Process", L"").c_str());
    SetWindowTextW(g_hDuration, IniReadString(L"Main", L"Duration", L"0").c_str());
    SendMessageW(g_hDir, CB_SETCURSEL,
                 static_cast<WPARAM>(IniReadInt(L"Main", L"Dir", 2)), 0);
    SendMessageW(g_hMatch, CB_SETCURSEL,
                 static_cast<WPARAM>(IniReadInt(L"Main", L"Match", 0)), 0);
    SendMessageW(g_hProto, CB_SETCURSEL,
                 static_cast<WPARAM>(IniReadInt(L"Main", L"Proto", 2)), 0);
    SetChecked(g_hVerbose, IniReadInt(L"Main", L"Verbose", 0) != 0);
    SetChecked(g_hHotkeyEnabled, g_hotkeyEnabled);

    // v1.3.0：丢包率。默认 100 —— 老配置里没有这两个键时，
    // 行为与升级前完全一致（100% 黑洞），不会因为升级就把丢包率改了。
    {
        wchar_t buffer[16] = { 0 };
        _snwprintf_s(buffer, sizeof(buffer) / sizeof(buffer[0]), _TRUNCATE, L"%d",
                     IniReadInt(L"Main", L"LossDown", 100));
        SetWindowTextW(g_hLossDown, buffer);

        _snwprintf_s(buffer, sizeof(buffer) / sizeof(buffer[0]), _TRUNCATE, L"%d",
                     IniReadInt(L"Main", L"LossUp", 100));
        SetWindowTextW(g_hLossUp, buffer);
    }

    // v1.5.0：限速（v1.6.0 起支持 300B / 200K / 2M）。默认 0 = 不限，
    // 老配置里没有这两个键时行为与升级前完全一致。
    {
        // 先读新的字节/秒键；没有就退回 v1.5.0 的 KB/s 键（×1024），保证老 ini 能用
        // v2.0.11：优先用"数字原文 + 单位下拉"恢复（这正是用户填的东西，不会有换算误差）；
        // 老配置没有这两个键时，再把字节/秒折算成合适的整单位 —— 注意**不能**把
        // 字节数直接填进输入框（裸数字按 KB/s 解析，会膨胀 1024 倍）。
        RestoreRateField(L"RateDownText", L"RateUnitDown",
                         g_hRateDown, g_hRateUnitDown,
                          ReadLegacyRateBps(L"RateDownBps", L"RateDown"));
        RestoreRateField(L"RateUpText", L"RateUnitUp",
                         g_hRateUp, g_hRateUnitUp,
                          ReadLegacyRateBps(L"RateUpBps", L"RateUp"));
    }

    // ---- “丢什么”的目标模式（三选一） ----------------------------------------
    //  优先读新的 Mode 键；如果是从 v1.1.0（只有 AllPorts）升级上来的老配置，
    //  就按老语义换算，保证升级后设置不丢。
    int mode = IniReadInt(L"Main", L"Mode", -1);
    if (mode < 0 || mode > 2) {
        const bool legacyAllPorts = IniReadInt(L"Main", L"AllPorts", 1) != 0;
        const bool hasProcess = !GetWideText(g_hProcess).empty();
        const bool hasPort    = !GetWideText(g_hPort).empty();
        if (legacyAllPorts) {
            mode = static_cast<int>(TargetMode::AllPorts);
        } else if (hasProcess) {
            mode = static_cast<int>(TargetMode::ByProcess);
        } else if (hasPort) {
            mode = static_cast<int>(TargetMode::ByPort);
        } else {
            mode = static_cast<int>(TargetMode::AllPorts);
        }
    }
    ApplyTargetMode(static_cast<TargetMode>(mode), false);

    UpdateHotkeyEdits();

    g_uiSyncing = false;
}

// -----------------------------------------------------------------------------
//  会话生命周期
// -----------------------------------------------------------------------------
void HandleSessionFinished()
{
    g_session.WaitForStop();
    g_running = false;

    const Stats stats = g_session.GetStats();
    const double seconds = static_cast<double>(g_session.ElapsedMs()) / 1000.0;
    char summary[512] = { 0 };
    std::snprintf(summary, sizeof(summary),
                  "本次断网结束：时长 %.1f 秒，丢弃 %s 包（TCP %s / UDP %s / 其它 %s），退出原因：%s",
                  seconds, FormatCount(stats.packets).c_str(),
                  FormatCount(stats.tcp).c_str(), FormatCount(stats.udp).c_str(),
                  FormatCount(stats.other).c_str(),
                  weaknet::StopReasonText(g_session.GetStopReason()));
    GuiLog(LogLevel::Info, summary, NULL);

    UpdateButtons();
    UpdateStatsDisplay();
}

void StartDrop(const char* trigger)
{
    if (g_running) {
        return;
    }

    Config cfg;
    std::string message;
    if (!ReadConfigFromUi(cfg, message)) {
        weaknet::DebugLogf("开始拦截被拒（参数有误）：%s", message.c_str());
        MessageBoxW(g_mainWindow, Utf8ToWide(message.c_str()).c_str(),
                    L"参数有误", MB_OK | MB_ICONWARNING);
        // 把焦点送到真正有问题的那一个输入框
        if (g_targetMode == TargetMode::ByProcess) {
            SetFocus(g_hProcess);
        } else {
            SetFocus(g_hPort);
        }
        return;
    }

    // 按钮与全局快捷键共用入口，避免快捷键启动后丢失本次有效设置。
    SaveSettings();

    g_sessionRefreshMs = cfg.processRefreshMs;
    weaknet::DebugLogf("开始拦截：触发=%s 模式=%s 过滤器=\"%s\"",
                       (trigger != NULL) ? trigger : "?",
                       cfg.processName.empty()
                           ? (cfg.ports.empty() ? "全部端口" : "指定端口")
                           : "按进程名",
                       weaknet::BuildFilter(cfg).c_str());
    const weaknet::StartResult started = g_session.Start(cfg, GuiLog, NULL);
    if (!started.ok) {
        weaknet::DebugLogf("启动失败：%s（错误码 %lu）",
                           started.message.c_str(),
                           static_cast<unsigned long>(started.errorCode));
        const std::wstring text = Utf8ToWide(started.message.c_str());
        GuiLog(LogLevel::Error, started.message.c_str(), NULL);
        MessageBoxW(g_mainWindow, text.c_str(), L"启动失败", MB_OK | MB_ICONERROR);
        UpdateButtons();
        UpdateStatsDisplay();
        return;
    }

    g_running = true;
    GuiLog(LogLevel::Info, trigger, NULL);
    GuiLog(LogLevel::Info, ("过滤器：" + g_session.FilterText()).c_str(), NULL);
    if (g_session.IsProcessMode()) {
        char note[320] = { 0 };
        std::snprintf(note, sizeof(note),
                      "按进程名丢包：%s（端口集合每 %u ms 重算一次；命中该进程本地端口的报文丢弃，"
                      "其余原样放行）。",
                      cfg.processName.c_str(), cfg.processRefreshMs);
        GuiLog(LogLevel::Info, note, NULL);
    }
    if (cfg.durationSec > 0) {
        char note[128] = { 0 };
        std::snprintf(note, sizeof(note), "将在 %ld 秒后自动恢复联网。", cfg.durationSec);
        GuiLog(LogLevel::Info, note, NULL);
    }
    UpdateButtons();
    UpdateFilterPreview();
    UpdateStatsDisplay();
    DrainLog();
}

void StopDrop(const char* trigger)
{
    if (!g_running) {
        return;
    }
    weaknet::DebugLogf("请求恢复联网：触发=%s", (trigger != NULL) ? trigger : "?");
    GuiLog(LogLevel::Info, trigger, NULL);
    DrainLog();
    g_session.Stop();
    g_running = false;
    HandleSessionFinished();
    weaknet::DebugLogf("已恢复联网：句柄已关闭，不再拦截任何报文");
    GuiLog(LogLevel::Info, "已恢复联网：句柄已关闭，不再拦截任何报文。", NULL);
    UpdateButtons();
    UpdateFilterPreview();
    DrainLog();
}

// 统一的“按下快捷键”处理：断网键 / 联网键 / 切换键都走这里，
// 这样鼠标侧键（钩子通道）与键盘热键（WM_HOTKEY 通道）行为完全一致。
void HandleHotkeyPressed(int id, const char* how)
{
    weaknet::DebugLogf("快捷键触发：id=%d 通道=%s 当前状态=%s",
                       id, (how != NULL) ? how : "?",
                       g_running ? "断网中" : "联网中");

    if (id == kHotkeyIdToggle) {
        if (g_running) {
            char note[256] = { 0 };
            std::snprintf(note, sizeof(note),
                          "收到切换键（%s，%s）：第二下 -> 恢复联网…",
                          weaknet::FormatHotkey(g_blockHotkey).c_str(), how);
            StopDrop(note);
        } else {
            char note[256] = { 0 };
            std::snprintf(note, sizeof(note),
                          "收到切换键（%s，%s）：第一下 -> 进入黑洞模式。",
                          weaknet::FormatHotkey(g_blockHotkey).c_str(), how);
            StartDrop(note);
        }
        DrainLog();
        return;
    }
    if (id == kHotkeyIdBlock) {
        if (g_running) {
            GuiLog(LogLevel::Info, "按下断网快捷键，但当前已经是断网状态。", NULL);
        } else {
            char note[256] = { 0 };
            std::snprintf(note, sizeof(note), "收到断网快捷键（%s）：进入黑洞模式。",
                          weaknet::FormatHotkey(g_blockHotkey).c_str());
            StartDrop(note);
        }
        DrainLog();
        return;
    }
    if (id == kHotkeyIdUnblock) {
        if (g_running) {
            char note[256] = { 0 };
            std::snprintf(note, sizeof(note), "收到联网快捷键（%s）：正在恢复联网…",
                          weaknet::FormatHotkey(g_unblockHotkey).c_str());
            StopDrop(note);
        } else {
            GuiLog(LogLevel::Info, "按下联网快捷键，但当前已经是联网状态。", NULL);
            DrainLog();
        }
        return;
    }
}

// 当前没有管理员权限时，提供一键提权重启
void RelaunchElevated()
{
    wchar_t exePath[MAX_PATH] = { 0 };
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) {
        return;
    }
    HINSTANCE result = ShellExecuteW(NULL, L"runas", exePath, NULL, NULL, SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(result) <= 32) {
        MessageBoxW(g_mainWindow,
                    L"提权启动失败（可能你取消了 UAC 提示）。\n"
                    L"也可以右键本程序 -> “以管理员身份运行”。",
                    L"提示", MB_OK | MB_ICONWARNING);
    }
}

// -----------------------------------------------------------------------------
//  窗口过程
// -----------------------------------------------------------------------------
void CreateControls(HWND window)
{
    g_mainWindow = window;

    // 取系统消息字体（已按 DPI 适配）
    NONCLIENTMETRICSW metrics;
    std::memset(&metrics, 0, sizeof(metrics));
    metrics.cbSize = sizeof(metrics);
    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0)) {
        g_font = CreateFontIndirectW(&metrics.lfMessageFont);
    }

    const DWORD labelStyle = SS_LEFT | SS_CENTERIMAGE;
    const DWORD editStyle  = ES_AUTOHSCROLL | WS_TABSTOP | WS_BORDER;

    // =========================================================================
    //  布局骨架（v1.7.0，仿 NetLimiter）
    //  ---------------------------------------------------------------------
    //  客户区尺寸由 kClientW/kClientH 决定；标签页让设置、活动、快捷键和日志
    //  分开排布，避免高 DPI 下单页内容超出工作区。
    // =========================================================================
    const int kMargin  = 10;

    // ---- 1. 状态栏：先建，因为它会自动贴到父窗口底部，高度要拿来算别的控件 ----
    g_hStatusBar = CreateWindowExW(
        0, STATUSCLASSNAMEW, L"",
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0, window,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_STATUS_BAR)),
        g_instance, NULL);
    int statusHeight = S(24);
    if (g_hStatusBar != NULL) {
        if (g_font != NULL) {
            SendMessageW(g_hStatusBar, WM_SETFONT, reinterpret_cast<WPARAM>(g_font), TRUE);
        }
        SendMessageW(g_hStatusBar, WM_SIZE, 0, 0);      // 自己贴到底部并定高
        RECT statusRect;
        GetWindowRect(g_hStatusBar, &statusRect);
        const int measured = statusRect.bottom - statusRect.top;
        if (measured > 0) { statusHeight = measured; }

        // 两格：左格状态文本（自适应宽度），右格统计。
        // 右格给 430 逻辑像素，因为统计串里要放"丢包率 下行 X%→Y% / 上行 ..."。
        const int parts[2] = { S(kClientW) - S(430), -1 };
        SendMessageW(g_hStatusBar, SB_SETPARTS, kStatusPaneCount,
                     reinterpret_cast<LPARAM>(parts));
    }

    // ---- 2. 标签控件 ----
    const int kTabsTop = kMargin;
    const int kActionH = 40;                                       // 底部按钮行
    const int kActionY = kClientH - statusHeight - kActionH;       // 按钮行 y
    const int kTabsH   = kActionY - kTabsTop - kMargin;
    const int kTabsW   = kClientW - 2 * kMargin;

    g_hTabs = CreateWindowExW(
        0, WC_TABCONTROLW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | TCS_TABS,
        S(kMargin), S(kTabsTop), S(kTabsW), S(kTabsH),
        window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_TABS)),
        g_instance, NULL);

    int pageW = kTabsW - 16;      // 页内容宽度（逻辑值，下面按实际内容区修正）
    if (g_hTabs != NULL) {
        if (g_font != NULL) {
            SendMessageW(g_hTabs, WM_SETFONT, reinterpret_cast<WPARAM>(g_font), TRUE);
        }
        const wchar_t* const titles[4] = { L"活动", L"拦截设置", L"全局快捷键", L"运行日志" };
        for (int i = 0; i < 4; ++i) {
            TCITEMW item;
            std::memset(&item, 0, sizeof(item));
            item.mask    = TCIF_TEXT;
            item.pszText = const_cast<LPWSTR>(titles[i]);
            SendMessageW(g_hTabs, TCM_INSERTITEMW, static_cast<WPARAM>(i),
                         reinterpret_cast<LPARAM>(&item));
        }
        // TCM_ADJUSTRECT 给出"内容区"在标签控件客户坐标里的位置（**物理像素**）。
        // 之后页内控件的坐标都写成相对内容区的**逻辑值**，由 TabCtl() 换算。
        RECT content;
        GetClientRect(g_hTabs, &content);
        TabCtrl_AdjustRect(g_hTabs, FALSE, &content);
        g_tabOriginX = S(kMargin) + content.left;
        g_tabOriginY = S(kTabsTop) + content.top;
        if (g_tabOriginX < S(kMargin)) { g_tabOriginX = S(kMargin); }
        if (g_tabOriginY < S(kTabsTop)) { g_tabOriginY = S(kTabsTop); }
        // 内容区宽度是物理像素，这里换回逻辑值再减掉一点内缩。
        // （千万不能再 S() 一次：那样宽度会被缩放两遍，控件会宽出屏幕。）
        pageW = MulDiv(content.right - content.left, 96, g_dpi) - 4;
        if (pageW < 200) { pageW = kTabsW - 16; }
    }

    // 分组框内左右内缩：内层控件统一从 x=12 开始，视觉上有"缩进"的层次感
    const int kInner = 12;
    const int kGroupW = pageW;

    // =========================================================================
    //  第 1 页：拦截设置
    // =========================================================================
    g_buildingPage = 1;
    {
        int y = 0;

        // ---- 分组 1：丢什么（三选一）--------------------------------------
        // 三个目标改成同一组单选按钮：原来"全部端口"是复选框、"按进程名"是单选框，
        // 而"按端口"是"两个都没勾"的隐含状态 —— 很难一眼看懂，也容易误操作。
        const int g1H = 108;
        TabCtl(L"BUTTON", L" 丢什么 ", BS_GROUPBOX, 0, y, kGroupW, g1H, 0);

        g_hAllPorts = TabCtl(L"BUTTON", L"全部端口（整体断网）",
                             BS_AUTORADIOBUTTON | WS_GROUP | WS_TABSTOP,
                             kInner, y + 22, 220, 22, IDC_CHK_ALLPORTS);

        g_hRadioByPort = TabCtl(L"BUTTON", L"按端口", BS_AUTORADIOBUTTON | WS_TABSTOP,
                                kInner, y + 50, 72, 22, IDC_RADIO_BYPORT);
        g_hPort = TabCtl(L"EDIT", L"8080", editStyle,
                         kInner + 78, y + 49, 140, 24, IDC_EDIT_PORT);
        g_hRadioByProcess = TabCtl(L"BUTTON", L"按进程名",
                                   BS_AUTORADIOBUTTON | WS_TABSTOP,
                                   kInner + 240, y + 50, 90, 22, IDC_RADIO_BYPROCESS);
        g_hProcess = TabCtl(L"EDIT", L"chrome.exe", editStyle,
                            kInner + 336, y + 49, 190, 24, IDC_EDIT_PROCESS);
        // v1.4.0：「浏览…」—— 打开进程选择器，从正在运行的程序里挑一个，
        // 不用去任务管理器查进程名。手输仍然保留（有些进程没有窗口，列表里找不到）。
        g_hBrowseProcess = TabCtl(L"BUTTON", L"浏览…", BS_PUSHBUTTON | WS_TABSTOP,
                                  kInner + 534, y + 49, 76, 24, IDC_BTN_BROWSE_PROCESS);

        // 进程模式状态行（非进程模式时为空，属正常）
        g_hProcessState = TabCtl(L"STATIC", L"", SS_LEFT | SS_ENDELLIPSIS,
                                 kInner, y + 82, kGroupW - kInner - 12, 20,
                                 IDC_LBL_PROCESS_STATE);
        y += g1H + 10;

        // ---- 分组 2：拦截范围 ---------------------------------------------
        const int g2H = 56;
        TabCtl(L"BUTTON", L" 拦截范围 ", BS_GROUPBOX, 0, y, kGroupW, g2H, 0);

        TabCtl(L"STATIC", L"方向", labelStyle, kInner, y + 25, 40, 20, IDC_LBL_DIR);
        g_hDir = TabCtl(L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_TABSTOP | WS_VSCROLL,
                        kInner + 42, y + 23, 170, 200, IDC_COMBO_DIR);
        SendMessageW(g_hDir, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"inbound（下行，本机收包）"));
        SendMessageW(g_hDir, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"outbound（上行，本机发包）"));
        SendMessageW(g_hDir, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"both（不区分方向）"));
        // v2.0.10：默认方向从"下行"改成"both（不区分方向）"。
        // 为什么：v2.0.10 让"方向"变成权威设置（选定单一方向就把另一方向清零），
        // 如果默认还是"下行"，那么默认的"按进程名断网"会退化成只断下行 ——
        // 把一直好用的断网功能弄残。默认改成 both 之后：
        //   * 断网（丢包率 100/100）仍然是两个方向都断 —— 与历史行为一致
        //   * 想只影响单一方向，显式选那一项即可
        SendMessageW(g_hDir, CB_SETCURSEL, 2, 0);

        TabCtl(L"STATIC", L"端口匹配", labelStyle, kInner + 236, y + 25, 64, 20, IDC_LBL_MATCH);
        g_hMatch = TabCtl(L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_TABSTOP | WS_VSCROLL,
                          kInner + 302, y + 23, 180, 200, IDC_COMBO_MATCH);
        SendMessageW(g_hMatch, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"src（源端口，对端服务）"));
        SendMessageW(g_hMatch, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"dst（目的端口，本机服务）"));
        SendMessageW(g_hMatch, CB_SETCURSEL, 0, 0);

        TabCtl(L"STATIC", L"协议", labelStyle, kInner + 506, y + 25, 32, 20, IDC_LBL_PROTO);
        g_hProto = TabCtl(L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_TABSTOP | WS_VSCROLL,
                          kInner + 540, y + 23, 140, 200, IDC_COMBO_PROTO);
        SendMessageW(g_hProto, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"TCP"));
        SendMessageW(g_hProto, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"UDP"));
        SendMessageW(g_hProto, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"TCP + UDP"));
        SendMessageW(g_hProto, CB_SETCURSEL, 2, 0);
        y += g2H + 10;

        // ---- 分组 3：网络质量（丢包率 / 限速 / 时长）------------------------
        const int g3H = 104;
        TabCtl(L"BUTTON", L" 网络质量 ", BS_GROUPBOX, 0, y, kGroupW, g3H, 0);

        // 丢包率：100 = 全部丢弃（旧版黑洞行为，默认）；0 = 该方向不接管；1~99 = 按概率丢
        TabCtl(L"STATIC", L"丢包率(%)", labelStyle, kInner, y + 25, 68, 20, IDC_LBL_LOSS);
        TabCtl(L"STATIC", L"下行", labelStyle, kInner + 74, y + 25, 36, 20, 0);
        g_hLossDown = TabCtl(L"EDIT", L"100", ES_CENTER | ES_NUMBER | WS_BORDER | WS_TABSTOP,
                             kInner + 112, y + 23, 60, 24, IDC_EDIT_LOSS_DOWN);
        TabCtl(L"STATIC", L"上行", labelStyle, kInner + 180, y + 25, 36, 20, 0);
        g_hLossUp = TabCtl(L"EDIT", L"100", ES_CENTER | ES_NUMBER | WS_BORDER | WS_TABSTOP,
                           kInner + 218, y + 23, 60, 24, IDC_EDIT_LOSS_UP);
        g_hLossHint = TabCtl(L"STATIC", L"100 = 全丢 · 0 = 不丢包 · 1~99 = 按概率丢",
                             SS_LEFT | SS_ENDELLIPSIS, kInner + 292, y + 25,
                             kGroupW - kInner - 292 - 12, 20, IDC_LBL_LOSS_HINT);

        // 限速：0 = 不限（默认）；>0 = 真正的整形——超速的报文排队等，不丢包
        // v2.0.11：改成「数字框 + 单位下拉」，和 NetLimiter 一样选单位，
        // 不用再手敲 K / KB / MB。数字框仍支持小数（如 1.2）。
        TabCtl(L"STATIC", L"限速", labelStyle, kInner, y + 57, 68, 20, IDC_LBL_RATE);
        TabCtl(L"STATIC", L"下行", labelStyle, kInner + 74, y + 57, 36, 20, 0);
        g_hRateDown = TabCtl(L"EDIT", L"0", ES_CENTER | WS_BORDER | WS_TABSTOP,
                             kInner + 112, y + 55, 56, 24, IDC_EDIT_RATE_DOWN);
        g_hRateUnitDown = TabCtl(L"COMBOBOX", L"",
                                 CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP,
                                 kInner + 172, y + 55, 60, 200, IDC_COMBO_RATE_UNIT_DOWN);
        TabCtl(L"STATIC", L"上行", labelStyle, kInner + 240, y + 57, 36, 20, 0);
        g_hRateUp = TabCtl(L"EDIT", L"0", ES_CENTER | WS_BORDER | WS_TABSTOP,
                           kInner + 278, y + 55, 56, 24, IDC_EDIT_RATE_UP);
        g_hRateUnitUp = TabCtl(L"COMBOBOX", L"",
                               CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP,
                               kInner + 338, y + 55, 60, 200, IDC_COMBO_RATE_UNIT_UP);
        {
            const wchar_t* const unitItems[] = { L"B/s", L"KB/s", L"MB/s" };
            HWND const unitCombos[2] = { g_hRateUnitDown, g_hRateUnitUp };
            for (int ci = 0; ci < 2; ++ci) {
                if (unitCombos[ci] == NULL) { continue; }
                for (int ui = 0; ui < 3; ++ui) {
                    SendMessageW(unitCombos[ci], CB_ADDSTRING, 0,
                                 reinterpret_cast<LPARAM>(unitItems[ui]));
                }
                // 默认 KB/s：与"裸数字按 KB 算"的历史行为保持一致
                SendMessageW(unitCombos[ci], CB_SETCURSEL, 1, 0);
            }
        }
        TabCtl(L"STATIC", L"0 = 不限 · 数字可带小数 · 单位用右侧下拉选 · 只限速不丢包就把丢包率填 0",
               SS_LEFT | SS_ENDELLIPSIS, kInner + 404, y + 57,
               kGroupW - kInner - 404 - 12, 20, 0);

        // 运行时长 / 显示被丢弃报文
        TabCtl(L"STATIC", L"运行时长（秒，0=不限）", labelStyle, kInner, y + 84, 140, 20,
               IDC_LBL_DURATION);
        g_hDuration = TabCtl(L"EDIT", L"0", editStyle, kInner + 146, y + 82, 70, 24,
                             IDC_EDIT_DURATION);
        g_hVerbose = TabCtl(L"BUTTON", L"显示被丢弃报文", BS_AUTOCHECKBOX | WS_TABSTOP,
                            kInner + 244, y + 83, 160, 22, IDC_CHK_VERBOSE);
        y += g3H + 10;

        // ---- 分组 4：过滤器预览 -------------------------------------------
        const int g4H = 118;
        TabCtl(L"BUTTON", L" 交给 WinDivert 的过滤器 ", BS_GROUPBOX, 0, y, kGroupW, g4H, 0);
        // 多行只读框：过滤器一行、丢包率一行、限速一行，比原来挤在一条单行里清楚得多。
        // 不给 WS_VSCROLL：内容最多三行，固定高度装得下，挂个滚动条反而显得多余。
        g_hFilter = TabCtl(L"EDIT", L"",
                           ES_MULTILINE | ES_READONLY | WS_BORDER | WS_TABSTOP,
                           kInner, y + 22, kGroupW - kInner - 12, 62, IDC_EDIT_FILTER);
        // 配置矛盾提示（正常为空）。单独占一行，塞进预览框里会被裁掉。
        g_hShapeWarn = TabCtl(L"STATIC", L"", SS_LEFT | SS_ENDELLIPSIS,
                              kInner, y + 90, kGroupW - kInner - 12, 20,
                              IDC_LBL_SHAPE_WARN);
        y += g4H + 8;

        // 页脚提示（原来在窗口最底部，现在归到设置页里）
        TabCtl(L"STATIC",
               L"提示：断网快捷键丢了什么，取决于上面的“过滤器”。"
               L"本机自测（客户端与服务端同机）时回环只在 outbound 可见，"
               L"请把方向设为 outbound、端口匹配设为 src。",
               SS_LEFT | SS_ENDELLIPSIS, 0, y, kGroupW, 20, IDC_LBL_HINT);
    }

    // =========================================================================
    //  第 2 页：全局快捷键
    // =========================================================================
    g_buildingPage = 2;
    {
        int y = 0;

        // ---- 分组 1：按键设置 ----------------------------------------------
        // 纵向顺序：勾选框 -> 按键行 -> 状态 -> 两条说明。
        // 一定要按这个顺序排，否则状态行会压到按键行上（踩过一次）。
        const int g1H = 158;
        TabCtl(L"BUTTON", L" 按键设置 ", BS_GROUPBOX, 0, y, kGroupW, g1H, IDC_GRP_HOTKEY);

        g_hHotkeyEnabled = TabCtl(L"BUTTON", L"启用全局快捷键",
                                  BS_AUTOCHECKBOX | WS_TABSTOP,
                                  kInner, y + 24, 180, 22, IDC_CHK_HOTKEY);

        TabCtl(L"STATIC", L"断网", labelStyle, kInner, y + 54, 40, 20, IDC_LBL_HOTKEY_BLOCK);
        g_hHotkeyBlock = TabCtl(L"EDIT", L"", ES_READONLY | ES_CENTER | WS_BORDER,
                                kInner + 44, y + 52, 150, 24, IDC_HOTKEY_BLOCK);
        g_hBtnSetBlock = TabCtl(L"BUTTON", L"设置", BS_PUSHBUTTON | WS_TABSTOP,
                                kInner + 202, y + 52, 70, 26, IDC_BTN_SET_BLOCK);

        TabCtl(L"STATIC", L"联网", labelStyle, kInner + 300, y + 54, 40, 20,
               IDC_LBL_HOTKEY_UNBLOCK);
        g_hHotkeyUnblock = TabCtl(L"EDIT", L"", ES_READONLY | ES_CENTER | WS_BORDER,
                                  kInner + 344, y + 52, 150, 24, IDC_HOTKEY_UNBLOCK);
        g_hBtnSetUnblock = TabCtl(L"BUTTON", L"设置", BS_PUSHBUTTON | WS_TABSTOP,
                                  kInner + 502, y + 52, 70, 26, IDC_BTN_SET_UNBLOCK);

        // 热键状态自检：绑定长组合键时会很长，必须带截止符
        g_hHotkeyStatus = TabCtl(L"STATIC", L"", SS_LEFT | SS_ENDELLIPSIS,
                                 kInner, y + 86, kGroupW - kInner - 12, 20,
                                 IDC_LBL_HOTKEY_STATUS);

        // 这两条说明对"断网/联网"都适用，各占一整行
        TabCtl(L"STATIC", L"（点“设置”后按单键或组合键即可绑定，Esc 取消）",
               SS_LEFT | SS_ENDELLIPSIS, kInner, y + 112,
               kGroupW - kInner - 12, 20, IDC_LBL_HOTKEY_HINT);
        TabCtl(L"STATIC", L"（注册失败时状态行会写明原因，多半是被别的程序占用了）",
               SS_LEFT | SS_ENDELLIPSIS, kInner, y + 134,
               kGroupW - kInner - 12, 20, 0);
        y += g1H + 10;

        // ---- 分组 2：用法说明 ----------------------------------------------
        // 这一页原来只有几行字、下面一大片空白；把最容易踩坑的几条单独成组，
        // 既填满页面又省得用户去翻 README。
        const int g2H = 118;
        TabCtl(L"BUTTON", L" 用法说明 ", BS_GROUPBOX, 0, y, kGroupW, g2H, 0);

        TabCtl(L"STATIC",
               L"· 把“断网”和“联网”设成同一个键（例如同一个鼠标侧键）就是切换键："
               L"按一下断网、再按一下联网。",
               SS_LEFT | SS_ENDELLIPSIS, kInner, y + 24, kGroupW - kInner - 12, 20,
               IDC_LBL_TOGGLE_HINT);
        TabCtl(L"STATIC",
               L"· 支持单键（F8、B…）、组合键（Ctrl+Alt+B）和鼠标侧键（X1 / X2）。",
               SS_LEFT | SS_ENDELLIPSIS, kInner, y + 50, kGroupW - kInner - 12, 20, 0);
        TabCtl(L"STATIC",
               L"· 快捷键由系统注册，窗口不在前台也有效；断网期间它依然可用。",
               SS_LEFT | SS_ENDELLIPSIS, kInner, y + 76, kGroupW - kInner - 12, 20, 0);
        TabCtl(L"STATIC",
               L"· 单键会全局独占该键，其它程序将收不到这个键（界面会提示）。",
               SS_LEFT | SS_ENDELLIPSIS, kInner, y + 98, kGroupW - kInner - 12, 20, 0);
    }

    // =========================================================================
    //  第 3 页：运行日志
    // =========================================================================
    g_buildingPage = 3;
    {
        const int y = 0;
        // 日志框铺满整页（原来只有 240 高，还得和别的控件抢地方）。
        // 注意高度写**逻辑值**：TabCtl 会做 DPI 缩放，这里不能再套一层 S()。
        g_hLog = TabCtl(L"EDIT", L"",
                        ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL | WS_BORDER,
                        0, y, kGroupW, kTabsH - 48, IDC_EDIT_LOG);
    }

    // =========================================================================
    //  第 1 页：活动（v2.0.0，仿 NetLimiter 的主视图）
    //  左：应用大表格（带真实图标）  右：信息视图面板
    // =========================================================================
    g_buildingPage = 0;
    {
        // ---- 顶部过滤行 ----
        const int rowY = 0;
        g_hActivityFilter = TabCtl(L"BUTTON", L"只显示有流量的",
                                   BS_AUTOCHECKBOX | WS_TABSTOP,
                                   0, rowY, 150, 20, IDC_CHK_ACTIVITY_FILTER);
        TabCtl(L"STATIC", L"搜索", SS_LEFT, 156, rowY + 2, 36, 18, 0);
        g_hActivitySearch = TabCtl(L"EDIT", L"",
                                   ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP,
                                   194, rowY, 150, 20, IDC_EDIT_ACTIVITY_SEARCH);
        TabCtl(L"STATIC", L"单位", SS_LEFT, 352, rowY + 2, 36, 18, 0);
        g_hActivityUnit = TabCtl(L"COMBOBOX", L"",
                                 CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP,
                                 390, rowY, 90, 200, IDC_COMBO_ACTIVITY_UNIT);
        if (g_hActivityUnit != NULL) {
            const wchar_t* const units[] = { L"自动", L"B/s", L"KB/s", L"MB/s" };
            for (int i = 0; i < 4; ++i) {
                SendMessageW(g_hActivityUnit, CB_ADDSTRING, 0,
                             reinterpret_cast<LPARAM>(units[i]));
            }
            SendMessageW(g_hActivityUnit, CB_SETCURSEL, 0, 0);
        }
        // 状态行占过滤行右边的剩余宽度
        const int statusX = 488;
        g_hAppRateStatus = TabCtl(L"STATIC", L"", SS_LEFT | SS_ENDELLIPSIS,
                                  statusX, rowY + 2, kGroupW - statusX, 18,
                                  IDC_LBL_APPRATE_STATUS);

        // ---- 主体：左右分栏 ----
        const int gap    = 8;
        const int bodyY  = rowY + 24;
        const int hintH  = 20;
        int bodyH = kTabsH - bodyY - hintH - 6;
        if (bodyH < 120) { bodyH = 120; }

        int rightW = kGroupW * 36 / 100;
        if (rightW < 300) { rightW = 300; }
        if (rightW > kGroupW - 320) { rightW = kGroupW - 320; }
        const int leftW = kGroupW - rightW - gap;

        // 左：应用列表
        g_hAppRateList = TabListView(IDC_LIST_APPRATE, 0, bodyY, leftW, bodyH);
        ListViewAddColumn(g_hAppRateList, 0, L"名称",     leftW - 430);
        ListViewAddColumn(g_hAppRateList, 1, L"下载速度", 110);
        ListViewAddColumn(g_hAppRateList, 2, L"上传速度", 110);
        ListViewAddColumn(g_hAppRateList, 3, L"累计下行", 100);
        ListViewAddColumn(g_hAppRateList, 4, L"累计上行", 100);

        // 应用图标列表（ImageList 的所有权归 ListView，随它一起销毁）
        if (g_hAppRateList != NULL) {
            const int iconCx = GetSystemMetrics(SM_CXSMICON);
            const int iconCy = GetSystemMetrics(SM_CYSMICON);
            g_appIconList = ImageList_Create(iconCx, iconCy, ILC_COLOR32 | ILC_MASK, 32, 32);
            if (g_appIconList != NULL) {
                ListView_SetImageList(g_hAppRateList, g_appIconList, LVSIL_SMALL);
            }
            UpdateSortIndicator();   // 默认按名称升序，列头上显示箭头
        }

        // 右：信息视图面板（用空分组框当边框，和 NetLimiter 的面板观感一致）
        const int infoX = leftW + gap;
        TabCtl(L"BUTTON", L"", BS_GROUPBOX, infoX, bodyY, rightW, bodyH, 0);
        TabCtl(L"STATIC", L"  信息视图", SS_LEFT,
               infoX + 2, bodyY + 2, rightW - 4, 18, IDC_LBL_INFO_CAPTION);

        const int innerX = infoX + 10;
        const int innerW = rightW - 20;
        g_hInfoPath = TabCtl(L"STATIC", L"（未选中应用）",
                             SS_LEFT | SS_ENDELLIPSIS,
                             innerX, bodyY + 22, innerW, 18, IDC_LBL_INFO_PATH);

        // 应用属性块
        const int attrTop = bodyY + 44;
        const int attrH   = (bodyH - 44 - 12) / 2;
        TabCtl(L"BUTTON", L" 应用属性 ", BS_GROUPBOX,
               infoX + 6, attrTop, rightW - 12, attrH, 0);
        g_hInfoProps = TabListView(IDC_LIST_INFO_PROPS,
                                   infoX + 14, attrTop + 18, innerW - 8, attrH - 28);
        ListViewAddColumn(g_hInfoProps, 0, L"属性", 96);
        ListViewAddColumn(g_hInfoProps, 1, L"值",   innerW - 8 - 110);

        // 规则块（NetLimiter 的"类型 × 下载/上传"小表）
        const int ruleTop = attrTop + attrH + 6;
        const int ruleH   = bodyH - (ruleTop - bodyY) - 8;
        TabCtl(L"BUTTON", L" 规则 ", BS_GROUPBOX,
               infoX + 6, ruleTop, rightW - 12, ruleH, 0);
        g_hInfoRules = TabListView(IDC_LIST_INFO_RULES,
                                   infoX + 14, ruleTop + 18, innerW - 8, ruleH - 28);
        ListViewAddColumn(g_hInfoRules, 0, L"类型",   76);
        ListViewAddColumn(g_hInfoRules, 1, L"下载",   (innerW - 8 - 88) / 2);
        ListViewAddColumn(g_hInfoRules, 2, L"上传",   (innerW - 8 - 88) / 2);

        // ---- 底部提示 ----
        TabCtl(L"STATIC",
               L"按进程实时统计上下行（ETW，TCP+UDP 全覆盖）。默认按名称排序（顺序固定）；"
               L"点列头可按速度排序（每 3 秒才重排一次，避免行乱跳）。双击某一行可把它填进"
               L"「拦截设置」；监控需要管理员权限（界面自带提权清单）。",
               SS_LEFT | SS_ENDELLIPSIS, 0, bodyY + bodyH + 2, kGroupW, hintH,
               IDC_LBL_APPRATE_HINT);
    }

    // =========================================================================
    //  底部固定区：操作按钮（任何页都可见）
    // =========================================================================
    g_buildingPage = -1;      // 这些控件不属于任何页，切页时不动它们
    g_hStart = MakeControl(L"BUTTON", L"开始拦截", BS_PUSHBUTTON | WS_TABSTOP,
                           kMargin, kActionY + 6, 120, 30, IDC_BTN_START);
    g_hStop  = MakeControl(L"BUTTON", L"停止丢包", BS_PUSHBUTTON | WS_TABSTOP,
                           kMargin + 128, kActionY + 6, 120, 30, IDC_BTN_STOP);

    // 统计与状态都进状态栏（v1.7.0）。
    // 这里不再创建 STATIC，只把两个句柄留给状态栏，避免两套显示互相打架。
    g_hStatus = g_hStatusBar;
    g_hStats  = g_hStatusBar;
    SetStatusText(L"未运行（联网状态）。设置好参数后点“开始拦截”，或用快捷键断网。");
    SetStatsText(L"丢弃 0 包 / 0.00 MiB");

    g_tabPagesReady = true;
    ShowTabPage(0);
    // 启动时就已经在「活动」页上 —— 但那只调用了 ShowTabPage，
    // 不会触发 TCN_SELCHANGE，所以监控必须在这里显式拉起来，
    // 否则用户一进来看到的是空列表（这是个真 bug）。
    EnsureAppRateMonitor();
    UpdateAppRateList(true);
}

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
{
    // 鼠标侧键通知：由 WH_MOUSE_LL 钩子 PostMessage 过来（异步）。
    // 必须在这里处理，而不是在钩子回调里同步处理 —— 因为处理过程会走到
    // RegisterHotkeys()，那里要卸载并重装钩子；在自己的钩子回调里装卸钩子
    // 会把整个系统的鼠标输入卡死（v1.2.3 修复的死机根因）。
    if (message == weaknet::MouseHotkeyNotifyMessage()) {
        DispatchMouseHotkey(static_cast<unsigned>(wParam));
        return 0;
    }

    switch (message) {
    case WM_CREATE:
        g_mainWindow = window;
        CreateControls(window);
        LoadSettings();
        UpdateFilterPreview();
        UpdateButtons();
        UpdateStatsDisplay();
        RegisterHotkeys();
        DrainLog();
        SetTimer(window, kTimerId, kTimerIntervalMs, NULL);
        return 0;

    case WM_NOTIFY:
    {
        // v2.0.0：活动页的列表交互
        {
            NMHDR* nh = reinterpret_cast<NMHDR*>(lParam);
            if (nh != NULL && nh->hwndFrom == g_hAppRateList &&
                nh->code == LVN_COLUMNCLICK) {
                // 点列头切换排序。名称默认升序，速率类默认降序（想看谁最快）。
                const LPNMLISTVIEW nlv = reinterpret_cast<LPNMLISTVIEW>(lParam);
                const int col = (nlv != NULL) ? nlv->iSubItem : 0;
                if (col == g_activitySortColumn) {
                    g_activitySortDesc = !g_activitySortDesc;
                } else {
                    g_activitySortColumn = col;
                    g_activitySortDesc = (col != 0);
                }
                g_activityResortNow = true;
                UpdateSortIndicator();
                UpdateAppRateList(true);
                return 0;
            }
            if (nh != NULL && nh->hwndFrom == g_hAppRateList &&
                nh->code == NM_DBLCLK) {
                if (g_running) {
                    SetStatusText(L"正在拦截中：请先停止，再从活动列表选择新目标。");
                    return 0;
                }
                // 双击某一行：把该进程名填进「拦截设置」并切过去。
                // （NetLimiter 是行内直接改限速；我们一次只能对一个目标生效，
                //   所以先把"选目标"这一步接上，避免摆一个改不动的框骗人。）
                const int sel = GetSelectedAppRow();
                if (sel >= 0) {
                    wchar_t name[260] = { 0 };
                    LVITEMW it;
                    std::memset(&it, 0, sizeof(it));
                    it.mask = LVIF_TEXT;
                    it.iItem = sel;
                    it.iSubItem = 0;
                    it.pszText = name;
                    it.cchTextMax = 260;
                    SendMessageW(g_hAppRateList, LVM_GETITEMTEXTW,
                                 static_cast<WPARAM>(sel), reinterpret_cast<LPARAM>(&it));
                    if (name[0] != L'\0') {
                        if (g_hProcess != NULL) { SetWindowTextW(g_hProcess, name); }
                        ApplyTargetMode(TargetMode::ByProcess, true);
                        if (g_hTabs != NULL) {
                            SendMessageW(g_hTabs, TCM_SETCURSEL, 1, 0);
                            ShowTabPage(1);
                        }
                    }
                }
                return 0;
            }
        }
        // v1.7.0：标签页切换 —— 只显示当前页的控件
        NMHDR* hdr = reinterpret_cast<NMHDR*>(lParam);
        if (hdr != NULL && hdr->idFrom == IDC_TABS && hdr->code == TCN_SELCHANGE &&
            g_hTabs != NULL) {
            const int tab = static_cast<int>(SendMessageW(g_hTabs, TCM_GETCURSEL, 0, 0));
            ShowTabPage(tab);
            if (tab == 0) {
                // 切到「应用速率」页时才拉起 ETW 监控（不切就不占资源）
                EnsureAppRateMonitor();
                UpdateAppRateList(true);
            }
            return 0;
        }
        break;
    }

    case WM_COMMAND:
    {
        const int id = LOWORD(wParam);
        const int notify = HIWORD(wParam);

        // ---- 活动页（v2.0.0）------------------------------------------------
        if (id == IDC_COMBO_ACTIVITY_UNIT && notify == CBN_SELCHANGE) {
            g_activityUnitMode = static_cast<int>(
                SendMessageW(g_hActivityUnit, CB_GETCURSEL, 0, 0));
            if (g_activityUnitMode < 0) { g_activityUnitMode = 0; }
            UpdateAppRateList(true);
            return 0;
        }
        if (id == IDC_CHK_ACTIVITY_FILTER && notify == BN_CLICKED) {
            UpdateAppRateList(true);
            return 0;
        }
        if (id == IDC_EDIT_ACTIVITY_SEARCH && notify == EN_CHANGE) {
            UpdateAppRateList(true);
            return 0;
        }

        // ---- 菜单（v1.7.0）---------------------------------------------------
        if (id >= 40000 && id <= 40099) {
            switch (id) {
            case IDM_EXIT:
                PostMessageW(window, WM_CLOSE, 0, 0);
                return 0;
            case IDM_OPEN_LOG:
            {
                const std::string path = weaknet::DebugLogPath();
                if (path.empty()) {
                    MessageBoxW(window, L"调试日志未启用（命令行版可用 --debug-log 指定路径）。",
                                L"查看调试日志", MB_OK | MB_ICONINFORMATION);
                } else {
                    const std::wstring wide = Utf8ToWide(path.c_str());
                    if (reinterpret_cast<INT_PTR>(ShellExecuteW(window, L"open", wide.c_str(),
                                                               NULL, NULL, SW_SHOWNORMAL)) <= 32) {
                        MessageBoxW(window, (L"打不开日志文件：\n" + wide).c_str(),
                                    L"查看调试日志", MB_OK | MB_ICONWARNING);
                    }
                }
                return 0;
            }
            case IDM_OPEN_FOLDER:
            {
                wchar_t exePath[MAX_PATH] = { 0 };
                GetModuleFileNameW(NULL, exePath, MAX_PATH);
                std::wstring dir(exePath);
                const size_t pos = dir.find_last_of(L"\\/");
                if (pos != std::wstring::npos) { dir.resize(pos); }
                ShellExecuteW(window, L"open", dir.c_str(), NULL, NULL, SW_SHOWNORMAL);
                return 0;
            }
            case IDM_HELP_README:
            {
                wchar_t exePath[MAX_PATH] = { 0 };
                GetModuleFileNameW(NULL, exePath, MAX_PATH);
                std::wstring dir(exePath);
                const size_t pos = dir.find_last_of(L"\\/");
                if (pos != std::wstring::npos) { dir.resize(pos); }
                const std::wstring readme = dir + L"\\README.md";
                if (reinterpret_cast<INT_PTR>(ShellExecuteW(window, L"open", readme.c_str(),
                                                           NULL, NULL, SW_SHOWNORMAL)) <= 32) {
                    MessageBoxW(window,
                                L"同目录下没有找到 README.md。\n\n"
                                L"要点：用「开始拦截」或全局快捷键断网；"
                                L"丢包率 100% = 完全断开，1~99% = 按概率丢；"
                                L"限速是排队整形，不靠丢包。",
                                L"使用说明", MB_OK | MB_ICONINFORMATION);
                }
                return 0;
            }
            case IDM_HELP_ABOUT:
            {
                const std::wstring text =
                    std::wstring(Utf8ToWide(weaknet::kToolName)) + L" GUI v" +
                    Utf8ToWide(weaknet::kToolVersion) + L"\n\n" +
                    L"基于 WinDivert 的弱网 / 断网测试工具。\n"
                    L"· 按端口 / 进程名选择性丢包（丢包率可按方向单独设置）\n"
                    L"· 按方向限速（令牌桶整形，超速排队而非丢包）\n"
                    L"· 全局快捷键断网 / 联网（支持鼠标侧键、同键切换）\n\n"
                    L"需要管理员权限才能开始拦截。";
                MessageBoxW(window, text.c_str(), L"关于", MB_OK | MB_ICONINFORMATION);
                return 0;
            }
            default:
                break;
            }
        }

        if (id == IDC_BTN_START && notify == BN_CLICKED) {
            StartDrop("收到“开始拦截”：进入黑洞模式。");
            DrainLog();
            return 0;
        }
        if (id == IDC_BTN_STOP && notify == BN_CLICKED) {
            StopDrop("收到“停止丢包”：正在恢复联网…");
            return 0;
        }
        if (id == IDC_BTN_SET_BLOCK && notify == BN_CLICKED) {
            StartCapture(1);
            return 0;
        }
        if (id == IDC_BTN_SET_UNBLOCK && notify == BN_CLICKED) {
            StartCapture(2);
            return 0;
        }
        if (id == IDC_BTN_BROWSE_PROCESS && notify == BN_CLICKED) {
            if (g_running) {
                return 0;      // 运行中不允许改目标
            }
            std::string picked;
            if (ChooseProcessFromRunning(picked)) {
                // 选中后把进程名填进输入框，并切到“按进程名丢包”模式；
                // 后面走的还是原有逻辑，引擎完全不知情。
                g_uiSyncing = true;
                SetWindowTextW(g_hProcess, Utf8ToWide(picked.c_str()).c_str());
                g_uiSyncing = false;
                ApplyTargetMode(TargetMode::ByProcess, true);
                SaveSettings();
                UpdateFilterPreview();
                UpdateButtons();
                GuiLog(LogLevel::Info,
                       ("已从列表中选中进程：" + picked).c_str(), NULL);
                DrainLog();
            }
            return 0;
        }
        if (id == IDC_RADIO_BYPORT && notify == BN_CLICKED) {
            // v1.7.0：三个目标现在是同一组单选按钮，点谁就是谁，不用再猜
            ApplyTargetMode(TargetMode::ByPort, true);
            SaveSettings();
            UpdateFilterPreview();
            UpdateButtons();
            return 0;
        }
        if (id == IDC_CHK_HOTKEY && notify == BN_CLICKED) {
            g_hotkeyEnabled = IsChecked(g_hHotkeyEnabled);
            SaveSettings();
            RegisterHotkeys();
            UpdateButtons();
            DrainLog();
            return 0;
        }
        if (id == IDC_CHK_ALLPORTS && notify == BN_CLICKED) {
            if (g_uiSyncing) {
                return 0;
            }
            // 勾选“全部端口” = 选择整体断网这一目标（互斥：清掉其它两种的输入）
            if (IsChecked(g_hAllPorts)) {
                ApplyTargetMode(TargetMode::AllPorts, true);
            } else if (g_targetMode == TargetMode::AllPorts) {
                // 刚被取消勾选：回到“按端口”，让端口框重新可用
                ApplyTargetMode(TargetMode::ByPort, false);
            }
            SaveSettings();
            UpdateFilterPreview();
            UpdateButtons();
            return 0;
        }
        if (id == IDC_RADIO_BYPROCESS && notify == BN_CLICKED) {
            if (g_uiSyncing) {
                return 0;
            }
            if (IsChecked(g_hRadioByProcess)) {
                ApplyTargetMode(TargetMode::ByProcess, true);
            }
            SaveSettings();
            UpdateFilterPreview();
            UpdateButtons();
            SetFocus(g_hProcess);
            return 0;
        }
        if (id == IDC_EDIT_PORT || id == IDC_EDIT_PROCESS || id == IDC_EDIT_DURATION ||
            id == IDC_EDIT_LOSS_DOWN || id == IDC_EDIT_LOSS_UP ||
            id == IDC_EDIT_RATE_DOWN || id == IDC_EDIT_RATE_UP) {
            if (notify == EN_CHANGE && !g_uiSyncing) {
                // 在端口框里打字 = 使用者想“按端口丢包”，自动把目标切过去（三选一联动）
                if (id == IDC_EDIT_PORT && g_targetMode != TargetMode::ByPort) {
                    ApplyTargetMode(TargetMode::ByPort, false);
                } else if (id == IDC_EDIT_PROCESS && g_targetMode != TargetMode::ByProcess) {
                    ApplyTargetMode(TargetMode::ByProcess, false);
                }
                // 丢包率改动也要重刷过滤器预览：方向与丢包率会互相影响
                // （某个方向丢包率为 0 时，过滤器里就不会有那个方向）。
                UpdateFilterPreview();
                UpdateButtons();
            }
            return 0;
        }
        if ((id == IDC_COMBO_DIR || id == IDC_COMBO_MATCH || id == IDC_COMBO_PROTO ||
             id == IDC_COMBO_RATE_UNIT_DOWN || id == IDC_COMBO_RATE_UNIT_UP) &&
            notify == CBN_SELCHANGE) {
            UpdateFilterPreview();
            return 0;
        }
        return 0;
    }

    case WM_KEYDOWN:
    case WM_SYSKEYDOWN:
        // 快捷键捕获模式：捕获期间把按键吃掉（StartCapture 里已把焦点设到主窗口）
        if (g_capturing != 0) {
            FinishCapture(static_cast<unsigned>(wParam));
            return 0;
        }
        break;

    case WM_HOTKEY:
        // ⚠ 捕获期间**绝不能**触发断网/联网动作。
        // 正常路径下 StartCapture 已经把热键全注销了，按键会以 WM_KEYDOWN 进来；
        // 这里再兜一道，防止“注销没成功”之类的意外导致按一下就断网。
        // 真收到就把热键 id 反推回按键值，当作本次要录入的键。
        if (g_capturing != 0) {
            const int id = static_cast<int>(wParam);
            unsigned vk = 0;
            if (id == kHotkeyIdBlock) {
                vk = g_blockHotkey.vk;
            } else if (id == kHotkeyIdUnblock) {
                vk = g_unblockHotkey.vk;
            } else if (id == kHotkeyIdToggle) {
                vk = g_blockHotkey.vk;      // 切换键用的就是断网键那个键
            }
            if (vk != 0) {
                FinishCapture(vk);
            }
            return 0;
        }
        // 键盘热键，以及（在支持的系统上）用 RegisterHotKey 注册成功的鼠标侧键，
        // 都从 WM_HOTKEY 进来，按同一套规则分发
        HandleHotkeyPressed(static_cast<int>(wParam), "热键");
        return 0;

    // 鼠标侧键：RegisterHotKey 对 VK_XBUTTON1/2 的支持不可靠，
    // 所以主通道是 WH_MOUSE_LL 钩子（+ PostMessage 通知）。
    // 这里接一份是为了兼容“系统确实投递了 WM_XBUTTON”的情况；两条通道靠
    // g_hotkeyRegistered 区分，保证一次按下只会被处理一次。
    case WM_XBUTTONUP:
    case WM_NCXBUTTONUP:
    {
        const unsigned button = weaknet::MouseButtonFromWMXButtonParam(
            static_cast<unsigned long long>(wParam));
        if (button == 0) {
            break;
        }
        if (g_capturing != 0) {
            FinishCapture(button);
            return 0;   // 吃掉：不让它变成浏览器的“后退/前进”
        }
        if (!g_hotkeyEnabled) {
            return 0;
        }
        const bool hookOwnsIt =
            (g_hotkeyRegistered[kHotkeyIdBlock] == kHotkeyViaHook && button == g_blockHotkey.vk) ||
            (g_hotkeyRegistered[kHotkeyIdUnblock] == kHotkeyViaHook && button == g_unblockHotkey.vk) ||
            (g_hotkeyRegistered[kHotkeyIdToggle] == kHotkeyViaHook && button == g_blockHotkey.vk);
        if (!hookOwnsIt) {
            if (IsToggleHotkey() && button == g_blockHotkey.vk) {
                HandleHotkeyPressed(kHotkeyIdToggle, "侧键");
            } else if (button == g_blockHotkey.vk) {
                HandleHotkeyPressed(kHotkeyIdBlock, "侧键");
            } else if (button == g_unblockHotkey.vk) {
                HandleHotkeyPressed(kHotkeyIdUnblock, "侧键");
            }
        }
        return 0;   // 吃掉：不让它变成浏览器的“后退/前进”
    }

    case WM_TIMER:
        if (wParam == kTimerId) {
            // 应用速率页在前台时刷新（函数内部还会限流到约 1 秒一次）
            if (g_hTabs != NULL && g_hAppRateList != NULL &&
                IsWindowVisible(g_hAppRateList) &&
                static_cast<int>(SendMessageW(g_hTabs, TCM_GETCURSEL, 0, 0)) == 0) {
                UpdateAppRateList(false);
            }

            // 鼠标侧键热键（钩子通道）：捕获中优先用于录入
            unsigned mouseVk = 0;
            while (weaknet::PollMouseHotkey(mouseVk)) {
                if (g_capturing != 0) {
                    FinishCapture(mouseVk);
                    break;
                }
                if (!g_hotkeyEnabled) {
                    continue;
                }
                // 若这个侧键已经由 RegisterHotKey 接管，就跳过钩子这条通道
                if (IsToggleHotkey() && mouseVk == g_blockHotkey.vk) {
                    if (g_hotkeyRegistered[kHotkeyIdToggle] == kHotkeyViaHook) {
                        HandleHotkeyPressed(kHotkeyIdToggle, "侧键");
                    }
                } else if (mouseVk == g_blockHotkey.vk) {
                    if (g_hotkeyRegistered[kHotkeyIdBlock] == kHotkeyViaHook) {
                        HandleHotkeyPressed(kHotkeyIdBlock, "侧键");
                    }
                } else if (mouseVk == g_unblockHotkey.vk) {
                    if (g_hotkeyRegistered[kHotkeyIdUnblock] == kHotkeyViaHook) {
                        HandleHotkeyPressed(kHotkeyIdUnblock, "侧键");
                    }
                }
            }

            // 兜底自检：把“界面显示”和“实际捕获状态”对齐。
            // 正常路径下 CancelCapture/CommitCapture 已经刷过了；这里再对一次是为了
            // 防止任何异常情况（例如按键事件被系统吞掉）让界面卡在“请按键…”上。
            {
                static int lastKnownCapturing = 0;
                if (lastKnownCapturing != g_capturing) {
                    lastKnownCapturing = g_capturing;
                    UpdateHotkeyStatusText();
                    const wchar_t* blockText   = (g_capturing == 1) ? L"请按键…" : L"设置";
                    const wchar_t* unblockText = (g_capturing == 2) ? L"请按键…" : L"设置";
                    SetWindowTextW(g_hBtnSetBlock, blockText);
                    SetWindowTextW(g_hBtnSetUnblock, unblockText);
                }
            }

            // 先看会话是否已自然结束，再取日志，最后刷新统计
            if (g_running && g_session.HasFinished()) {
                HandleSessionFinished();
                UpdateFilterPreview();
            }
            DrainLog();
            UpdateStatsDisplay();
            // 进程模式：运行中要实时显示“识别到哪些 PID / 多少个端口”
            if (g_targetMode == TargetMode::ByProcess) {
                UpdateProcessStateLabel();
            }
        }
        return 0;

    case WM_CLOSE:
        if (g_running) {
            StopDrop("窗口关闭：正在恢复联网…");
        }
        SaveSettings();
        DestroyWindow(window);
        return 0;

    case WM_DESTROY:
        KillTimer(window, kTimerId);
        weaknet::SetMouseHotkeyListener(false);
        UnregisterHotkeys();
        // 应用速率监控：停掉 ETW 会话，别把会话留给下一个进程
        weaknet::StopAppRateMonitor();
        if (g_appIconList != NULL) {
            ImageList_Destroy(g_appIconList);   // ListView 不会替你销毁它
            g_appIconList = NULL;
        }
        weaknet::DebugLogf("窗口关闭：热键已注销、鼠标钩子已卸载、速率监控已停止");
        if (g_font != NULL) {
            DeleteObject(g_font);
            g_font = NULL;
        }
        weaknet::ShutdownDebugLog();   // 收尾：写完最后一行再关文件
        PostQuitMessage(0);
        return 0;

    case WM_CTLCOLORSTATIC:
        // 让静态文本背景与对话框一致，避免出现灰块
        SetBkMode(reinterpret_cast<HDC>(wParam), TRANSPARENT);
        return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_3DFACE));

    default:
        break;
    }
    return DefWindowProcW(window, message, wParam, lParam);
}

}  // namespace

// =============================================================================
//  入口
// =============================================================================

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int showCommand)
{
    g_instance = instance;

    // 高 DPI：先声明 DPI 感知，再按系统 DPI 缩放布局；
    // 字体直接用系统消息字体（它自带 DPI 适配）
    SetProcessDPIAware();

    // ListView 属于 Common Controls，必须先初始化（v1.4.0 进程选择器要用）
    // v1.7.0 又用上了 Tab 控件和状态栏，一并初始化
    {
        INITCOMMONCONTROLSEX icc;
        icc.dwSize = sizeof(icc);
        icc.dwICC  = ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_BAR_CLASSES;
        InitCommonControlsEx(&icc);
    }
    HDC screen = GetDC(NULL);
    if (screen != NULL) {
        g_dpi = GetDeviceCaps(screen, LOGPIXELSX);
        ReleaseDC(NULL, screen);
    }

    InitializeCriticalSection(&g_logLock);
    g_logLockReady = true;

    // 尽早打开调试日志：之后任何一步失败/崩溃都能在文件里查到。
    // 放在窗口创建之前，连“注册窗口类失败”这类问题也能留下记录。
    StartDebugLog();
    weaknet::DebugLogf("GUI 启动：命令行参数已忽略，准备创建窗口");

    WNDCLASSEXW wc;
    std::memset(&wc, 0, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WindowProc;
    wc.hInstance     = instance;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_3DFACE + 1);
    wc.lpszClassName = L"WeakNetToolGuiWindow";
    wc.hIcon         = LoadIcon(NULL, IDI_APPLICATION);
    if (RegisterClassExW(&wc) == 0) {
        MessageBoxW(NULL, L"注册窗口类失败。", L"WeakNetTool GUI", MB_OK | MB_ICONERROR);
        return 1;
    }

    // 客户区目标尺寸 -> 反算窗口尺寸
    // 窗口和控件布局共用 kClientW/kClientH，避免两处尺寸不一致。
    HMENU appMenu = BuildAppMenu();
    RECT rect = { 0, 0, S(kClientW), S(kClientH) };
    // bMenu = TRUE：把菜单栏高度也算进去，否则客户区会被菜单吃掉一条
    AdjustWindowRect(&rect, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, TRUE);

    const std::wstring title = std::wstring(Utf8ToWide(weaknet::kToolName)) + L" GUI v" +
                               Utf8ToWide(weaknet::kToolVersion) +
                               L" —— 弱网测试（断网 / 联网）";
    HWND window = CreateWindowExW(
        0, wc.lpszClassName, title.c_str(),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        rect.right - rect.left, rect.bottom - rect.top,
        NULL, appMenu, instance, NULL);
    if (window == NULL) {
        MessageBoxW(NULL, L"创建窗口失败。", L"WeakNetTool GUI", MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(window, showCommand);
    UpdateWindow(window);

    // 运行期权限自检（正常情况下清单已经提权，这里只是兜底）
    if (!weaknet::IsElevated()) {
        const weaknet::Elevation state = weaknet::QueryElevation();
        const std::wstring advice = Utf8ToWide(weaknet::ElevationAdvice(state).c_str());
        GuiLog(LogLevel::Warning, "当前没有管理员权限，开始拦截会失败。", NULL);
        DrainLog();
        if (MessageBoxW(window,
                        (advice + L"\n\n是否现在以管理员身份重新启动？").c_str(),
                        L"需要管理员权限", MB_YESNO | MB_ICONWARNING) == IDYES) {
            RelaunchElevated();
            DestroyWindow(window);
            return 0;
        }
    }

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        // 捕获快捷键期间**不能**走 IsDialogMessage：
        // 它会把 Esc（以及 Enter/Tab/方向键）当作对话框导航键自己吃掉并返回 TRUE，
        // WM_KEYDOWN 永远到不了 WindowProc，表现就是“按 Esc 取消失效、
        // 界面还停在‘请按键…’状态”。
        // 所以捕获中直接派发，让 Esc 能正常进到我们的处理里。
        const bool capturing = (g_capturing != 0);
        if (!capturing && IsDialogMessageW(window, &msg)) {   // 让 Tab 键在控件间正常切换
            continue;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (g_logLockReady) {
        DeleteCriticalSection(&g_logLock);
        g_logLockReady = false;
    }
    return static_cast<int>(msg.wParam);
}
