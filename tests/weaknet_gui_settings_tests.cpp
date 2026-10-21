#include "../src/gui_main.cpp"

#include <cstdio>

namespace weaknet { extern volatile LONG g_testFailEtwStart; }

#define CHECK(expr) do { if (!(expr)) { \
    std::fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #expr); \
    return 1; \
} } while (0)

static HWND MakeControl(HWND parent, const wchar_t* cls)
{
    return CreateWindowExW(0, cls, L"", WS_CHILD | WS_VISIBLE,
                           0, 0, 120, 24, parent, NULL, GetModuleHandleW(NULL), NULL);
}

static void MakeCombo(HWND parent, HWND& combo, int count, int selected)
{
    combo = CreateWindowExW(0, WC_COMBOBOXW, L"", WS_CHILD | CBS_DROPDOWNLIST,
                            0, 0, 120, 80, parent, NULL, GetModuleHandleW(NULL), NULL);
    for (int i = 0; i < count; ++i) {
        SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"unit"));
    }
    SendMessageW(combo, CB_SETCURSEL, selected, 0);
}

int main()
{
    wchar_t cwd[MAX_PATH] = { 0 };
    CHECK(GetCurrentDirectoryW(MAX_PATH, cwd) > 0);
    g_testIniPath = std::wstring(cwd) + L"\\weaknet_gui_test_" +
                    std::to_wstring(GetCurrentProcessId()) + L".ini";
    CHECK(GetFileAttributesW(g_testIniPath.c_str()) == INVALID_FILE_ATTRIBUTES);

    HWND parent = CreateWindowExW(0, L"STATIC", L"settings test", WS_OVERLAPPED,
                                  0, 0, 500, 400, NULL, NULL, GetModuleHandleW(NULL), NULL);
    CHECK(parent != NULL);
    g_hPort = MakeControl(parent, L"EDIT");
    g_hProcess = MakeControl(parent, L"EDIT");
    g_hDuration = MakeControl(parent, L"EDIT");
    g_hLossDown = MakeControl(parent, L"EDIT");
    g_hLossUp = MakeControl(parent, L"EDIT");
    g_hRateDown = MakeControl(parent, L"EDIT");
    g_hRateUp = MakeControl(parent, L"EDIT");
    MakeCombo(parent, g_hDir, 3, 2);
    MakeCombo(parent, g_hMatch, 2, 0);
    MakeCombo(parent, g_hProto, 3, 2);
    MakeCombo(parent, g_hRateUnitDown, 3, 1);
    MakeCombo(parent, g_hRateUnitUp, 3, 0);
    g_targetMode = TargetMode::AllPorts;
    SetWindowTextW(g_hPort, L"8080");
    SetWindowTextW(g_hDuration, L"0");
    SetWindowTextW(g_hLossDown, L"0");
    SetWindowTextW(g_hLossUp, L"0");
    SetWindowTextW(g_hRateDown, L"200");
    SetWindowTextW(g_hRateUp, L"300");
    CHECK(SaveSettings());
    CHECK(IniReadString(L"Main", L"RateDownBps", L"") == L"204800");
    CHECK(IniReadString(L"Main", L"RateUpBps", L"") == L"300");

    // 改速率与单位并重载，必须保留数值及单位，不发生 1024 倍膨胀。
    SetWindowTextW(g_hRateDown, L"2");
    SendMessageW(g_hRateUnitDown, CB_SETCURSEL, 2, 0);
    CHECK(SaveSettings());
    SetWindowTextW(g_hRateDown, L"999");
    SendMessageW(g_hRateUnitDown, CB_SETCURSEL, 0, 0);
    LoadSettings();
    CHECK(GetWideText(g_hRateDown) == L"2");
    CHECK(SendMessageW(g_hRateUnitDown, CB_GETCURSEL, 0, 0) == 2);
    CHECK(IniReadString(L"Main", L"RateDownBps", L"") == L"2097152");

    // ETW 启动被拒绝时，活动页要显示失败原因，不能提示为监控中。
    g_hAppRateStatus = MakeControl(parent, L"STATIC");
    weaknet::g_testFailEtwStart = 1;
    EnsureAppRateMonitor();
    const std::wstring status = GetWideText(g_hAppRateStatus);
    CHECK(status.find(L"无法启动监控") == 0);
    CHECK(status.find(L"管理员权限") != std::wstring::npos);
    CHECK(!weaknet::IsAppRateMonitorRunning());
    weaknet::g_testFailEtwStart = 0;

    // 输入无效时不覆盖上一次有效的 INI。
    SetWindowTextW(g_hRateDown, L"invalid");
    CHECK(!SaveSettings());
    CHECK(IniReadString(L"Main", L"RateDownBps", L"") == L"2097152");

    DestroyWindow(parent);
    CHECK(DeleteFileW(g_testIniPath.c_str()) != FALSE);
    std::puts("weaknet_gui_settings_tests: INI round-trip, invalid input, ETW error UI passed");
    return 0;
}
