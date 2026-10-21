# =============================================================================
#  WeakNetTool —— Windows 弱网测试工具（WinDivert 版）
#
#  本工程产出两个可执行文件（共用同一份引擎 src/weaknet_core.cpp）：
#     WeakNetTool.exe      命令行版（控制台程序）
#     WeakNetToolGUI.exe   图形界面版（Win32 原生控件，清单请求管理员权限）
#
#  构建示例：
#     cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
#     cmake --build build
#  如果 WinDivert 不在默认的 windivert/ 或 WinDivert-*/ 目录：
#     cmake -S . -B build -DWINDIVERT_ROOT="D:/sdk/WinDivert-2.2.2-A"
# =============================================================================

cmake_minimum_required(VERSION 3.15)

project(WeakNetTool VERSION 2.0.11 LANGUAGES CXX)

# -----------------------------------------------------------------------------
#  一、通用编译设置
# -----------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 11)             # 需求要求 C++11 或以上
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 静态链接 MSVC 运行库：产出的 exe 可以直接拷到测试机运行，不需要装 VC 运行库
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# 单配置生成器（Ninja / Makefile）未指定构建类型时，默认 Release
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "构建类型" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

if(NOT WIN32)
    message(FATAL_ERROR "本工具依赖 WinDivert，只能在 Windows 平台上构建。")
endif()

# -----------------------------------------------------------------------------
#  二、定位 WinDivert
#       1) -DWINDIVERT_ROOT=<目录>
#       2) 项目根目录下的 windivert/
#       3) 项目根目录下的 WinDivert-*/
#     既支持官方发行包布局（include/ + x64/ + x86/），也支持文件平铺布局。
# -----------------------------------------------------------------------------
set(WINDIVERT_ROOT "" CACHE PATH "WinDivert 解压目录（内含 include/ 与 x64/ 或 x86/）")

if(NOT WINDIVERT_ROOT)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/windivert")
        set(WINDIVERT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/windivert")
    else()
        file(GLOB _windivert_candidates LIST_DIRECTORIES true "${CMAKE_CURRENT_SOURCE_DIR}/WinDivert-*")
        foreach(_candidate ${_windivert_candidates})
            if(IS_DIRECTORY "${_candidate}" AND EXISTS "${_candidate}/include/windivert.h")
                set(WINDIVERT_ROOT "${_candidate}")
                break()
            endif()
        endforeach()
        unset(_windivert_candidates)
    endif()
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(WINDIVERT_ARCH_DIR "x64")
else()
    set(WINDIVERT_ARCH_DIR "x86")
endif()

find_path(WINDIVERT_INCLUDE_DIR
    NAMES windivert.h
    PATHS "${WINDIVERT_ROOT}/include" "${WINDIVERT_ROOT}"
    NO_DEFAULT_PATH)

find_library(WINDIVERT_LIBRARY
    NAMES WinDivert windivert
    PATHS "${WINDIVERT_ROOT}/${WINDIVERT_ARCH_DIR}" "${WINDIVERT_ROOT}/lib" "${WINDIVERT_ROOT}"
    NO_DEFAULT_PATH)

if(NOT WINDIVERT_INCLUDE_DIR OR NOT WINDIVERT_LIBRARY)
    message(FATAL_ERROR
        "\n无法定位 WinDivert：\n"
        "  windivert.h  : ${WINDIVERT_INCLUDE_DIR}\n"
        "  WinDivert.lib: ${WINDIVERT_LIBRARY}\n"
        "  WINDIVERT_ROOT = ${WINDIVERT_ROOT}\n"
        "\n解决办法（任选其一）：\n"
        "  1) 从 https://www.reqrypt.org/windivert.html 下载 WinDivert-2.2.2-A.zip，\n"
        "     解压后把整个目录重命名为 windivert 放到本工程根目录，最终结构形如：\n"
        "        <工程根目录>/windivert/include/windivert.h\n"
        "        <工程根目录>/windivert/x64/WinDivert.lib\n"
        "        <工程根目录>/windivert/x64/WinDivert.dll\n"
        "        <工程根目录>/windivert/x64/WinDivert64.sys\n"
        "  2) 或手工指定路径：cmake -S . -B build -DWINDIVERT_ROOT=\"D:/sdk/WinDivert-2.2.2-A\"\n")
endif()

# 运行期依赖：WinDivert.dll 必须与 exe 同目录；.sys 由驱动按需加载。
find_file(WINDIVERT_DLL
    NAMES WinDivert.dll
    PATHS "${WINDIVERT_ROOT}/${WINDIVERT_ARCH_DIR}" "${WINDIVERT_ROOT}"
    NO_DEFAULT_PATH)

set(WINDIVERT_RUNTIME_FILES "")
if(WINDIVERT_DLL)
    list(APPEND WINDIVERT_RUNTIME_FILES "${WINDIVERT_DLL}")
endif()
foreach(_sysname WinDivert64.sys WinDivert32.sys)
    find_file(_windivert_sys_${_sysname}
        NAMES ${_sysname}
        PATHS "${WINDIVERT_ROOT}/${WINDIVERT_ARCH_DIR}" "${WINDIVERT_ROOT}"
        NO_DEFAULT_PATH)
    if(_windivert_sys_${_sysname})
        list(APPEND WINDIVERT_RUNTIME_FILES "${_windivert_sys_${_sysname}}")
    endif()
endforeach()

# -----------------------------------------------------------------------------
#  三、公用源码
# -----------------------------------------------------------------------------
set(WEAKNET_CORE_SOURCES
    src/weaknet_core.cpp
    src/weaknet_core.h)

# 公共编译/链接设置，应用到两个目标
function(weaknet_apply_common target)
    target_include_directories(${target} PRIVATE "${WINDIVERT_INCLUDE_DIR}")
    target_link_libraries(${target} PRIVATE "${WINDIVERT_LIBRARY}")

    # ---- 系统库 ---------------------------------------------------------------
    # iphlpapi：GetExtendedTcpTable / GetExtendedUdpTable（“进程 -> 本地端口”映射）
    # 源码里对应 #include <iphlpapi.h>；CreateToolhelp32Snapshot / Process32NextW
    # 来自 kernel32，MSVC 默认已链接，MinGW 也一样，无需额外处理。
    target_link_libraries(${target} PRIVATE iphlpapi)

    # version：GetFileVersionInfo / VerQueryValue（v1.4.0 进程选择器里读“程序说明”）
    # comctl32：ListView（v1.4.0 进程选择器的列表控件）
    # winmm：timeBeginPeriod / timeEndPeriod（v1.5.0 限速要毫秒级定时精度）
    target_link_libraries(${target} PRIVATE version comctl32 winmm)

    if(MINGW)
        # MinGW 的 iphlpapi 实现分散在 ws2_32 里
        target_link_libraries(${target} PRIVATE ws2_32)
    endif()

    if(MSVC)
        target_compile_options(${target} PRIVATE
            /W4          # 高等级警告
            /utf-8       # 源码是 UTF-8，中文注释/字符串才不会乱码（非常重要）
            /permissive- # 更严格的标准一致性
            /nologo)
    elseif(MINGW)
        target_compile_options(${target} PRIVATE -Wall -Wextra)
        target_link_options(${target} PRIVATE -municode -static -static-libgcc -static-libstdc++)
    endif()

    # 构建后把 WinDivert.dll / *.sys 拷到 exe 所在目录
    foreach(_file ${WINDIVERT_RUNTIME_FILES})
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${_file}" "$<TARGET_FILE_DIR:${target}>"
            COMMENT "拷贝 WinDivert 运行期文件到 $<TARGET_FILE_DIR:${target}>")
    endforeach()
endfunction()

# -----------------------------------------------------------------------------
#  四、命令行版
# -----------------------------------------------------------------------------
add_executable(WeakNetTool src/main.cpp ${WEAKNET_CORE_SOURCES})
set_target_properties(WeakNetTool PROPERTIES
    WIN32_EXECUTABLE OFF        # 控制台程序，要有控制台窗口看输出
    OUTPUT_NAME "WeakNetTool")
weaknet_apply_common(WeakNetTool)

if(MSVC)
    # 可选：给命令行版也嵌入“需要管理员权限”的清单（双击自动提权）。
    # 默认关闭，以便程序自身的权限自检提示生效。
    option(WEAKNET_REQUIRE_ADMIN "为命令行版嵌入 requireAdministrator 清单" OFF)
    if(WEAKNET_REQUIRE_ADMIN)
        target_link_options(WeakNetTool PRIVATE "/MANIFESTUAC:level='requireAdministrator'")
    endif()
endif()

# -----------------------------------------------------------------------------
#  五、图形界面版
# -----------------------------------------------------------------------------
add_executable(WeakNetToolGUI WIN32 src/gui_main.cpp ${WEAKNET_CORE_SOURCES})
set_target_properties(WeakNetToolGUI PROPERTIES
    WIN32_EXECUTABLE ON         # /SUBSYSTEM:WINDOWS
    OUTPUT_NAME "WeakNetToolGUI")
weaknet_apply_common(WeakNetToolGUI)

# 不打开 WinDivert 驱动的核心算法回归测试。
include(CTest)
if(BUILD_TESTING)
    add_executable(WeakNetToolCoreTests tests/weaknet_core_tests.cpp)
    target_compile_definitions(WeakNetToolCoreTests PRIVATE WEAKNET_TEST_HOOKS)
    weaknet_apply_common(WeakNetToolCoreTests)
    add_test(NAME WeakNetToolCoreTests COMMAND WeakNetToolCoreTests)

    add_executable(WeakNetToolGuiSettingsTests tests/weaknet_gui_settings_tests.cpp
                   src/weaknet_core.cpp)
    target_compile_definitions(WeakNetToolGuiSettingsTests PRIVATE
                               WEAKNET_GUI_TEST_HOOKS WEAKNET_TEST_HOOKS)
    weaknet_apply_common(WeakNetToolGuiSettingsTests)
    add_test(NAME WeakNetToolGuiSettingsTests COMMAND WeakNetToolGuiSettingsTests)
endif()

if(MSVC)
    # GUI 版一律请求管理员权限：双击即弹 UAC，体验最好；
    # 同时显式指定宽字符入口点，避免链接器选错 WinMainCRTStartup。
    target_link_options(WeakNetToolGUI PRIVATE
        "/MANIFESTUAC:level='requireAdministrator'"
        "/ENTRY:wWinMainCRTStartup")
endif()

# -----------------------------------------------------------------------------
#  六、配置摘要
# -----------------------------------------------------------------------------
message(STATUS "")
message(STATUS "==================== WeakNetTool 配置摘要 ====================")
message(STATUS " 版本            : ${PROJECT_VERSION}")
message(STATUS " 构建类型        : ${CMAKE_BUILD_TYPE}")
message(STATUS " 目标架构        : ${WINDIVERT_ARCH_DIR} (${CMAKE_SIZEOF_VOID_P} 字节指针)")
message(STATUS " WinDivert 目录  : ${WINDIVERT_ROOT}")
message(STATUS " 头文件          : ${WINDIVERT_INCLUDE_DIR}")
message(STATUS " 导入库          : ${WINDIVERT_LIBRARY}")
message(STATUS " 运行期文件      : ${WINDIVERT_RUNTIME_FILES}")
message(STATUS " 产出            : WeakNetTool.exe（命令行） / WeakNetToolGUI.exe（图形界面）")
message(STATUS "=============================================================")
