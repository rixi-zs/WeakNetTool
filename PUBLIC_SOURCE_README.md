# WeakNetTool 2.0.11 源码版说明

本仓库是独立的源码仓库，不包含旧本地仓库的 Git 历史，也不包含 WeakNetTool 可执行文件或 WinDivert 预编译 DLL、驱动、导入库和示例程序。这里的 `WinDivert-2.2.2-A/` 仅保留上游 `LICENSE`、`README` 和 `VERSION`，**不是完整 SDK**。

WeakNetTool 自身源码和文档采用 [MIT 许可证](LICENSE)。WinDivert 是独立的第三方依赖，本项目对其采用 **GNU 宽通用公共许可证第 3 版（LGPL v3）**选项。许可范围、版权声明和上游材料见 [第三方声明](THIRD_PARTY_NOTICES.md) 与 `WinDivert-2.2.2-A/LICENSE`；WeakNetTool 的 MIT 许可不覆盖 WinDivert。

## 获取依赖并构建

从 [WinDivert 官方 v2.2.2 发布页](https://github.com/basil00/WinDivert/releases/tag/v2.2.2) 获取 `WinDivert-2.2.2-A.zip`，自行核对来源，解压到本仓库之外。MSVC x64 构建需要 `include/windivert.h`、`x64/WinDivert.lib`、`x64/WinDivert.dll` 和 `x64/WinDivert64.sys`。在 Windows 上安装 Visual Studio C++ 工具、Windows SDK、CMake 和 Ninja，然后在 PowerShell 中执行：

```powershell
$env:WINDIVERT_ROOT = 'D:\sdk\WinDivert-2.2.2-A' # 改为实际 SDK 路径
.\build.bat Release
ctest --test-dir build --output-on-failure
```

`build.bat` 读取 `WINDIVERT_ROOT`，不会自动下载 SDK。最后一行需要 `ctest` 位于 `PATH`。构建时脚本会将外部 SDK 的运行期文件复制到本地 `build/`；这不代表这些预编译文件已获准用于公开二进制发布。

`make_release.bat` 调用 `make_release.ps1`，先构建 Release，再把程序和 SDK 的 DLL、驱动复制到二进制压缩包，同时附上 WeakNetTool 的 MIT 许可文本及 WinDivert 的许可与声明。该脚本同样依赖外部 `WINDIVERT_ROOT`，不会下载或核验 SDK。**预编译依赖的来源、逐文件哈希及适用的 LGPL v3 交付要求尚未复核完成，不应公开发布该二进制包。**

使用方法见 [README.md](README.md)，历史版本与测试边界见 [RELEASE_NOTES.md](RELEASE_NOTES.md)。历史记录不能代替当前版本的真实网络、GUI 或 ETW 验证。
