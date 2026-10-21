# WeakNetTool public source snapshot

This directory is a standalone, source-only Git repository with new history. It does not inherit the historical local repository's commits or author metadata. It contains no WinDivert precompiled DLL, driver, import library, sample executable, or generated WeakNetTool binary. The historical local repository and its binaries remain unchanged.

WeakNetTool's own source and documentation use the [MIT License](LICENSE). WinDivert has a separate license; this project selects the **GNU Lesser General Public License version 3** option for it. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and the complete upstream `WinDivert-2.2.2-A/LICENSE`.

WinDivert is a build and runtime dependency. Obtain the exact `WinDivert-2.2.2-A.zip` archive from the [official v2.2.2 release](https://github.com/basil00/WinDivert/releases/tag/v2.2.2) and verify its provenance before use. Extract it **outside** this source directory, for example to `D:\sdk\WinDivert-2.2.2-A`. The `WinDivert-2.2.2-A` folder here contains only the upstream `LICENSE`, `README`, and `VERSION`, checked against the official Git tree; it is not a complete SDK. A build needs the external package's `include/windivert.h`, x64 `WinDivert.lib`, `WinDivert.dll`, and `WinDivert64.sys`.

On Windows with Visual Studio C++ tools, the Windows SDK, CMake, and Ninja, build with the external SDK in PowerShell:

```powershell
$env:WINDIVERT_ROOT = 'D:\sdk\WinDivert-2.2.2-A' # change to your extracted SDK
.\build.bat Release
ctest --test-dir build --output-on-failure
```

`build.bat` reads `WINDIVERT_ROOT`; it does not download WinDivert. CTest must be available on `PATH` to run the last command. The local verification of this snapshot used the existing SDK in the private project directory. That confirms the source builds, but does **not** clear those SDK binaries for public redistribution.

`make_release.bat` invokes `make_release.ps1`, which first runs `build.bat Release`. It therefore needs the same external `WINDIVERT_ROOT`; it then copies the built executables and the SDK DLL/driver from `build/` into a zip, along with this project's MIT `LICENSE`, the WinDivert license and README, and `THIRD_PARTY_NOTICES.md`. The script does not download or authenticate the SDK. Its binary output must remain private until the precompiled dependencies and applicable LGPL source-delivery requirements are verified.

`RELEASE_NOTES.md` in this snapshot has one historical user-directory path redacted. The source files are otherwise copied from the local working tree. No claim is made that the original Git history has been sanitized.
