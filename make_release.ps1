# =============================================================================
#  make_release.ps1 —— 生成发布包（可重复执行）
# -----------------------------------------------------------------------------
#  做四件事：
#    1) 用 build.bat 构建 Release（失败即中止，绝不产出半成品）
#    2) 组装 release\WeakNetTool-<版本>-win64\
#    3) 压缩成同名 zip
#    4) 打印产物清单与 SHA256，便于校验
#
#  版本号直接从源码 src\weaknet_core.cpp 里读，避免文档与代码不一致。
#  本脚本刻意保持 ASCII 安全（Windows PowerShell 5.1 会把无 BOM 的 .ps1 当 ANSI 解码），
#  中文只出现在读取/写入的文件内容里。
# =============================================================================

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$cli  = Join-Path $root 'build\WeakNetTool.exe'
$gui  = Join-Path $root 'build\WeakNetToolGUI.exe'

# ---- 1. 版本号取自源码（定义在 weaknet_core.cpp，头文件里只是声明） ----------
$coreSource = Join-Path $root 'src\weaknet_core.cpp'
if (-not (Test-Path $coreSource)) { throw "missing $coreSource" }
$version = $null
foreach ($line in [System.IO.File]::ReadAllLines($coreSource, [System.Text.Encoding]::UTF8)) {
    $m = [regex]::Match($line, 'kToolVersion\s*=\s*"([^"]+)"')
    if ($m.Success) { $version = $m.Groups[1].Value; break }
}
if (-not $version) { throw 'cannot read kToolVersion from src\weaknet_core.cpp' }
Write-Host "[release] version = $version"

# ---- 2. 构建 -----------------------------------------------------------------
Write-Host '[release] building Release ...'
$buildOut = & cmd.exe /c "cd /d `"$root`" && build.bat Release" 2>&1
$buildRc  = $LASTEXITCODE
$buildOut | Out-Host
if ($buildRc -ne 0) { throw "build failed (exit $buildRc)" }
foreach ($f in @($cli, $gui)) {
    if (-not (Test-Path $f)) { throw "build did not produce $f" }
}

# ---- 3. 组装发布目录 ---------------------------------------------------------
$arch    = 'win64'
$pkgName = "WeakNetTool-$version-$arch"
$relDir  = Join-Path $root 'release'
$pkgDir  = Join-Path $relDir $pkgName

# 注意：如果 WinDivert 驱动此刻正从**旧发布目录**加载着（例如之前从这个目录
# 运行过程序），内核会一直占着 WinDivert64.sys，删不掉也覆盖不了 —— 会报
# "对路径 WinDivert64.sys 的访问被拒绝"。这不是脚本 bug，是驱动还没卸载。
# 所以这里改成**逐文件删除 + 明确提示**，而不是直接 Remove-Item 整个目录，
# 这样报错时用户能立刻看懂该怎么办。
if (Test-Path $pkgDir) {
    $locked = @()
    foreach ($f in Get-ChildItem $pkgDir -Recurse -Force) {
        try {
            Remove-Item $f.FullName -Recurse -Force -ErrorAction Stop
        } catch {
            $locked += $f.FullName
        }
    }
    if ($locked.Count -gt 0) {
        Write-Host ''
        Write-Host '[ERROR] 以下文件被占用，无法覆盖：' -ForegroundColor Red
        foreach ($f in $locked) { Write-Host "        $f" -ForegroundColor Red }
        Write-Host ''
        Write-Host '原因：WinDivert 内核驱动正在从上面这个目录运行（之前从该目录启动过程序），' -ForegroundColor Yellow
        Write-Host '      驱动会一直占着 WinDivert64.sys，直到卸载或重启。' -ForegroundColor Yellow
        Write-Host ''
        Write-Host '处理办法（任选其一）：' -ForegroundColor Yellow
        Write-Host '  1) 注销 / 重启电脑后重新打包（最省事）；' -ForegroundColor Yellow
        Write-Host '  2) 管理员执行： sc stop WinDivert  然后重新打包；' -ForegroundColor Yellow
        Write-Host '  3) 如果确需另发新版本，先统一更新 kToolVersion、CMake 和发布说明。' -ForegroundColor Yellow
        throw "release 目录被占用的文件无法覆盖（多数是 WinDivert 驱动仍在使用该目录）"
    }
    Remove-Item $pkgDir -Recurse -Force -ErrorAction SilentlyContinue
}
[void](New-Item -ItemType Directory -Force -Path $pkgDir)

$files = @(
    @{ Src = $cli;                                    Name = 'WeakNetTool.exe' },
    @{ Src = $gui;                                    Name = 'WeakNetToolGUI.exe' },
    @{ Src = (Join-Path $root 'build\WinDivert.dll'); Name = 'WinDivert.dll' },
    @{ Src = (Join-Path $root 'build\WinDivert64.sys'); Name = 'WinDivert64.sys' },
    @{ Src = (Join-Path $root 'WinDivert-2.2.2-A\LICENSE'); Name = 'WinDivert-LICENSE.txt' },
    @{ Src = (Join-Path $root 'WinDivert-2.2.2-A\README'); Name = 'WinDivert-README.txt' },
    @{ Src = (Join-Path $root 'THIRD_PARTY_NOTICES.md'); Name = 'THIRD_PARTY_NOTICES.md' },
    @{ Src = (Join-Path $root 'LICENSE'); Name = 'LICENSE' },
    @{ Src = (Join-Path $root 'README.md');           Name = 'README.md' },
    @{ Src = (Join-Path $root 'RELEASE_NOTES.md');    Name = 'RELEASE_NOTES.md' },
    # 完整版文档（原理 / 全部参数 / 逐条测试记录）。README 只讲"怎么用"，
    # 想看细节的人可以从 README 末尾的链接点进来。
    @{ Src = (Join-Path $root 'DESIGN.md');           Name = 'DESIGN.md' }
)
foreach ($item in $files) {
    if (-not (Test-Path $item.Src)) { throw "missing input file: $($item.Src)" }
    Copy-Item $item.Src (Join-Path $pkgDir $item.Name) -Force
}

# ---- 4. 压缩（把整个目录打进 zip，解压后自然有文件夹） ----------------------
$zipPath = Join-Path $relDir "$pkgName.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Write-Host '[release] compressing ...'
Compress-Archive -Path $pkgDir -DestinationPath $zipPath -CompressionLevel Optimal

# ---- 5. 清单与校验 -----------------------------------------------------------
Write-Host ''
Write-Host '===================== release 产物 ====================='
Get-ChildItem $pkgDir | ForEach-Object {
    Write-Host ('  {0,-22} {1,10:N0} bytes' -f $_.Name, $_.Length)
}
$zipItem = Get-Item $zipPath
Write-Host ('  {0,-22} {1,10:N0} bytes' -f $zipItem.Name, $zipItem.Length)
Write-Host ''
Write-Host 'SHA256:'
foreach ($name in @('WeakNetTool.exe', 'WeakNetToolGUI.exe', 'WinDivert.dll', 'WinDivert64.sys')) {
    $path = Join-Path $pkgDir $name
    $hash = (Get-FileHash $path -Algorithm SHA256).Hash
    Write-Host ('  {0,-22} {1}' -f $name, $hash)
}
Write-Host '======================================================='
Write-Host ('[release] done -> ' + $pkgDir)
Write-Host ('[release] zip  -> ' + $zipPath)
