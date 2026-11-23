#Requires -Version 5.1
<#
.SYNOPSIS
    把车载演示环境一次备好：模拟器 → root → frida-server → 靶子安装 → 拉起应用。

.DESCRIPTION
    仅用于授权测试（自有设备与自有 APK）。

    8773 的「新建 AAOS 采集」在设备阶段会逐条硬校验，缺任何一条都会中止：
      1. 设备在线，且 `pm list features` 含 android.hardware.type.automotive
      2. ro.build.version.sdk = 35（scope=all 时不做低版本降级）
      3. 目标包装在 user 10 下、是单一 APK（非 split）、sha256 与上传的 APK 一致
      4. 应用正在运行（pidof 有输出），否则报 app_not_running
      5. frida-server 在设备上监听 127.0.0.1:27043（core/frida_host/run.py 会自己建 forward）

    本脚本按上述顺序逐条落实并复核，每步失败都给出可直接执行的下一步。
    模拟器由本脚本启动时是独立进程，脚本退出后仍继续运行。

.PARAMETER Serial
    adb serial，默认 emulator-5554。

.PARAMETER Avd
    AVD 名称，默认 VScanner_AAOS_35_P1（位于 output/vehicle-device-setup/avd）。

.PARAMETER User
    应用所在 AAOS 用户，默认 10。

.PARAMETER Apk
    要装的 APK，默认 self 靶子 vehicle/targets/target-app/.../app-debug.apk。

.PARAMETER Package
    包名，默认 com.vscanner.targetapp。

.PARAMETER NoEmulator
    不启动模拟器（设备已由别处启动时用）；其余检查照做。

.PARAMETER SkipApp
    只准备设备与 frida，不安装/拉起应用。

.PARAMETER BootTimeoutSec
    等待开机的秒数，默认 240。

.EXAMPLE
    .\prepare-vehicle-device.ps1
    .\prepare-vehicle-device.ps1 -NoEmulator
    .\prepare-vehicle-device.ps1 -Apk D:\tmp\other.apk -Package com.example.app -Activity com.example.app/.Main
#>
param(
    [string]$Serial = 'emulator-5554',
    [string]$Avd = 'VScanner_AAOS_35_P1',
    [int]$User = 10,
    [string]$Apk,
    [string]$Package = 'com.vscanner.targetapp',
    [string]$Activity = 'com.vscanner.targetapp/.MainActivity',
    [switch]$NoEmulator,
    [switch]$SkipApp,
    [int]$BootTimeoutSec = 240
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

$Root = $PSScriptRoot
if (-not $Apk) {
    $Apk = Join-Path $Root 'vehicle\targets\target-app\app\build\outputs\apk\debug\app-debug.apk'
}

function Write-Step([string]$Text) { Write-Host "[..] $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text) { Write-Host "[ok] $Text" -ForegroundColor Green }
function Write-Warn2([string]$Text) { Write-Host "[!]  $Text" -ForegroundColor Yellow }
function Write-Err2([string]$Text) { Write-Host "[x]  $Text" -ForegroundColor Red }

function Repair-ProxyEnvCase {
    # Git Bash 会同时导出 HTTPS_PROXY 与 https_proxy；PS 5.1 的 Start-Process 复制环境块时
    # 直接抛「已添加项。字典中的关键字」，模拟器一个都起不来。归一到大写，只留一份。
    $keys = @([Environment]::GetEnvironmentVariables().Keys |
        Where-Object { $_ -match '(?i)^(http|https|no|all)_proxy$' })
    if ($keys.Count -le 1) { return }
    $values = @{}
    foreach ($key in $keys) {
        $upper = $key.ToUpperInvariant()
        if (-not $values.ContainsKey($upper)) { $values[$upper] = [Environment]::GetEnvironmentVariable($key) }
    }
    foreach ($key in $keys) { [Environment]::SetEnvironmentVariable($key, $null, 'Process') }
    foreach ($key in $values.Keys) { [Environment]::SetEnvironmentVariable($key, $values[$key], 'Process') }
}

function Get-Adb {
    $envFile = Join-Path $Root 'environment.ps1'
    if (Test-Path -LiteralPath $envFile) {
        try { . $envFile } catch { Write-Warn2 ("environment.ps1 载入失败：{0}" -f $_.Exception.Message) }
    }
    $candidates = @()
    if ($env:VSCAN_ADB) { $candidates += $env:VSCAN_ADB }
    if ($env:ANDROID_SDK_ROOT) { $candidates += (Join-Path $env:ANDROID_SDK_ROOT 'platform-tools\adb.exe') }
    $candidates += (Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe')
    foreach ($path in $candidates) {
        if ($path -and (Test-Path -LiteralPath $path)) { return $path }
    }
    $cmd = Get-Command adb -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw '找不到 adb。设 VSCAN_ADB 指向 platform-tools\adb.exe，或用 environment.ps1 的默认 SDK 路径。'
}

function Invoke-Adb {
    # 统一走 -Arguments 数组：adb 的 --user / -r 会被 PowerShell 当命名参数解析。
    # 临时放宽 ErrorActionPreference：adb 把进度/提示写在 stderr，Stop 模式下会被当成终止错误。
    param([string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $output = & $script:Adb -s $Serial @Arguments 2>&1 } finally { $ErrorActionPreference = $previous }
    return @{ code = $LASTEXITCODE; text = (($output | Out-String).Trim()) }
}

function Test-DeviceOnline {
    return ((& $script:Adb devices) -join "`n") -match ([regex]::Escape($Serial) + '\s+(device|recovery)\b')
}

function Start-EmulatorIfNeeded {
    if ($NoEmulator) { Write-Warn2 '跳过模拟器启动（-NoEmulator）'; return }
    if (Test-DeviceOnline) { Write-Ok "$Serial 已在线，不再启动模拟器"; return }

    $sdk = if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } else { Join-Path $env:LOCALAPPDATA 'Android\Sdk' }
    $emu = Join-Path $sdk 'emulator\emulator.exe'
    if (-not (Test-Path -LiteralPath $emu)) { throw "找不到模拟器：$emu" }
    $avdHome = Join-Path $Root 'output\vehicle-device-setup\avd'
    if (-not (Test-Path -LiteralPath (Join-Path $avdHome "$Avd.ini"))) {
        throw "找不到 AVD $Avd：$avdHome。确认 output/vehicle-device-setup/avd 下有 $Avd.ini。"
    }
    $env:ANDROID_AVD_HOME = $avdHome
    Write-Step "启动模拟器 $Avd（独立进程，脚本退出后继续运行）"
    $logDir = Join-Path $Root 'output\logs'
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    Start-Process -FilePath $emu -ArgumentList '-avd', $Avd, '-no-snapshot', '-no-boot-anim' `
        -RedirectStandardOutput (Join-Path $logDir 'emulator.out.log') `
        -RedirectStandardError (Join-Path $logDir 'emulator.err.log') | Out-Null
    Write-Ok "已拉起 $Avd，日志 output\logs\emulator.*.log"
}

function Wait-Boot([int]$TimeoutSec = 240) {
    Write-Step "等待 $Serial 开机完成（最多 $TimeoutSec 秒）"
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (Test-DeviceOnline) {
            $boot = (Invoke-Adb -Arguments @('shell', 'getprop', 'sys.boot_completed')).text
            if ($boot -eq '1') { Write-Ok '开机完成'; return }
        }
        Start-Sleep -Seconds 3
    }
    throw "等待开机超时。看 output\logs\emulator.err.log；必要时手动 adb -s $Serial shell getprop sys.boot_completed 复核。"
}

function Enable-Root {
    Write-Step '切换 adbd 到 root（tcpdump 与 frida-server 需要）'
    # 不看 `adb root` 的回显（不同镜像下它可能输出到 stderr 或干脆不说话），
    # 直接以 `shell id` 的 uid 为准；root 会让 adbd 重启，所以要重试几轮。
    Invoke-Adb -Arguments @('root') | Out-Null
    for ($i = 0; $i -lt 10; $i++) {
        Start-Sleep -Seconds 1
        if (-not (Test-DeviceOnline)) { continue }
        $who = (Invoke-Adb -Arguments @('shell', 'id')).text
        if ($who -match 'uid=0') { Write-Ok "adbd 已是 root（$who）"; return }
    }
    Write-Warn2 'adbd 不是 root：tcpdump 与 frida-server 可能起不来（userdebug 镜像应可 root）'
}

function Assert-Aaos {
    $features = (Invoke-Adb -Arguments @('shell', 'pm', 'list', 'features')).text
    if ($features -notmatch 'android\.hardware\.type\.automotive') {
        throw "目标不是 AAOS（pm list features 无 automotive）。车载动态采集不能用手机镜像。"
    }
    $sdk = (Invoke-Adb -Arguments @('shell', 'getprop', 'ro.build.version.sdk')).text
    if ($sdk -ne '35') {
        Write-Warn2 "设备 API $sdk ≠ 35；8773 的 scope=all 只校准到 API 35，采集会被拒（除非改 scope=general）"
    }
    $current = (Invoke-Adb -Arguments @('shell', 'am', 'get-current-user')).text
    Write-Ok ("AAOS 特征齐全：API {0}，当前用户 {1}" -f $sdk, $current)
}

function Ensure-Frida {
    $remote = '/data/local/tmp/frida-server'
    $running = (Invoke-Adb -Arguments @('shell', 'pidof', 'frida-server')).text
    if ($running) { Write-Ok "frida-server 已在运行（pid $running）"; return }
    $local = Join-Path $Root 'output\vehicle-device-setup\frida-server'
    if (-not (Test-Path -LiteralPath $local)) { throw "找不到 $local；frida-server 版本必须等于宿主 frida 版本" }
    Write-Step '推送 frida-server（约 111 MB，首次较慢）'
    & $script:Adb -s $Serial push $local $remote | Out-Null
    Invoke-Adb -Arguments @('shell', 'chmod', '755', $remote) | Out-Null
    Write-Step '启动 frida-server（监听 127.0.0.1:27043，不是默认 27042）'
    # 必须 nohup + 关掉三个流：否则 adb shell 会等这条 pty 关闭，脚本就卡在这儿。
    # 客户端再包一层超时——即便它不退出，frida 已脱离会话，不会拖住流程。
    $shellCommand = "nohup $remote -l 127.0.0.1:27043 >/dev/null 2>&1 </dev/null &"
    $client = Start-Process -FilePath $script:Adb -ArgumentList '-s', $Serial, 'shell', $shellCommand `
        -WindowStyle Hidden -PassThru
    if (-not $client.WaitForExit(10000)) { try { $client.Kill() } catch { } }
    Start-Sleep -Seconds 2
    $pidValue = (Invoke-Adb -Arguments @('shell', 'pidof', 'frida-server')).text
    if (-not $pidValue) { throw 'frida-server 未起来。手动执行后看回显：adb shell /data/local/tmp/frida-server -l 127.0.0.1:27043' }
    Write-Ok "frida-server 已启动（pid $pidValue）"
}

function Install-App {
    if ($SkipApp) { Write-Warn2 '跳过应用安装（-SkipApp）'; return }
    if (-not (Test-Path -LiteralPath $Apk)) { throw "找不到 APK：$Apk" }
    $localHash = (Get-FileHash -LiteralPath $Apk -Algorithm SHA256).Hash.ToLowerInvariant()
    $remote = (Invoke-Adb -Arguments @('shell', 'pm', 'path', '--user', "$User", $Package)).text -replace 'package:', ''
    if ($remote) {
        $tmp = Join-Path $env:TEMP ("vscan-installed-$([guid]::NewGuid().ToString('N')).apk")
        # 用 Invoke-Adb 而不是直接调用：adb pull 的进度写在 stderr，Stop 模式下会被当终止错误。
        Invoke-Adb -Arguments @('pull', $remote, $tmp) | Out-Null
        $installed = if (Test-Path -LiteralPath $tmp) { (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash.ToLowerInvariant() } else { '' }
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        if ($installed -eq $localHash) { Write-Ok "已安装同一份 APK（sha256 ${localHash}0…）"; return }
        Write-Warn2 '设备上的版本与本地 APK 不一致，重装'
    } else {
        Write-Step "安装到 user $User"
    }
    $install = Invoke-Adb -Arguments @('install', '--user', "$User", '-r', $Apk)
    if ($install.code -ne 0) {
        throw "安装失败：$($install.text)。若提示 INSTALL_FAILED_UPDATE_INCOMPATIBLE，先 adb uninstall --user $User $Package"
    }
    Write-Ok "安装完成：$Package（user $User）"
}

function Start-App {
    if ($SkipApp) { return }
    Write-Step "拉起 $Activity"
    Invoke-Adb -Arguments @('shell', 'am', 'start', '--user', "$User", '-n', $Activity) | Out-Null
    Start-Sleep -Seconds 3
    $pidValue = (Invoke-Adb -Arguments @('shell', 'pidof', $Package)).text
    if (-not $pidValue) {
        throw "应用未运行（pidof 无输出）。手动打开该应用后重试：adb -s $Serial shell am start --user $User -n $Activity"
    }
    Write-Ok "应用在运行（pid $pidValue）"
}

Write-Host ('-' * 62)
Repair-ProxyEnvCase
$script:Adb = Get-Adb
Write-Ok "adb：$($script:Adb)"
Write-Host ('-' * 62)

Start-EmulatorIfNeeded
Wait-Boot -TimeoutSec $BootTimeoutSec
Enable-Root
Assert-Aaos
Ensure-Frida
Install-App
Start-App

Write-Host ('-' * 62)
Write-Ok '设备已就绪。现在：'
Write-Host '  1) start-vehicle.bat        （若还没启动工作台；默认已带 AI 辅助复核）'
Write-Host '  2) http://127.0.0.1:8773 → 上传同一份 APK → 选「新建 AAOS 采集」'
Write-Host '  3) 窗口内点「读取 VHAL」→「外泄 HTTP」两个按钮'
Write-Host '     不要点「索权演示」：它会拉起运行时权限框，实测把应用拖死，'
Write-Host '     随后 frida detach 卡住 → 整轮 capture_unhealthy。权限结论来自清单静态分析。'
Write-Host ('-' * 62)
Write-Host ("  收尾：adb -s {0} shell cmd car_service enable-uxr true" -f $Serial)
Write-Host ("        adb -s {0} emu kill   （演示结束再执行，会关掉模拟器）" -f $Serial)
