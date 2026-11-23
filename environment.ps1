# 当前主机入口；仅用于授权测试。Dot-source: . .\environment.ps1
#
# 覆盖值优先；默认值按当前确实存在的工具解析，不把另一台开发机路径当成本机事实。

function Get-VScanSetting([string]$Name, [string]$Default) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($Name))) { $Default }
    else { [Environment]::GetEnvironmentVariable($Name) }
}

function Find-VScanSdk {
    foreach ($candidate in @("$env:LOCALAPPDATA\Android\Sdk", $env:ANDROID_SDK_ROOT, $env:ANDROID_HOME,
                             'E:\Android\android-sdk', 'D:\Android\SDK', 'D:\Anroid\SDK')) {
        if ($candidate -and (Test-Path -LiteralPath (Join-Path $candidate 'platform-tools/adb.exe'))) { return $candidate }
    }
    return "$env:LOCALAPPDATA\Android\Sdk"
}
function Find-VScanJdk {
    foreach ($candidate in @($env:JAVA_HOME, 'D:\Android\JDK', 'D:\Anroid\JDK', 'E:\Android\openjdk\jdk-17.0.12')) {
        if (-not $candidate -or -not (Test-Path -LiteralPath (Join-Path $candidate 'bin/java.exe'))) { continue }
        $release = Join-Path $candidate 'release'
        if ((Test-Path -LiteralPath $release) -and
            ((Get-Content -LiteralPath $release) -match '^JAVA_VERSION="(17|21)(\.|\")')) { return $candidate }
    }
    return 'D:\Android\JDK'
}
$VScanSdk = Get-VScanSetting 'VSCAN_SDK' (Find-VScanSdk)
$VScanJdk = Get-VScanSetting 'VSCAN_JDK' (Find-VScanJdk)
# 显式覆盖 > 项目虚拟环境 > 已有实际解释器，禁止回退 WindowsApps 别名。
$VScanDefaultPython = Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe'
if (Test-Path -LiteralPath (Join-Path $PSScriptRoot '.venv/Scripts/python.exe')) {
    $VScanDefaultPython = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
}
$VScanPython = Get-VScanSetting 'VSCAN_PYTHON' $VScanDefaultPython

foreach ($probe in @(@($VScanSdk, 'ANDROID SDK'), @($VScanJdk, 'JDK'), @($VScanPython, 'Python'))) {
    if (-not (Test-Path -LiteralPath $probe[0])) {
        Write-Warning "找不到 $($probe[1])：$($probe[0])（设 VSCAN_SDK / VSCAN_JDK / VSCAN_PYTHON 覆盖）"
    }
}

$env:ANDROID_HOME = $VScanSdk
$env:ANDROID_SDK_ROOT = $VScanSdk
if (Test-Path -LiteralPath $VScanJdk) { $env:JAVA_HOME = $VScanJdk }

# 本机 JDK17 的 AF_UNIX connect 失败；不存在的 socket 目录使 JDK 按自身逻辑回退 TCP。
# 默认放在系统临时目录，不创建此叶目录。显式 VSCAN_TEMP 保持用户指定的原意。
$VScanTemp = Get-VScanSetting 'VSCAN_TEMP' (Join-Path ([IO.Path]::GetTempPath()) 'vscanner-nio-tcp-fallback/unavailable')
$VScanJavaOptions = $env:JAVA_TOOL_OPTIONS -replace '(?:^|\s)-Djdk\.net\.unixdomain\.tmpdir=(?:"[^"]*"|\S+)', ''
$env:JAVA_TOOL_OPTIONS = ($VScanJavaOptions + ' -Djdk.net.unixdomain.tmpdir="' + $VScanTemp + '"').Trim()

$env:PYTHONUTF8 = '1'
$VScanPythonDir = Split-Path -Parent $VScanPython
$env:PATH = "$VScanSdk\platform-tools;$VScanSdk\emulator;$VScanPythonDir;" +
    (Join-Path $VScanPythonDir 'Scripts') + ';' + $env:PATH

# Gradle 由各工程的 gradlew 包装器提供（发行版已在 ~\.gradle\wrapper\dists 缓存）。
$VScanGradle = (Get-ChildItem -Path (Join-Path $env:USERPROFILE '.gradle\wrapper\dists\gradle-8.13-bin') `
        -Recurse -Filter 'gradle.bat' -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName)
if (-not $VScanGradle) { Write-Warning 'Gradle 8.13 未在 wrapper 缓存中找到；各工程仍可用 gradlew 包装器构建。' }

# 设备 pcap 的可选解码器。已安装版本可放在 PATH，或把组织提供的便携版本放到项目 output。
if (-not $env:VSCAN_TSHARK -and -not (Get-Command tshark -CommandType Application -ErrorAction SilentlyContinue)) {
    $VScanTshark = Join-Path $PSScriptRoot 'output\_tools\wireshark\tshark.exe'
    if (Test-Path -LiteralPath $VScanTshark -PathType Leaf) { $env:VSCAN_TSHARK = $VScanTshark }
}
