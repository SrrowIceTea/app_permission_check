# 项目统一 Python 入口（仅用于授权测试）。
#
# 用途：把「用哪个解释器」这件事固定下来，避免默认 `python`（本机是 WindowsApps 的
# 3.15，缺 frida/mitmproxy/cryptography/jsonschema）让回归冒出成片 ModuleNotFoundError。
# 本脚本只做转发：不修改系统默认 python、不改 PATH、不安装任何包。
#
# 用法（在仓库根执行）：
#   .\tools\python313.ps1 tools\run_regressions.py --mobile
#   .\tools\python313.ps1 mobile\tools\run_mobile_checks.py
#   .\tools\python313.ps1 -m unittest test_completion
#
# 解释器选择顺序与 environment.ps1 一致：
#   VSCAN_PYTHON > 项目 .venv > %LOCALAPPDATA%\Programs\Python\Python313

$ErrorActionPreference = 'Stop'
$env:PYTHONUTF8 = '1'

# 不用 param 块：$args 会原样收下 -m / --mobile 这类形似参数名的实参。
if ($args.Count -eq 0) {
    Write-Output '用法: .\tools\python313.ps1 <脚本及参数>，例如 tools\run_regressions.py --mobile'
    exit 0
}

$root = Split-Path -Parent $PSScriptRoot
$candidates = @()
if ($env:VSCAN_PYTHON) { $candidates += ,@($env:VSCAN_PYTHON, 'VSCAN_PYTHON') }
$candidates += ,@((Join-Path $root '.venv\Scripts\python.exe'), '项目 .venv')
$candidates += ,@((Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe'), 'Python 3.13 安装目录')

$chosen = $null
foreach ($candidate in $candidates) {
    if ($candidate[0] -and (Test-Path -LiteralPath $candidate[0])) { $chosen = $candidate; break }
}

if (-not $chosen) {
    $tried = ($candidates | ForEach-Object { $_[1] }) -join '、'
    [Console]::Error.WriteLine("[python313] 找不到项目解释器（试过：$tried）。")
    [Console]::Error.WriteLine('[python313] 请按 requirements.txt 准备 Python 3.13，或设 VSCAN_PYTHON 指向它。')
    exit 2
}

$python = $chosen[0]
& $python @args
$code = $LASTEXITCODE
if ($null -eq $code) { $code = 1 }
exit $code
