#Requires -Version 5.1
<#
.SYNOPSIS
    一键启动 V-Scanner 前后端（仅用于授权测试）。

.DESCRIPTION
    起 3 个常驻服务，等健康检查通过后打开浏览器；支持只起其中几个、查看状态、一键停止。
    服务与端口：
        pipeline  : 8771  一键审计流水线（移动端动态，mobile/pipeline）
        workbench : 8770  静态工作台（反编译 / 规则命中 / 静动交叉，vehicle/workbench）
        frontend  : 8090  零构建前端（frontend/，入口 app.html）
        vehicle   : 8773  车载工作台（vehicle/webapp，默认不起，用 -Only vehicle 显式开）

    为什么不用 start-frontend.bat：那个脚本用 cmd 开三个窗口，关窗口才停；
    这里把 PID 落到 output\logs\start-all.json，可 -Status 查、-Stop 停，日志也留盘。

.PARAMETER Only
    只起指定服务，默认 frontend,pipeline,workbench。

.PARAMETER NoBrowser
    不自动打开浏览器。

.PARAMETER Stop
    停止上次由本脚本启动的服务（按 state 文件里的 PID）。

.PARAMETER Status
    只查状态，不启动。

.PARAMETER TimeoutSec
    每个服务等待健康检查的秒数，默认 30。

.EXAMPLE
    .\start-all.ps1
    .\start-all.ps1 -Only pipeline,frontend
    .\start-all.ps1 -Status
    .\start-all.ps1 -Stop
#>
param(
    [ValidateSet('frontend', 'pipeline', 'workbench', 'vehicle')]
    [string[]]$Only = @('frontend', 'pipeline', 'workbench'),
    [switch]$NoBrowser,
    [switch]$Stop,
    [switch]$Status,
    [int]$TimeoutSec = 30
)

$ErrorActionPreference = 'Stop'
# 进度条会往重定向的控制台里插「正在读取 Web 响应」并打乱中文行。
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

$Root = $PSScriptRoot
$LogDir = Join-Path $Root 'output\logs'
$StateFile = Join-Path $LogDir 'start-all.json'

function Write-Step([string]$Text) { Write-Host "[..] $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text) { Write-Host "[ok] $Text" -ForegroundColor Green }
function Write-Warn2([string]$Text) { Write-Host "[!]  $Text" -ForegroundColor Yellow }
function Write-Err2([string]$Text) { Write-Host "[x]  $Text" -ForegroundColor Red }

function Repair-ProxyEnvCase {
    # Windows 环境变量大小写不敏感，但 Git Bash 会同时导出 HTTPS_PROXY 和 https_proxy。
    # PS 5.1 的 Start-Process 在为子进程复制环境块时直接抛「已添加项。字典中的关键字」，
    # 服务一个都起不来。这里把成对的同名变量归一到大写，只留一份。
    $keys = @([Environment]::GetEnvironmentVariables().Keys |
        Where-Object { $_ -match '(?i)^(http|https|no|all)_proxy$' })
    if ($keys.Count -le 1) { return }
    $values = @{}
    foreach ($key in $keys) {
        $upper = $key.ToUpperInvariant()
        if (-not $values.ContainsKey($upper)) {
            $values[$upper] = [Environment]::GetEnvironmentVariable($key)
        }
    }
    foreach ($key in $keys) { [Environment]::SetEnvironmentVariable($key, $null, 'Process') }
    foreach ($key in $values.Keys) { [Environment]::SetEnvironmentVariable($key, $values[$key], 'Process') }
}

function Resolve-Python {
    # 与 tools\python313.ps1 同一顺序：VSCAN_PYTHON > 项目 .venv > Python313 安装目录。
    $candidates = @()
    if ($env:VSCAN_PYTHON) { $candidates += , @($env:VSCAN_PYTHON, 'VSCAN_PYTHON') }
    $candidates += , @((Join-Path $Root '.venv\Scripts\python.exe'), '项目 .venv')
    $candidates += , @((Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe'), 'Python 3.13 安装目录')
    foreach ($item in $candidates) {
        $path, $label = $item
        if ($path -and (Test-Path -LiteralPath $path)) {
            # 用 --version 而不是 -c：PS 5.1 往原生程序传带引号/百分号的 -c 实参会二次解析。
            $version = (& $path --version 2>&1) -join ' '
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "$version（$label）：$path"
                return $path
            }
        }
    }
    throw '找不到可用的 Python 3.13。设 VSCAN_PYTHON 指向解释器，或安装到 %LOCALAPPDATA%\Programs\Python\Python313。'
}

function Get-PortOwner([int]$Port) {
    # 只查是谁占着，不杀。占用的可能是用户自己的进程，脚本无权替他做决定。
    try {
        $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop |
            Select-Object -First 1
        if ($conn) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            if ($proc) { return ("{0} (PID {1})" -f $proc.ProcessName, $proc.Id) }
            return ("PID {0}" -f $conn.OwningProcess)
        }
    } catch { }
    return $null
}

function Test-Health([string]$Url) {
    try {
        $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2
        return ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 400)
    } catch {
        return $false
    }
}

function Get-Services {
    $py = Resolve-Python
    $common = @{ Python = $py; Root = $Root }
    return @(
        @{
            Name    = 'pipeline'
            Port    = 8771
            Health  = 'http://127.0.0.1:8771/api/stages'
            WorkDir = $Root
            File    = $common.Python
            Args    = @('mobile\pipeline\server.py', '--port', '8771',
                '--workdir', (Join-Path $Root 'output\pipeline-runs'))
            Note    = '一键审计流水线（动态阶段需要 adb 设备）'
        },
        @{
            Name    = 'workbench'
            Port    = 8770
            Health  = 'http://127.0.0.1:8770/'
            WorkDir = $Root
            File    = $common.Python
            Args    = @('vehicle\workbench\server.py', '--port', '8770')
            Note    = '静态工作台（反编译 / 规则命中）'
        },
        @{
            Name    = 'frontend'
            Port    = 8090
            Health  = 'http://127.0.0.1:8090/app.html'
            WorkDir = Join-Path $Root 'frontend'
            File    = $common.Python
            Args    = @('-m', 'http.server', '8090', '--bind', '127.0.0.1')
            Note    = '前端静态页（零构建）'
        },
        @{
            Name    = 'vehicle'
            Port    = 8773
            Health  = 'http://127.0.0.1:8773/'
            WorkDir = $Root
            File    = $common.Python
            Args    = @('vehicle\webapp\server.py', '--port', '8773')
            Note    = '车载工作台（默认不启动）'
        }
    )
}

function Read-State {
    if (-not (Test-Path -LiteralPath $StateFile)) { return @() }
    try {
        $raw = Get-Content -LiteralPath $StateFile -Raw -Encoding UTF8 | ConvertFrom-Json
        return @($raw)
    } catch {
        Write-Warn2 "状态文件损坏，按空处理：$StateFile"
        return @()
    }
}

function Save-State($Items) {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    $json = ConvertTo-Json -InputObject @($Items) -Depth 4
    # UTF8 无 BOM 写 JSON：BOM 会让 ConvertFrom-Json 在某些版本上读出乱码。
    [IO.File]::WriteAllText($StateFile, $json, (New-Object Text.UTF8Encoding($false)))
}

function Invoke-Status($Services) {
    $states = @(Read-State)
    # 不用 Format-Table：PS 5.1 在 GBK 控制台上按字符数算宽度，中文列头会被截断成乱码。
    Write-Host ("{0,-10} {1,-6} {2,-6} {3}" -f 'SERVICE', 'PORT', 'HEALTH', 'OWNER')
    Write-Host ("{0,-10} {1,-6} {2,-6} {3}" -f '----------', '------', '------', '------------------------------')
    foreach ($svc in $Services) {
        $owner = Get-PortOwner $svc.Port
        $alive = Test-Health $svc.Health
        $target = 'not running'
        if ($owner) { $target = $owner }
        elseif ($alive) { $target = 'listening (pid unknown)' }
        Write-Host ("{0,-10} {1,-6} {2,-6} {3}" -f $svc.Name, $svc.Port,
            $(if ($alive) { 'ok' } else { '-' }), $target)
    }
    Write-Host ('-' * 62)
    foreach ($svc in $Services) { Write-Host ("  {0,-10} {1}" -f $svc.Name, $svc.Note) }
    if ($states.Count -gt 0) {
        Write-Host ('-' * 62)
        Write-Host 'started by this script:'
        foreach ($row in $states) {
            if (-not $row.name) { continue }
            $proc = Get-Process -Id $row.pid -ErrorAction SilentlyContinue
            $state = if ($proc) { 'alive' } else { 'stale' }
            Write-Host ("  {0,-10} PID {1,-7} {2,-6} {3}" -f $row.name, $row.pid, $state, $row.started)
        }
    }
}

function Invoke-Stop {
    $states = Read-State
    if ($states.Count -eq 0) { Write-Warn2 '没有本脚本登记过的服务。'; return }
    foreach ($row in $states) {
        if (-not $row.pid) { continue }
        $proc = Get-Process -Id $row.pid -ErrorAction SilentlyContinue
        if (-not $proc) { Write-Warn2 ("{0}：PID {1} 已不在" -f $row.name, $row.pid); continue }
        try {
            Stop-Process -Id $row.pid -Force -ErrorAction Stop
            Write-Ok ("已停止 {0}（PID {1}）" -f $row.name, $row.pid)
        } catch {
            Write-Err2 ("停止 {0} 失败：{1}" -f $row.name, $_.Exception.Message)
        }
    }
    Remove-Item -LiteralPath $StateFile -Force -ErrorAction SilentlyContinue
}

Repair-ProxyEnvCase
$services = Get-Services

if ($Status) { Invoke-Status $services; exit 0 }
if ($Stop) { Invoke-Stop; exit 0 }

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$selected = $services | Where-Object { $Only -contains $_.Name }
if (-not $selected) { Write-Err2 "没有匹配的服务：$($Only -join ', ')"; exit 1 }

$started = @()
$failed = @()
foreach ($svc in $selected) {
    $owner = Get-PortOwner $svc.Port
    if ($owner) {
        Write-Warn2 ("{0} 端口 {1} 已被占用：{2}；跳过（不替你结束别人的进程）" -f $svc.Name, $svc.Port, $owner)
        $failed += $svc.Name
        continue
    }

    $outLog = Join-Path $LogDir ("{0}.out.log" -f $svc.Name)
    $errLog = Join-Path $LogDir ("{0}.err.log" -f $svc.Name)
    Write-Step ("启动 {0}（:{1}）→ {2}" -f $svc.Name, $svc.Port, ($svc.Args -join ' '))
    $proc = Start-Process -FilePath $svc.File -ArgumentList $svc.Args `
        -WorkingDirectory $svc.WorkDir -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $outLog -RedirectStandardError $errLog
    $started += [pscustomobject]@{
        name    = $svc.Name
        pid     = $proc.Id
        port    = $svc.Port
        started = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        health  = $svc.Health
        out     = $outLog
        err     = $errLog
    }
}

Save-State $started

$deadline = (Get-Date).AddSeconds($TimeoutSec)
foreach ($row in $started) {
    $ok = $false
    while ((Get-Date) -lt $deadline) {
        if (Test-Health $row.health) { $ok = $true; break }
        $proc = Get-Process -Id $row.pid -ErrorAction SilentlyContinue
        if (-not $proc) { break }
        Start-Sleep -Milliseconds 400
    }
    if ($ok) {
        Write-Ok ("{0} 就绪：{1}" -f $row.name, $row.health)
    } else {
        Write-Err2 ("{0} 未就绪，看日志：{1} / {2}" -f $row.name, $row.err, $row.out)
        $failed += $row.name
    }
}

if (-not $NoBrowser -and ($started.name -contains 'frontend')) {
    Start-Process 'http://localhost:8090/app.html'
    Write-Ok '浏览器已打开：http://localhost:8090/app.html'
}

Write-Host ('-' * 62)
if ($failed.Count -eq 0) {
    Write-Ok ("全部就绪：{0}" -f (($started | ForEach-Object { "$($_.name):$($_.port)" }) -join '  '))
} else {
    Write-Warn2 ("部分服务未就绪：{0}" -f ($failed -join ', '))
}
Write-Host '  查看状态：.\start-all.ps1 -Status'
Write-Host '  停止服务：.\start-all.ps1 -Stop'
exit $(if ($failed.Count -eq 0) { 0 } else { 1 })
