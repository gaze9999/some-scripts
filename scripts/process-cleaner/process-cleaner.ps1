[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [ValidateRange(0, 86400)][int]$MinimumAgeSeconds = 300,
    [int[]]$TargetIds = @(),
    [string]$ReportPath
)

$ErrorActionPreference = 'Stop'
if (-not $ReportPath) { $ReportPath = Join-Path $PSScriptRoot 'last-check.json' }
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$targetNames = '^(node|python|pythonw|serena|cmd|uv|uvx|npm|npx|pnpm)\.exe$'
$knownMcp = '(?i)\bstart-mcp-server\b|\b(jev_mcp|rtk_mcp|document_mcp)\b|[/\\]node_modules[/\\](@playwright[/\\]mcp|@spartan-ng[/\\]mcp|mcp-echarts)[/\\]|textlint-mcp\.cjs\b'
$session = (Get-Process -Id $PID).SessionId
$userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$lock = New-Object System.Threading.Mutex($false, ('Local\ProcessResidueCleaner-' + $userSid))
$locked = $false

function Get-Snapshot {
    $items = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    $index = @{}
    foreach ($item in $items) { $index[[int]$item.ProcessId] = $item }
    return ,$index
}

function Test-ParentAlive($item, $index) {
    $parent = $index[[int]$item.ParentProcessId]
    return ($null -ne $parent -and $null -ne $item.CreationDate -and $null -ne $parent.CreationDate -and $parent.CreationDate -le $item.CreationDate)
}

function Get-Family($root, $index) {
    if ($null -eq $root) { return @() }
    $family = @($root)
    $queue = New-Object System.Collections.Generic.Queue[object]
    $queue.Enqueue($root)
    while ($queue.Count -gt 0) {
        $parent = $queue.Dequeue()
        foreach ($child in $index.Values) {
            if ($child.ParentProcessId -eq $parent.ProcessId -and $null -ne $child.CreationDate -and $child.CreationDate -ge $parent.CreationDate) {
                $family += $child
                $queue.Enqueue($child)
            }
        }
    }
    return $family
}

function Get-Network {
    return @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -in 'Listen', 'Established' })
}

function Test-NetworkBusy($ids, $connections) {
    foreach ($connection in $connections) {
        if ($connection.OwningProcess -notin $ids) { continue }
        if ($connection.State -eq 'Listen') {
            if ($connection.LocalAddress -notin '127.0.0.1', '::1') { return $true }
            continue
        }
        $reverse = @($connections | Where-Object {
            $_.OwningProcess -eq $connection.OwningProcess -and $_.LocalAddress -eq $connection.RemoteAddress -and
            $_.LocalPort -eq $connection.RemotePort -and $_.RemoteAddress -eq $connection.LocalAddress -and $_.RemotePort -eq $connection.LocalPort
        })
        if ($reverse.Count -eq 0) { return $true }
    }
    return $false
}

function Get-Role($item) {
    if ($item.CommandLine -match $knownMcp) { return 'MCP' }
    if ($item.CommandLine -match '(?i)node.repl|node_repl|kernel\.js|trusted-worker\.js') { return 'Codex helper' }
    if ($item.CommandLine -match '(?i)cliDaemon\.js|playwright') { return 'Browser tool' }
    if ($item.CommandLine -match '(?i)local.activity.monitor|watch\.py|launch\.py') { return 'Monitor' }
    return 'Other'
}

try {
    try { $locked = $lock.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) { Write-Host '另一個排查已在執行, 請等待它完成'; exit 0 }
    if (-not ('ProcessCleanerNative' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'native.cs') }
    $snapshot = Get-Snapshot
    $targets = @($snapshot.Values | Where-Object { $_.Name -match $targetNames -and $_.SessionId -eq $session -and ($TargetIds.Count -eq 0 -or $_.ProcessId -in $TargetIds) } | Sort-Object CreationDate)
    $protected = @($PID)
    $ancestor = $snapshot[$PID]
    while ($null -ne $ancestor -and (Test-ParentAlive $ancestor $snapshot)) {
        $protected += [int]$ancestor.ParentProcessId
        $ancestor = $snapshot[[int]$ancestor.ParentProcessId]
    }
    $rows = @()
    $terminated = @()
    $layout = [ProcessCleanerNative]::LayoutSupported()
    $orphans = @($targets | Where-Object { -not (Test-ParentAlive $_ $snapshot) })
    Write-Host ('已找到 {0} 個目標程序, 其中 {1} 個失去上層程序' -f $targets.Count, $orphans.Count)

    foreach ($item in $targets) {
        $parent = $snapshot[[int]$item.ParentProcessId]
        $parentName = '已結束'
        if (Test-ParentAlive $item $snapshot) { $parentName = $parent.Name }
        $row = [pscustomobject]@{Id=[int]$item.ProcessId;Name=$item.Name;Role=(Get-Role $item);Parent=$parentName;InputState='NotChecked';Action='保留';Reason='上層程序仍在執行'}
        $rows += $row
        if (Test-ParentAlive $item $snapshot) { continue }
        $row.Reason = '用途或連線狀態無法確認'
        if ($item.ProcessId -in $protected -or $item.CommandLine -notmatch $knownMcp) { continue }
        if (-not $layout) { $row.Reason = '目前環境無法驗證標準輸入管線'; continue }
        if ($null -eq $item.CreationDate -or ((Get-Date) - $item.CreationDate).TotalSeconds -lt $MinimumAgeSeconds) { $row.Reason = '啟動時間未滿保護期間'; continue }
        $family = @(Get-Family $item $snapshot)
        $ids = @($family | ForEach-Object { [int]$_.ProcessId })
        if (@($family | Where-Object { $_.Name -notmatch $targetNames -or $_.SessionId -ne $session -or $_.ProcessId -in $protected }).Count -gt 0) { $row.Reason = '有其他類型的子程序或工作'; continue }
        if (@($family | Where-Object { $_.ProcessId -ne $item.ProcessId -and $_.CommandLine -notmatch $knownMcp }).Count -gt 0) { $row.Reason = '子程序用途無法確認'; continue }
        $owned = $true
        foreach ($member in $family) {
            try { $owner = Invoke-CimMethod -InputObject $member -MethodName GetOwnerSid -ErrorAction Stop } catch { $owned = $false; break }
            if ($owner.ReturnValue -ne 0 -or $owner.Sid -ne $userSid) { $owned = $false; break }
        }
        if (-not $owned) { $row.Reason = '無法確認程序擁有者'; continue }
        $identities = @{}
        foreach ($member in $family) {
            $times = [ProcessCleanerNative]::Times([uint32]$member.ProcessId)
            if ($null -eq $times -or $null -eq $member.CreationDate -or [math]::Abs(([datetime]::FromFileTimeUtc($times[0]) - $member.CreationDate.ToUniversalTime()).TotalMilliseconds) -gt 1) { $owned = $false; break }
            $identities[[int]$member.ProcessId] = $times
        }
        if (-not $owned) { $row.Reason = '無法確認程序識別資訊'; continue }
        $rootTimes = $identities[[int]$item.ProcessId]
        $row.InputState = [ProcessCleanerNative]::InputState([uint32]$item.ProcessId, $rootTimes[0])
        if ($row.InputState -ne 'Disconnected') { $row.Reason = '標準輸入仍連線或無法確認'; continue }
        try {
            if (@([ProcessCleanerNative]::VisibleProcessIds() | Where-Object { $_ -in $ids }).Count -gt 0) { $row.Reason = '有可見視窗'; continue }
            if (Test-NetworkBusy $ids (Get-Network)) { $row.Reason = '有其他程序連線或網路服務'; continue }
        } catch { $row.Reason = '無法完整驗證視窗或網路狀態'; continue }
        Start-Sleep -Seconds 2
        $quiet = $true
        foreach ($member in $family) {
            $before = $identities[[int]$member.ProcessId]
            $after = [ProcessCleanerNative]::Times([uint32]$member.ProcessId)
            if ($null -eq $after -or $after[0] -ne $before[0] -or $after[1] -lt $before[1] -or ($after[1] - $before[1]) -gt 200000) { $quiet = $false; break }
        }
        if (-not $quiet) { $row.Reason = '程序狀態有變化或仍在處理工作'; continue }
        $fresh = Get-Snapshot
        $current = $fresh[[int]$item.ProcessId]
        $currentFamily = @(Get-Family $current $fresh)
        if ($null -eq $current -or (Test-ParentAlive $current $fresh) -or $currentFamily.Count -ne $family.Count -or @($currentFamily | Where-Object { $_.ProcessId -notin $ids }).Count -gt 0) { $row.Reason = '上層或子程序狀態已改變'; continue }
        if ([ProcessCleanerNative]::InputState([uint32]$item.ProcessId, $rootTimes[0]) -ne 'Disconnected' -or @([ProcessCleanerNative]::VisibleProcessIds() | Where-Object { $_ -in $ids }).Count -gt 0) { $row.Reason = '管線或視窗狀態已改變'; continue }
        try { if (Test-NetworkBusy $ids (Get-Network)) { $row.Reason = '連線狀態已改變'; continue } } catch { $row.Reason = '無法重新驗證網路狀態'; continue }
        $row.Reason = '已確認為失去呼叫端且閒置的 MCP 程序'
        if ($AuditOnly) { $row.Action = '可清理'; continue }
        $success = $true
        [array]::Reverse($family)
        foreach ($member in $family) {
            $identity = $identities[[int]$member.ProcessId]
            if ([ProcessCleanerNative]::TerminateExact([uint32]$member.ProcessId, $identity[0])) { $terminated += [int]$member.ProcessId }
            else { $success = $false; break }
        }
        if ($success) { $row.Action = '已清理' } else { $row.Action = '部分清理'; $row.Reason = '部分程序已結束或無法終止, 請查看清理結果' }
    }

    foreach ($row in $rows) {
        if ($row.Id -in $terminated -and $row.Action -ne '已清理') { $row.Action = '已清理'; $row.Reason = '隨殘留 MCP 上層程序完成清理' }
    }
    $report = [pscustomobject]@{CheckedAt=(Get-Date).ToString('o');Completed=$true;AuditOnly=[bool]$AuditOnly;InputLayoutSupported=$layout;Total=$targets.Count;ParentMissing=$orphans.Count;TerminatedIds=$terminated;Processes=$rows}
    $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
    $rows | Format-Table Id,Name,Role,Parent,Action -AutoSize | Out-Host
    $details = @($rows | Where-Object { $_.Parent -eq '已結束' })
    if ($details.Count -gt 0) { $details | Format-Table Id,Name,Action,Reason -Wrap -AutoSize | Out-Host }
    Write-Host ('完成, 已清理 {0} 個程序, 報告: {1}' -f $terminated.Count, $ReportPath)
    if ($AuditOnly) { Write-Host '本次為唯讀檢查' }
} catch {
    $failure = [pscustomobject]@{CheckedAt=(Get-Date).ToString('o');Completed=$false;AuditOnly=[bool]$AuditOnly;Error=$_.Exception.Message;TerminatedIds=$terminated}
    try { $failure | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $ReportPath -Encoding UTF8 } catch { }
    Write-Host ('排查未完成: {0}' -f $_.Exception.Message) -ForegroundColor Red
    Write-Host '請保留錯誤訊息, 目前無法確認的程序會保留'
    exit 1
} finally {
    if ($locked) { $lock.ReleaseMutex() }
    $lock.Dispose()
}
