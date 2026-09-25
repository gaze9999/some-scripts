<#
.SYNOPSIS
取得目前帳號所有 Codex Cloud Task ID

.DESCRIPTION
自動執行 `codex cloud list`
並持續追蹤輸出中的 `--cursor` 直到所有分頁取得完成

從每一頁中擷取:
    task_e_...

最後會:
1. 顯示總 Task 數
2. 顯示所有 Task ID
3. 產生 JavaScript string array
4. 自動複製 JavaScript array 到 Windows 剪貼簿

此 Script 只讀取 Codex Cloud task
不會刪除或修改任何資料

.REQUIREMENTS
- Windows PowerShell 5.1+
- Codex CLI
- 已登入 Codex CLI

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\get-codex-cloud-task-ids.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# 設定
# ------------------------------------------------------------

# 避免因 API / CLI 異常造成無限分頁
$MaxPages = 100

# ------------------------------------------------------------
# Helper
# ------------------------------------------------------------

<#
.SYNOPSIS
確認 Codex CLI 是否存在
#>
function Test-CodexCli {
    $command = Get-Command codex -ErrorAction SilentlyContinue

    if (-not $command) {
        throw '找不到 Codex CLI，請先確認 codex 已安裝並存在於 PATH'
    }
}

<#
.SYNOPSIS
執行單頁 Codex Cloud List

.PARAMETER Cursor
下一頁 Cursor
第一頁傳入 $null

.OUTPUTS
System.String
#>
function Get-CodexCloudPage {
    param(
        [Parameter()]
        [AllowNull()]
        [string] $Cursor
    )

    if ([string]::IsNullOrWhiteSpace($Cursor)) {
        $output = & codex cloud list 2>&1
    }
    else {
        $output = & codex cloud list --cursor="$Cursor" 2>&1
    }

    if ($LASTEXITCODE -ne 0) {
        throw @"
codex cloud list 執行失敗

Exit Code:
$LASTEXITCODE

Output:
$($output -join [Environment]::NewLine)
"@
    }

    return ($output -join [Environment]::NewLine)
}

<#
.SYNOPSIS
從 Codex Cloud List 內容擷取 Task ID

.PARAMETER Content
codex cloud list 原始輸出

.OUTPUTS
System.String[]
#>
function Get-TaskIdsFromContent {
    param(
        [Parameter(Mandatory)]
        [string] $Content
    )

    $matches = [regex]::Matches(
        $Content,
        'task_e_[0-9A-Za-z_-]+'
    )

    foreach ($match in $matches) {
        $match.Value
    }
}

<#
.SYNOPSIS
從 Codex Cloud List 內容取得下一頁 Cursor

.PARAMETER Content
codex cloud list 原始輸出

.OUTPUTS
System.String 或 $null
#>
function Get-NextCursor {
    param(
        [Parameter(Mandatory)]
        [string] $Content
    )

    # Codex CLI 目前輸出格式:
    #
    # To fetch the next page, run codex cloud list --cursor='...'
    #
    $match = [regex]::Match(
        $Content,
        "codex cloud list --cursor='([^']+)'"
    )

    if (-not $match.Success) {
        return $null
    }

    return $match.Groups[1].Value
}

<#
.SYNOPSIS
將 Task ID 轉成可直接貼到 DevTools Console 的 JavaScript Array

.PARAMETER TaskIds
Task ID 清單

.OUTPUTS
System.String
#>
function ConvertTo-JavaScriptTaskArray {
    param(
        [Parameter(Mandatory)]
        [string[]] $TaskIds
    )

    if ($TaskIds.Count -eq 0) {
        return 'const taskIds = [];'
    }

    $items = foreach ($taskId in $TaskIds) {
        "  '$taskId'"
    }

    return @"
const taskIds = [
$($items -join ",`r`n")
];
"@
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

Test-CodexCli

Write-Host '讀取 Codex Cloud Tasks...' -ForegroundColor Cyan

# 保留原始順序並去除重複 ID
$taskIds = [System.Collections.Generic.List[string]]::new()
$seenTaskIds = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal
)

# 避免 Cursor 循環
$seenCursors = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal
)

$cursor = $null
$page = 1

while ($page -le $MaxPages) {
    Write-Host "讀取第 $page 頁..." -ForegroundColor DarkGray

    $content = Get-CodexCloudPage -Cursor $cursor

    $pageTaskIds = @(
        Get-TaskIdsFromContent -Content $content
    )

    foreach ($taskId in $pageTaskIds) {
        if ($seenTaskIds.Add($taskId)) {
            $taskIds.Add($taskId)
        }
    }

    Write-Host (
        "  本頁: {0} 筆 / 累計: {1} 筆" -f
        $pageTaskIds.Count,
        $taskIds.Count
    ) -ForegroundColor DarkGray

    $nextCursor = Get-NextCursor -Content $content

    if ([string]::IsNullOrWhiteSpace($nextCursor)) {
        break
    }

    if (-not $seenCursors.Add($nextCursor)) {
        throw '偵測到重複 Cursor，已停止以避免無限循環'
    }

    $cursor = $nextCursor
    $page++
}

if ($page -gt $MaxPages) {
    throw "超過最大分頁數 $MaxPages，已停止"
}

Write-Host ''
Write-Host "Codex Cloud Task 總數: $($taskIds.Count)" -ForegroundColor Green
Write-Host ''

foreach ($taskId in $taskIds) {
    Write-Host $taskId
}

$javascript = ConvertTo-JavaScriptTaskArray -TaskIds $taskIds.ToArray()

Write-Host ''
Write-Host 'JavaScript Array:' -ForegroundColor Cyan
Write-Host ''
Write-Host $javascript

if ($taskIds.Count -gt 0) {
    $javascript | Set-Clipboard

    Write-Host ''
    Write-Host '已將 JavaScript Array 複製到剪貼簿' -ForegroundColor Green
    Write-Host '可直接貼到 ChatGPT DevTools Console 的刪除 Script' -ForegroundColor Green
}
else {
    Write-Host '目前沒有 Codex Cloud Task' -ForegroundColor Yellow
}