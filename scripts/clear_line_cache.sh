#!/bin/zsh
# macOS 26 Tahoe – LINE 廣告快取深度清理（對話資料安全）
# 目標：移除 WebKit/URLSession 層的廣告素材與旗標殘留，不動訊息資料庫
# 無需 sudo。可置於快捷指令「執行 Shell 指令」。

set -euo pipefail
DRY_RUN="${DRY_RUN:-0}"
VERBOSE="${VERBOSE:-1}"
VERIFY="${VERIFY:-1}"

log() { [[ "$VERBOSE" == "1" ]] && echo "[INFO] $*"; }
dry() { [[ "$DRY_RUN" == "1" ]]; }

run() {
  if dry; then
    printf '[DRY] %s\n' "$*"
  else
    eval "$*"
  fi
}

# 0) 關閉 LINE，避免檔案鎖定
log "結束 LINE..."
osascript -e 'quit app "LINE"' >/dev/null 2>&1 || true
sleep 2

# 1) 安全：定義「訊息資料庫」關鍵片語，以避免誤刪
#   我們會完全避開含有下列字串的路徑
SAFE_EXCLUDE_PATTERNS=(
  "MessageStorage"
  "chat.db"
  "message.db"
  "Messages.sqlite"
)

typeset -a EXCLUDE_ARGS=()
for p in "${SAFE_EXCLUDE_PATTERNS[@]}"; do
  EXCLUDE_ARGS+=(-not -path "*${p}*")
done

# 2) 主要清理節點（僅快取／WebKit／WebsiteData 層）
NODES=(
  # LINE 容器內
  "$HOME/Library/Containers/jp.naver.line.mac/Data/Library/Caches"
  "$HOME/Library/Containers/jp.naver.line.mac/Data/Library/WebKit"
  "$HOME/Library/Containers/jp.naver.line.mac/Data/Library/WebKit/WebsiteData"
  "$HOME/Library/Containers/jp.naver.line.mac/Data/Library/Application Support/LINE/Cache"
  "$HOME/Library/Containers/jp.naver.line.mac/Data/Library/Application Support/LINE/IndexedDB"
  "$HOME/Library/Containers/jp.naver.line.mac/Data/Library/Application Support/LINE/Local Storage"
  "$HOME/Library/Application Support/LINE/Cache"
  "$HOME/Library/Application Support/LINE/IndexedDB"
  "$HOME/Library/Application Support/LINE/Local Storage"

  # 常見全域快取
  "$HOME/Library/Caches/jp.naver.line.mac"

  # WebKit 子節點（常見廣告素材殘留處）
  "$HOME/Library/Containers/jp.naver.line.mac/Data/Library/WebKit/NetworkCache"
  "$HOME/Library/Containers/jp.naver.line.mac/Data/Library/WebKit/WebsiteData/ServiceWorker"
  "$HOME/Library/Containers/jp.naver.line.mac/Data/Library/WebKit/WebsiteData/CacheStorage"
  "$HOME/Library/Containers/jp.naver.line.mac/Data/Library/WebKit/WebsiteData/ResourceLoadStatistics"
  "$HOME/Library/Containers/jp.naver.line.mac/Data/Library/Caches/com.apple.WebKit.Networking"
  "$HOME/Library/Containers/jp.naver.line.mac/Data/Library/Caches/com.apple.WebKit.WebContent"
  "$HOME/Library/Containers/jp.naver.line.mac/Data/Library/Caches/*/fsCachedData"
  "$HOME/Library/Containers/jp.naver.line.mac/Data/Library/Caches/*/GPUCache"
  "$HOME/Library/Containers/jp.naver.line.mac/Data/Library/Caches/*/Code Cache"
  "$HOME/Library/Containers/jp.naver.line.mac/Data/Library/Caches/*/CacheStorage"
)

# 3) 服務子容器（LINE.*Service）內的 Caches/WebKit
for svc in "$HOME/Library/Containers"/LINE.*Service; do
  [[ -d "$svc/Data/Library/Caches" ]] && NODES+=("$svc/Data/Library/Caches")
  [[ -d "$svc/Data/Library/WebKit" ]] && NODES+=("$svc/Data/Library/WebKit")
done

# 3b) Group Containers 內的共用快取層
for grp in "$HOME/Library/Group Containers"/*line*; do
  [[ -d "$grp" ]] || continue
  [[ -d "$grp/Library/Caches" ]] && NODES+=("$grp/Library/Caches")
  [[ -d "$grp/Library/WebKit" ]] && NODES+=("$grp/Library/WebKit")
  [[ -d "$grp/Data/Library/Caches" ]] && NODES+=("$grp/Data/Library/Caches")
  [[ -d "$grp/Data/Library/WebKit" ]] && NODES+=("$grp/Data/Library/WebKit")
done

# 4) URLSession 共用快取（關鍵）
#    注意：這是使用者層級、跨 App 的 HTTP 快取，常殘留已載入的廣告素材。
NSURLSESSION_DIR="$HOME/Library/Caches/com.apple.nsurlsessiond"
[[ -d "$NSURLSESSION_DIR" ]] && NODES+=("$NSURLSESSION_DIR")

# 5) 加強：WebKit WebsiteData 內的 sqlite/db 也要清（不影響聊天資料庫，聊天 DB 不在此層）
#    僅限 WebKit/WebsiteData/ 與 Caches/ 這些「暫存層」的 .sqlite/.db
delete_in_node() {
  local node="$1"
  [[ -d "$node" ]] || return 0
  log "清理：$node"

  # 避開訊息資料庫關鍵字
  # 刪檔案（包含 .sqlite/.db，因為此層屬於 WebKit/快取，不是聊天 DB）
  if dry; then
    log "[DRY] 模擬刪除上述節點內快取檔案"
    find "$node" -type f "${EXCLUDE_ARGS[@]}" -print 2>/dev/null || true
  else
    find "$node" -type f "${EXCLUDE_ARGS[@]}" -delete 2>/dev/null || true
  fi

  # 刪空資料夾
  if dry; then
    find "$node" -type d -empty -print
  else
    find "$node" -type d -empty -delete 2>/dev/null || true
  fi
}

verify_node() {
  local node="$1"
  [[ -d "$node" ]] || return 0
  local leftover
  leftover=$(find "$node" -type f "${EXCLUDE_ARGS[@]}" -print -quit 2>/dev/null | tr -d '\n')
  if [[ -n "$leftover" ]]; then
    log "[WARN] 仍有殘留快取：$leftover"
    return 1
  fi
  log "已確認清空：$node"
  return 0
}

typeset -A NODE_SEEN=()
typeset -a ACTUAL_NODES=()

for n in "${NODES[@]}"; do
  # 展開萬用字元節點
  for p in $n; do
    [[ -d "$p" ]] || continue
    if [[ -z "${NODE_SEEN[$p]-}" ]]; then
      NODE_SEEN[$p]=1
      ACTUAL_NODES+=("$p")
      delete_in_node "$p"
    fi
  done
done

# 6) 偏好檔中的「廣告/實驗旗標」鍵值移除（僅刪鍵，保留其餘設定）
#    位置：~/Library/Containers/jp.naver.line.mac/Data/Library/Preferences/jp.naver.line.mac.plist
PREFS="$HOME/Library/Containers/jp.naver.line.mac/Data/Library/Preferences/jp.naver.line.mac.plist"
if [[ -f "$PREFS" ]]; then
  log "清理偏好檔內的廣告/實驗鍵值（僅刪鍵，不刪檔）..."
  # 以常見命名清單嘗試移除（實際存在與否皆允許失敗）
  KEYS=(
    "Advertisement" "Ads" "AdConfig" "AdSettings" "AdFlags"
    "A/BTest" "ABTest" "Experiment" "RemoteConfig" "Tracking"
    "GADApplicationIdentifier" "GoogleAnalytics" "GAITracking"
  )
  for k in "${KEYS[@]}"; do
    if dry; then
      echo "[DRY] defaults delete 'jp.naver.line.mac' '$k' || true"
    else
      /usr/bin/defaults delete "jp.naver.line.mac" "$k" >/dev/null 2>&1 || true
    fi
  done
fi

# 7) 重新啟動 URLSession 與 WebKit Daemon（清記憶體層）
log "重啟 URLSession / WebKit 服務..."
run "launchctl kickstart -k gui/$UID/com.apple.nsurlsessiond"
run "launchctl kickstart -k gui/$UID/com.apple.WebKit.Networking"
run "launchctl kickstart -k gui/$UID/com.apple.WebKit.WebContent" || true

if dry; then
  log "DRY_RUN 啟用中：僅模擬清理，未實際刪除資料。"
  VERIFY=0
fi

if [[ "$VERIFY" == "1" && "${#ACTUAL_NODES[@]}" -gt 0 ]]; then
  log "驗證快取節點是否已清空..."
  remaining=0
  for node in "${ACTUAL_NODES[@]}"; do
    if ! verify_node "$node"; then
      ((remaining++))
    fi
  done
  if (( remaining == 0 )); then
    log "驗證完成：所有指定節點均已清空。"
  else
    log "部分節點仍有快取，請檢視上方警示並手動確認。"
    exit 1
  fi
fi

echo "[DONE] 已完成 LINE 廣告快取深度清理（聊天資料未變更）。"
