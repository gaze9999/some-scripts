#!/usr/bin/env bash
set -euo pipefail

# find all remote dependabot branches and prune them from origin

echo "搜尋 dependabot/npm_and_yarn 遠端分支"
remote_branches=()
while IFS= read -r remote; do
  [[ -z "$remote" ]] && continue
  remote_branches+=("$remote")
done < <(git for-each-ref --format='%(refname:short)' 'refs/remotes/origin/dependabot' || true)

if [[ ${#remote_branches[@]} -eq 0 ]]; then
  echo "沒有找到符合的分支"
  exit 0
fi

branches=()
for remote in "${remote_branches[@]}"; do
  branch=${remote#origin/}
  echo "找到分支: $branch"
  branches+=("$branch")
done

echo
printf '總共找到 %s 個分支\n' "${#branches[@]}"
read -r -p "按 Enter 開始刪除，或 Ctrl+C 取消..." _

echo "開始刪除遠端分支"
for branch in "${branches[@]}"; do
  git push origin --delete "$branch"

done

echo
# prune any stale tracking refs now that remote branches are gone
echo "清理本地追蹤"
git fetch origin --prune

echo "完成"
