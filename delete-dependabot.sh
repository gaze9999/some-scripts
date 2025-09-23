@echo off
setlocal enabledelayedexpansion

echo 搜尋 dependabot/npm_and_yarn 遠端分支
set list=
set count=0

for /f "tokens=*" %%b in ('git for-each-ref --format="%%(refname:short)" refs/remotes/origin/dependabot') do (
    set branch=%%b
    set branch=!branch:origin/=!
    echo 找到分支: !branch!
    set list=!list! !branch!
    set /a count+=1
)

if %count%==0 (
    echo 沒有找到符合的分支
    goto :end
)

echo.
echo 總共找到 %count% 個分支
pause

echo 開始刪除遠端分支
for %%b in (%list%) do (
    git push origin --delete %%b
)

echo.
echo 清理本地追蹤
git fetch origin --prune

:end
echo 完成
pause
