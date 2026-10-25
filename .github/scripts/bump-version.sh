#!/usr/bin/env bash
# 按 Conventional Commits 计算下一个扩展版本号并写回版本文件。
#
# 版本规则（x1.x2.x3 = 主.次.补丁）：
#   - fix:                补丁 +1        （漏洞修复）
#   - feat:               次版本 +1，补丁归零
#   - BREAKING CHANGE / !: 主版本 +1，次版本与补丁归零
#
# 输出到 $GITHUB_OUTPUT：version / bump / skip / notes
set -euo pipefail

BUMP_INPUT="${BUMP:-auto}"
CURRENT=$(grep -m1 '^version = "' build.gradle.kts | sed -E 's/^version = "([^"]+)".*/\1/')
if [ -z "$CURRENT" ]; then
  echo "无法从 build.gradle.kts 读取当前版本" >&2
  exit 1
fi
IFS=. read -r X1 X2 X3 <<< "$CURRENT"

# 提交范围：优先用本次 push 的 before 提交；手动触发时退回上一个 tag。
FROM="${BEFORE:-}"
if [ -z "$FROM" ] || printf '%s' "$FROM" | grep -qE '^0+$'; then
  FROM=$(git describe --tags --abbrev=0 2>/dev/null || true)
fi

if [ -n "$FROM" ]; then
  COMMITS=$(git log --pretty=format:%s "$FROM"..HEAD || true)
else
  COMMITS=$(git log --pretty=format:%s -n 50 || true)
fi

if [ "$BUMP_INPUT" = "auto" ]; then
  if [ -z "$COMMITS" ]; then
    echo "skip=true" >> "$GITHUB_OUTPUT"
    echo "本次没有新提交，跳过发布"
    exit 0
  fi
  if printf '%s\n' "$COMMITS" | grep -qE '^(feat|fix)(\(.+\))?!:|BREAKING[ -]CHANGE'; then
    BUMP=major
  elif printf '%s\n' "$COMMITS" | grep -qE '^feat(\(.+\))?:'; then
    BUMP=minor
  elif printf '%s\n' "$COMMITS" | grep -qE '^fix(\(.+\))?:'; then
    BUMP=patch
  else
    echo "skip=true" >> "$GITHUB_OUTPUT"
    echo "本批提交没有 fix / feat / BREAKING CHANGE，跳过发布"
    exit 0
  fi
else
  BUMP="$BUMP_INPUT"
fi

case "$BUMP" in
  major) X1=$((X1 + 1)); X2=0; X3=0 ;;
  minor) X2=$((X2 + 1)); X3=0 ;;
  patch) X3=$((X3 + 1)) ;;
  *) echo "未知的版本提升类型: $BUMP" >&2; exit 1 ;;
esac

NEW="$X1.$X2.$X3"
echo "版本: $CURRENT → $NEW ($BUMP)"

# 两处版本号保持一致：Gradle 构建版本 + Geyser 扩展清单版本
sed -i -E "s/^version = \".*\"/version = \"$NEW\"/" build.gradle.kts
sed -i -E "s/^version: .*/version: $NEW/" src/main/resources/extension.yml

# 更新日志 = 本次范围内的 commit 标题
NOTES="${RUNNER_TEMP:-/tmp}/release-notes.md"
{
  echo "## v$NEW ($BUMP)"
  echo
  echo "> 适配 Geyser **2.9.4**（\`extension.yml\` 的 \`api: 2.9.4\`），实测可在 Geyser 2.9.4 ~ 2.10.1 上加载。"
  echo "> 本仓库只发布 2.9.4 兼容版本；Geyser 2.11.3 的源码见 \`2.11.3\` 分支。"
  echo
  echo "### 变更"
  echo
  if [ -n "$FROM" ]; then
    git log --pretty=format:'- %s（%h）' "$FROM"..HEAD || true
  else
    git log --pretty=format:'- %s（%h）' -n 50 || true
  fi
  echo
} > "$NOTES"

{
  echo "version=$NEW"
  echo "bump=$BUMP"
  echo "skip=false"
  echo "notes=$NOTES"
} >> "$GITHUB_OUTPUT"
