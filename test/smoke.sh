#!/bin/bash
#
# End-to-end smoke test for the built Docker image. Gates every push to
# Docker Hub — if any step fails, don't push.
#
# Flow mirrors what a real user does on a fresh install:
#   1. Build / use the image
#   2. Start a container with just /config mounted
#   3. /health works (pre-auth)
#   4. / → 303 /setup
#   5. GET /setup → wizard form
#   6. POST /setup → admin created, auto-logged-in, 303 /
#   7. Dashboard shows empty state
#   8. Settings page loads
#   9. POST /settings persists
#  10. GET /repos/new → wizard
#  11. Fleet export CSV serves (empty header-only is fine)
#  12. Logout + restart + admin persists

set -e
cd "$(dirname "$0")/.."

IMAGE="${IMAGE:-tehrobot/restore-runner:local-smoke}"
PORT=38920
NAME="restorerunner-smoke-$$"
TMP=$(mktemp -d)
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT

echo "==> Building image (as $IMAGE)..."
docker build --target runtime -t "$IMAGE" -q . | head -1

echo "==> Starting container ($NAME on :$PORT, config in $TMP)..."
docker run -d --name "$NAME" \
  -p 127.0.0.1:$PORT:8920 \
  -v "$TMP:/config" \
  "$IMAGE" >/dev/null

# Wait for /health.
for i in $(seq 1 30); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/health" || true)
  [ "$CODE" = "200" ] && break
  sleep 1
done
[ "$CODE" = "200" ] || { docker logs "$NAME"; echo "FAIL: /health never came up"; exit 1; }

pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*"; docker logs "$NAME"; exit 1; }

echo "==> 1. /health (public, pre-auth)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/health")
[ "$CODE" = "200" ] && pass "/health → 200" || fail "/health → $CODE"

echo "==> 2. / with no admin → 303 /setup"
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "http://127.0.0.1:$PORT/")
[[ "$LOC" == *"/setup" ]] && pass "/ → /setup" || fail "/ → $LOC"

echo "==> 3. /setup form loads"
BODY=$(curl -s "http://127.0.0.1:$PORT/setup")
echo "$BODY" | grep -q 'Welcome to RestoreRunner' && pass "/setup shows wizard" || fail "/setup missing heading"

echo "==> 4. POST /setup creates admin + auto-logs in"
COOKIE="$TMP/cookie.txt"
LOC=$(curl -s -c "$COOKIE" -o /dev/null -w '%{redirect_url}' \
    -d 'username=admin&password=testpass1&confirm=testpass1' \
    "http://127.0.0.1:$PORT/setup")
[[ "$LOC" == *"/" && "$LOC" != *"/setup" && "$LOC" != *"/login" ]] \
    && pass "POST /setup → $LOC" || fail "POST /setup → $LOC"

echo "==> 5. Dashboard renders with session"
BODY=$(curl -s -b "$COOKIE" "http://127.0.0.1:$PORT/")
echo "$BODY" | grep -q 'Backup repos' && pass "dashboard has heading" || fail "dashboard missing heading"
echo "$BODY" | grep -q 'No repos yet' && pass "dashboard shows first-run hint" || fail "dashboard missing first-run hint"

echo "==> 6. Settings page loads"
BODY=$(curl -s -b "$COOKIE" "http://127.0.0.1:$PORT/settings")
echo "$BODY" | grep -q '<legend>Defaults</legend>' && pass "settings has Defaults fieldset" || fail "settings missing fieldset"

echo "==> 7. POST /settings persists"
LOC=$(curl -s -b "$COOKIE" -o /dev/null -w '%{redirect_url}' \
    -d 'default_cadence_hours=24&default_sample_size=50&scratch_dir=%2Ftmp%2Frr&notify_on_fail=on&apprise_urls=ntfy%3A%2F%2Ft' \
    "http://127.0.0.1:$PORT/settings")
[[ "$LOC" == *"saved=1" ]] && pass "settings save → $LOC" || fail "settings save → $LOC"

echo "==> 8. /repos/new wizard loads"
BODY=$(curl -s -b "$COOKIE" "http://127.0.0.1:$PORT/repos/new")
echo "$BODY" | grep -q 'New backup repo' && pass "wizard has heading" || fail "wizard missing heading"
echo "$BODY" | grep -q 'name="repo_url"' && pass "wizard has repo_url input" || fail "wizard missing repo_url input"

echo "==> 9. /repo/unknown returns 404"
CODE=$(curl -s -b "$COOKIE" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/repo/99999")
[ "$CODE" = "404" ] && pass "/repo/99999 → 404" || fail "/repo/99999 → $CODE"

echo "==> 10. Fleet CSV export serves"
HDR=$(curl -s -b "$COOKIE" -D - -o "$TMP/fleet.csv" "http://127.0.0.1:$PORT/export/rehearsals.csv" | tr -d '\r')
echo "$HDR" | grep -qi '^Content-Type: text/csv' && pass "export Content-Type is text/csv" || fail "export missing Content-Type"
echo "$HDR" | grep -Eqi 'Content-Disposition:.*fleet\.restore-runner-export\.' && pass "export filename matches convention" || fail "export filename wrong: $HDR"
head -1 "$TMP/fleet.csv" | grep -q 'repo_name,repo_kind,repo_url' && pass "CSV has header row" || fail "CSV header missing"

echo "==> 11. Logout clears session"
curl -s -b "$COOKIE" -c "$COOKIE" -o /dev/null -X POST "http://127.0.0.1:$PORT/logout"

echo "==> 12. / without session, admin exists → 303 /login"
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "http://127.0.0.1:$PORT/")
[[ "$LOC" == *"/login" ]] && pass "/ → /login" || fail "/ → $LOC"

echo "==> 13. Container restart — admin persists"
docker restart "$NAME" >/dev/null
for i in $(seq 1 30); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/health" || true)
  [ "$CODE" = "200" ] && break
  sleep 1
done
[ "$CODE" = "200" ] && pass "/health post-restart → 200" || fail "/health post-restart → $CODE"
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "http://127.0.0.1:$PORT/")
[[ "$LOC" == *"/login" ]] && pass "/ post-restart → /login (admin persisted)" || fail "/ post-restart → $LOC"

echo
echo "==> ALL CHECKS PASSED"
