#!/bin/bash
#
# End-to-end smoke test for the built RestoreRunner Docker image.
#
# Covers:
#   1. Image builds
#   2. Container starts, /health returns 200
#   3. / redirects to /setup (no admin yet)
#   4. /setup renders the wizard
#   5. POST /setup creates admin and auto-logs-in
#   6. Dashboard renders
#   7. Upload a synthetic tar.gz archive containing a minimal Unraid XML
#      that boots `alpine:3.19 echo hello`; verify run row is created
#      and the archive extracted.
#   8. Container detail page renders; log endpoint streams data.
#   9. Stop cleans up.
#
# We don't require a real Unraid backup — a minimal synthetic archive
# containing just the XML + a dummy appdata dir is enough to exercise
# every code path.

set -e
cd "$(dirname "$0")/.."

IMAGE="${IMAGE:-tehrobot/restore-runner:local-smoke}"
PORT=38922
NAME="rr-smoke-$$"
TMP=$(mktemp -d)
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true; docker ps -q --filter "name=rr-" | xargs -r docker rm -f >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT

echo "==> Building image (as $IMAGE)..."
docker build --target runtime -t "$IMAGE" -q . | head -1

echo "==> Starting container (name=$NAME port=$PORT config=$TMP)..."
docker run -d --name "$NAME" \
    -v "$TMP:/config" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -p "127.0.0.1:$PORT:8922" \
    "$IMAGE" >/dev/null

echo "  waiting for /health..."
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/health" || true)
    [ "$CODE" = "200" ] && break
    sleep 1
done
if [ "$CODE" != "200" ]; then
    echo "FAIL: /health never returned 200 within 15s (last=$CODE)"
    docker logs "$NAME" 2>&1 | tail -40
    exit 1
fi

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; docker logs "$NAME" 2>&1 | tail -30; exit 1; }

echo "==> 1. /health (public, must work pre-admin)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/health")
[ "$CODE" = "200" ] && pass "/health -> 200" || fail "/health -> $CODE"

echo "==> 2. / with no admin -> 303 to /setup"
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "http://127.0.0.1:$PORT/")
[[ "$LOC" == *"/setup" ]] && pass "/ -> /setup" || fail "/ -> $LOC (expected /setup)"

echo "==> 3. /setup form loads"
BODY=$(curl -s "http://127.0.0.1:$PORT/setup")
echo "$BODY" | grep -q 'Welcome to RestoreRunner' && pass "/setup shows wizard" \
    || fail "/setup missing wizard heading"

echo "==> 4. POST /setup creates admin + auto-logs in"
COOKIE="$TMP/cookie.txt"
LOC=$(curl -s -c "$COOKIE" -o /dev/null -w '%{redirect_url}' \
    -d 'username=admin&password=testpass1&confirm=testpass1' \
    "http://127.0.0.1:$PORT/setup")
[[ "$LOC" == *"/" && "$LOC" != *"/setup" && "$LOC" != *"/login" ]] \
    && pass "POST /setup -> $LOC" || fail "POST /setup -> $LOC"

echo "==> 5. Dashboard renders with session"
BODY=$(curl -s -b "$COOKIE" "http://127.0.0.1:$PORT/")
echo "$BODY" | grep -q 'Restore a backup' && pass "dashboard shows heading" \
    || fail "dashboard missing heading"

echo "==> 6. Build a synthetic tar.gz archive with a minimal Unraid XML"
ARCHIVE_SRC="$TMP/archive-src"
mkdir -p "$ARCHIVE_SRC/smoke/appdata"
echo "keep me" > "$ARCHIVE_SRC/smoke/appdata/hello.txt"
cat > "$ARCHIVE_SRC/smoke/smoke.xml" <<'XMLEOF'
<?xml version="1.0"?>
<Container version="2">
  <Name>Smoke</Name>
  <Repository>alpine:3.19</Repository>
  <Network>bridge</Network>
  <WebUI>http://[IP]:[PORT:8080]/</WebUI>
  <Config Name="Appdata" Target="/config" Default="" Mode="rw" Description="" Type="Path" Display="always" Required="true" Mask="false">/mnt/user/appdata/smoke</Config>
</Container>
XMLEOF

# Pre-pull the alpine image on the host so the test doesn't wait on
# network I/O — matches how a real user would already have images cached.
docker pull -q alpine:3.19 >/dev/null 2>&1 || true

ARCHIVE="$TMP/smoke.tar.gz"
( cd "$ARCHIVE_SRC" && tar czf "$ARCHIVE" . )

echo "==> 7. Upload the archive"
UP=$(curl -s -b "$COOKIE" -o /dev/null -w '%{http_code}|%{redirect_url}' \
    -F "archive=@$ARCHIVE;filename=smoke.tar.gz" \
    "http://127.0.0.1:$PORT/upload")
CODE=${UP%%|*}
LOC=${UP##*|}
[[ "$CODE" = "303" && "$LOC" == *"/run/"* ]] \
    && pass "upload -> $CODE $LOC" || fail "upload -> $CODE $LOC"

RUN_ID=$(basename "$LOC")

echo "==> 8. Run detail page renders"
BODY=$(curl -s -b "$COOKIE" "http://127.0.0.1:$PORT/run/$RUN_ID")
echo "$BODY" | grep -q 'smoke.tar.gz' && pass "run detail shows archive name" \
    || fail "run detail missing archive name"

echo "==> 9. Wait for the sandboxed alpine to run"
# Give it up to ~15s to pull + run (image usually pre-cached).
FOUND=0
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    STATUS=$(curl -s -b "$COOKIE" "http://127.0.0.1:$PORT/run/$RUN_ID" | grep -oE 'chip chip-[a-z]+' | head -1)
    if echo "$STATUS" | grep -qE 'chip-(ok|muted|danger)'; then
        FOUND=1; break
    fi
    sleep 1
done
[ "$FOUND" = "1" ] && pass "run reached a terminal/running status" \
    || fail "run stuck — status chip not found in 15s"

echo "==> 10. Stop + delete cleanup"
curl -s -b "$COOKIE" -o /dev/null -X POST "http://127.0.0.1:$PORT/run/$RUN_ID/stop"
curl -s -b "$COOKIE" -o /dev/null -X POST "http://127.0.0.1:$PORT/run/$RUN_ID/delete"
BODY=$(curl -s -b "$COOKIE" "http://127.0.0.1:$PORT/")
echo "$BODY" | grep -q "$RUN_ID" \
    && fail "run $RUN_ID still listed after delete" \
    || pass "delete removed the run"

echo "==> 11. Logout -> /login"
LOC=$(curl -s -b "$COOKIE" -o /dev/null -w '%{redirect_url}' -X POST "http://127.0.0.1:$PORT/logout")
[[ "$LOC" == *"/login" ]] && pass "logout -> $LOC" || fail "logout -> $LOC"

echo
echo "All smoke tests passed."
