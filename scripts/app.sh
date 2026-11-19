#!/usr/bin/env bash
# SecureBank Labs — local app lifecycle helper.
#
#   ./scripts/app.sh start    start the Spring Boot app (background), wait for health
#   ./scripts/app.sh stop     stop it
#   ./scripts/app.sh restart  stop + start
#   ./scripts/app.sh log      tail the log
#   ./scripts/app.sh status   is it up?
#
# The app runs on the host; Postgres runs in Docker (see docker-compose.yml).

set -uo pipefail
cd "$(dirname "$0")/.."

LOG=/tmp/securebank-app.log
PIDFILE=/tmp/securebank-app.pid
SECRETFILE=/tmp/securebank-jwt-secret

# The JWT signing secret (LAB 8).
#
# The secret is no longer in the source tree, so it has to come from
# somewhere. A real deployment reads it from a secret manager; here it is
# a file outside the repository, generated once and reused, so tokens
# survive a restart. The file is never committed and never logged.
jwt_secret() {
    if [[ -n "${APP_JWT_SECRET:-}" ]]; then
        printf '%s' "$APP_JWT_SECRET"
        return 0
    fi
    if [[ ! -f "$SECRETFILE" ]]; then
        python3 -c "import secrets; print(secrets.token_hex(32))" > "$SECRETFILE"
        chmod 600 "$SECRETFILE"
    fi
    cat "$SECRETFILE"
}

stop_app() {
    if [[ -f "$PIDFILE" ]]; then
        local pid
        pid="$(cat "$PIDFILE")"
        # Kill the whole process group: mvnw spawns a child JVM.
        kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null
        rm -f "$PIDFILE"
    fi
    # Fall back to whatever is holding port 8080.
    local holder
    holder="$(ss -lptn 'sport = :8080' 2>/dev/null | grep -oP 'pid=\K[0-9]+' | head -1)"
    if [[ -n "${holder}" ]]; then
        kill "$holder" 2>/dev/null
    fi
    # Wait for the port to actually free up. If it does not, escalate to
    # SIGKILL — a stale app left holding port 8080 would silently serve the
    # OLD classes, which is very hard to debug.
    for _ in $(seq 1 30); do
        ss -lnt 'sport = :8080' 2>/dev/null | grep -q 8080 || return 0
        sleep 0.5
    done
    holder="$(ss -lptn 'sport = :8080' 2>/dev/null | grep -oP 'pid=\K[0-9]+' | head -1)"
    if [[ -n "${holder}" ]]; then
        echo "port 8080 still held by pid $holder — sending SIGKILL"
        kill -9 "$holder" 2>/dev/null
        sleep 1
    fi
    for _ in $(seq 1 20); do
        ss -lnt 'sport = :8080' 2>/dev/null | grep -q 8080 || return 0
        sleep 0.5
    done
    echo "ERROR: port 8080 is still in use — the old app did not stop"
    return 1
}

start_app() {
    # The Maven project lives in backend/, so the wrapper is invoked from
    # there. The process group is what gets killed on stop.
    #
    # stdin and stdout are both redirected: a caller that captures our output
    # (the isolation matrix does) waits for the pipe to close, and a
    # backgrounded maven holding stdout open would hang it forever.
    pushd backend > /dev/null || return 1
    # Truncate the log first: the failure check below greps it, and a stale
    # "BUILD FAILURE" from the previous run would abort this one instantly.
    : > "$LOG"
    APP_JWT_SECRET="$(jwt_secret)" setsid ./mvnw -o spring-boot:run < /dev/null > "$LOG" 2>&1 &
    echo $! > "$PIDFILE"
    popd > /dev/null
    for i in $(seq 1 120); do
        if curl -sf http://localhost:8080/api/health >/dev/null 2>&1; then
            echo "app up after ${i}s (log: $LOG)"
            return 0
        fi
        # -a: the log can contain binary bytes (the Lab 6 backup.zip is
        # echoed into it), and grep treats a binary file as "no match".
        if grep -aq "APPLICATION FAILED TO START\|BUILD FAILURE" "$LOG" 2>/dev/null; then
            echo "app FAILED to start — see $LOG"
            grep -aE "ERROR|Caused by" "$LOG" | head -5
            return 1
        fi
        sleep 1
    done
    echo "app did not come up in time — see $LOG"
    return 1
}

case "${1:-start}" in
    start)   start_app ;;
    stop)    stop_app && echo "app stopped" ;;
    restart) stop_app; start_app ;;
    log)     tail -n "${2:-60}" "$LOG" ;;
    status)
        code="$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/api/health 2>/dev/null)"
        [[ "$code" == "200" ]] && echo "app up" || echo "app down (http ${code:-000})"
        ;;
    *) echo "usage: $0 {start|stop|restart|log|status}"; exit 1 ;;
esac
