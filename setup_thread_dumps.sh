#!/usr/bin/env bash
#
# setup_thread_dumps.sh - adds JVM thread dump support to the OpenShift TCPDump tool.
#
# Run from the ROOT of your repository (the folder that contains go.mod):
#
#     bash setup_thread_dumps.sh              # install, then build + vet + test
#     bash setup_thread_dumps.sh --dry-run    # only check; change nothing
#     bash setup_thread_dumps.sh --skip-checks   # install without go build/vet/test
#
# What it does
#   1. checks the repo layout and that python3 is available
#   2. writes the new files (internal/diag, internal/k8s/diag.go, internal/handlers/diagnostics*.go,
#      web/static/diagnostics.js + snippet, deploy/diag-exec-rbac.yaml)
#   3. patches cmd/server/main.go and web/static/index.html (keeps *.bak copies)
#   4. runs gofmt check, go build, go vet and the unit tests
# It is safe to run more than once. Existing files of this feature are updated in place.
#
set -euo pipefail

DRY=false
CHECKS=true
for arg in "$@"; do
  case "$arg" in
    --dry-run)      DRY=true ;;
    --skip-checks)  CHECKS=false ;;
    -h|--help)      sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $arg (use --help)"; exit 2 ;;
  esac
done

MODULE="github.com/openshift-tcpdump/openshift-tcpdump"
say()  { printf '\n==> %s\n' "$*"; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

# ------------------------------------------------------------------ 1. preconditions
say "Checking the repository"
[ -f go.mod ]                    || die "go.mod not found - run this script from the repository root."
grep -q "^module ${MODULE}\$" go.mod \
                                 || die "go.mod module is not '${MODULE}'. The new files import that path; adjust them or run from the right repo."
for f in cmd/server/main.go web/static/index.html; do
  [ -f "$f" ] || die "$f not found."
done
for d in internal/capture internal/handlers internal/k8s internal/middleware; do
  [ -d "$d" ] || die "$d/ not found - this does not look like the TCPDump tool repo."
done
grep -q 'gorilla/websocket' go.mod || die "github.com/gorilla/websocket is not in go.mod (the capture code needs it too)."
grep -q 'go-chi/chi/v5'      go.mod || die "github.com/go-chi/chi/v5 is not in go.mod."
PY="$(command -v python3 || command -v python || true)"
[ -n "$PY" ] || die "python3 (or python) is required to patch main.go / index.html."
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' || die "Python 3.6 or newer is required ($PY is older)."
echo "   layout OK, module ${MODULE}"

PATCHER="$(mktemp)"
trap 'rm -f "$PATCHER"' EXIT
cat > "$PATCHER" <<'__TD_PATCHER_EOF__'
#!/usr/bin/env python3
"""Patch cmd/server/main.go and web/static/index.html for thread dumps.

usage: patcher.py [--check]
  --check   only verify that every anchor exists; change nothing.
Idempotent. Keeps <file>.bak (first time only). Aborts before writing anything if an anchor is missing.
"""
import pathlib, re, shutil, sys

CHECK = "--check" in sys.argv
ROOT = pathlib.Path.cwd()
MAIN = ROOT / "cmd/server/main.go"
HTML = ROOT / "web/static/index.html"
SNIP = ROOT / "web/static/diagnostics-snippet.html"
MOD = "github.com/openshift-tcpdump/openshift-tcpdump"


def fail(msg):
    print("   ERROR: " + msg)
    print("   Nothing was changed.")
    sys.exit(1)


def indent_block(block, ind):
    return "\n".join((ind + l) if l.strip() else l for l in block.split("\n"))


def find(pattern, text, what):
    m = re.search(pattern, text, re.M)
    if not m:
        fail("could not find " + what)
    return m


main = MAIN.read_text(encoding="utf-8")
html = HTML.read_text(encoding="utf-8")
snippet = SNIP.read_text(encoding="utf-8").strip("\n") if SNIP.exists() else ""
if not CHECK and not snippet:
    fail("web/static/diagnostics-snippet.html is missing")

new_main, new_html = main, html
status = []

# ---------------------------------------------------------------- main.go
if "diag.NewManager" in main:
    status.append("main.go: already patched")
else:
    m_imp = find(r'^([ \t]*)"' + re.escape(MOD) + r'/internal/config"\n', main, 'the import of internal/config in main.go')
    m_mgr = find(r'^([ \t]*)// Reconcile existing capture pods on startup', main, 'the "Reconcile existing capture pods on startup" comment in main.go')
    m_rt = find(r'^([ \t]*)auth\.Get\("/captures/\{captureID\}/pods/\{targetPod\}/download",[^\n]*\n', main, 'the capture download route in main.go')
    m_st = find(r'^([ \t]*)// Static file server at root', main, 'the "Static file server at root" comment in main.go')
    if not (m_imp.start() < m_mgr.start() < m_rt.start() < m_st.start()):
        fail("main.go anchors are not in the expected order")

    block_mgr = (
        "// Thread dump manager (execs into pods; uses the ServiceAccount in-cluster, the user's token locally)\n"
        "diagMgr := diag.NewManager(diag.ConfigFromEnv())\n"
        "go diag.StartCleanupLoop(ctx, diagMgr)\n"
        'log.Println("Thread dump manager started")\n\n'
    )
    block_routes = (
        "\n// Thread dump routes\n"
        'auth.Get("/namespaces/{namespace}/pods/{pod}/containers", handlers.NewDiagContainersHandler())\n'
        'auth.Post("/diagnostics/start", handlers.NewDiagStartHandler(diagMgr))\n'
        'auth.Get("/diagnostics/status", handlers.NewDiagStatusHandler(diagMgr))\n'
        'auth.Post("/diagnostics/{jobID}/cancel", handlers.NewDiagCancelHandler(diagMgr))\n'
        'auth.Post("/diagnostics/{jobID}/ticket", handlers.NewDiagTicketHandler(diagMgr))\n'
    )
    block_dl = (
        "// Thread dump download: the one-time ticket in the URL is the credential (a plain link cannot send a Bearer header)\n"
        'r.Get("/download/diag/{ticket}", handlers.NewDiagDownloadHandler(diagMgr))\n\n'
    )
    # build from the end so earlier offsets stay valid
    out = main
    out = out[:m_st.start()] + indent_block(block_dl, m_st.group(1)) + out[m_st.start():]
    out = out[:m_rt.end()] + indent_block(block_routes, m_rt.group(1)) + out[m_rt.end():]
    out = out[:m_mgr.start()] + indent_block(block_mgr, m_mgr.group(1)) + out[m_mgr.start():]
    out = out[:m_imp.end()] + f'{m_imp.group(1)}"{MOD}/internal/diag"\n' + out[m_imp.end():]
    new_main = out
    status.append("main.go: will be patched (import, manager, 5 routes, download route)")

# ---------------------------------------------------------------- index.html
out = html
if 'id="diag-type-bar"' in out:
    status.append("index.html: UI block already present")
else:
    m = find(r'^([ \t]*)<!-- Capture Configuration Card -->', out, 'the "<!-- Capture Configuration Card -->" comment in index.html')
    out = out[:m.start()] + indent_block(snippet, m.group(1)) + "\n\n" + out[m.start():]
    status.append("index.html: UI block will be inserted before the Capture Configuration Card")
if "diagnostics.js" in out:
    status.append("index.html: script tag already present")
else:
    idx = out.rfind("</body>")
    if idx < 0:
        fail("no </body> tag found in index.html")
    out = out[:idx] + '    <script src="./diagnostics.js"></script>\n' + out[idx:]
    status.append("index.html: <script src=\"./diagnostics.js\"> will be added before </body>")
new_html = out

for s in status:
    print("   " + s)

if CHECK:
    print("   (check only - nothing written)")
    sys.exit(0)

for path, old, new in ((MAIN, main, new_main), (HTML, html, new_html)):
    if new != old:
        bak = pathlib.Path(str(path) + ".bak")
        if not bak.exists():
            shutil.copy2(path, bak)
        path.write_text(new, encoding="utf-8")
        print(f"   wrote {path.relative_to(ROOT)} (backup: {bak.name})")
__TD_PATCHER_EOF__

say "Checking that main.go and index.html can be patched (nothing is changed yet)"
"$PY" "$PATCHER" --check || die "cannot patch automatically (see above). No file was written. Send me the message above."
$DRY && echo "   (dry run: nothing will be written)"

# ------------------------------------------------------------------ 2. write files
say "Writing files"
write_file() {   # write_file <relative-path>   (content comes from stdin)
  local path="$1" tmp
  tmp="$(mktemp)"
  cat > "$tmp"
  if [ -f "$path" ] && cmp -s "$tmp" "$path"; then
    printf '   unchanged  %s\n' "$path"; rm -f "$tmp"; return
  fi
  if [ -f "$path" ]; then printf '   updated    %s\n' "$path"; else printf '   created    %s\n' "$path"; fi
  if $DRY; then rm -f "$tmp"; else mkdir -p "$(dirname "$path")"; mv "$tmp" "$path"; chmod 644 "$path"; fi
}

write_file 'deploy/diag-exec-rbac.yaml' <<'__TD_EOF__'
# RBAC for thread dumps when the backend runs IN a cluster (it then execs with its own ServiceAccount).
# Users are still checked with THEIR token (create pods/exec); this only lets the backend perform the exec.
#
# 1) Create the role once (cluster-scoped definition, grants nothing by itself):
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: tcpdump-thread-dump-exec
rules:
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create", "get"]   # WebSocket exec is sent as an HTTP GET upgrade, so both verbs are listed
---
# 2) Grant it ONLY in the namespaces whose pods should be dumpable (least privilege).
#    Repeat per namespace, or use: oc create rolebinding ... (see UPDATE.md).
#    Adjust the ServiceAccount name/namespace if yours differ.
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: tcpdump-thread-dump-exec
  namespace: <TARGET-NAMESPACE>
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: tcpdump-thread-dump-exec
subjects:
  - kind: ServiceAccount
    name: tcpdump-backend-sa
    namespace: openshift-tcpdump
# Alternative (broad, convenient, NOT least-privilege): bind the same ClusterRole with a ClusterRoleBinding.
__TD_EOF__

write_file 'internal/diag/diag_test.go' <<'__TD_EOF__'
package diag

import (
	"errors"
	"strings"
	"testing"
)

func TestParseDiscovery(t *testing.T) {
	out := `TOOL jcmd /opt/java/openjdk/bin/jcmd
TOOL jstack /opt/java/bin/js tack
TOOL jcmd ../evil
TOOL jmap /usr/bin/jmap
PID 1
PID abc
PID -5
TMPW 1
UID 1000680000
`
	info := ParseDiscovery(out)
	if info.Tools["jcmd"] != "/opt/java/openjdk/bin/jcmd" {
		t.Errorf("jcmd path wrong: %q", info.Tools["jcmd"])
	}
	if _, bad := info.Tools["jstack"]; bad {
		t.Error("path containing a space must be rejected")
	}
	if _, bad := info.Tools["jmap"]; bad {
		t.Error("unsupported tools must be ignored")
	}
	if len(info.PIDs) != 1 || info.PIDs[0] != 1 {
		t.Errorf("PIDs = %v, want [1]", info.PIDs)
	}
	if !info.TmpWritable || info.UID != 1000680000 {
		t.Errorf("unexpected tmp/uid: %+v", info)
	}
	if pid, err := info.SinglePID(); err != nil || pid != 1 {
		t.Errorf("SinglePID = %d, %v", pid, err)
	}
	multi := ParseDiscovery("PID 7\nPID 1\n")
	if _, err := multi.SinglePID(); err == nil || !strings.Contains(err.Error(), "2 Java processes") {
		t.Errorf("expected refusal for multiple JVMs, got %v", err)
	}
	if _, err := ParseDiscovery("TMPW 1\n").SinglePID(); err == nil {
		t.Error("expected error when no JVM present")
	}
}

func TestLimitedBuffer(t *testing.T) {
	b := &limitedBuffer{max: 5}
	if n, _ := b.Write([]byte("abc")); n != 3 {
		t.Fatal("short write")
	}
	if n, _ := b.Write([]byte("defg")); n != 4 { // reports a full write but drops data
		t.Fatal("must report full write so the exec stream keeps draining")
	}
	if !b.over || b.String() != "abc" {
		t.Errorf("over=%v content=%q", b.over, b.String())
	}
}

func TestNormalize(t *testing.T) {
	cfg := ConfigFromEnv()
	cfg.BaseDir = t.TempDir()
	cfg.ProdClusters = map[string]bool{"prod-east": true}
	m := NewManager(cfg)

	if _, err := m.Normalize(TypeThread, Options{}, "prod-east"); err == nil {
		t.Error("PROD cluster without typed confirmation must be refused")
	}
	if _, err := m.Normalize(TypeThread, Options{ConfirmCluster: "prod-east"}, "prod-east"); err != nil {
		t.Errorf("PROD cluster with exact confirmation must pass: %v", err)
	}
	if _, err := m.Normalize(TypeThread, Options{ConfirmCluster: "PROD-EAST"}, "prod-east"); err == nil {
		t.Error("confirmation must match the cluster name exactly (case-sensitive)")
	}
	o, err := m.Normalize(TypeThread, Options{}, "dev")
	if err != nil || o.Count != 3 || o.IntervalSec != 5 || o.MaxSizeMB != 50 || o.TimeoutSec != 3*5+120 {
		t.Errorf("thread defaults wrong: %+v %v", o, err)
	}
	if _, err := m.Normalize(TypeThread, Options{Count: 11}, "dev"); err == nil {
		t.Error("count > 10 must be refused")
	}
	if _, err := m.Normalize(TypeThread, Options{IntervalSec: 61}, "dev"); err == nil {
		t.Error("interval > 60 must be refused")
	}
	if _, err := m.Normalize("heap", Options{}, "dev"); err == nil {
		t.Error("unsupported type must be refused")
	}
}

func TestConfigExecIdentity(t *testing.T) {
	t.Setenv("DIAG_EXEC_IDENTITY", "")
	if got := ConfigFromEnv().ExecIdentity; got != "auto" {
		t.Errorf("default = %q, want auto", got)
	}
	t.Setenv("DIAG_EXEC_IDENTITY", " User ")
	if got := ConfigFromEnv().ExecIdentity; got != "user" {
		t.Errorf("user override = %q", got)
	}
	t.Setenv("DIAG_EXEC_IDENTITY", "serviceaccount") // unknown values must not silently change behaviour
	if got := ConfigFromEnv().ExecIdentity; got != "auto" {
		t.Errorf("unknown value = %q, want auto", got)
	}
}

func TestValidateTarget(t *testing.T) {
	if err := ValidateTarget("ns1", "dep-1", "pod-a", "app"); err != nil {
		t.Errorf("valid target rejected: %v", err)
	}
	if err := ValidateTarget("ns1", "", "pod-a", "app"); err != nil {
		t.Errorf("empty deployment must be allowed: %v", err)
	}
	for _, bad := range [][4]string{
		{"../x", "", "p", "c"}, {"ns", "", "p/q", "c"}, {"ns", "", "P", "c"}, {"ns", "", "p", ""},
		{"ns", "", "p", "c;rm"}, {"ns", "a/b", "p", "c"}, {"", "", "p", "c"},
	} {
		if ValidateTarget(bad[0], bad[1], bad[2], bad[3]) == nil {
			t.Errorf("%v should be rejected", bad)
		}
	}
}

func TestExplainExecErrorMentionsTheRightIdentity(t *testing.T) {
	forbidden := errors.New("exec refused by API server (HTTP 403): pods \"p\" is forbidden")
	user := Target{Namespace: "ns1"}.explainExecError(forbidden)
	sa := Target{Namespace: "ns1", AsServiceAccount: true}.explainExecError(forbidden)
	if !strings.Contains(user, "your account") || strings.Contains(user, "ServiceAccount") {
		t.Errorf("user wording wrong: %q", user)
	}
	for _, want := range []string{"backend ServiceAccount", "ns1", "pods/exec", "DIAG_EXEC_IDENTITY=user"} {
		if !strings.Contains(sa, want) {
			t.Errorf("SA wording misses %q: %q", want, sa)
		}
	}
	if m := (Target{}).explainExecError(errors.New("HTTP 401 unauthorized")); !strings.Contains(m, "token expired") {
		t.Errorf("user 401: %q", m)
	}
	if m := (Target{AsServiceAccount: true}).explainExecError(errors.New("HTTP 401 unauthorized")); !strings.Contains(m, "ServiceAccount token") {
		t.Errorf("SA 401: %q", m)
	}
	if m := (Target{}).explainExecError(errors.New("cannot exec in a stopped container")); !strings.Contains(m, "not running") {
		t.Errorf("stopped container: %q", m)
	}
	if m := (Target{}).explainExecError(errors.New("OCI runtime exec failed: exec: \"sh\": executable file not found in $PATH")); !strings.Contains(m, "no shell") {
		t.Errorf("no shell: %q", m)
	}
}
__TD_EOF__

write_file 'internal/diag/exec.go' <<'__TD_EOF__'
package diag

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// Target identifies one container to exec into. Token is the exec credential chosen by the
// HTTP layer: the backend ServiceAccount token in-cluster, the user's token locally.
type Target struct {
	APIURL           string
	Token            string
	Namespace        string
	Pod              string
	Container        string
	AsServiceAccount bool // only used to word error messages
}

// ExecResult is the outcome of a command that ran to completion inside the container.
type ExecResult struct {
	ExitCode int
	Stderr   string
}

const maxStderrBytes = 8 << 10

// execHook, when set (tests only), replaces the real WebSocket exec.
var execHook func(ctx context.Context, t Target, argv []string, stdout io.Writer) (ExecResult, error)

// execStatus is the JSON document the API server sends on channel 3 when the command ends.
type execStatus struct {
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
	Details struct {
		Causes []struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		} `json:"causes"`
	} `json:"details"`
}

// Exec runs argv inside the container and streams stdout to the given writer (may be nil).
//
// argv is always passed as a discrete argument list (no shell interpolation of user input).
// It uses the same WebSocket exec protocol (v4.channel.k8s.io) as capture.ExecInPod, but:
//   - the container name is a parameter (capture.ExecInPod hard-codes "capture"),
//   - the exit code is read from the status channel (channel 3),
//   - it honours ctx cancellation, and
//   - it sends a WebSocket ping every 30s so silent long-running commands are not
//     dropped by idle-timeout load balancers.
//
// A non-nil error means the command could not be run or the stream broke. A command that
// ran and exited non-zero is reported via ExecResult.ExitCode with a nil error.
func (t Target) Exec(ctx context.Context, argv []string, stdout io.Writer) (ExecResult, error) {
	var res ExecResult
	if len(argv) == 0 {
		return res, errors.New("empty command")
	}
	if execHook != nil {
		return execHook(ctx, t, argv, stdout)
	}

	wsURL := strings.Replace(t.APIURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)

	params := url.Values{}
	for _, a := range argv {
		params.Add("command", a)
	}
	params.Set("container", t.Container)
	params.Set("stdout", "true")
	params.Set("stderr", "true")
	params.Set("stdin", "false")
	params.Set("tty", "false")

	wsURL = strings.TrimRight(wsURL, "/") +
		"/api/v1/namespaces/" + url.PathEscape(t.Namespace) +
		"/pods/" + url.PathEscape(t.Pod) +
		"/exec?" + params.Encode()

	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // matches existing client (self-signed OpenShift API certs)
		Subprotocols:     []string{"v4.channel.k8s.io"},
		HandshakeTimeout: 20 * time.Second,
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+t.Token)

	conn, resp, err := dialer.DialContext(ctx, wsURL, header)
	if err != nil {
		if resp != nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			return res, fmt.Errorf("exec refused by API server (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		return res, fmt.Errorf("exec dial: %w", err)
	}
	defer conn.Close()

	// Keep-alive + cancellation watcher.
	done := make(chan struct{})
	defer close(done)
	go func() {
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				_ = conn.WriteControl(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, "cancelled"),
					time.Now().Add(time.Second))
				_ = conn.Close() // unblocks ReadMessage below
				return
			case <-tick.C:
				_ = conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second))
			}
		}
	}()

	var stderr bytes.Buffer
	gotStatus := false
	var apiFailure string

	for {
		_, msg, rerr := conn.ReadMessage()
		if rerr != nil {
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			if gotStatus {
				break // normal: server closes after the status message
			}
			return res, fmt.Errorf("exec stream ended without an exit status: %w", rerr)
		}
		if len(msg) < 2 {
			continue
		}
		payload := msg[1:]
		switch msg[0] {
		case 1: // stdout
			if stdout != nil {
				if _, werr := stdout.Write(payload); werr != nil {
					return res, fmt.Errorf("writing command output: %w", werr)
				}
			}
		case 2: // stderr
			if stderr.Len() < maxStderrBytes {
				stderr.Write(payload)
			}
		case 3: // status
			gotStatus = true
			var st execStatus
			if json.Unmarshal(payload, &st) != nil {
				apiFailure = strings.TrimSpace(string(payload))
				continue
			}
			if st.Status == "Success" {
				res.ExitCode = 0
				continue
			}
			res.ExitCode = 1
			isExit := false
			for _, c := range st.Details.Causes {
				if c.Reason == "ExitCode" {
					if n, convErr := strconv.Atoi(c.Message); convErr == nil {
						res.ExitCode = n
						isExit = true
					}
				}
			}
			if !isExit {
				// e.g. "executable file not found in $PATH", "container not found"
				apiFailure = st.Message
			}
		}
	}

	res.Stderr = strings.TrimSpace(stderr.String())
	if apiFailure != "" {
		return res, errors.New(apiFailure)
	}
	return res, nil
}

// RunText runs argv and returns stdout as a string (capped at maxBytes).
func (t Target) RunText(ctx context.Context, argv []string, maxBytes int) (string, ExecResult, error) {
	buf := &limitedBuffer{max: maxBytes}
	res, err := t.Exec(ctx, argv, buf)
	return buf.String(), res, err
}

// limitedBuffer stores at most max bytes and always reports a full write so the exec
// stream keeps draining. Check over to see whether output was dropped.
type limitedBuffer struct {
	max  int
	buf  bytes.Buffer
	over bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.over {
		return len(p), nil
	}
	if b.buf.Len()+len(p) > b.max {
		b.over = true
		return len(p), nil
	}
	b.buf.Write(p)
	return len(p), nil
}

func (b *limitedBuffer) String() string { return b.buf.String() }
func (b *limitedBuffer) Bytes() []byte  { return b.buf.Bytes() }

// explainExecError turns low-level exec errors into actionable messages. The wording depends on
// which identity was used, because the fix differs (RBAC for the ServiceAccount vs. the user's role).
func (t Target) explainExecError(err error) string {
	s := err.Error()
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "executable file not found"),
		strings.Contains(l, "no such file or directory") && strings.Contains(l, "\"sh\""):
		return "The container has no shell (sh), so the JVM cannot be inspected. Distroless/scratch images are not supported."
	case strings.Contains(l, "http 403"), strings.Contains(l, "forbidden"):
		if t.AsServiceAccount {
			return "Forbidden: the backend ServiceAccount is not allowed to exec into pods in namespace " + t.Namespace +
				". Grant it get/create on pods/exec there (see the setup guide), or set DIAG_EXEC_IDENTITY=user. (" + s + ")"
		}
		return "Forbidden: your account needs 'create' permission on pods/exec in this namespace. (" + s + ")"
	case strings.Contains(l, "http 401"), strings.Contains(l, "unauthorized"):
		if t.AsServiceAccount {
			return "The API server rejected the backend ServiceAccount token. (" + s + ")"
		}
		return "Your token expired while the job was running. Start the job again with a fresh token."
	case strings.Contains(l, "not running"), strings.Contains(l, "stopped container"):
		return "The container is not running (it may have restarted). (" + s + ")"
	case strings.Contains(l, "container not found"), strings.Contains(l, "not valid for pod"), strings.Contains(l, "http 404"):
		return "Pod or container not found (it may have restarted or been replaced). (" + s + ")"
	}
	return s
}
__TD_EOF__

write_file 'internal/diag/hook.go' <<'__TD_EOF__'
package diag

import (
	"context"
	"io"
)

// SetExecHookForTest replaces the real WebSocket exec with a fake. For tests only; pass nil to restore.
func SetExecHookForTest(f func(ctx context.Context, t Target, argv []string, stdout io.Writer) (ExecResult, error)) {
	execHook = f
}
__TD_EOF__

write_file 'internal/diag/jvm.go' <<'__TD_EOF__'
package diag

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// discoverScript is a FIXED, read-only shell script run inside the container with `sh -c`.
// No user input is ever interpolated into it.
const discoverScript = `
for t in jcmd jstack; do
  p=$(command -v "$t" 2>/dev/null)
  if [ -z "$p" ] && [ -n "$JAVA_HOME" ] && [ -x "$JAVA_HOME/bin/$t" ]; then p="$JAVA_HOME/bin/$t"; fi
  if [ -n "$p" ]; then echo "TOOL $t $p"; fi
done
for d in /proc/[0-9]*; do
  e=$(readlink "$d/exe" 2>/dev/null)
  case "$e" in */java) echo "PID ${d#/proc/}";; esac
done
if [ -w /tmp ]; then echo "TMPW 1"; fi
id -u 2>/dev/null | awk '{print "UID " $1}'
exit 0
`

// JVMInfo is the parsed result of discoverScript.
type JVMInfo struct {
	Tools       map[string]string // jcmd/jstack -> absolute path
	PIDs        []int
	TmpWritable bool
	UID         int
}

var safeToolPath = regexp.MustCompile(`^/[A-Za-z0-9_./+\-]+$`)

// ParseDiscovery strictly parses discoverScript output. Tool paths must be absolute and
// contain only [A-Za-z0-9_./+-]; PIDs must be positive integers. Unknown lines are ignored.
func ParseDiscovery(out string) *JVMInfo {
	info := &JVMInfo{Tools: map[string]string{}, UID: -1}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 3)
		switch parts[0] {
		case "TOOL":
			if len(parts) == 3 && (parts[1] == "jcmd" || parts[1] == "jstack") &&
				safeToolPath.MatchString(parts[2]) {
				info.Tools[parts[1]] = parts[2]
			}
		case "PID":
			if len(parts) >= 2 {
				if n, err := strconv.Atoi(parts[1]); err == nil && n > 0 {
					info.PIDs = append(info.PIDs, n)
				}
			}
		case "TMPW":
			info.TmpWritable = true
		case "UID":
			if len(parts) >= 2 {
				if n, err := strconv.Atoi(parts[1]); err == nil {
					info.UID = n
				}
			}
		}
	}
	sort.Ints(info.PIDs)
	return info
}

// SinglePID returns the one Java PID, or an error if there are zero or several.
func (j *JVMInfo) SinglePID() (int, error) {
	switch len(j.PIDs) {
	case 1:
		return j.PIDs[0], nil
	case 0:
		return 0, fmt.Errorf("no Java process was found in this container (checked /proc/*/exe)")
	default:
		return 0, fmt.Errorf("found %d Java processes (PIDs %v); automatic selection is refused", len(j.PIDs), j.PIDs)
	}
}

// explainAttachError recognises common JVM attach failures.
func explainAttachError(text string) string {
	l := strings.ToLower(text)
	switch {
	case strings.Contains(l, "attachnotsupportedexception"), strings.Contains(l, "disableattachmechanism"):
		return "The JVM has attach disabled (-XX:+DisableAttachMechanism); jcmd/jstack cannot connect."
	case strings.Contains(l, "unable to open socket file"), strings.Contains(l, "doesn't respond"), strings.Contains(l, "target process"):
		return "Could not attach to the JVM. Typical causes: the exec user differs from the JVM user, /tmp is not writable, or the JVM is not responding."
	case strings.Contains(l, "permission denied"):
		return "Permission denied while attaching to the JVM (different user or read-only /tmp)."
	}
	t := strings.TrimSpace(text)
	if len(t) > 400 {
		t = t[:400] + "..."
	}
	return t
}
__TD_EOF__

write_file 'internal/diag/manager.go' <<'__TD_EOF__'
package diag

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Sentinel errors returned by Manager methods.
var (
	ErrQueueFull   = errors.New("too many diagnostics are queued; try again later")
	ErrPodBusy     = errors.New("a diagnostic is already running for this pod")
	ErrNotFound    = errors.New("job not found")
	ErrNotReady    = errors.New("job has no downloadable file")
	ErrBadTicket   = errors.New("download link is invalid or expired")
	ErrNotCancelOK = errors.New("job already finished")
)

// Kubernetes object names (DNS-1123 subdomain); also safe as path components.
var nameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

// ValidateTarget checks the names that end up in API URLs and directory paths.
// deployment may be empty.
func ValidateTarget(namespace, deployment, pod, container string) error {
	for label, v := range map[string]string{"namespace": namespace, "pod": pod, "container": container} {
		if !nameRe.MatchString(v) {
			return fmt.Errorf("invalid or missing %s name", label)
		}
	}
	if deployment != "" && !nameRe.MatchString(deployment) {
		return errors.New("invalid deployment name")
	}
	return nil
}

// Caller carries per-request identity. APIURL/Token are the EXEC credential chosen by the HTTP
// layer (ServiceAccount + in-cluster URL, or the user's token + the user's cluster URL).
// The credential is held only for the lifetime of the job goroutine.
type Caller struct {
	APIURL   string
	Token    string
	ExecAs   string // ExecAsUser or ExecAsServiceAccount
	Cluster  string // cluster display name (X-Cluster)
	Username string // who asked for the dump
}

// PodRef selects one container in one pod.
type PodRef struct {
	Name      string
	Container string
}

// StartRequest describes one job (one pod).
type StartRequest struct {
	Type       string
	Namespace  string
	Deployment string
	Pod        PodRef
	Options    Options
}

type ticket struct {
	jobID   string
	expires time.Time
}

// Manager owns all jobs, concurrency limits and download tickets.
type Manager struct {
	cfg Config

	mu      sync.RWMutex
	jobs    map[string]*Job
	podBusy map[string]string // "cluster/ns/pod" -> job id
	tickets map[string]ticket

	threadSem chan struct{}
}

// NewManager creates a Manager and ensures the base directory exists.
func NewManager(cfg Config) *Manager {
	if cfg.ThreadConcurrency < 1 {
		cfg.ThreadConcurrency = 1
	}
	if cfg.MaxQueued < 1 {
		cfg.MaxQueued = 1
	}
	if cfg.ExecIdentity != "user" {
		cfg.ExecIdentity = "auto"
	}
	if err := os.MkdirAll(cfg.BaseDir, 0o750); err != nil {
		log.Printf("WARNING: diag: creating %s: %v (thread dumps will fail until the volume is mounted)", cfg.BaseDir, err)
	}
	return &Manager{
		cfg:       cfg,
		jobs:      make(map[string]*Job),
		podBusy:   make(map[string]string),
		tickets:   make(map[string]ticket),
		threadSem: make(chan struct{}, cfg.ThreadConcurrency),
	}
}

// BaseDir returns the root directory for stored diagnostics.
func (m *Manager) BaseDir() string { return m.cfg.BaseDir }

// ExecIdentity returns "auto" (same rule as TCP capture) or "user" (always the user's token).
func (m *Manager) ExecIdentity() string { return m.cfg.ExecIdentity }

// Normalize validates options, applies defaults and enforces the safeguards that do not
// need the cluster (PROD typed confirmation, limits).
func (m *Manager) Normalize(typ string, o Options, cluster string) (Options, error) {
	if typ != TypeThread {
		return o, fmt.Errorf("unsupported diagnostic type %q", typ)
	}
	if m.cfg.ProdClusters[strings.ToLower(cluster)] && o.ConfirmCluster != cluster {
		return o, fmt.Errorf("%q is a production cluster: type the exact cluster name to confirm", cluster)
	}
	if o.Count == 0 {
		o.Count = 3
	}
	if o.Count < 1 || o.Count > 10 {
		return o, errors.New("count must be between 1 and 10")
	}
	if o.IntervalSec == 0 {
		o.IntervalSec = 5
	}
	if o.IntervalSec < 1 || o.IntervalSec > 60 {
		return o, errors.New("interval must be between 1 and 60 seconds")
	}
	if o.MaxSizeMB == 0 {
		o.MaxSizeMB = 50
	}
	if o.MaxSizeMB < 1 || o.MaxSizeMB > 200 {
		return o, errors.New("size limit must be between 1 and 200 MB")
	}
	if o.TimeoutSec == 0 {
		o.TimeoutSec = o.Count*o.IntervalSec + 120
	}
	if o.TimeoutSec < 10 || o.TimeoutSec > 1800 {
		return o, errors.New("timeout must be between 10 and 1800 seconds")
	}
	return o, nil
}

// Start registers a job and launches its runner goroutine. It returns immediately.
func (m *Manager) Start(c Caller, r StartRequest) (string, error) {
	if err := ValidateTarget(r.Namespace, r.Deployment, r.Pod.Name, r.Pod.Container); err != nil {
		return "", err
	}
	if c.ExecAs != ExecAsServiceAccount {
		c.ExecAs = ExecAsUser
	}
	opts, err := m.Normalize(r.Type, r.Options, c.Cluster)
	if err != nil {
		return "", err
	}

	id := randomHex(16)
	ctx, cancel := context.WithCancel(context.Background())
	busyKey := c.Cluster + "/" + r.Namespace + "/" + r.Pod.Name

	m.mu.Lock()
	if _, busy := m.podBusy[busyKey]; busy {
		m.mu.Unlock()
		cancel()
		return "", ErrPodBusy
	}
	queued := 0
	for _, j := range m.jobs {
		if j.Status == StatusQueued {
			queued++
		}
	}
	if queued >= m.cfg.MaxQueued {
		m.mu.Unlock()
		cancel()
		return "", ErrQueueFull
	}
	m.jobs[id] = &Job{
		ID: id, Type: r.Type, Cluster: c.Cluster, Owner: c.Username, ExecAs: c.ExecAs,
		Namespace: r.Namespace, Deployment: r.Deployment, Pod: r.Pod.Name, Container: r.Pod.Container,
		Options: opts, Status: StatusQueued, Stage: "Queued", CreatedAt: time.Now(), cancel: cancel,
	}
	m.podBusy[busyKey] = id
	m.mu.Unlock()

	log.Printf("diag: job=%s type=%s user=%s exec_as=%s cluster=%s target=%s/%s/%s queued",
		id, r.Type, c.Username, c.ExecAs, c.Cluster, r.Namespace, r.Pod.Name, r.Pod.Container)

	go m.run(ctx, id, c)
	return id, nil
}

// Get returns a copy of the job.
func (m *Manager) Get(id string) (Job, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[id]
	if !ok {
		return Job{}, false
	}
	return *j, true
}

// Cancel requests cancellation of a queued or running job.
func (m *Manager) Cancel(id string) error {
	m.mu.RLock()
	j, ok := m.jobs[id]
	var cancel func()
	terminal := false
	if ok {
		cancel = j.cancel
		terminal = IsTerminal(j.Status)
	}
	m.mu.RUnlock()
	if !ok {
		return ErrNotFound
	}
	if terminal {
		return ErrNotCancelOK
	}
	cancel()
	return nil
}

func (m *Manager) mutate(id string, fn func(*Job)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if j, ok := m.jobs[id]; ok {
		fn(j)
	}
}

func (m *Manager) finish(id, status, msg string) {
	m.mutate(id, func(j *Job) {
		if IsTerminal(j.Status) {
			return
		}
		j.Status, j.Error, j.Stage = status, msg, ""
		j.FinishedAt = time.Now()
		delete(m.podBusy, j.Cluster+"/"+j.Namespace+"/"+j.Pod)
		log.Printf("diag: job=%s status=%s exec_as=%s size=%d err=%q", j.ID, status, j.ExecAs, j.SizeBytes, msg)
	})
}

func (m *Manager) hooksFor(id string) hooks {
	return hooks{
		stage: func(s string) { m.mutate(id, func(j *Job) { j.Stage = s }) },
		progress: func(done, total int64) {
			m.mutate(id, func(j *Job) {
				j.BytesDone = done
				if total > 0 {
					j.BytesTotal = total
				}
			})
		},
		warn: func(s string) { m.mutate(id, func(j *Job) { j.Warning = s }) },
	}
}

// run waits for a concurrency slot, applies the timeout, and records the final status.
func (m *Manager) run(pctx context.Context, id string, c Caller) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ERROR: diag: job %s panicked: %v", id, r)
			m.finish(id, StatusError, fmt.Sprintf("internal error: %v", r))
		}
	}()

	s, ok := m.Get(id)
	if !ok {
		return
	}
	select {
	case m.threadSem <- struct{}{}:
		defer func() { <-m.threadSem }()
	case <-pctx.Done():
		m.finish(id, StatusCancelled, "cancelled while queued")
		return
	}
	if pctx.Err() != nil {
		m.finish(id, StatusCancelled, "cancelled while queued")
		return
	}

	tctx, cancel := context.WithTimeout(pctx, time.Duration(s.Options.TimeoutSec)*time.Second)
	defer cancel()
	m.mutate(id, func(j *Job) { j.Status, j.StartedAt = StatusInProgress, time.Now() })

	err := m.execute(tctx, s, c)
	switch {
	case err == nil:
		m.finish(id, StatusComplete, "")
	case pctx.Err() != nil:
		m.finish(id, StatusCancelled, "cancelled by user")
	case errors.Is(tctx.Err(), context.DeadlineExceeded):
		m.finish(id, StatusTimedOut, fmt.Sprintf("timed out after %d seconds", s.Options.TimeoutSec))
	default:
		m.finish(id, StatusError, err.Error())
	}
}

// execute detects the JVM, runs the thread dump and stores the result on the PVC.
// The pod/container checks with the USER's token already happened in the HTTP layer.
func (m *Manager) execute(ctx context.Context, s Job, c Caller) error {
	h := m.hooksFor(s.ID)
	t := Target{
		APIURL: c.APIURL, Token: c.Token, Namespace: s.Namespace, Pod: s.Pod, Container: s.Container,
		AsServiceAccount: c.ExecAs == ExecAsServiceAccount,
	}

	h.stage("Detecting Java process")
	out, res, err := t.RunText(ctx, []string{"sh", "-c", discoverScript}, 64<<10)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New(t.explainExecError(err))
	}
	if res.ExitCode != 0 && strings.TrimSpace(out) == "" {
		return fmt.Errorf("JVM discovery failed (exit %d): %s", res.ExitCode, res.Stderr)
	}
	jvm := ParseDiscovery(out)
	pid, err := jvm.SinglePID()
	if err != nil {
		return err
	}
	if !jvm.TmpWritable {
		return errors.New("/tmp is not writable in the container; jcmd/jstack need it to attach to the JVM")
	}

	dep := s.Deployment
	if dep == "" {
		dep = "unknown"
	}
	dir := filepath.Join(m.cfg.BaseDir, s.Type, s.Namespace, dep, s.Pod, s.ID)
	if err := checkDisk(m.cfg.BaseDir, uint64(s.Options.MaxSizeMB)<<20*2); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}
	m.mutate(s.ID, func(j *Job) { j.Dir = dir })

	name := fmt.Sprintf("thread-dump-%s-%s.txt", s.Pod, time.Now().UTC().Format("20060102-150405"))
	final := filepath.Join(dir, name)
	part := final + ".part"

	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		os.RemoveAll(dir)
		return fmt.Errorf("creating output file: %w", err)
	}
	success := false
	defer func() {
		f.Close()
		if !success {
			os.RemoveAll(dir)
			pruneEmptyParents(dir, m.cfg.BaseDir)
		}
	}()

	tool, err := runThreadDump(ctx, t, jvm, pid, s.Options, f, h)
	if err != nil {
		return err
	}

	h.stage("Finalising")
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(part, final); err != nil {
		return fmt.Errorf("finalising output file: %w", err)
	}
	st, err := os.Stat(final)
	if err != nil {
		return err
	}
	md := Metadata{
		JobID: s.ID, Type: s.Type, Cluster: s.Cluster, Owner: s.Owner, ExecAs: s.ExecAs,
		Namespace: s.Namespace, Deployment: s.Deployment, Pod: s.Pod, Container: s.Container,
		JVMPid: pid, Tool: tool, File: name, SizeBytes: st.Size(), CompletedAt: time.Now(), Options: s.Options,
	}
	if err := writeMetadata(dir, md); err != nil {
		log.Printf("WARNING: diag: writing metadata for job %s: %v", s.ID, err)
	}
	m.mutate(s.ID, func(j *Job) { j.File, j.SizeBytes = name, st.Size() })
	success = true
	return nil
}

// IssueTicket creates a single-use download ticket valid for 2 minutes. A plain browser
// download link cannot send the Bearer header, so the UI first asks (authenticated) for a
// ticket and then navigates to it.
func (m *Manager) IssueTicket(jobID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[jobID]
	if !ok {
		return "", ErrNotFound
	}
	if j.Status != StatusComplete || j.File == "" {
		return "", ErrNotReady
	}
	now := time.Now()
	for k, t := range m.tickets {
		if now.After(t.expires) {
			delete(m.tickets, k)
		}
	}
	tk := randomHex(32)
	m.tickets[tk] = ticket{jobID: jobID, expires: now.Add(2 * time.Minute)}
	return tk, nil
}

// RedeemTicket consumes a ticket and returns the job it refers to.
func (m *Manager) RedeemTicket(tk string) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tickets[tk]
	if !ok {
		return Job{}, ErrBadTicket
	}
	delete(m.tickets, tk) // single use
	if time.Now().After(t.expires) {
		return Job{}, ErrBadTicket
	}
	j, ok := m.jobs[t.jobID]
	if !ok || j.Status != StatusComplete || j.File == "" {
		return Job{}, ErrNotReady
	}
	return *j, nil
}

// StartCleanupLoop deletes expired dumps (DIAG_THREAD_TTL_HOURS, default 168), stale .part
// files left by a crash, and forgets old finished jobs. Runs hourly.
func StartCleanupLoop(ctx context.Context, m *Manager) {
	log.Printf("diag cleanup loop started (thread dump TTL %s)", m.cfg.ThreadTTL)
	m.cleanup()
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			m.cleanup()
		}
	}
}

func (m *Manager) dirActive(dir string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, j := range m.jobs {
		if j.Dir == dir && !IsTerminal(j.Status) {
			return true
		}
	}
	return false
}

func (m *Manager) cleanup() {
	now := time.Now()
	base := m.cfg.BaseDir

	var expired []string
	_ = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		dir := filepath.Dir(path)
		switch {
		case strings.HasSuffix(info.Name(), ".part"):
			if now.Sub(info.ModTime()) > 6*time.Hour && !m.dirActive(dir) {
				expired = append(expired, dir)
			}
		case info.Name() == metadataName:
			md, rerr := readMetadata(path)
			if rerr != nil {
				log.Printf("WARNING: diag cleanup: %s: %v", path, rerr)
				return nil
			}
			if now.Sub(md.CompletedAt) > m.cfg.ThreadTTL {
				expired = append(expired, dir)
			}
		}
		return nil
	})
	for _, dir := range expired {
		if err := os.RemoveAll(dir); err != nil {
			log.Printf("WARNING: diag cleanup: removing %s: %v", dir, err)
			continue
		}
		pruneEmptyParents(dir, base)
		log.Printf("diag cleanup: removed %s", dir)
	}

	m.mu.Lock()
	for id, j := range m.jobs {
		if IsTerminal(j.Status) && now.Sub(j.FinishedAt) > 24*time.Hour {
			delete(m.jobs, id)
		}
	}
	for k, t := range m.tickets {
		if now.After(t.expires) {
			delete(m.tickets, k)
		}
	}
	m.mu.Unlock()
}

func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)[:n]
}
__TD_EOF__

write_file 'internal/diag/manager_test.go' <<'__TD_EOF__'
package diag

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const fullDump = "2024-01-01 00:00:00\nFull thread dump OpenJDK 64-Bit Server VM (17.0.9):\n\"main\" #1 prio=5 RUNNABLE\n"
const goodDiscovery = "TOOL jcmd /usr/bin/jcmd\nPID 1\nTMPW 1\nUID 1001\n"

type fakeContainer struct {
	discovery string
	dumpCount int32
	dumpOut   string
	dumpExit  int
	dumpSleep time.Duration
	lastToken atomic.Value // string: credential the last exec was made with
	lastURL   atomic.Value
	lastSA    atomic.Bool
}

func (f *fakeContainer) install(t *testing.T) {
	execHook = func(ctx context.Context, tg Target, argv []string, stdout io.Writer) (ExecResult, error) {
		f.lastToken.Store(tg.Token)
		f.lastURL.Store(tg.APIURL)
		f.lastSA.Store(tg.AsServiceAccount)
		if tg.Container != "app" {
			return ExecResult{}, fmt.Errorf("container not found")
		}
		switch {
		case len(argv) >= 3 && argv[0] == "sh" && argv[1] == "-c":
			io.WriteString(stdout, f.discovery)
			return ExecResult{}, nil
		case strings.HasSuffix(argv[0], "jcmd") || strings.HasSuffix(argv[0], "jstack"):
			atomic.AddInt32(&f.dumpCount, 1)
			if f.dumpSleep > 0 {
				select {
				case <-time.After(f.dumpSleep):
				case <-ctx.Done():
					return ExecResult{}, ctx.Err()
				}
			}
			io.WriteString(stdout, f.dumpOut)
			return ExecResult{ExitCode: f.dumpExit}, nil
		}
		return ExecResult{ExitCode: 127}, nil
	}
	t.Cleanup(func() { execHook = nil })
}

func newMgr(t *testing.T) *Manager {
	cfg := ConfigFromEnv()
	cfg.BaseDir = t.TempDir()
	cfg.ThreadConcurrency = 2
	cfg.MaxQueued = 3
	return NewManager(cfg)
}

func caller(execAs string) Caller {
	return Caller{APIURL: "https://api.example", Token: "exec-token", ExecAs: execAs, Cluster: "dev", Username: "alice"}
}

func waitTerminal(t *testing.T, m *Manager, id string, d time.Duration) Job {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		j, ok := m.Get(id)
		if !ok {
			t.Fatalf("job %s vanished", id)
		}
		if IsTerminal(j.Status) {
			return j
		}
		time.Sleep(20 * time.Millisecond)
	}
	j, _ := m.Get(id)
	t.Fatalf("job %s not finished in %s (status=%s stage=%s)", id, d, j.Status, j.Stage)
	return j
}

func startReq(pod, ctr string, o Options) StartRequest {
	return StartRequest{Type: TypeThread, Namespace: "ns1", Deployment: "dep1", Pod: PodRef{Name: pod, Container: ctr}, Options: o}
}

func TestHappyPathAndExecCredential(t *testing.T) {
	fc := &fakeContainer{discovery: goodDiscovery, dumpOut: fullDump}
	fc.install(t)
	m := newMgr(t)

	id, err := m.Start(caller(ExecAsServiceAccount), startReq("pod-a", "app", Options{Count: 3, IntervalSec: 1}))
	if err != nil {
		t.Fatal(err)
	}
	j := waitTerminal(t, m, id, 15*time.Second)
	if j.Status != StatusComplete {
		t.Fatalf("status=%s error=%q", j.Status, j.Error)
	}
	if got := atomic.LoadInt32(&fc.dumpCount); got != 3 {
		t.Errorf("jcmd ran %d times, want 3", got)
	}
	// The exact credential chosen by the HTTP layer is what reaches the exec call.
	if fc.lastToken.Load() != "exec-token" || fc.lastURL.Load() != "https://api.example" || !fc.lastSA.Load() {
		t.Errorf("exec used token=%v url=%v sa=%v", fc.lastToken.Load(), fc.lastURL.Load(), fc.lastSA.Load())
	}

	data, err := os.ReadFile(filepath.Join(j.Dir, j.File))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), "Full thread dump"); n != 3 {
		t.Errorf("file has %d dumps, want 3", n)
	}
	for _, want := range []string{"Thread dump 1/3", "Thread dump 3/3", "ns1/pod-a/app", "pid 1", "jcmd"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("missing %q in output file", want)
		}
	}
	if strings.Contains(string(data), "exec-token") {
		t.Error("the credential must never be written to the output")
	}
	if want := filepath.Join(m.BaseDir(), "thread", "ns1", "dep1", "pod-a", id); j.Dir != want {
		t.Errorf("dir = %s, want %s", j.Dir, want)
	}
	var md Metadata
	raw, err := os.ReadFile(filepath.Join(j.Dir, metadataName))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &md); err != nil || md.Owner != "alice" || md.ExecAs != ExecAsServiceAccount || md.Tool != "jcmd" {
		t.Errorf("bad metadata: %+v err=%v", md, err)
	}
	if parts, _ := filepath.Glob(filepath.Join(j.Dir, "*.part")); len(parts) != 0 {
		t.Errorf("leftover .part files: %v", parts)
	}
	if v := View(j); !v.Downloadable || v.File == "" || v.SizeBytes == 0 {
		t.Errorf("view not downloadable: %+v", v)
	}
	// Pod is free again after completion.
	id2, err := m.Start(caller(ExecAsUser), startReq("pod-a", "app", Options{Count: 1}))
	if err != nil {
		t.Fatalf("pod should be startable again: %v", err)
	}
	waitTerminal(t, m, id2, 10*time.Second) // don't leave a job writing into the temp dir
}

func TestUnknownExecAsDefaultsToUser(t *testing.T) {
	fc := &fakeContainer{discovery: goodDiscovery, dumpOut: fullDump}
	fc.install(t)
	m := newMgr(t)
	id, _ := m.Start(caller(""), startReq("pod-a", "app", Options{Count: 1}))
	j := waitTerminal(t, m, id, 10*time.Second)
	if j.ExecAs != ExecAsUser || fc.lastSA.Load() {
		t.Errorf("ExecAs=%q sa=%v", j.ExecAs, fc.lastSA.Load())
	}
}

func TestTicketIsOneTime(t *testing.T) {
	(&fakeContainer{discovery: goodDiscovery, dumpOut: fullDump}).install(t)
	m := newMgr(t)
	id, _ := m.Start(caller(ExecAsUser), startReq("pod-a", "app", Options{Count: 1}))
	waitTerminal(t, m, id, 10*time.Second)

	tk, err := m.IssueTicket(id)
	if err != nil || len(tk) != 32 {
		t.Fatalf("ticket %q err=%v", tk, err)
	}
	if j, err := m.RedeemTicket(tk); err != nil || j.ID != id {
		t.Fatalf("redeem: %v %v", j.ID, err)
	}
	if _, err := m.RedeemTicket(tk); err != ErrBadTicket {
		t.Errorf("second redeem must fail, got %v", err)
	}
	if _, err := m.RedeemTicket("nonsense"); err != ErrBadTicket {
		t.Errorf("unknown ticket must fail, got %v", err)
	}
}

func TestFailures(t *testing.T) {
	cases := []struct {
		name    string
		fc      *fakeContainer
		wantErr string
	}{
		{"no jcmd/jstack", &fakeContainer{discovery: "PID 1\nTMPW 1\n", dumpOut: fullDump}, "neither jcmd nor jstack"},
		{"no java process", &fakeContainer{discovery: "TOOL jcmd /usr/bin/jcmd\nTMPW 1\n", dumpOut: fullDump}, "no Java process"},
		{"two JVMs", &fakeContainer{discovery: "TOOL jcmd /usr/bin/jcmd\nPID 1\nPID 9\nTMPW 1\n", dumpOut: fullDump}, "2 Java processes"},
		{"tmp not writable", &fakeContainer{discovery: "TOOL jcmd /usr/bin/jcmd\nPID 1\n", dumpOut: fullDump}, "/tmp is not writable"},
		{"attach fails (exit 1)", &fakeContainer{discovery: goodDiscovery, dumpOut: "Unable to open socket file: target process 1 doesn't respond", dumpExit: 1}, "attach to the JVM"},
		{"output without header", &fakeContainer{discovery: goodDiscovery, dumpOut: "some garbage"}, "did not contain 'Full thread dump'"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.fc.install(t)
			m := newMgr(t)
			id, err := m.Start(caller(ExecAsUser), startReq("pod-a", "app", Options{Count: 2, IntervalSec: 1}))
			if err != nil {
				t.Fatal(err)
			}
			j := waitTerminal(t, m, id, 10*time.Second)
			if j.Status != StatusError || !strings.Contains(strings.ToLower(j.Error), strings.ToLower(c.wantErr)) {
				t.Errorf("status=%s error=%q, want error containing %q", j.Status, j.Error, c.wantErr)
			}
			var leftovers []string
			filepath.Walk(m.BaseDir(), func(p string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() {
					leftovers = append(leftovers, p)
				}
				return nil
			})
			if len(leftovers) != 0 {
				t.Errorf("failed job left files behind: %v", leftovers)
			}
			if _, err := m.IssueTicket(id); err == nil {
				t.Error("failed job must not give out a download ticket")
			}
		})
	}
}

func TestExecErrorsAreExplainedPerIdentity(t *testing.T) {
	for _, tc := range []struct {
		execAs, want string
	}{
		{ExecAsServiceAccount, "backend ServiceAccount is not allowed"},
		{ExecAsUser, "your account needs"},
	} {
		execHook = func(ctx context.Context, tg Target, argv []string, out io.Writer) (ExecResult, error) {
			return ExecResult{}, fmt.Errorf("exec refused by API server (HTTP 403): forbidden")
		}
		m := newMgr(t)
		id, _ := m.Start(caller(tc.execAs), startReq("pod-a", "app", Options{Count: 1}))
		j := waitTerminal(t, m, id, 5*time.Second)
		if j.Status != StatusError || !strings.Contains(j.Error, tc.want) {
			t.Errorf("%s: status=%s error=%q, want %q", tc.execAs, j.Status, j.Error, tc.want)
		}
	}
	t.Cleanup(func() { execHook = nil })
}

func TestStaleContainerFailsAtExec(t *testing.T) {
	(&fakeContainer{discovery: goodDiscovery, dumpOut: fullDump}).install(t)
	m := newMgr(t)
	id, _ := m.Start(caller(ExecAsUser), startReq("pod-a", "gone", Options{Count: 1})) // fake: only "app" exists
	j := waitTerminal(t, m, id, 5*time.Second)
	if j.Status != StatusError || !strings.Contains(j.Error, "not found") {
		t.Errorf("status=%s error=%q", j.Status, j.Error)
	}
}

func TestPartialFailureDiscardsFile(t *testing.T) {
	var n int32
	execHook = func(ctx context.Context, tg Target, argv []string, stdout io.Writer) (ExecResult, error) {
		if argv[0] == "sh" {
			io.WriteString(stdout, goodDiscovery)
			return ExecResult{}, nil
		}
		if atomic.AddInt32(&n, 1) == 1 {
			io.WriteString(stdout, fullDump)
		} else {
			io.WriteString(stdout, "broken")
		}
		return ExecResult{}, nil
	}
	t.Cleanup(func() { execHook = nil })
	m := newMgr(t)
	id, _ := m.Start(caller(ExecAsUser), startReq("pod-a", "app", Options{Count: 3, IntervalSec: 1}))
	j := waitTerminal(t, m, id, 10*time.Second)
	if j.Status != StatusError || !strings.Contains(j.Error, "dump 2") {
		t.Errorf("status=%s err=%q", j.Status, j.Error)
	}
	if _, err := os.Stat(j.Dir); !os.IsNotExist(err) {
		t.Errorf("output dir should be removed, stat err=%v", err)
	}
}

func TestCancelRunning(t *testing.T) {
	(&fakeContainer{discovery: goodDiscovery, dumpOut: fullDump, dumpSleep: 5 * time.Second}).install(t)
	m := newMgr(t)
	id, _ := m.Start(caller(ExecAsUser), startReq("pod-a", "app", Options{Count: 2, IntervalSec: 1}))
	for i := 0; i < 200; i++ {
		if j, _ := m.Get(id); j.Status == StatusInProgress && strings.HasPrefix(j.Stage, "Taking thread dump") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := m.Cancel(id); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	j := waitTerminal(t, m, id, 3*time.Second)
	if j.Status != StatusCancelled || time.Since(start) > 2*time.Second {
		t.Errorf("status=%s err=%q after %s", j.Status, j.Error, time.Since(start))
	}
	if err := m.Cancel(id); err != ErrNotCancelOK {
		t.Errorf("cancelling a finished job: %v", err)
	}
	if err := m.Cancel("does-not-exist"); err != ErrNotFound {
		t.Errorf("unknown job: %v", err)
	}
	if _, err := os.Stat(j.Dir); !os.IsNotExist(err) {
		t.Errorf("cancelled job must remove its output dir (err=%v)", err)
	}
}

func TestTimeout(t *testing.T) {
	(&fakeContainer{discovery: goodDiscovery, dumpOut: fullDump, dumpSleep: 30 * time.Second}).install(t)
	m := newMgr(t)
	id, err := m.Start(caller(ExecAsUser), startReq("pod-a", "app", Options{Count: 1, TimeoutSec: 10}))
	if err != nil {
		t.Fatal(err)
	}
	if j := waitTerminal(t, m, id, 15*time.Second); j.Status != StatusTimedOut {
		t.Errorf("status=%s err=%q", j.Status, j.Error)
	}
}

func TestPodBusyAndQueueLimits(t *testing.T) {
	(&fakeContainer{discovery: goodDiscovery, dumpOut: fullDump, dumpSleep: 2 * time.Second}).install(t)
	m := newMgr(t) // concurrency 2, max queued 3
	c := caller(ExecAsUser)

	id1, err := m.Start(c, startReq("pod-1", "app", Options{Count: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(c, startReq("pod-1", "app", Options{Count: 1})); err != ErrPodBusy {
		t.Errorf("same pod twice: got %v, want ErrPodBusy", err)
	}
	c2 := c
	c2.Cluster = "other"
	id2, err := m.Start(c2, startReq("pod-1", "app", Options{Count: 1}))
	if err != nil {
		t.Errorf("same pod name on another cluster must be allowed: %v", err)
	}
	var ids []string
	var lastErr error
	for i := 0; i < 8; i++ {
		id, err := m.Start(c, startReq(fmt.Sprintf("q-%d", i), "app", Options{Count: 1}))
		if err != nil {
			lastErr = err
			break
		}
		ids = append(ids, id)
	}
	if lastErr != ErrQueueFull {
		t.Errorf("expected ErrQueueFull, got %v after %d starts", lastErr, len(ids))
	}
	all := append(ids, id1, id2)
	for _, id := range all {
		m.Cancel(id)
	}
	for _, id := range all {
		waitTerminal(t, m, id, 5*time.Second)
	}
}

func TestInputValidation(t *testing.T) {
	m := newMgr(t)
	bad := []StartRequest{
		startReq("../etc", "app", Options{}),
		startReq("pod/a", "app", Options{}),
		startReq("POD", "app", Options{}),
		startReq("pod-a", "", Options{}),
		startReq("pod-a", "app;rm", Options{}),
		{Type: TypeThread, Namespace: "../x", Pod: PodRef{Name: "p", Container: "c"}},
		{Type: TypeThread, Namespace: "ns", Deployment: "a/b", Pod: PodRef{Name: "p", Container: "c"}},
		{Type: "heap", Namespace: "ns", Pod: PodRef{Name: "p", Container: "c"}},
	}
	for i, r := range bad {
		if id, err := m.Start(caller(ExecAsUser), r); err == nil {
			t.Errorf("case %d: expected rejection, got job %s", i, id)
		}
	}
}

func TestCleanup(t *testing.T) {
	m := newMgr(t)
	m.cfg.ThreadTTL = time.Hour
	mk := func(rel string, completed time.Time) string {
		dir := filepath.Join(m.BaseDir(), rel)
		os.MkdirAll(dir, 0o750)
		writeMetadata(dir, Metadata{JobID: "x", Type: TypeThread, File: "f.txt", CompletedAt: completed})
		os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o640)
		return dir
	}
	old := mk("thread/ns1/dep1/pod-old/aaa", time.Now().Add(-2*time.Hour))
	fresh := mk("thread/ns1/dep1/pod-new/bbb", time.Now().Add(-10*time.Minute))
	crashed := filepath.Join(m.BaseDir(), "thread/ns1/dep1/pod-crash/ccc")
	os.MkdirAll(crashed, 0o750)
	pf := filepath.Join(crashed, "x.txt.part")
	os.WriteFile(pf, []byte("partial"), 0o640)
	os.Chtimes(pf, time.Now().Add(-7*time.Hour), time.Now().Add(-7*time.Hour))

	m.cleanup()

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("expired dump should be deleted")
	}
	if _, err := os.Stat(filepath.Join(m.BaseDir(), "thread/ns1/dep1/pod-old")); !os.IsNotExist(err) {
		t.Error("empty parent directory should be pruned")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("fresh dump must be kept")
	}
	if _, err := os.Stat(crashed); !os.IsNotExist(err) {
		t.Error("stale .part directory should be deleted")
	}
	if _, err := os.Stat(m.BaseDir()); err != nil {
		t.Error("base dir must never be removed")
	}
}
__TD_EOF__

write_file 'internal/diag/storage.go' <<'__TD_EOF__'
package diag

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const metadataName = ".metadata.json"

// freeBytes returns the bytes available to unprivileged users on the filesystem holding path.
func freeBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

// checkDisk verifies that `need` bytes fit on the PVC while keeping DiskReserveBytes free.
func checkDisk(dir string, need uint64) error {
	free, err := freeBytes(dir)
	if err != nil {
		return fmt.Errorf("cannot determine free space on the backend volume: %w", err)
	}
	if free < need+DiskReserveBytes {
		return fmt.Errorf("not enough space on the backend volume: need %d MB (+%d MB reserve), only %d MB free",
			need>>20, DiskReserveBytes>>20, free>>20)
	}
	return nil
}

func writeMetadata(dir string, md Metadata) error {
	data, err := json.MarshalIndent(md, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, metadataName), data, 0o640)
}

func readMetadata(path string) (*Metadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var md Metadata
	if err := json.Unmarshal(data, &md); err != nil {
		return nil, err
	}
	return &md, nil
}

// pruneEmptyParents removes empty directories from childDir's parent up to (not including) base.
func pruneEmptyParents(childDir, base string) {
	base = filepath.Clean(base)
	dir := filepath.Dir(childDir)
	for dir != base && dir != "." && dir != "/" && len(dir) > len(base) {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) > 0 {
			return
		}
		if os.Remove(dir) != nil {
			return
		}
		dir = filepath.Dir(dir)
	}
}
__TD_EOF__

write_file 'internal/diag/thread.go' <<'__TD_EOF__'
package diag

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// hooks lets the runner report progress without knowing about the Manager.
type hooks struct {
	stage    func(string)
	progress func(done, total int64)
	warn     func(string)
}

// runThreadDump takes o.Count thread dumps, o.IntervalSec apart, into one text stream.
//
//	jcmd <pid> Thread.print   (preferred)   or   jstack <pid>
//
// Every dump must contain "Full thread dump" in its first 4 KB, otherwise the whole job
// fails (the caller discards the partial file). A shared size cap applies across all dumps.
// Returns the tool name used.
func runThreadDump(ctx context.Context, t Target, jvm *JVMInfo, pid int, o Options, out io.Writer, h hooks) (string, error) {
	var argv []string
	var tool string
	if p, ok := jvm.Tools["jcmd"]; ok {
		tool = "jcmd"
		argv = []string{p, strconv.Itoa(pid), "Thread.print"}
	} else if p, ok := jvm.Tools["jstack"]; ok {
		tool = "jstack"
		argv = []string{p, strconv.Itoa(pid)}
	} else {
		return "", errors.New("neither jcmd nor jstack was found in the container (a JRE-only image has neither); no other method was attempted")
	}

	maxBytes := int64(o.MaxSizeMB) << 20
	var written int64

	for i := 1; i <= o.Count; i++ {
		if err := ctx.Err(); err != nil {
			return tool, err
		}
		h.stage(fmt.Sprintf("Taking thread dump %d of %d", i, o.Count))

		remaining := maxBytes - written
		if remaining <= 0 {
			return tool, fmt.Errorf("size limit of %d MB reached before dump %d", o.MaxSizeMB, i)
		}
		buf := &limitedBuffer{max: int(remaining)}
		res, err := t.Exec(ctx, argv, buf)
		if err != nil {
			if ctx.Err() != nil {
				return tool, ctx.Err()
			}
			return tool, errors.New(t.explainExecError(err))
		}
		if res.ExitCode != 0 {
			return tool, fmt.Errorf("%s failed (exit %d): %s", tool, res.ExitCode, explainAttachError(res.Stderr+"\n"+buf.String()))
		}
		if buf.over {
			return tool, fmt.Errorf("dump %d exceeds the remaining size limit (%d MB total)", i, o.MaxSizeMB)
		}

		body := buf.Bytes()
		head := body
		if len(head) > 4096 {
			head = head[:4096]
		}
		if !strings.Contains(string(head), "Full thread dump") {
			return tool, fmt.Errorf("dump %d did not contain 'Full thread dump'; output starts with: %s",
				i, explainAttachError(string(head)))
		}

		header := fmt.Sprintf("===== Thread dump %d/%d | %s | %s/%s/%s | pid %d | %s =====\n",
			i, o.Count, time.Now().UTC().Format(time.RFC3339), t.Namespace, t.Pod, t.Container, pid, tool)
		if _, err := io.WriteString(out, header); err != nil {
			return tool, err
		}
		n, err := out.Write(body)
		if err != nil {
			return tool, err
		}
		if _, err := io.WriteString(out, "\n"); err != nil {
			return tool, err
		}
		written += int64(len(header)) + int64(n) + 1
		h.progress(written, 0)

		if i < o.Count {
			select {
			case <-time.After(time.Duration(o.IntervalSec) * time.Second):
			case <-ctx.Done():
				return tool, ctx.Err()
			}
		}
	}
	return tool, nil
}
__TD_EOF__

write_file 'internal/diag/types.go' <<'__TD_EOF__'
// Package diag adds on-demand JVM thread dumps to the OpenShift TCPDump tool.
//
// A thread dump runs INSIDE the target container through the Kubernetes pods/exec API.
// Which identity performs the exec is decided by the HTTP layer (see handlers/diagnostics.go)
// with the same rule as TCP capture: the backend ServiceAccount when running in a cluster,
// the user's own token when running locally.
package diag

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Diagnostic types.
const (
	TypeThread = "thread"
)

// Identity that performed the exec (recorded in logs and metadata).
const (
	ExecAsUser           = "user"
	ExecAsServiceAccount = "serviceaccount"
)

// Job status values.
const (
	StatusQueued     = "queued"
	StatusInProgress = "in_progress"
	StatusComplete   = "complete"
	StatusError      = "error"
	StatusTimedOut   = "timed_out"
	StatusCancelled  = "cancelled"
)

// IsTerminal reports whether a job status is final.
func IsTerminal(s string) bool {
	switch s {
	case StatusComplete, StatusError, StatusTimedOut, StatusCancelled:
		return true
	}
	return false
}

// DiskReserveBytes is the free space that must remain on the PVC after a dump is stored.
const DiskReserveBytes uint64 = 500 << 20

// Options are the user-supplied parameters. Zero values are replaced by defaults in Normalize().
type Options struct {
	Count       int `json:"count"`        // number of dumps, 1..10 (default 3)
	IntervalSec int `json:"interval_sec"` // seconds between dumps, 1..60 (default 5)
	TimeoutSec  int `json:"timeout_sec"`  // overall deadline, starts when the job leaves the queue
	MaxSizeMB   int `json:"max_size_mb"`  // total text cap across all dumps (default 50)

	// Production confirmation: user must type the exact cluster name.
	ConfirmCluster string `json:"confirm_cluster"`
}

// Job is the in-memory record of one diagnostic run against one pod/container.
// The exec credential (SA or user token) is NEVER stored here; it lives only on the runner goroutine's stack.
type Job struct {
	ID         string
	Type       string
	Cluster    string
	Owner      string // OpenShift username that started the job
	ExecAs     string // ExecAsUser or ExecAsServiceAccount
	Namespace  string
	Deployment string
	Pod        string
	Container  string
	Options    Options

	Status     string
	Stage      string
	Error      string
	Warning    string
	CreatedAt  time.Time
	StartedAt  time.Time
	FinishedAt time.Time

	BytesDone  int64
	BytesTotal int64

	Dir       string // directory on the PVC
	File      string // final file name inside Dir (set on success)
	SizeBytes int64

	cancel func()
}

// JobView is the JSON shape returned to the UI.
type JobView struct {
	JobID        string `json:"job_id"`
	Type         string `json:"type"`
	Namespace    string `json:"namespace"`
	Pod          string `json:"pod"`
	Container    string `json:"container"`
	Status       string `json:"status"`
	Stage        string `json:"stage,omitempty"`
	Error        string `json:"error,omitempty"`
	Warning      string `json:"warning,omitempty"`
	CreatedAt    string `json:"created_at"`
	StartedAt    string `json:"started_at,omitempty"`
	FinishedAt   string `json:"finished_at,omitempty"`
	ElapsedSec   int    `json:"elapsed_seconds"`
	BytesDone    int64  `json:"bytes_done"`
	BytesTotal   int64  `json:"bytes_total"`
	File         string `json:"file,omitempty"`
	SizeBytes    int64  `json:"size_bytes,omitempty"`
	Downloadable bool   `json:"downloadable"`
}

// View converts a Job snapshot to its JSON view.
func View(j Job) JobView {
	ts := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	}
	elapsed := 0
	if !j.StartedAt.IsZero() {
		end := j.FinishedAt
		if end.IsZero() {
			end = time.Now()
		}
		elapsed = int(end.Sub(j.StartedAt).Seconds())
	}
	return JobView{
		JobID: j.ID, Type: j.Type, Namespace: j.Namespace, Pod: j.Pod, Container: j.Container,
		Status: j.Status, Stage: j.Stage, Error: j.Error, Warning: j.Warning,
		CreatedAt: ts(j.CreatedAt), StartedAt: ts(j.StartedAt), FinishedAt: ts(j.FinishedAt),
		ElapsedSec: elapsed, BytesDone: j.BytesDone, BytesTotal: j.BytesTotal,
		File: j.File, SizeBytes: j.SizeBytes,
		Downloadable: j.Status == StatusComplete && j.File != "",
	}
}

// Metadata is written next to every stored dump (used by the cleanup loop).
type Metadata struct {
	JobID       string    `json:"job_id"`
	Type        string    `json:"type"`
	Cluster     string    `json:"cluster"`
	Owner       string    `json:"owner"`
	ExecAs      string    `json:"exec_as"`
	Namespace   string    `json:"namespace"`
	Deployment  string    `json:"deployment"`
	Pod         string    `json:"pod"`
	Container   string    `json:"container"`
	JVMPid      int       `json:"jvm_pid"`
	Tool        string    `json:"tool"`
	File        string    `json:"file"`
	SizeBytes   int64     `json:"size_bytes"`
	CompletedAt time.Time `json:"completed_at"`
	Options     Options   `json:"options"`
}

// Config holds runtime settings, normally loaded from environment variables.
type Config struct {
	BaseDir           string
	ThreadConcurrency int
	MaxQueued         int
	ProdClusters      map[string]bool // lower-cased cluster names that need typed confirmation
	ThreadTTL         time.Duration
	// ExecIdentity: "auto" (default) = same rule as TCP capture (ServiceAccount in-cluster, user token
	// locally); "user" = always exec with the user's own token.
	ExecIdentity string
}

// ConfigFromEnv builds a Config from DIAG_* environment variables.
func ConfigFromEnv() Config {
	c := Config{
		BaseDir:           envStr("DIAG_BASE_DIR", "/data/diagnostics"),
		ThreadConcurrency: envInt("DIAG_THREAD_CONCURRENCY", 6),
		MaxQueued:         envInt("DIAG_MAX_QUEUED", 20),
		ProdClusters:      map[string]bool{},
		ThreadTTL:         time.Duration(envInt("DIAG_THREAD_TTL_HOURS", 168)) * time.Hour,
		ExecIdentity:      "auto",
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("DIAG_EXEC_IDENTITY")), "user") {
		c.ExecIdentity = "user"
	}
	for _, n := range strings.Split(os.Getenv("DIAG_PROD_CLUSTERS"), ",") {
		if n = strings.TrimSpace(n); n != "" {
			c.ProdClusters[strings.ToLower(n)] = true
		}
	}
	return c
}

func envStr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
__TD_EOF__

write_file 'internal/handlers/diagnostics.go' <<'__TD_EOF__'
package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/openshift-tcpdump/openshift-tcpdump/internal/capture"
	"github.com/openshift-tcpdump/openshift-tcpdump/internal/diag"
	"github.com/openshift-tcpdump/openshift-tcpdump/internal/k8s"
	"github.com/openshift-tcpdump/openshift-tcpdump/internal/middleware"
)

// Seams for tests. In production they are exactly what captures.go uses.
var (
	diagReadSAToken       = capture.ReadSAToken
	diagBackendClusterURL = resolveBackendClusterURL
)

func diagJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func diagErr(w http.ResponseWriter, code int, msg string) {
	diagJSON(w, code, map[string]string{"error": msg})
}

// diagIdentity resolves the AuthContext and re-validates the token to get the username.
// Used on every diagnostics call so job ownership can be enforced (dumps may contain sensitive data).
func diagIdentity(w http.ResponseWriter, r *http.Request) (*middleware.AuthContext, string, bool) {
	ac := middleware.GetAuthContext(r.Context())
	if ac == nil {
		diagErr(w, http.StatusInternalServerError, "missing auth context")
		return nil, "", false
	}
	u, err := k8s.ValidateToken(ac.ClusterURL, ac.Token)
	if err != nil {
		diagErr(w, http.StatusUnauthorized, "Invalid or expired token")
		return nil, "", false
	}
	return ac, u.Username, true
}

// ownedJob returns the job only if it was started by this user on this cluster.
func ownedJob(m *diag.Manager, id, username string, ac *middleware.AuthContext) (diag.Job, bool) {
	j, ok := m.Get(id)
	if !ok || j.Owner != username || j.Cluster != ac.ClusterName {
		return diag.Job{}, false
	}
	return j, true
}

// execAuth is the credential used for pods/exec.
type execAuth struct {
	apiURL string
	token  string
	as     string // diag.ExecAsUser or diag.ExecAsServiceAccount
}

// resolveDiagExecAuth decides which identity runs the exec, with the same rule as TCP capture
// (resolveBackendAuth in captures.go):
//
//   - in a cluster (ServiceAccount token mounted): the backend ServiceAccount, through the
//     in-cluster API URL, and only for the cluster the backend runs on;
//   - locally (no ServiceAccount token): the user's own token against the user's cluster URL.
//
// mode "user" (DIAG_EXEC_IDENTITY=user) always selects the user's token.
// Whatever is chosen here, the user must separately pass the pods/exec access check
// (done by the caller with the USER's token), so the ServiceAccount never widens who can dump what.
func resolveDiagExecAuth(mode string, ac *middleware.AuthContext) (execAuth, error) {
	userAuth := execAuth{apiURL: ac.ClusterURL, token: ac.Token, as: diag.ExecAsUser}
	if mode == "user" {
		return userAuth, nil
	}
	saToken, err := diagReadSAToken()
	if err != nil {
		log.Printf("WARNING: diag: error reading SA token: %v, falling back to user token", err)
		return userAuth, nil
	}
	if saToken == "" {
		log.Printf("diag: SA token not found (local dev mode), using the user's token for exec")
		return userAuth, nil
	}

	// In-cluster: the ServiceAccount token is only valid on the local cluster, and the exec would
	// run there. Refuse unless we can prove the user selected that very cluster; otherwise the
	// user's rights on one cluster would be "spent" by the ServiceAccount on another.
	backendURL := diagBackendClusterURL()
	if backendURL == "" {
		return execAuth{}, errors.New("BACKEND_CLUSTER_NAME is not set (or is not in the clusters config), so the backend cannot verify " +
			"that the selected cluster is the one it runs on. Set it, or set DIAG_EXEC_IDENTITY=user to use each user's own token.")
	}
	if ac.ClusterURL != backendURL {
		return execAuth{}, errors.New("Thread dumps are only supported on the cluster where the backend is deployed. Selected: " +
			ac.ClusterURL + ", Backend: " + backendURL)
	}
	return execAuth{apiURL: capture.InClusterAPIURL, token: saToken, as: diag.ExecAsServiceAccount}, nil
}

// precheckTarget verifies, with the USER's token, that the container exists and is running.
func precheckTarget(ac *middleware.AuthContext, ns, deployment, pod, ctr string) error {
	if err := diag.ValidateTarget(ns, deployment, pod, ctr); err != nil {
		return err
	}
	phase, containers, err := k8s.GetPodContainers(ac.ClusterURL, ac.Token, ns, pod)
	if err != nil {
		return fmt.Errorf("cannot read pod %s/%s: %w", ns, pod, err)
	}
	found, running := false, false
	for _, c := range containers {
		if c.Name == ctr {
			found, running = true, c.Running
		}
	}
	switch {
	case !found:
		return fmt.Errorf("container %q does not belong to pod %s", ctr, pod)
	case phase != "Running" || !running:
		return fmt.Errorf("pod %s (phase %s) / container %s is not running", pod, phase, ctr)
	}
	return nil
}

// NewDiagContainersHandler serves GET /api/namespaces/{namespace}/pods/{pod}/containers.
func NewDiagContainersHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ac := middleware.GetAuthContext(r.Context())
		if ac == nil {
			diagErr(w, http.StatusInternalServerError, "missing auth context")
			return
		}
		phase, cs, err := k8s.GetPodContainers(ac.ClusterURL, ac.Token, chi.URLParam(r, "namespace"), chi.URLParam(r, "pod"))
		if err != nil {
			diagErr(w, http.StatusBadGateway, err.Error())
			return
		}
		diagJSON(w, http.StatusOK, map[string]interface{}{"phase": phase, "containers": cs})
	}
}

type diagStartRequest struct {
	Type       string `json:"type"`
	Namespace  string `json:"namespace"`
	Deployment string `json:"deployment"`
	Pods       []struct {
		Name      string `json:"name"`
		Container string `json:"container"`
	} `json:"pods"`
	Options diag.Options `json:"options"`
}

type diagStartResult struct {
	Pod   string `json:"pod"`
	JobID string `json:"job_id,omitempty"`
	Error string `json:"error,omitempty"`
}

// NewDiagStartHandler serves POST /api/diagnostics/start (one job per selected pod).
func NewDiagStartHandler(m *diag.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ac, username, ok := diagIdentity(w, r)
		if !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var req diagStartRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			diagErr(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}
		if req.Namespace == "" || len(req.Pods) == 0 {
			diagErr(w, http.StatusBadRequest, "namespace and at least one pod are required")
			return
		}
		if len(req.Pods) > 20 {
			diagErr(w, http.StatusBadRequest, "at most 20 pods per request")
			return
		}
		// Fail fast on option problems (PROD confirmation, limits) before touching the cluster.
		if _, err := m.Normalize(req.Type, req.Options, ac.ClusterName); err != nil {
			diagErr(w, http.StatusBadRequest, err.Error())
			return
		}
		// Which identity will exec (same rule as TCP capture); may refuse a cross-cluster request.
		ea, err := resolveDiagExecAuth(m.ExecIdentity(), ac)
		if err != nil {
			diagErr(w, http.StatusBadRequest, err.Error())
			return
		}
		// Authorization is ALWAYS checked with the user's token, even when a ServiceAccount will exec.
		allowed, err := k8s.CheckExecPermission(ac.ClusterURL, ac.Token, req.Namespace)
		if err != nil {
			diagErr(w, http.StatusBadGateway, "could not check exec permission: "+err.Error())
			return
		}
		if !allowed {
			diagErr(w, http.StatusForbidden,
				"Your account cannot 'create' pods/exec in namespace "+req.Namespace+". Ask for edit/admin access to that namespace.")
			return
		}

		caller := diag.Caller{APIURL: ea.apiURL, Token: ea.token, ExecAs: ea.as, Cluster: ac.ClusterName, Username: username}
		results := make([]diagStartResult, 0, len(req.Pods))
		for _, p := range req.Pods {
			res := diagStartResult{Pod: p.Name}
			if err := precheckTarget(ac, req.Namespace, req.Deployment, p.Name, p.Container); err != nil {
				res.Error = err.Error()
				results = append(results, res)
				continue
			}
			id, err := m.Start(caller, diag.StartRequest{
				Type: req.Type, Namespace: req.Namespace, Deployment: req.Deployment,
				Pod: diag.PodRef{Name: p.Name, Container: p.Container}, Options: req.Options,
			})
			if err != nil {
				res.Error = err.Error()
			} else {
				res.JobID = id
			}
			results = append(results, res)
		}
		diagJSON(w, http.StatusOK, map[string]interface{}{"jobs": results})
	}
}

// NewDiagStatusHandler serves GET /api/diagnostics/status?ids=a,b,c (batch, own jobs only).
func NewDiagStatusHandler(m *diag.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ac, username, ok := diagIdentity(w, r)
		if !ok {
			return
		}
		views := []diag.JobView{}
		ids := strings.Split(r.URL.Query().Get("ids"), ",")
		if len(ids) > 100 {
			ids = ids[:100]
		}
		for _, id := range ids {
			if j, ok := ownedJob(m, strings.TrimSpace(id), username, ac); ok {
				views = append(views, diag.View(j))
			}
		}
		diagJSON(w, http.StatusOK, map[string]interface{}{"jobs": views})
	}
}

// NewDiagCancelHandler serves POST /api/diagnostics/{jobID}/cancel.
func NewDiagCancelHandler(m *diag.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ac, username, ok := diagIdentity(w, r)
		if !ok {
			return
		}
		id := chi.URLParam(r, "jobID")
		if _, ok := ownedJob(m, id, username, ac); !ok {
			diagErr(w, http.StatusNotFound, "job not found")
			return
		}
		if err := m.Cancel(id); err != nil {
			if errors.Is(err, diag.ErrNotCancelOK) {
				diagErr(w, http.StatusConflict, err.Error())
				return
			}
			diagErr(w, http.StatusNotFound, err.Error())
			return
		}
		diagJSON(w, http.StatusOK, map[string]string{"status": "cancelling"})
	}
}

// NewDiagTicketHandler serves POST /api/diagnostics/{jobID}/ticket and returns a one-time
// download URL. A plain browser link cannot send the Bearer header; the ticket replaces it.
func NewDiagTicketHandler(m *diag.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ac, username, ok := diagIdentity(w, r)
		if !ok {
			return
		}
		id := chi.URLParam(r, "jobID")
		if _, ok := ownedJob(m, id, username, ac); !ok {
			diagErr(w, http.StatusNotFound, "job not found")
			return
		}
		tk, err := m.IssueTicket(id)
		if err != nil {
			diagErr(w, http.StatusConflict, err.Error())
			return
		}
		diagJSON(w, http.StatusOK, map[string]string{"url": "/download/diag/" + tk})
	}
}

// NewDiagDownloadHandler serves GET /download/diag/{ticket}. Register it OUTSIDE the auth
// middleware group: the one-time ticket is the credential. Range requests are supported.
func NewDiagDownloadHandler(m *diag.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		j, err := m.RedeemTicket(chi.URLParam(r, "ticket"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		full := filepath.Clean(filepath.Join(j.Dir, j.File))
		base := filepath.Clean(m.BaseDir()) + string(os.PathSeparator)
		if !strings.HasPrefix(full, base) {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		f, err := os.Open(full)
		if err != nil {
			http.Error(w, "file no longer available", http.StatusNotFound)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || st.IsDir() {
			http.Error(w, "file no longer available", http.StatusNotFound)
			return
		}

		log.Printf("diag AUDIT: download job=%s owner=%s exec_as=%s target=%s/%s file=%s size=%d from=%s",
			j.ID, j.Owner, j.ExecAs, j.Namespace, j.Pod, j.File, st.Size(), r.RemoteAddr)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", j.File))
		w.Header().Set("Cache-Control", "no-store")
		http.ServeContent(w, r, j.File, st.ModTime(), f)
	}
}
__TD_EOF__

write_file 'internal/handlers/diagnostics_test.go' <<'__TD_EOF__'
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/openshift-tcpdump/openshift-tcpdump/internal/capture"
	"github.com/openshift-tcpdump/openshift-tcpdump/internal/diag"
	authmw "github.com/openshift-tcpdump/openshift-tcpdump/internal/middleware"
)

const testDump = "Full thread dump OpenJDK 64-Bit Server VM (17.0.9):\n\"main\" #1 RUNNABLE\n"

// fakeCluster implements just enough of the OpenShift/Kubernetes API, and records which
// bearer tokens were presented to it.
type fakeCluster struct {
	mu         sync.Mutex
	users      map[string]string // token -> username
	execAllow  map[string]bool   // username -> may create pods/exec
	ssarCalled int
	tokensSeen map[string]int
}

func (f *fakeCluster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	f.tokensSeen[tok]++
	user, ok := f.users[tok]
	f.mu.Unlock()
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case r.URL.Path == "/apis/user.openshift.io/v1/users/~":
		fmt.Fprintf(w, `{"metadata":{"name":%q},"groups":["system:authenticated"]}`, user)
	case r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
		f.mu.Lock()
		f.ssarCalled++
		f.mu.Unlock()
		var req struct {
			Spec struct {
				ResourceAttributes struct{ Namespace, Verb, Resource, Subresource string }
			}
		}
		json.NewDecoder(r.Body).Decode(&req)
		ra := req.Spec.ResourceAttributes
		allowed := f.execAllow[user] && ra.Verb == "create" && ra.Resource == "pods" && ra.Subresource == "exec"
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"status":{"allowed":%v}}`, allowed)
	case strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/ns1/pods/"):
		if strings.HasSuffix(r.URL.Path, "/pending-pod") {
			fmt.Fprint(w, `{"spec":{"containers":[{"name":"app"}]},"status":{"phase":"Pending","containerStatuses":[{"name":"app","state":{"waiting":{}}}]}}`)
			return
		}
		fmt.Fprint(w, `{"spec":{"containers":[{"name":"app"},{"name":"istio-proxy"}]},"status":{"phase":"Running","containerStatuses":[{"name":"app","state":{"running":{}}},{"name":"istio-proxy","state":{"running":{}}}]}}`)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeCluster) saw(tok string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokensSeen[tok]
}

// execRecorder is the fake WebSocket exec; it records who exec'd where.
type execRecorder struct {
	mu      sync.Mutex
	targets []diag.Target
	failErr error
}

func (e *execRecorder) last() (diag.Target, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.targets) == 0 {
		return diag.Target{}, false
	}
	return e.targets[len(e.targets)-1], true
}

type env struct {
	srv  *httptest.Server
	mgr  *diag.Manager
	dir  string
	fc   *fakeCluster
	api  *httptest.Server
	exec *execRecorder
}

// newEnv wires the router exactly like cmd/server/main.go. By default the backend runs LOCALLY
// (no ServiceAccount token); use inCluster() to simulate running inside a cluster.
func newEnv(t *testing.T, mutate ...func(*diag.Config)) *env {
	t.Helper()
	fc := &fakeCluster{
		users:      map[string]string{"tok-alice": "alice", "tok-bob": "bob", "tok-carol": "carol"},
		execAllow:  map[string]bool{"alice": true, "bob": true, "carol": false},
		tokensSeen: map[string]int{},
	}
	api := httptest.NewTLSServer(fc)
	t.Cleanup(api.Close)

	rec := &execRecorder{}
	diag.SetExecHookForTest(func(ctx context.Context, tg diag.Target, argv []string, out io.Writer) (diag.ExecResult, error) {
		rec.mu.Lock()
		rec.targets = append(rec.targets, tg)
		failErr := rec.failErr
		rec.mu.Unlock()
		if failErr != nil {
			return diag.ExecResult{}, failErr
		}
		if argv[0] == "sh" {
			io.WriteString(out, "TOOL jcmd /usr/bin/jcmd\nPID 1\nTMPW 1\n")
		} else {
			io.WriteString(out, testDump)
		}
		return diag.ExecResult{}, nil
	})
	t.Cleanup(func() { diag.SetExecHookForTest(nil) })

	// Local dev by default: no SA token, no backend cluster configured.
	origRead, origBackend := diagReadSAToken, diagBackendClusterURL
	diagReadSAToken = func() (string, error) { return "", nil }
	diagBackendClusterURL = func() string { return "" }
	t.Cleanup(func() { diagReadSAToken, diagBackendClusterURL = origRead, origBackend })

	cfg := diag.ConfigFromEnv()
	cfg.BaseDir = t.TempDir()
	cfg.ProdClusters = map[string]bool{}
	for _, m := range mutate {
		m(&cfg)
	}
	mgr := diag.NewManager(cfg)

	resolver := func(name string) (string, bool) {
		if name == "dev" || name == "prod-east" {
			return api.URL, true
		}
		return "", false
	}
	r := chi.NewRouter()
	r.Route("/api", func(a chi.Router) {
		a.Group(func(auth chi.Router) {
			auth.Use(authmw.AuthMiddleware(resolver))
			auth.Get("/namespaces/{namespace}/pods/{pod}/containers", NewDiagContainersHandler())
			auth.Post("/diagnostics/start", NewDiagStartHandler(mgr))
			auth.Get("/diagnostics/status", NewDiagStatusHandler(mgr))
			auth.Post("/diagnostics/{jobID}/cancel", NewDiagCancelHandler(mgr))
			auth.Post("/diagnostics/{jobID}/ticket", NewDiagTicketHandler(mgr))
		})
	})
	r.Get("/download/diag/{ticket}", NewDiagDownloadHandler(mgr))
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return &env{srv: srv, mgr: mgr, dir: cfg.BaseDir, fc: fc, api: api, exec: rec}
}

// inCluster simulates a pod with a mounted ServiceAccount token on cluster `backendURL`.
func inCluster(saToken, backendURL string) {
	diagReadSAToken = func() (string, error) { return saToken, nil }
	diagBackendClusterURL = func() string { return backendURL }
}

func (e *env) do(t *testing.T, method, path, token, cluster string, body any, hdr map[string]string) (int, []byte, http.Header) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if cluster != "" {
		req.Header.Set("X-Cluster", cluster)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

func (e *env) start(t *testing.T, token, cluster string, opts map[string]any) (int, map[string]any) {
	return e.startPod(t, token, cluster, "pod-a", "app", opts)
}

func (e *env) startPod(t *testing.T, token, cluster, pod, ctr string, opts map[string]any) (int, map[string]any) {
	t.Helper()
	code, b, _ := e.do(t, "POST", "/api/diagnostics/start", token, cluster, map[string]any{
		"type": "thread", "namespace": "ns1", "deployment": "dep1",
		"pods": []map[string]string{{"name": pod, "container": ctr}}, "options": opts,
	}, nil)
	var m map[string]any
	json.Unmarshal(b, &m)
	return code, m
}

func (e *env) waitDone(t *testing.T, token, cluster, id string) map[string]any {
	t.Helper()
	for i := 0; i < 300; i++ {
		_, b, _ := e.do(t, "GET", "/api/diagnostics/status?ids="+id, token, cluster, nil, nil)
		var res struct{ Jobs []map[string]any }
		json.Unmarshal(b, &res)
		if len(res.Jobs) == 1 {
			if s := res.Jobs[0]["status"].(string); s != "queued" && s != "in_progress" {
				return res.Jobs[0]
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("job did not finish")
	return nil
}

func jobID(t *testing.T, m map[string]any) string {
	t.Helper()
	jobs, _ := m["jobs"].([]any)
	if len(jobs) != 1 {
		t.Fatalf("unexpected start response: %v", m)
	}
	id, _ := jobs[0].(map[string]any)["job_id"].(string)
	if id == "" {
		t.Fatalf("no job_id: %v", m)
	}
	return id
}

func (e *env) storedFiles() []string {
	var out []string
	filepath.Walk(e.dir, func(p string, i os.FileInfo, err error) error {
		if err == nil && !i.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	return out
}

func (e *env) metadata(t *testing.T) diag.Metadata {
	t.Helper()
	for _, p := range e.storedFiles() {
		if strings.HasSuffix(p, ".metadata.json") {
			var md diag.Metadata
			raw, _ := os.ReadFile(p)
			if err := json.Unmarshal(raw, &md); err != nil {
				t.Fatal(err)
			}
			return md
		}
	}
	t.Fatal("no metadata file stored")
	return diag.Metadata{}
}

// ------------------------------------------------------------------------------------------
// Identity: local (user token) vs in-cluster (ServiceAccount), same rule as TCP capture
// ------------------------------------------------------------------------------------------

func TestLocalDevExecsWithUserToken(t *testing.T) {
	e := newEnv(t) // no SA token => local dev
	code, m := e.start(t, "tok-alice", "dev", map[string]any{"count": 1})
	if code != 200 {
		t.Fatalf("start: %d %v", code, m)
	}
	e.waitDone(t, "tok-alice", "dev", jobID(t, m))
	tg, ok := e.exec.last()
	if !ok {
		t.Fatal("exec never ran")
	}
	if tg.Token != "tok-alice" || tg.APIURL != e.api.URL || tg.AsServiceAccount {
		t.Errorf("local mode must exec with the user's token on the user's cluster: %+v", tg)
	}
	if md := e.metadata(t); md.ExecAs != diag.ExecAsUser || md.Owner != "alice" {
		t.Errorf("metadata: %+v", md)
	}
}

func TestInClusterExecsWithServiceAccount(t *testing.T) {
	e := newEnv(t)
	inCluster("sa-secret-token", e.api.URL) // backend runs on the cluster the user selected
	code, m := e.start(t, "tok-alice", "dev", map[string]any{"count": 1})
	if code != 200 {
		t.Fatalf("start: %d %v", code, m)
	}
	e.waitDone(t, "tok-alice", "dev", jobID(t, m))

	tg, _ := e.exec.last()
	if tg.Token != "sa-secret-token" || tg.APIURL != capture.InClusterAPIURL || !tg.AsServiceAccount {
		t.Errorf("in-cluster must exec with the ServiceAccount via the in-cluster URL: %+v", tg)
	}
	if tg.Token == "tok-alice" {
		t.Error("the user's token must not be used for exec in-cluster")
	}
	// The SA token must never be sent to the (user-selected) API endpoint, and the user's token
	// is still used for what the user is entitled to do: identity, access review, pod lookup.
	if e.fc.saw("sa-secret-token") != 0 {
		t.Error("ServiceAccount token leaked to the user-selected API URL")
	}
	if e.fc.saw("tok-alice") < 3 || e.fc.ssarCalled != 1 {
		t.Errorf("user token should be used for identity/SSAR/pod lookup: saw=%d ssar=%d", e.fc.saw("tok-alice"), e.fc.ssarCalled)
	}
	md := e.metadata(t)
	if md.ExecAs != diag.ExecAsServiceAccount || md.Owner != "alice" {
		t.Errorf("metadata must record who asked and who executed: %+v", md)
	}
}

func TestInClusterStillRequiresUserExecPermission(t *testing.T) {
	e := newEnv(t)
	inCluster("sa-secret-token", e.api.URL)
	code, m := e.start(t, "tok-carol", "dev", nil) // carol may not exec
	if code != 403 || !strings.Contains(fmt.Sprint(m["error"]), "pods/exec") {
		t.Errorf("a user without pods/exec must be refused even though the SA could do it: %d %v", code, m)
	}
	if _, ran := e.exec.last(); ran || len(e.storedFiles()) != 0 {
		t.Error("nothing may run or be stored for a forbidden user")
	}
}

func TestInClusterRefusesOtherCluster(t *testing.T) {
	e := newEnv(t)
	inCluster("sa-secret-token", "https://api.some-other-cluster:6443")
	code, m := e.start(t, "tok-alice", "dev", map[string]any{"count": 1})
	msg := fmt.Sprint(m["error"])
	if code != 400 || !strings.Contains(msg, "only supported on the cluster where the backend is deployed") ||
		!strings.Contains(msg, e.api.URL) || !strings.Contains(msg, "https://api.some-other-cluster:6443") {
		t.Errorf("cross-cluster request: %d %v", code, m)
	}
	if e.fc.ssarCalled != 0 {
		t.Error("must be refused before any cluster call")
	}
	if _, ran := e.exec.last(); ran {
		t.Error("must not exec")
	}
}

func TestInClusterRefusesWhenBackendClusterUnknown(t *testing.T) {
	e := newEnv(t)
	inCluster("sa-secret-token", "") // BACKEND_CLUSTER_NAME not configured
	code, m := e.start(t, "tok-alice", "dev", map[string]any{"count": 1})
	if code != 400 || !strings.Contains(fmt.Sprint(m["error"]), "BACKEND_CLUSTER_NAME") {
		t.Errorf("unverifiable cluster must be refused: %d %v", code, m)
	}
	if _, ran := e.exec.last(); ran {
		t.Error("must not exec")
	}
}

func TestExecIdentityUserOverrideIgnoresServiceAccount(t *testing.T) {
	e := newEnv(t, func(c *diag.Config) { c.ExecIdentity = "user" })
	inCluster("sa-secret-token", "https://api.some-other-cluster:6443") // would be refused in auto mode
	code, m := e.start(t, "tok-alice", "dev", map[string]any{"count": 1})
	if code != 200 {
		t.Fatalf("override should allow it: %d %v", code, m)
	}
	e.waitDone(t, "tok-alice", "dev", jobID(t, m))
	if tg, _ := e.exec.last(); tg.Token != "tok-alice" || tg.APIURL != e.api.URL || tg.AsServiceAccount {
		t.Errorf("override must use the user's token on the user's cluster: %+v", tg)
	}
}

func TestServiceAccountForbiddenGivesActionableError(t *testing.T) {
	e := newEnv(t)
	inCluster("sa-secret-token", e.api.URL)
	e.exec.failErr = fmt.Errorf("exec refused by API server (HTTP 403): pods \"pod-a\" is forbidden")
	_, m := e.start(t, "tok-alice", "dev", map[string]any{"count": 1})
	st := e.waitDone(t, "tok-alice", "dev", jobID(t, m))
	msg := fmt.Sprint(st["error"])
	if st["status"] != "error" || !strings.Contains(msg, "backend ServiceAccount is not allowed") || !strings.Contains(msg, "ns1") {
		t.Errorf("status=%v error=%q", st["status"], msg)
	}
}

func TestResolveDiagExecAuthUnit(t *testing.T) {
	ac := &authmw.AuthContext{Token: "u", ClusterURL: "https://c1", ClusterName: "dev"}
	origRead, origBackend := diagReadSAToken, diagBackendClusterURL
	defer func() { diagReadSAToken, diagBackendClusterURL = origRead, origBackend }()

	diagReadSAToken = func() (string, error) { return "", fmt.Errorf("permission denied") } // unreadable => fall back like captures.go
	if ea, err := resolveDiagExecAuth("auto", ac); err != nil || ea.token != "u" || ea.as != diag.ExecAsUser {
		t.Errorf("unreadable SA token must fall back to the user token: %+v %v", ea, err)
	}
	inCluster("sa", "https://c1/") // trailing slash differs from the user's URL -> refused (same strict equality as captures.go)
	if _, err := resolveDiagExecAuth("auto", ac); err == nil {
		t.Error("URL mismatch must be refused")
	}
	inCluster("sa", "https://c1")
	if ea, err := resolveDiagExecAuth("auto", ac); err != nil || ea.token != "sa" || ea.apiURL != capture.InClusterAPIURL || ea.as != diag.ExecAsServiceAccount {
		t.Errorf("matching cluster: %+v %v", ea, err)
	}
	if ea, _ := resolveDiagExecAuth("user", ac); ea.token != "u" {
		t.Errorf("user mode: %+v", ea)
	}
}

// ------------------------------------------------------------------------------------------
// Pod pre-check (with the user's token) and the rest of the HTTP behaviour
// ------------------------------------------------------------------------------------------

func TestPrecheckReportsPerPodWithoutStartingJobs(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct{ pod, ctr, want string }{
		{"pending-pod", "app", "is not running"},
		{"pod-a", "nope", "does not belong to pod"},
		{"../bad", "app", "invalid or missing pod name"},
	} {
		code, m := e.startPod(t, "tok-alice", "dev", tc.pod, tc.ctr, map[string]any{"count": 1})
		jobs, _ := m["jobs"].([]any)
		if code != 200 || len(jobs) != 1 {
			t.Fatalf("%s: %d %v", tc.pod, code, m)
		}
		j := jobs[0].(map[string]any)
		if j["job_id"] != nil || !strings.Contains(fmt.Sprint(j["error"]), tc.want) {
			t.Errorf("%s: %v, want error containing %q", tc.pod, j, tc.want)
		}
	}
	if _, ran := e.exec.last(); ran || len(e.storedFiles()) != 0 {
		t.Error("rejected targets must not exec or store anything")
	}
}

func TestMixedPodsReportedIndividually(t *testing.T) {
	e := newEnv(t)
	code, b, _ := e.do(t, "POST", "/api/diagnostics/start", "tok-alice", "dev", map[string]any{
		"type": "thread", "namespace": "ns1",
		"pods":    []map[string]string{{"name": "ok-pod", "container": "app"}, {"name": "pending-pod", "container": "app"}},
		"options": map[string]any{"count": 1},
	}, nil)
	var res struct {
		Jobs []struct {
			Pod   string `json:"pod"`
			JobID string `json:"job_id"`
			Error string `json:"error"`
		}
	}
	json.Unmarshal(b, &res)
	if code != 200 || len(res.Jobs) != 2 || res.Jobs[0].JobID == "" || res.Jobs[1].Error == "" || res.Jobs[1].JobID != "" {
		t.Errorf("per-pod results: %d %s", code, b)
	}
	e.waitDone(t, "tok-alice", "dev", res.Jobs[0].JobID)
}

func TestEndToEndOverHTTP(t *testing.T) {
	e := newEnv(t)
	code, m := e.start(t, "tok-alice", "dev", map[string]any{"count": 2, "interval_sec": 1})
	if code != 200 {
		t.Fatalf("start: %d %v", code, m)
	}
	id := jobID(t, m)
	if e.fc.ssarCalled != 1 {
		t.Errorf("exec permission must be checked exactly once per request, got %d", e.fc.ssarCalled)
	}
	if st := e.waitDone(t, "tok-alice", "dev", id); st["status"] != "complete" || st["downloadable"] != true {
		t.Fatalf("job: %v", st)
	}

	code, b, _ := e.do(t, "POST", "/api/diagnostics/"+id+"/ticket", "tok-alice", "dev", nil, nil)
	var tk struct{ URL string }
	json.Unmarshal(b, &tk)
	if code != 200 || !strings.HasPrefix(tk.URL, "/download/diag/") {
		t.Fatalf("ticket: %d %s", code, b)
	}
	// No Authorization header: a plain browser navigation.
	code, b, hdr := e.do(t, "GET", tk.URL, "", "", nil, nil)
	if code != 200 || strings.Count(string(b), "Full thread dump") != 2 {
		t.Fatalf("download: %d dumps=%d", code, strings.Count(string(b), "Full thread dump"))
	}
	if cd := hdr.Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, "thread-dump-pod-a-") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if !strings.HasPrefix(hdr.Get("Content-Type"), "text/plain") || hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("headers: %v", hdr)
	}
	if code, _, _ := e.do(t, "GET", tk.URL, "", "", nil, nil); code != 404 {
		t.Errorf("reusing a ticket must 404, got %d", code)
	}
	_, b, _ = e.do(t, "POST", "/api/diagnostics/"+id+"/ticket", "tok-alice", "dev", nil, nil)
	json.Unmarshal(b, &tk)
	code, b, hdr = e.do(t, "GET", tk.URL, "", "", nil, map[string]string{"Range": "bytes=0-9"})
	if code != 206 || len(b) != 10 || !strings.HasPrefix(hdr.Get("Content-Range"), "bytes 0-9/") {
		t.Errorf("range request: code=%d len=%d content-range=%q", code, len(b), hdr.Get("Content-Range"))
	}
}

func TestAuthAndIsolation(t *testing.T) {
	e := newEnv(t)
	if code, _ := e.start(t, "", "dev", nil); code != 401 {
		t.Errorf("no token: %d", code)
	}
	if code, _ := e.start(t, "tok-nobody", "dev", nil); code != 401 {
		t.Errorf("bad token: %d", code)
	}
	if code, _ := e.start(t, "tok-alice", "nowhere", nil); code != 400 {
		t.Errorf("unknown cluster: %d", code)
	}
	if code, m := e.start(t, "tok-carol", "dev", nil); code != 403 || !strings.Contains(fmt.Sprint(m["error"]), "pods/exec") {
		t.Errorf("no exec permission: %d %v", code, m)
	}

	_, m := e.start(t, "tok-alice", "dev", map[string]any{"count": 1})
	id := jobID(t, m)
	e.waitDone(t, "tok-alice", "dev", id)

	var res struct{ Jobs []any }
	_, b, _ := e.do(t, "GET", "/api/diagnostics/status?ids="+id, "tok-bob", "dev", nil, nil)
	json.Unmarshal(b, &res)
	if len(res.Jobs) != 0 {
		t.Errorf("bob must not see alice's job: %s", b)
	}
	if code, _, _ := e.do(t, "POST", "/api/diagnostics/"+id+"/ticket", "tok-bob", "dev", nil, nil); code != 404 {
		t.Errorf("bob asking for a ticket: %d", code)
	}
	if code, _, _ := e.do(t, "POST", "/api/diagnostics/"+id+"/cancel", "tok-bob", "dev", nil, nil); code != 404 {
		t.Errorf("bob cancelling: %d", code)
	}
	_, b, _ = e.do(t, "GET", "/api/diagnostics/status?ids="+id, "tok-alice", "prod-east", nil, nil)
	json.Unmarshal(b, &res)
	if len(res.Jobs) != 0 {
		t.Errorf("job must be scoped to its cluster: %s", b)
	}
	_, b, _ = e.do(t, "GET", "/api/diagnostics/status?ids="+id, "tok-alice", "dev", nil, nil)
	json.Unmarshal(b, &res)
	if len(res.Jobs) != 1 {
		t.Errorf("alice must see her own job: %s", b)
	}
	if code, _, _ := e.do(t, "POST", "/api/diagnostics/"+id+"/cancel", "tok-alice", "dev", nil, nil); code != 409 {
		t.Errorf("cancelling finished job: %d", code)
	}
	if code, _, _ := e.do(t, "GET", "/download/diag/"+strings.Repeat("0", 32), "", "", nil, nil); code != 404 {
		t.Errorf("unknown ticket: %d", code)
	}
}

func TestProdConfirmationAndValidation(t *testing.T) {
	e := newEnv(t, func(c *diag.Config) { c.ProdClusters = map[string]bool{"prod-east": true} })

	code, m := e.start(t, "tok-alice", "prod-east", map[string]any{"count": 1})
	if code != 400 || !strings.Contains(fmt.Sprint(m["error"]), "production cluster") {
		t.Errorf("prod without confirmation: %d %v", code, m)
	}
	if e.fc.ssarCalled != 0 {
		t.Error("option validation must fail fast, before contacting the cluster")
	}
	if code, _ := e.start(t, "tok-alice", "prod-east", map[string]any{"count": 1, "confirm_cluster": "wrong"}); code != 400 {
		t.Errorf("prod with wrong confirmation: %d", code)
	}
	code, m = e.start(t, "tok-alice", "prod-east", map[string]any{"count": 1, "confirm_cluster": "prod-east"})
	if code != 200 {
		t.Fatalf("prod with exact confirmation: %d %v", code, m)
	}
	e.waitDone(t, "tok-alice", "prod-east", jobID(t, m))

	for _, o := range []map[string]any{{"count": 11}, {"count": -1}, {"interval_sec": 99}, {"max_size_mb": 1000}, {"timeout_sec": 5}} {
		if code, m := e.start(t, "tok-alice", "dev", o); code != 400 {
			t.Errorf("options %v should be rejected, got %d %v", o, code, m)
		}
	}
	for _, body := range []any{nil, map[string]any{"type": "thread"}, map[string]any{"type": "thread", "namespace": "ns1", "pods": []any{}}} {
		if code, _, _ := e.do(t, "POST", "/api/diagnostics/start", "tok-alice", "dev", body, nil); code != 400 {
			t.Errorf("body %v: %d", body, code)
		}
	}
}

func TestContainersEndpoint(t *testing.T) {
	e := newEnv(t)
	code, b, _ := e.do(t, "GET", "/api/namespaces/ns1/pods/pod-a/containers", "tok-alice", "dev", nil, nil)
	if code != 200 || !strings.Contains(string(b), `"name":"app"`) || !strings.Contains(string(b), `"phase":"Running"`) {
		t.Errorf("containers: %d %s", code, b)
	}
	if code, _, _ := e.do(t, "GET", "/api/namespaces/other/pods/pod-a/containers", "tok-alice", "dev", nil, nil); code != 502 {
		t.Errorf("missing pod should surface as 502, got %d", code)
	}
}

func TestDownloadAfterFileRemoved(t *testing.T) {
	e := newEnv(t)
	_, m := e.start(t, "tok-alice", "dev", map[string]any{"count": 1})
	id := jobID(t, m)
	e.waitDone(t, "tok-alice", "dev", id)
	for _, p := range e.storedFiles() {
		if strings.HasSuffix(p, ".txt") {
			os.Remove(p)
		}
	}
	_, b, _ := e.do(t, "POST", "/api/diagnostics/"+id+"/ticket", "tok-alice", "dev", nil, nil)
	var tk struct{ URL string }
	json.Unmarshal(b, &tk)
	if code, _, _ := e.do(t, "GET", tk.URL, "", "", nil, nil); code != 404 {
		t.Errorf("deleted file: %d", code)
	}
}
__TD_EOF__

write_file 'internal/k8s/diag.go' <<'__TD_EOF__'
package k8s

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ContainerState is a container of a pod and whether it is currently running.
type ContainerState struct {
	Name    string `json:"name"`
	Running bool   `json:"running"`
}

// GetPodContainers returns the pod phase and its containers (spec order) using the USER's token.
func GetPodContainers(clusterURL, token, namespace, pod string) (string, []ContainerState, error) {
	client := newInsecureClient()
	reqURL := strings.TrimRight(clusterURL, "/") +
		"/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods/" + url.PathEscape(pod)
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return "", nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("requesting pod: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, fmt.Errorf("reading pod response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := string(body)
		if len(msg) > 200 {
			msg = msg[:200] + "..."
		}
		return "", nil, fmt.Errorf("K8s API status %d: %s", resp.StatusCode, msg)
	}

	var p struct {
		Spec struct {
			Containers []struct {
				Name string `json:"name"`
			} `json:"containers"`
		} `json:"spec"`
		Status struct {
			Phase             string `json:"phase"`
			ContainerStatuses []struct {
				Name  string `json:"name"`
				State struct {
					Running *struct{} `json:"running"`
				} `json:"state"`
			} `json:"containerStatuses"`
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return "", nil, fmt.Errorf("parsing pod response: %w", err)
	}

	running := map[string]bool{}
	for _, cs := range p.Status.ContainerStatuses {
		running[cs.Name] = cs.State.Running != nil
	}
	out := make([]ContainerState, 0, len(p.Spec.Containers))
	for _, c := range p.Spec.Containers {
		out = append(out, ContainerState{Name: c.Name, Running: running[c.Name]})
	}
	return p.Status.Phase, out, nil
}

// CheckExecPermission asks the API server (SelfSubjectAccessReview, user's token) whether the
// user may `create` the `pods/exec` subresource in the namespace.
func CheckExecPermission(clusterURL, token, namespace string) (bool, error) {
	client := newInsecureClient()
	payload, err := json.Marshal(map[string]interface{}{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       "SelfSubjectAccessReview",
		"spec": map[string]interface{}{
			"resourceAttributes": map[string]string{
				"namespace":   namespace,
				"verb":        "create",
				"resource":    "pods",
				"subresource": "exec",
			},
		},
	})
	if err != nil {
		return false, err
	}
	reqURL := strings.TrimRight(clusterURL, "/") + "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
	req, err := http.NewRequest(http.MethodPost, reqURL, strings.NewReader(string(payload)))
	if err != nil {
		return false, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("requesting access review: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("reading access review: %w", err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("access review returned status %d", resp.StatusCode)
	}
	var r struct {
		Status struct {
			Allowed bool `json:"allowed"`
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return false, fmt.Errorf("parsing access review: %w", err)
	}
	return r.Status.Allowed, nil
}
__TD_EOF__

write_file 'web/static/diagnostics-snippet.html' <<'__TD_EOF__'
<!-- ===== Thread dump UI ===== -->

<!-- Diagnostic type selector -->
<div id="diag-type-bar" class="mt-6 border-t border-ocp-border pt-6">
    <h3 class="text-lg font-semibold text-ocp-text mb-3">Diagnostic</h3>
    <div class="flex items-center gap-2">
        <button type="button" data-diag-type="tcp"    class="bg-ocp-accent text-ocp-bg font-semibold px-4 py-2 rounded">TCP capture</button>
        <button type="button" data-diag-type="thread" class="bg-ocp-border text-ocp-text font-semibold px-4 py-2 rounded">Thread dump</button>
    </div>
</div>

<!-- Thread dump configuration -->
<div id="diag-config" class="hidden mt-6">
    <h3 class="text-lg font-semibold text-ocp-text mb-4">Thread Dump Configuration</h3>

    <div class="mb-4">
        <label class="block text-sm text-ocp-muted mb-1">Container to inspect (per selected pod)</label>
        <div id="diag-pods" class="text-sm text-ocp-text"></div>
    </div>

    <div class="grid grid-cols-2 md:grid-cols-3 gap-4 mb-4">
        <div>
            <label for="diag-count" class="block text-sm text-ocp-muted mb-1">Number of dumps (1-10)</label>
            <input id="diag-count" type="number" value="3" min="1" max="10"
                   class="w-full bg-ocp-bg border border-ocp-border text-ocp-text rounded px-3 py-2 focus:outline-none focus:border-ocp-accent">
        </div>
        <div>
            <label for="diag-interval" class="block text-sm text-ocp-muted mb-1">Interval (seconds)</label>
            <input id="diag-interval" type="number" value="5" min="1" max="60"
                   class="w-full bg-ocp-bg border border-ocp-border text-ocp-text rounded px-3 py-2 focus:outline-none focus:border-ocp-accent">
        </div>
    </div>

    <div class="mb-4">
        <label for="diag-confirm-cluster" class="block text-sm text-ocp-muted mb-1">Production confirmation</label>
        <input id="diag-confirm-cluster" type="text" placeholder="Type the exact cluster name (required on production clusters)"
               class="w-full bg-ocp-bg border border-ocp-border text-ocp-text rounded px-3 py-2 focus:outline-none focus:border-ocp-accent">
    </div>

    <div class="flex items-center gap-4">
        <button id="diag-start-btn"
                class="bg-ocp-accent text-ocp-bg font-semibold px-6 py-2 rounded hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed">
            Start
        </button>
        <div id="diag-start-error" class="hidden text-red-400 text-sm"></div>
    </div>
</div>

<!-- Thread dump status -->
<div id="diag-status-panel" class="hidden mt-6 border-t border-ocp-border pt-6"></div>

<!-- ===== end of thread dump UI ===== -->
__TD_EOF__

write_file 'web/static/diagnostics.js' <<'__TD_EOF__'
/*
 * Thread dump UI for the OpenShift TCPDump tool.
 *
 * Loaded AFTER the inline script in index.html. It reuses these globals from that script:
 *   apiFetch, nsSelect, deploySelect, getSelectedAppPods, escapeHtml,
 *   updateSelectedCount, resetPodTable, handleAuthExpired, newSession
 * and wraps the last four so it stays in sync; the TCP capture flow itself is untouched.
 */
(function () {
    'use strict';

    // Sidecars we should not pick as the default container.
    var SIDECARS = ['istio-proxy', 'linkerd-proxy', 'oauth-proxy', 'envoy', 'vault-agent', 'jaeger-agent', 'otel-agent'];
    var POLL_MS = 3000;
    var TERMINAL = ['complete', 'error', 'timed_out', 'cancelled'];

    var diagType = 'tcp';
    var jobs = {};            // job_id -> JobView
    var order = [];           // job ids in start order
    var startFailures = [];   // [{pod, error}]
    var containerInfo = {};   // pod name -> [containerName,...]  (cache, per namespace)
    var containerNs = '';     // namespace the cache belongs to
    var containerChoice = {}; // pod name -> chosen container
    var pollTimer = null;

    function $(id) { return document.getElementById(id); }
    function isTerminal(s) { return TERMINAL.indexOf(s) !== -1; }

    function fmtBytes(n) {
        if (!n) return '0 KB';
        if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';
        return Math.max(1, Math.round(n / 1024)) + ' KB';
    }
    function fmtElapsed(s) {
        if (s == null || s < 0) return '—';
        var m = Math.floor(s / 60), r = s % 60;
        return m > 0 ? m + 'm ' + r + 's' : r + 's';
    }
    function defaultContainer(list) {
        for (var i = 0; i < list.length; i++) {
            if (SIDECARS.indexOf(list[i]) === -1) return list[i];
        }
        return list[0] || '';
    }

    // ------------------------------------------------------------------ type selector
    var ACTIVE = 'bg-ocp-accent text-ocp-bg font-semibold px-4 py-2 rounded';
    var IDLE = 'bg-ocp-border text-ocp-text font-semibold px-4 py-2 rounded';

    function setType(t) {
        diagType = t;
        document.querySelectorAll('#diag-type-bar [data-diag-type]').forEach(function (b) {
            b.className = (b.dataset.diagType === t) ? ACTIVE : IDLE;
        });
        // Let the existing code decide whether the TCP form is shown (our wrapper hides it for 'thread').
        updateSelectedCount();
    }

    // ------------------------------------------------------------------ pod / container list
    function loadContainers(ns, podName) {
        if (containerInfo[podName]) return Promise.resolve();
        return apiFetch('/api/namespaces/' + encodeURIComponent(ns) + '/pods/' + encodeURIComponent(podName) + '/containers')
            .then(function (r) { return r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status)); })
            .then(function (d) {
                var names = (d.containers || []).map(function (c) { return c.name; });
                containerInfo[podName] = names;
                if (!containerChoice[podName]) containerChoice[podName] = defaultContainer(names);
            })
            .catch(function () { /* leave uncached so a later refresh retries */ });
    }

    function fillSelect(sel, podName) {
        var names = containerInfo[podName];
        sel.innerHTML = '';
        if (!names || !names.length) {
            var o = document.createElement('option');
            o.value = ''; o.textContent = names ? '(no containers)' : 'Loading...';
            sel.appendChild(o);
            return;
        }
        names.forEach(function (n) {
            var o = document.createElement('option');
            o.value = n; o.textContent = n;
            if (n === containerChoice[podName]) o.selected = true;
            sel.appendChild(o);
        });
    }

    function refreshConfig() {
        var cfg = $('diag-config');
        if (diagType !== 'thread') { cfg.classList.add('hidden'); return; }
        var pods = getSelectedAppPods();
        if (!pods.length) { cfg.classList.add('hidden'); return; }
        cfg.classList.remove('hidden');

        var ns = nsSelect.value;
        if (ns !== containerNs) { containerInfo = {}; containerChoice = {}; containerNs = ns; }

        var box = $('diag-pods');
        box.innerHTML = '';
        pods.forEach(function (p) {
            var row = document.createElement('div');
            row.className = 'flex items-center gap-2 mb-2';
            var label = document.createElement('span');
            label.className = 'text-ocp-text text-sm truncate max-w-xs';
            label.textContent = p.name;
            label.title = p.name;
            var sel = document.createElement('select');
            sel.className = 'bg-ocp-bg border border-ocp-border text-ocp-text rounded px-3 py-2 text-sm';
            sel.dataset.pod = p.name;
            sel.addEventListener('change', function () { containerChoice[p.name] = sel.value; });
            row.appendChild(label);
            row.appendChild(sel);
            box.appendChild(row);

            fillSelect(sel, p.name);
            if (!containerInfo[p.name]) {
                loadContainers(ns, p.name).then(function () { fillSelect(sel, p.name); });
            }
        });
    }

    // ------------------------------------------------------------------ start
    function showStartError(msg) {
        var e = $('diag-start-error');
        e.textContent = msg;
        e.classList.toggle('hidden', !msg);
    }

    function startDiag() {
        showStartError('');
        var pods = getSelectedAppPods().map(function (p) {
            return { name: p.name, container: containerChoice[p.name] || '' };
        });
        if (!pods.length) return;
        if (pods.some(function (p) { return !p.container; })) {
            showStartError('Pick a container for every selected pod (wait until the list has loaded).');
            return;
        }
        var options = {
            confirm_cluster: $('diag-confirm-cluster').value.trim(),
            count: parseInt($('diag-count').value, 10) || 3,
            interval_sec: parseInt($('diag-interval').value, 10) || 5
        };

        var btn = $('diag-start-btn');
        btn.disabled = true; btn.textContent = 'Starting...';
        apiFetch('/api/diagnostics/start', {
            method: 'POST',
            body: JSON.stringify({
                type: 'thread', namespace: nsSelect.value, deployment: deploySelect.value,
                pods: pods, options: options
            })
        }).then(function (r) {
            return r.json().then(function (d) { return { ok: r.ok, d: d }; });
        }).then(function (x) {
            if (!x.ok) { showStartError(x.d.error || 'Failed to start'); return; }
            (x.d.jobs || []).forEach(function (j) {
                if (j.job_id) {
                    order.push(j.job_id);
                    jobs[j.job_id] = {
                        job_id: j.job_id, type: 'thread', pod: j.pod, container: containerChoice[j.pod] || '',
                        status: 'queued', stage: 'Queued', bytes_done: 0, bytes_total: 0, elapsed_seconds: 0
                    };
                } else {
                    startFailures.push({ pod: j.pod, error: j.error || 'failed to start' });
                }
            });
            render();
            startPolling();
        }).catch(function (err) {
            showStartError('Network error: ' + err.message);
        }).then(function () {
            btn.disabled = false; btn.textContent = 'Start';
        });
    }

    // ------------------------------------------------------------------ polling
    function startPolling() {
        if (pollTimer) return;
        pollOnce();
        pollTimer = setInterval(pollOnce, POLL_MS);
    }
    function stopPolling() {
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    }
    function pollOnce() {
        var active = order.filter(function (id) { return !isTerminal(jobs[id].status); });
        if (!active.length) { stopPolling(); return; }
        apiFetch('/api/diagnostics/status?ids=' + encodeURIComponent(active.join(',')))
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (d) {
                if (!d) return;
                var seen = {};
                (d.jobs || []).forEach(function (v) { jobs[v.job_id] = v; seen[v.job_id] = true; });
                // Jobs the server no longer knows (e.g. backend restarted) must not spin forever.
                active.forEach(function (id) {
                    if (!seen[id] && jobs[id]) {
                        jobs[id].status = 'error';
                        jobs[id].error = 'The backend no longer knows this job (it may have restarted).';
                    }
                });
                render();
            })
            .catch(function () { /* transient; try again on next tick */ });
    }

    // ------------------------------------------------------------------ rendering
    function statusHtml(s) {
        var m = {
            queued: '<span class="text-gray-400">○ Queued</span>',
            in_progress: '<span class="text-ocp-accent">◆ In Progress</span>',
            complete: '<span class="text-green-400">✓ Complete</span>',
            error: '<span class="text-red-400">✗ Error</span>',
            timed_out: '<span class="text-orange-400">⚠ Timed Out</span>',
            cancelled: '<span class="text-gray-400">■ Cancelled</span>'
        };
        return m[s] || escapeHtml(s || '');
    }

    function rowHtml(j) {
        var detail = '';
        if (j.status === 'in_progress' || j.status === 'queued') {
            detail = escapeHtml(j.stage || '');
            if (j.bytes_done > 0) detail += ' — ' + fmtBytes(j.bytes_done) + ' captured';
        } else if (j.status === 'complete') {
            detail = escapeHtml(j.file || '') + ' (' + fmtBytes(j.size_bytes) + ')';
        } else if (j.error) {
            detail = '<span class="text-red-300 whitespace-pre-wrap">' + escapeHtml(j.error) + '</span>';
        }
        if (j.warning) {
            detail += '<div class="mt-1 px-2 py-1 bg-yellow-900/50 border border-yellow-700 rounded text-yellow-300 text-xs whitespace-pre-wrap">' +
                escapeHtml(j.warning) + '</div>';
        }
        var actions = '';
        if (j.status === 'queued' || j.status === 'in_progress') {
            actions = '<button class="bg-red-600 text-white text-xs font-semibold px-2 py-1 rounded hover:bg-red-700" data-diag-cancel="' + escapeHtml(j.job_id) + '">Cancel</button>';
        } else if (j.status === 'complete') {
            actions = '<button class="bg-ocp-accent/20 text-ocp-accent text-xs font-semibold px-2 py-1 rounded" data-diag-download="' + escapeHtml(j.job_id) + '">Download</button>';
        }
        return '<tr>' +
            '<td class="px-3 py-2 border-b border-ocp-border text-ocp-text text-sm truncate max-w-[180px]" title="' + escapeHtml(j.pod) + '">' + escapeHtml(j.pod) +
            '<div class="text-ocp-muted text-xs">' + escapeHtml(j.container || '') + '</div></td>' +
            '<td class="px-3 py-2 border-b border-ocp-border text-sm">' + statusHtml(j.status) + '</td>' +
            '<td class="px-3 py-2 border-b border-ocp-border text-ocp-muted text-sm">' + detail + '</td>' +
            '<td class="px-3 py-2 border-b border-ocp-border text-ocp-muted text-sm">' + fmtElapsed(j.elapsed_seconds) + '</td>' +
            '<td class="px-3 py-2 border-b border-ocp-border text-center">' + actions + '</td>' +
            '</tr>';
    }

    function render() {
        var panel = $('diag-status-panel');
        if (!order.length && !startFailures.length) { panel.classList.add('hidden'); panel.innerHTML = ''; return; }
        var html = '<div class="flex items-center justify-between mb-3">' +
            '<h3 class="text-lg font-semibold text-ocp-text">Thread Dumps</h3>' +
            '<button id="diag-clear-btn" class="bg-ocp-border text-ocp-text text-xs font-semibold px-2 py-1 rounded">Clear finished</button></div>';
        startFailures.forEach(function (f) {
            html += '<div class="mb-2 p-3 bg-red-900/50 border border-red-700 rounded text-red-300 text-sm"><strong>' +
                escapeHtml(f.pod) + ':</strong> ' + escapeHtml(f.error) + '</div>';
        });
        if (order.length) {
            html += '<div class="overflow-x-auto"><table class="w-full table-auto border-collapse">' +
                '<thead><tr class="bg-ocp-bg text-ocp-muted text-sm uppercase tracking-wider">' +
                '<th class="px-3 py-2 border-b border-ocp-border text-left">Pod</th>' +
                '<th class="px-3 py-2 border-b border-ocp-border text-left w-36">Status</th>' +
                '<th class="px-3 py-2 border-b border-ocp-border text-left">Details</th>' +
                '<th class="px-3 py-2 border-b border-ocp-border text-left w-24">Elapsed</th>' +
                '<th class="px-3 py-2 border-b border-ocp-border text-center w-28">Actions</th>' +
                '</tr></thead><tbody>';
            order.forEach(function (id) { html += rowHtml(jobs[id]); });
            html += '</tbody></table></div>';
        }
        panel.innerHTML = html;
        panel.classList.remove('hidden');
    }

    // ------------------------------------------------------------------ actions
    function download(id) {
        apiFetch('/api/diagnostics/' + encodeURIComponent(id) + '/ticket', { method: 'POST' })
            .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
            .then(function (x) {
                if (!x.ok) { alert('Download failed: ' + (x.d.error || 'unknown error')); return; }
                // Native browser download: a plain link cannot send the Bearer header, hence the one-time ticket.
                var a = document.createElement('a');
                a.href = x.d.url;
                a.rel = 'noopener';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
            })
            .catch(function (e) { alert('Download failed: ' + e.message); });
    }

    function cancel(id) {
        apiFetch('/api/diagnostics/' + encodeURIComponent(id) + '/cancel', { method: 'POST' })
            .then(function () { pollOnce(); });
    }

    function clearFinished() {
        order = order.filter(function (id) {
            if (isTerminal(jobs[id].status)) { delete jobs[id]; return false; }
            return true;
        });
        startFailures = [];
        render();
    }

    function resetAll() {
        stopPolling();
        jobs = {}; order = []; startFailures = [];
        containerInfo = {}; containerChoice = {}; containerNs = '';
        render();
        refreshConfig();
        showStartError('');
    }

    // ------------------------------------------------------------------ wiring
    function init() {
        document.querySelectorAll('#diag-type-bar [data-diag-type]').forEach(function (b) {
            b.addEventListener('click', function () { setType(b.dataset.diagType); });
        });
        $('diag-start-btn').addEventListener('click', startDiag);
        $('diag-status-panel').addEventListener('click', function (e) {
            var t = e.target;
            if (t.dataset.diagDownload) download(t.dataset.diagDownload);
            else if (t.dataset.diagCancel) cancel(t.dataset.diagCancel);
            else if (t.id === 'diag-clear-btn') clearFinished();
        });

        // Wrap the page's own functions. The inline script calls them by global name, so the
        // wrapped versions are what it will invoke from now on.
        var origUpdate = window.updateSelectedCount;
        window.updateSelectedCount = function () {
            var r = origUpdate.apply(this, arguments);
            if (diagType === 'thread') {
                var cap = $('capture-config');
                if (cap) cap.classList.add('hidden');   // the TCP form is not used in thread-dump mode
            }
            refreshConfig();
            return r;
        };
        var origReset = window.resetPodTable;
        window.resetPodTable = function () {
            var r = origReset.apply(this, arguments);
            refreshConfig();
            return r;
        };
        var origExpired = window.handleAuthExpired;
        window.handleAuthExpired = function () { resetAll(); return origExpired.apply(this, arguments); };
        var origNew = window.newSession;
        window.newSession = function () { resetAll(); return origNew.apply(this, arguments); };

        setType('tcp');
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
__TD_EOF__


# Files from an earlier version of this feature that no longer apply (they would not compile any more).
for old in internal/diag/http_test.go internal/diag/export_test.go; do
  if [ -f "$old" ]; then
    if $DRY; then echo "   would remove obsolete $old"; else rm -f "$old"; echo "   removed    $old (obsolete)"; fi
  fi
done

# ------------------------------------------------------------------ 3. patch main.go + index.html
say "Patching cmd/server/main.go and web/static/index.html"
"$PY" "$PATCHER" || die "patching failed (see above)."

# ------------------------------------------------------------------ 4. build + test
if $DRY; then
  say "Dry run finished - nothing was changed"
  exit 0
fi

if ! $CHECKS; then
  say "Skipping build/test (--skip-checks)"
elif ! command -v go >/dev/null 2>&1; then
  say "Go is not installed here - skipping build/test"
  echo "   Run later:  gofmt -l ./cmd ./internal && go build ./... && go vet ./... && go test ./internal/diag/ ./internal/handlers/"
else
  say "gofmt"
  UNFORMATTED="$(gofmt -l internal/diag internal/k8s/diag.go internal/handlers/diagnostics.go internal/handlers/diagnostics_test.go 2>/dev/null || true)"
  if [ -n "$UNFORMATTED" ]; then
    echo "   not gofmt-formatted (cosmetic, not an error):"; echo "$UNFORMATTED" | sed 's/^/     /'
  else
    echo "   all new Go files are formatted"
  fi
  if [ -f cmd/server/main.go.bak ] && [ -z "$(gofmt -l cmd/server/main.go.bak 2>/dev/null || true)" ] \
     && [ -n "$(gofmt -l cmd/server/main.go 2>/dev/null || true)" ]; then
    echo "   note: the main.go edit is not gofmt-formatted; run: gofmt -w cmd/server/main.go"
  fi
  say "go build ./..."
  go build ./... || die "build failed. Your original files are in *.bak; send me the compiler output."
  say "go vet ./..."
  go vet ./... || die "go vet reported problems (see above)."
  say "go test (thread dump packages, ~20 s)"
  go test -count=1 ./internal/diag/ ./internal/handlers/ || die "tests failed (see above)."
fi

# ------------------------------------------------------------------ done
cat <<'DONE'

==> Thread dump support is installed.

Next steps
  1. Review the change:         git diff cmd/server/main.go web/static/index.html
  2. Rebuild and redeploy the image (the static files are embedded in the binary).
  3. In OpenShift only:
       oc set env deployment/<backend> -n <backend-ns> BACKEND_CLUSTER_NAME=<cluster-name>   # if not set yet
       oc create rolebinding tcpdump-thread-dump-exec --clusterrole=tcpdump-thread-dump-exec \
          --serviceaccount=<backend-ns>:<backend-sa> -n <target-ns>        # after: oc apply -f deploy/diag-exec-rbac.yaml
     (ServiceAccount defaults used in the manifest: tcpdump-backend-sa in openshift-tcpdump - check yours.)
  4. Optional settings: DIAG_PROD_CLUSTERS, DIAG_EXEC_IDENTITY=user, DIAG_THREAD_TTL_HOURS,
     DIAG_THREAD_CONCURRENCY, DIAG_MAX_QUEUED, DIAG_BASE_DIR  (defaults are fine).
  5. Try it: open the tool, pick a Java pod, click "Thread dump" in the new Diagnostic bar, Start, Download.

Rollback:  cp cmd/server/main.go.bak cmd/server/main.go; cp web/static/index.html.bak web/static/index.html
           (then delete internal/diag, internal/k8s/diag.go, internal/handlers/diagnostics*.go, web/static/diagnostics*)
DONE
