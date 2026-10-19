//go:build linux

package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/statetrack/statetrack/pkg/diff"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// These tests run the real agent against the real /etc of a throwaway
// container: `scripts/dev.ps1 test-e2e` or `make test-e2e`. They edit
// system files, add users and install packages, so they refuse to run
// anywhere else.

const e2eDir = "/opt/statetrack-e2e" // outside the /tmp blacklist

const sessionScript = `echo 1000 > /proc/self/loginuid 2>/dev/null
cat /proc/self/loginuid > ` + e2eDir + `/loginuid.out
export SSH_CONNECTION="203.0.113.7 51234 10.0.0.5 22" SSH_CLIENT="203.0.113.7 51234 22"
` + e2eDir + `/bin/bash "$@"
`

// sudo resets the environment for the command it runs (env_reset).
const sudoScript = `env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "$@"
`

// A vim-style atomic save: probe file, rename the original to a backup,
// write the new file from the editor process itself, drop the backup. The
// editor stays open afterwards, like a real one.
const vimScript = `f="$1"; d=$(dirname "$f")
: > "$d/4913"; rm -f "$d/4913"
mv "$f" "$f~"
printf '[db]\nhost = db.internal\npassword = new-Secret-42\npool = 20\n' > "$f"
rm -f "$f~"
sleep 1
`

type e2e struct {
	t       *testing.T
	agent   *Agent
	cancel  context.CancelFunc
	done    chan error
	seq     atomic.Int32
	logFile string
}

func requireE2E(t *testing.T) {
	t.Helper()
	if os.Getenv("STATETRACK_E2E") != "1" {
		t.Skip("set STATETRACK_E2E=1 (see scripts/dev.ps1 test-e2e)")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Skip("e2e tests modify /etc and only run inside a container")
	}
	if os.Geteuid() != 0 {
		t.Skip("e2e tests need root")
	}
}

func sh(t *testing.T, script string) string {
	t.Helper()
	out, err := exec.Command("sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", script, err, out)
	}
	return string(out)
}

func writeFile(t *testing.T, p, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func buildDeb(t *testing.T, name, version, conf string) string {
	t.Helper()
	root := filepath.Join(e2eDir, "deb", name+"-"+version)
	writeFile(t, filepath.Join(root, "DEBIAN", "control"), fmt.Sprintf(
		"Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: e2e <e2e@example.com>\nDescription: StateTrack e2e fixture\n",
		name, version), 0o644)
	writeFile(t, filepath.Join(root, "etc", name, "app.conf"), conf, 0o644)
	writeFile(t, filepath.Join(root, "usr", "share", name, "VERSION"), version+"\n", 0o644)
	out := filepath.Join(e2eDir, "deb", name+"_"+version+"_all.deb")
	sh(t, "dpkg-deb --root-owner-group --build "+root+" "+out+" >/dev/null")
	return out
}

func startAgent(t *testing.T) *e2e {
	requireE2E(t)
	for _, n := range []string{"sshd", "bash", "sudo", "vim"} {
		sh(t, "mkdir -p "+e2eDir+"/bin && cp /bin/sh "+e2eDir+"/bin/"+n)
	}
	writeFile(t, e2eDir+"/session.sh", sessionScript, 0o755)
	writeFile(t, e2eDir+"/sudo.sh", sudoScript, 0o755)
	writeFile(t, e2eDir+"/vim.sh", vimScript, 0o755)

	// Pre-existing state, captured silently by the Day-0 baseline.
	sh(t, "id alice >/dev/null 2>&1 || useradd -u 1000 -m alice")
	writeFile(t, "/etc/nginx/sites-enabled/default", "server {\n    listen 80;\n    root /var/www/html;\n}\n", 0o644)
	writeFile(t, "/etc/app/db.conf", "[db]\nhost = db.internal\npassword = old-Secret-41\npool = 10\n", 0o640)
	sh(t, "mkdir -p /etc/sudoers.d /etc/e2e-noisy /var/spool/cron/crontabs")
	sh(t, "dpkg -i "+buildDeb(t, "statetrack-e2e", "1.0", "mode = classic\nworkers = 2\n")+" >/dev/null")
	buildDeb(t, "statetrack-e2e", "2.0", "mode = modern\nworkers = 4\n")
	buildDeb(t, "statetrack-e2e-extra", "1.0", "enabled = true\n")
	writeFile(t, e2eDir+"/apk/installed", "P:tree\nV:2.1.1-r0\nA:x86_64\n\nP:musl\nV:1.2.5-r0\nA:x86_64\n\n", 0o644)

	writeFile(t, "/etc/statetrack/agent.yaml", `host_id: e2e-host
log_level: debug
reload_interval: 1s
baseline:
  pace: 0s
watch:
  paths: [/etc, /var/spool/cron, /root/.ssh, /home/*/.ssh]
packages:
  enabled: true
  dpkg_log: /var/log/dpkg.log
  apk_log: `+e2eDir+`/apk/apk.log
  apk_db: `+e2eDir+`/apk/installed
`, 0o644)
	os.RemoveAll("/var/lib/statetrack")

	e := &e2e{t: t, done: make(chan error, 1), logFile: filepath.Join(t.TempDir(), "agent.log")}
	lf, err := os.Create(e.logFile)
	if err != nil {
		t.Fatal(err)
	}
	level := new(slog.LevelVar)
	log := slog.New(slog.NewJSONHandler(lf, &slog.HandlerOptions{Level: level}))
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	ready := make(chan *Agent, 1)
	go func() {
		e.done <- Run(ctx, Options{Logger: log, LogLevel: level, TickInterval: 200 * time.Millisecond,
			Ready: func(a *Agent) { ready <- a }})
		lf.Close()
	}()
	select {
	case e.agent = <-ready:
	case err := <-e.done:
		t.Fatalf("agent exited during startup: %v\n%s", err, e.logs())
	case <-time.After(60 * time.Second):
		t.Fatalf("agent did not start\n%s", e.logs())
	}
	t.Logf("collectors: %v", e.agent.Platform)
	t.Cleanup(func() { e.t = t; e.stop() })
	return e
}

func (e *e2e) logs() string {
	b, _ := os.ReadFile(e.logFile)
	return string(b)
}

func (e *e2e) stop() {
	if e.cancel == nil {
		return
	}
	e.cancel()
	e.cancel = nil
	select {
	case err := <-e.done:
		if err != nil {
			e.t.Errorf("agent shutdown: %v", err)
		}
	case <-time.After(20 * time.Second):
		e.t.Error("agent did not shut down")
	}
	if e.t.Failed() {
		e.t.Logf("agent log:\n%s", e.logs())
	}
}

func (e *e2e) fanotify() bool { return e.agent.Platform["fanotify"] == "true" }

// checkShortLived checks a change made by a sub-millisecond command. Without
// audit records (unavailable on Docker Desktop) neither inotify nor fanotify
// can guarantee the writer or its parents are still in /proc when the event
// is read, so the session identity is asserted whenever it was captured.
func (e *e2e) checkShortLived(ev *pb.MutationEvent) {
	e.t.Helper()
	lin := ev.Actor.GetProcessLineage()
	if slices.Contains(lin, "sshd") {
		e.checkHuman(ev)
		return
	}
	e.t.Logf("%s: session exited before it could be snapshotted (attribution %s, lineage %v)",
		ev.Summary, ev.Metadata["attribution"], lin)
}

// session runs script as alice over "SSH": sshd -> bash -> script. Like an
// interactive login, the shell stays open briefly after the command.
func (e *e2e) session(script string) {
	e.t.Helper()
	p := fmt.Sprintf("%s/cmd-%d.sh", e2eDir, e.seq.Add(1))
	writeFile(e.t, p, script+"sleep 0.5\n", 0o755)
	out, err := exec.Command(e2eDir+"/bin/sshd", e2eDir+"/session.sh", p).CombinedOutput()
	if err != nil {
		e.t.Fatalf("session %s: %v\n%s", script, err, out)
	}
}

func (e *e2e) loginUIDSet() bool {
	b, _ := os.ReadFile(e2eDir + "/loginuid.out")
	return strings.TrimSpace(string(b)) == "1000"
}

func (e *e2e) events() []*pb.MutationEvent {
	evs, err := e.agent.Spool.ReadBatch(context.Background(), 100000, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	return evs
}

// waitFor polls the spool until match returns a non-nil event.
func (e *e2e) waitFor(what string, timeout time.Duration, match func(*pb.MutationEvent) bool) *pb.MutationEvent {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		for _, ev := range e.events() {
			if match(ev) {
				return ev
			}
		}
		if time.Now().After(deadline) {
			var b strings.Builder
			for _, ev := range e.events() {
				fmt.Fprintf(&b, "  %s %s %s parent=%q\n", ev.Level, ev.Action, ev.Summary, ev.ParentEventId)
			}
			e.t.Fatalf("timed out waiting for %s; spooled events:\n%s", what, b.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func fileEvent(path string, action pb.Action) func(*pb.MutationEvent) bool {
	return func(ev *pb.MutationEvent) bool {
		return ev.GetTarget().GetPathOrKey() == path && ev.Action == action
	}
}

func unzipDiff(t *testing.T, ev *pb.MutationEvent) string {
	t.Helper()
	if len(ev.UnifiedDiffZstd) == 0 {
		t.Fatalf("%s: no diff", ev.Summary)
	}
	d, err := diff.DecompressString(ev.UnifiedDiffZstd)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func hasSuffix(lineage []string, want ...string) bool {
	return len(lineage) >= len(want) && slices.Equal(lineage[len(lineage)-len(want):], want)
}

// checkHuman verifies the change is traced back to alice's SSH session.
func (e *e2e) checkHuman(ev *pb.MutationEvent) {
	e.t.Helper()
	a := ev.Actor
	if a == nil {
		e.t.Fatalf("%s: no actor (attribution %q)", ev.Summary, ev.Metadata["attribution"])
	}
	if a.RemoteIp != "203.0.113.7" {
		e.t.Errorf("%s: remote_ip %q, want 203.0.113.7 (lineage %v)", ev.Summary, a.RemoteIp, a.ProcessLineage)
	}
	if e.loginUIDSet() {
		if a.LoginUid != "1000" || a.LoginUsername != "alice" {
			e.t.Errorf("%s: login %q/%q, want 1000/alice", ev.Summary, a.LoginUid, a.LoginUsername)
		}
	} else {
		e.t.Logf("loginuid not writable in this container; skipping loginuid assertions")
	}
	if !slices.Contains(a.ProcessLineage, "sshd") || !slices.Contains(a.ProcessLineage, "sudo") {
		e.t.Errorf("%s: lineage %v lacks sshd/sudo", ev.Summary, a.ProcessLineage)
	}
}

func TestE2ELinuxCollectors(t *testing.T) {
	e := startAgent(t)
	if n := len(e.events()); n != 0 {
		t.Fatalf("Day-0 baseline must be silent, got %d events", n)
	}

	t.Run("sed_in_place_over_ssh_sudo", func(t *testing.T) {
		e.t = t
		e.session(e2eDir + "/bin/sudo " + e2eDir + "/sudo.sh sed -i 's/listen 80;/listen 8080;/' /etc/nginx/sites-enabled/default\n")
		ev := e.waitFor("sed modification", 10*time.Second, fileEvent("/etc/nginx/sites-enabled/default", pb.Action_ACTION_MODIFIED))
		d := unzipDiff(t, ev)
		if !strings.Contains(d, "-    listen 80;") || !strings.Contains(d, "+    listen 8080;") {
			t.Fatalf("diff:\n%s", d)
		}
		if ev.Level != pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL {
			t.Errorf("level %v", ev.Level)
		}
		e.checkShortLived(ev)
		lin := ev.Actor.GetProcessLineage()
		if e.fanotify() && (len(lin) == 0 || lin[len(lin)-1] != "sed") {
			t.Errorf("fanotify must identify sed as the writer: lineage %v", lin)
		}
		if ev.Actor != nil && ev.Actor.Username != "root" {
			t.Errorf("user %q", ev.Actor.Username)
		}
		if slices.Contains(lin, "sshd") && !hasSuffix(lin, "sshd", "bash", "sudo", "sed") && !hasSuffix(lin, "sshd", "bash", "sudo") {
			t.Errorf("lineage %v", lin)
		}
		t.Logf("sed: attribution=%s lineage=%v", ev.Metadata["attribution"], ev.Actor.GetProcessLineage())
	})

	t.Run("vim_atomic_save_is_one_redacted_modification", func(t *testing.T) {
		e.t = t
		e.session(e2eDir + "/bin/sudo " + e2eDir + "/sudo.sh " + e2eDir + "/bin/vim " + e2eDir + "/vim.sh /etc/app/db.conf\n")
		ev := e.waitFor("vim save", 10*time.Second, fileEvent("/etc/app/db.conf", pb.Action_ACTION_MODIFIED))
		d := unzipDiff(t, ev)
		if strings.Contains(d, "Secret-4") || !strings.Contains(d, "[REDACTED:sha256:") {
			t.Fatalf("secret leaked or not redacted:\n%s", d)
		}
		if !strings.Contains(d, "-pool = 10") || !strings.Contains(d, "+pool = 20") {
			t.Fatalf("diff:\n%s", d)
		}
		for _, other := range e.events() {
			p := other.GetTarget().GetPathOrKey()
			if p == "/etc/app/db.conf" && other.Action != pb.Action_ACTION_MODIFIED || strings.HasPrefix(p, "/etc/app/db.conf~") ||
				strings.HasSuffix(p, "/4913") {
				t.Errorf("atomic save leaked an extra event: %s", other.Summary)
			}
		}
		e.checkHuman(ev)
		if !hasSuffix(ev.Actor.ProcessLineage, "sshd", "bash", "sudo", "vim") &&
			!hasSuffix(ev.Actor.ProcessLineage, "sshd", "bash", "sudo", "vim", "mv") {
			t.Errorf("lineage %v should end with the editor", ev.Actor.ProcessLineage)
		}
		t.Logf("vim: attribution=%s lineage=%v", ev.Metadata["attribution"], ev.Actor.ProcessLineage)
	})

	t.Run("useradd_and_sudoers", func(t *testing.T) {
		e.t = t
		e.session(e2eDir + "/bin/sudo " + e2eDir + "/sudo.sh useradd -m -u 1001 -s /bin/bash bob\n")
		ev := e.waitFor("passwd change", 10*time.Second, fileEvent("/etc/passwd", pb.Action_ACTION_MODIFIED))
		if ev.Category != pb.Category_CATEGORY_USER || !strings.Contains(unzipDiff(t, ev), "+bob:x:1001:1001::/home/bob:/bin/bash") {
			t.Fatalf("passwd event: %v\n%s", ev.Category, unzipDiff(t, ev))
		}
		e.checkHuman(ev)
		e.waitFor("shadow change", 10*time.Second, fileEvent("/etc/shadow", pb.Action_ACTION_MODIFIED))
		for _, other := range e.events() {
			if p := other.GetTarget().GetPathOrKey(); strings.HasSuffix(p, "+") || strings.HasSuffix(p, "-") || strings.HasSuffix(p, ".lock") {
				t.Errorf("shadow-utils temp file leaked: %s", other.Summary)
			}
		}

		e.session(e2eDir + "/bin/sudo " + e2eDir + "/sudo.sh sh -c 'echo \"bob ALL=(ALL) NOPASSWD: ALL\" | tee /etc/sudoers.d/90-bob >/dev/null'\n")
		ev = e.waitFor("sudoers drop-in", 10*time.Second, fileEvent("/etc/sudoers.d/90-bob", pb.Action_ACTION_CREATED))
		if ev.Category != pb.Category_CATEGORY_USER || !strings.Contains(unzipDiff(t, ev), "+bob ALL=(ALL) NOPASSWD: ALL") {
			t.Fatalf("sudoers diff:\n%s", unzipDiff(t, ev))
		}
		e.checkShortLived(ev)
		t.Logf("sudoers: attribution=%s lineage=%v", ev.Metadata["attribution"], ev.Actor.GetProcessLineage())

		// A new /home/*/.ssh directory is picked up by glob re-expansion.
		sh(t, "mkdir -p /home/bob/.ssh && echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForE2E bob@laptop' > /home/bob/.ssh/authorized_keys")
		ev = e.waitFor("authorized_keys", 15*time.Second, fileEvent("/home/bob/.ssh/authorized_keys", pb.Action_ACTION_CREATED))
		if ev.Category != pb.Category_CATEGORY_USER || ev.Level != pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL {
			t.Fatalf("authorized_keys: %v %v", ev.Level, ev.Category)
		}
	})

	t.Run("dpkg_upgrade_is_one_transaction", func(t *testing.T) {
		e.t = t
		e.session(e2eDir + "/bin/sudo " + e2eDir + "/sudo.sh dpkg -i " + e2eDir + "/deb/statetrack-e2e_2.0_all.deb " +
			e2eDir + "/deb/statetrack-e2e-extra_1.0_all.deb\n")
		parent := e.waitFor("dpkg transaction", 20*time.Second, func(ev *pb.MutationEvent) bool {
			return ev.Metadata["event_type"] == "TRANSACTION" && strings.Contains(ev.Metadata["packages"], "statetrack-e2e 1.0 -> 2.0")
		})
		if parent.Level != pb.ImpactLevel_IMPACT_LEVEL_2_GROUPED || parent.Category != pb.Category_CATEGORY_PACKAGE ||
			!strings.Contains(parent.Metadata["packages"], "statetrack-e2e-extra 1.0") {
			t.Fatalf("parent: %v %v %v", parent.Level, parent.Category, parent.Metadata)
		}
		var pkgs, files int
		for _, ev := range e.events() {
			if ev.ParentEventId != parent.EventId {
				continue
			}
			switch {
			case ev.Category == pb.Category_CATEGORY_PACKAGE:
				pkgs++
				if ev.Target.PathOrKey == "statetrack-e2e" && (ev.Target.VersionBefore != "1.0" || ev.Target.VersionAfter != "2.0" ||
					ev.Action != pb.Action_ACTION_UPGRADED) {
					t.Errorf("package event: %+v", ev.Target)
				}
			case ev.Target.PathOrKey == "/etc/statetrack-e2e/app.conf":
				files++
				if d := unzipDiff(t, ev); !strings.Contains(d, "+mode = modern") {
					t.Errorf("conffile diff:\n%s", d)
				}
			}
		}
		if pkgs != 2 || files != 1 {
			t.Fatalf("children: %d package events, %d conffile events (want 2, 1)", pkgs, files)
		}
		if a := parent.Actor; a == nil || a.ProcessName != "dpkg" || a.RemoteIp != "203.0.113.7" ||
			(e.loginUIDSet() && a.LoginUsername != "alice") {
			t.Errorf("parent actor: %+v", a)
		}
		t.Logf("dpkg transaction: %s (lineage %v)", parent.Summary, parent.Actor.GetProcessLineage())
	})

	t.Run("apk_upgrade_from_log_and_database", func(t *testing.T) {
		e.t = t
		writeFile(t, e2eDir+"/apk/apk.log", "Running `apk upgrade tree` at 2026-10-13 21:21:56\n", 0o644)
		writeFile(t, e2eDir+"/apk/installed", "P:tree\nV:2.2.0-r0\nA:x86_64\n\nP:musl\nV:1.2.5-r0\nA:x86_64\n\n", 0o644)
		parent := e.waitFor("apk transaction", 15*time.Second, func(ev *pb.MutationEvent) bool {
			return ev.Metadata["event_type"] == "TRANSACTION" && ev.Metadata["tool"] == "apk"
		})
		if parent.Metadata["packages"] != "tree 2.1.1-r0 -> 2.2.0-r0" || parent.ChildCount != 1 {
			t.Fatalf("parent: %v", parent.Metadata)
		}
		child := e.waitFor("apk child", time.Second, func(ev *pb.MutationEvent) bool { return ev.ParentEventId == parent.EventId })
		if child.Metadata["command"] != "apk upgrade tree" || child.Action != pb.Action_ACTION_UPGRADED {
			t.Fatalf("child: %v", child.Metadata)
		}
	})

	t.Run("self_tamper_and_hot_reload", func(t *testing.T) {
		e.t = t
		until := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
		cfg, _ := os.ReadFile("/etc/statetrack/agent.yaml")
		updated := strings.Replace(string(cfg), "watch:\n", "forensic_until: "+until+"\nwatch:\n  exclude: [\"/etc/e2e-noisy/**\"]\n", 1)
		writeFile(t, "/etc/statetrack/agent.yaml", updated, 0o644)
		ev := e.waitFor("self-tamper", 10*time.Second, fileEvent("/etc/statetrack/agent.yaml", pb.Action_ACTION_MODIFIED))
		if ev.Category != pb.Category_CATEGORY_AGENT_HEALTH || ev.Level != pb.ImpactLevel_IMPACT_LEVEL_1_CRITICAL {
			t.Fatalf("self-tamper: %v %v", ev.Level, ev.Category)
		}
		deadline := time.Now().Add(10 * time.Second)
		for !e.agent.Classifier.ForensicActive(time.Now()) {
			if time.Now().After(deadline) {
				t.Fatal("forensic_until was not hot-reloaded")
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !e.agent.Classifier.Blacklisted("/etc/e2e-noisy/state.json") {
			t.Fatal("exclude rule was not hot-reloaded")
		}
		writeFile(t, "/etc/e2e-noisy/state.json", "{}\n", 0o644)
		writeFile(t, "/etc/e2e-marker.conf", "marker = 1\n", 0o644)
		e.waitFor("marker", 10*time.Second, fileEvent("/etc/e2e-marker.conf", pb.Action_ACTION_CREATED))
		for _, ev := range e.events() {
			if strings.HasPrefix(ev.GetTarget().GetPathOrKey(), "/etc/e2e-noisy/") {
				t.Fatalf("excluded path reported: %s", ev.Summary)
			}
		}
	})

	t.Run("clean_shutdown_and_restart_reconciles_offline_changes", func(t *testing.T) {
		e.t = t
		e.stop()
		// Changed while the agent is down.
		writeFile(t, "/etc/nginx/sites-enabled/default", "server {\n    listen 9090;\n}\n", 0o644)
		os.Remove("/etc/e2e-marker.conf")

		lf, _ := os.OpenFile(e.logFile, os.O_APPEND|os.O_WRONLY, 0o644)
		defer lf.Close()
		ctx, cancel := context.WithCancel(context.Background())
		e.cancel, e.done = cancel, make(chan error, 1)
		ready := make(chan *Agent, 1)
		go func() {
			e.done <- Run(ctx, Options{Logger: slog.New(slog.NewJSONHandler(io.MultiWriter(lf), nil)),
				TickInterval: 200 * time.Millisecond, Ready: func(a *Agent) { ready <- a }})
		}()
		select {
		case e.agent = <-ready:
		case err := <-e.done:
			t.Fatalf("restart failed: %v", err)
		case <-time.After(60 * time.Second):
			t.Fatal("restart timed out")
		}
		ev := e.waitFor("offline modification", 10*time.Second, func(ev *pb.MutationEvent) bool {
			return ev.Target.GetPathOrKey() == "/etc/nginx/sites-enabled/default" && ev.Metadata["attribution"] == "offline"
		})
		if d := unzipDiff(t, ev); !strings.Contains(d, "+    listen 9090;") || !strings.Contains(d, "-    listen 8080;") {
			t.Fatalf("offline diff:\n%s", d)
		}
		e.waitFor("offline deletion", 10*time.Second, fileEvent("/etc/e2e-marker.conf", pb.Action_ACTION_DELETED))
	})
}
