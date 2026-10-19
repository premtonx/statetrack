package linux

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// PackageChange is one package install/upgrade/removal.
type PackageChange struct {
	Manager string // dpkg, dnf, yum, apk
	Name    string
	Arch    string
	Op      string // install, upgrade, downgrade, reinstall, remove, purge
	Before  string // version before ("" when newly installed)
	After   string // version after ("" when removed)
	At      time.Time
	Source  string // log or database the change was read from
	Command string // invoking command line, when the log records it (apk)
}

// Action maps the operation onto the event schema.
func (c PackageChange) Action() pb.Action {
	switch c.Op {
	case "install":
		return pb.Action_ACTION_CREATED
	case "remove", "purge":
		return pb.Action_ACTION_DELETED
	case "reinstall":
		return pb.Action_ACTION_MODIFIED
	}
	return pb.Action_ACTION_UPGRADED
}

// Summary renders a one-line description.
func (c PackageChange) Summary() string {
	verb := map[string]string{"install": "Installed", "upgrade": "Upgraded", "downgrade": "Downgraded",
		"reinstall": "Reinstalled", "remove": "Removed", "purge": "Purged"}[c.Op]
	switch {
	case c.Before != "" && c.After != "" && c.Before != c.After:
		return verb + " " + c.Name + " " + c.Before + " -> " + c.After
	case c.After != "":
		return verb + " " + c.Name + " " + c.After
	case c.Before != "":
		return verb + " " + c.Name + " " + c.Before
	}
	return verb + " " + c.Name
}

// Metadata returns event metadata.
func (c PackageChange) Metadata() map[string]string {
	md := map[string]string{"event_type": "PACKAGE_" + strings.ToUpper(c.Op), "package_action": c.Op,
		"package_manager": c.Manager, "source": c.Source}
	if c.Arch != "" {
		md["arch"] = c.Arch
	}
	if c.Command != "" {
		md["command"] = c.Command
	}
	return md
}

// Target returns the event target.
func (c PackageChange) Target() *pb.TargetResource {
	return &pb.TargetResource{TargetType: "package", PathOrKey: c.Name, VersionBefore: c.Before, VersionAfter: c.After}
}

// ParseDpkgLine parses one /var/log/dpkg.log line, e.g.
// "2026-10-13 21:21:56 upgrade nginx:amd64 1.24.0-1 1.26.1-1".
func ParseDpkgLine(line string, loc *time.Location) (PackageChange, bool) {
	f := strings.Fields(line)
	if len(f) < 6 {
		return PackageChange{}, false
	}
	switch f[2] {
	case "install", "upgrade", "remove", "purge":
	default:
		return PackageChange{}, false
	}
	at, err := time.ParseInLocation("2006-01-02 15:04:05", f[0]+" "+f[1], loc)
	if err != nil {
		return PackageChange{}, false
	}
	name, arch, _ := strings.Cut(f[3], ":")
	none := func(v string) string {
		if v == "<none>" {
			return ""
		}
		return v
	}
	c := PackageChange{Manager: "dpkg", Name: name, Arch: arch, Op: f[2], Before: none(f[4]), After: none(f[5]), At: at}
	if c.Op == "install" && c.Before != "" {
		// Reinstalling over a removed-but-configured package.
		c.Op = "upgrade"
	}
	return c, true
}

var rpmArches = map[string]bool{"x86_64": true, "noarch": true, "i686": true, "i386": true, "aarch64": true,
	"ppc64le": true, "s390x": true, "armv7hl": true, "src": true, "riscv64": true}

// ParseNEVRA splits an RPM name-[epoch:]version-release.arch string, also
// accepting yum's epoch:name-version-release.arch form.
func ParseNEVRA(s string) (name, version, arch string) {
	epoch := ""
	if i := strings.IndexByte(s, ':'); i > 0 && !strings.Contains(s[:i], "-") {
		epoch, s = s[:i], s[i+1:]
	}
	if i := strings.LastIndexByte(s, '.'); i > 0 && rpmArches[s[i+1:]] {
		s, arch = s[:i], s[i+1:]
	}
	rel := strings.LastIndexByte(s, '-')
	if rel <= 0 {
		return s, "", arch
	}
	ver := strings.LastIndexByte(s[:rel], '-')
	if ver <= 0 {
		return s, "", arch
	}
	name, version = s[:ver], s[ver+1:]
	if epoch != "" && epoch != "0" && !strings.Contains(version, ":") {
		version = epoch + ":" + version
	}
	return name, version, arch
}

// DnfParser parses dnf4's /var/log/dnf.rpm.log. Upgrades are logged as
// "Upgrade: <new>" followed later by "Upgraded: <old>", so the new version
// is held until its counterpart arrives.
type DnfParser struct {
	pending map[string]PackageChange
}

// Line parses one log line.
func (p *DnfParser) Line(line string) []PackageChange {
	f := strings.Fields(line)
	if len(f) < 4 || !strings.HasSuffix(f[2], ":") {
		return nil
	}
	at, err := time.Parse("2006-01-02T15:04:05-0700", f[0])
	if err != nil {
		if at, err = time.Parse(time.RFC3339, f[0]); err != nil {
			return nil
		}
	}
	name, version, arch := ParseNEVRA(f[3])
	key := name + "." + arch
	c := PackageChange{Manager: "dnf", Name: name, Arch: arch, At: at}
	if p.pending == nil {
		p.pending = make(map[string]PackageChange)
	}
	switch strings.TrimSuffix(f[2], ":") {
	case "Installed", "Install":
		c.Op, c.After = "install", version
	case "Erase", "Erased":
		c.Op, c.Before = "remove", version
	case "Reinstall":
		c.Op, c.Before, c.After = "reinstall", version, version
	case "Upgrade", "Downgrade":
		c.Op, c.After = strings.ToLower(strings.TrimSuffix(f[2], ":")), version
		p.pending[key] = c
		return nil
	case "Upgraded", "Downgraded":
		held, ok := p.pending[key]
		if !ok {
			return nil
		}
		delete(p.pending, key)
		held.Before = version
		return []PackageChange{held}
	default:
		return nil
	}
	return []PackageChange{c}
}

// Flush releases upgrades whose counterpart line never arrived within
// maxAge.
func (p *DnfParser) Flush(now time.Time, maxAge time.Duration) []PackageChange {
	var out []PackageChange
	for k, c := range p.pending {
		if now.Sub(c.At) >= maxAge {
			out = append(out, c)
			delete(p.pending, k)
		}
	}
	return out
}

// ParseYumLine parses one /var/log/yum.log line, e.g.
// "Oct 13 21:21:56 Updated: 1:nginx-1.20.1-10.el7.x86_64". yum omits the
// year; ref supplies it.
func ParseYumLine(line string, ref time.Time) (PackageChange, bool) {
	f := strings.Fields(line)
	if len(f) < 5 {
		return PackageChange{}, false
	}
	at, err := time.ParseInLocation("Jan 2 15:04:05 2006", strings.Join(f[:3], " ")+" "+ref.Format("2006"), ref.Location())
	if err != nil {
		return PackageChange{}, false
	}
	if at.After(ref.Add(24 * time.Hour)) {
		at = at.AddDate(-1, 0, 0)
	}
	name, version, arch := ParseNEVRA(f[4])
	c := PackageChange{Manager: "yum", Name: name, Arch: arch, At: at}
	switch f[3] {
	case "Installed:":
		c.Op, c.After = "install", version
	case "Updated:":
		c.Op, c.After = "upgrade", version
	case "Erased:":
		c.Op, c.Before = "remove", version
	default:
		return PackageChange{}, false
	}
	return c, true
}

// ParseApkInstalled parses /lib/apk/db/installed into name -> version
// (and arch).
func ParseApkInstalled(data []byte) map[string][2]string {
	m := make(map[string][2]string)
	var name, ver, arch string
	flush := func() {
		if name != "" {
			m[name] = [2]string{ver, arch}
		}
		name, ver, arch = "", "", ""
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		switch line[0] {
		case 'P':
			name = string(line[2:])
		case 'V':
			ver = string(line[2:])
		case 'A':
			arch = string(line[2:])
		}
	}
	flush()
	return m
}

// DiffApk compares two installed-database snapshots.
func DiffApk(before, after map[string][2]string, at time.Time) []PackageChange {
	var out []PackageChange
	for n, a := range after {
		b, had := before[n]
		switch {
		case !had:
			out = append(out, PackageChange{Manager: "apk", Name: n, Arch: a[1], Op: "install", After: a[0], At: at})
		case b[0] != a[0]:
			out = append(out, PackageChange{Manager: "apk", Name: n, Arch: a[1], Op: "upgrade", Before: b[0], After: a[0], At: at})
		}
	}
	for n, b := range before {
		if _, ok := after[n]; !ok {
			out = append(out, PackageChange{Manager: "apk", Name: n, Arch: b[1], Op: "remove", Before: b[0], At: at})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ParseApkLogCommand extracts the command from an apk.log line such as
// "Running `apk add -q tree` at 2026-10-13 21:21:56".
func ParseApkLogCommand(line string) (string, bool) {
	if !strings.HasPrefix(line, "Running `") {
		return "", false
	}
	rest := line[len("Running `"):]
	end := strings.IndexByte(rest, '`')
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}

// Tailer follows a log file from its end at startup (or from the start if
// it appears later), surviving rotation and truncation.
type Tailer struct {
	Path string

	f       *os.File
	offset  int64
	partial []byte
	started bool
}

// Poll returns the complete lines appended since the last call.
func (t *Tailer) Poll() ([]string, error) {
	if !t.started {
		t.started = true
		if f, err := os.Open(t.Path); err == nil {
			end, _ := f.Seek(0, io.SeekEnd)
			t.f, t.offset = f, end
		}
		return nil, nil
	}
	var lines []string
	if t.f != nil {
		// Drain the open handle first: after a rename-rotation it still
		// refers to the old file and holds its last lines.
		lines = t.read(lines)
	}
	fi, err := os.Stat(t.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return lines, nil
	}
	if err != nil {
		return lines, err
	}
	if t.f != nil {
		cur, _ := t.f.Stat()
		switch {
		case cur != nil && !os.SameFile(cur, fi):
			t.f.Close()
			t.f = nil
		case fi.Size() < t.offset:
			// Truncated in place (copytruncate).
			t.offset, t.partial = 0, nil
			t.f.Seek(0, io.SeekStart)
		}
	}
	if t.f == nil {
		f, err := os.Open(t.Path)
		if err != nil {
			return lines, err
		}
		t.f, t.offset, t.partial = f, 0, nil
	}
	return t.read(lines), nil
}

func (t *Tailer) read(lines []string) []string {
	buf := make([]byte, 64<<10)
	for {
		n, err := t.f.ReadAt(buf, t.offset)
		if n > 0 {
			t.offset += int64(n)
			data := append(t.partial, buf[:n]...)
			for {
				i := bytes.IndexByte(data, '\n')
				if i < 0 {
					break
				}
				lines = append(lines, strings.TrimRight(string(data[:i]), "\r"))
				data = data[i+1:]
			}
			if len(data) > 64<<10 {
				data = nil // unterminated garbage; drop it
			}
			t.partial = append([]byte(nil), data...)
		}
		if err != nil || n < len(buf) {
			return lines
		}
	}
}

// Close releases the file handle.
func (t *Tailer) Close() {
	if t.f != nil {
		t.f.Close()
		t.f = nil
	}
}

// PackagesOptions configures the package collector. Empty paths disable a
// source.
type PackagesOptions struct {
	DpkgLog, DnfLog, YumLog, ApkLog, ApkDB string
	Interval                               time.Duration
	Emit                                   func(context.Context, PackageChange)
	Logger                                 *slog.Logger
	Now                                    func() time.Time
}

// Packages follows package manager logs (and the apk database).
type Packages struct {
	o   PackagesOptions
	log *slog.Logger

	dpkg, dnf, yum, apkLog *Tailer
	dnfParser              DnfParser
	apkDB                  map[string][2]string
	apkStat                fs.FileInfo
	apkCmd                 string
	apkCmdAt               time.Time
}

// NewPackages creates the collector.
func NewPackages(o PackagesOptions) *Packages {
	if o.Interval <= 0 {
		o.Interval = 500 * time.Millisecond
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	p := &Packages{o: o, log: o.Logger.With("collector", "packages")}
	mk := func(path string) *Tailer {
		if path == "" {
			return nil
		}
		return &Tailer{Path: path}
	}
	p.dpkg, p.dnf, p.yum, p.apkLog = mk(o.DpkgLog), mk(o.DnfLog), mk(o.YumLog), mk(o.ApkLog)
	return p
}

// Run polls until ctx is done.
func (p *Packages) Run(ctx context.Context) error {
	defer p.Close()
	p.Poll(ctx)
	p.log.Info("package collector started", "dpkg", p.o.DpkgLog, "dnf", p.o.DnfLog, "yum", p.o.YumLog,
		"apk_db", p.o.ApkDB, "apk_packages", len(p.apkDB))
	t := time.NewTicker(p.o.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			p.Poll(ctx)
		}
	}
}

// Close releases the log file handles.
func (p *Packages) Close() {
	for _, t := range []*Tailer{p.dpkg, p.dnf, p.yum, p.apkLog} {
		if t != nil {
			t.Close()
		}
	}
}

// Poll performs one collection pass.
func (p *Packages) Poll(ctx context.Context) {
	now := p.o.Now()
	emit := func(c PackageChange, source string) {
		c.Source = source
		p.o.Emit(ctx, c)
	}
	for _, line := range p.lines(p.dpkg) {
		if c, ok := ParseDpkgLine(line, time.Local); ok {
			emit(c, p.o.DpkgLog)
		}
	}
	for _, line := range p.lines(p.dnf) {
		for _, c := range p.dnfParser.Line(line) {
			emit(c, p.o.DnfLog)
		}
	}
	for _, c := range p.dnfParser.Flush(now, 30*time.Second) {
		emit(c, p.o.DnfLog)
	}
	for _, line := range p.lines(p.yum) {
		if c, ok := ParseYumLine(line, now); ok {
			emit(c, p.o.YumLog)
		}
	}
	for _, line := range p.lines(p.apkLog) {
		if cmd, ok := ParseApkLogCommand(line); ok {
			p.apkCmd, p.apkCmdAt = cmd, now
		}
	}
	p.pollApkDB(now, func(c PackageChange) {
		if p.apkCmd != "" && now.Sub(p.apkCmdAt) < time.Minute {
			c.Command = p.apkCmd
		}
		emit(c, p.o.ApkDB)
	})
}

func (p *Packages) lines(t *Tailer) []string {
	if t == nil {
		return nil
	}
	lines, err := t.Poll()
	if err != nil {
		p.log.Debug("tail failed", "path", t.Path, "err", err)
	}
	return lines
}

func (p *Packages) pollApkDB(now time.Time, emit func(PackageChange)) {
	if p.o.ApkDB == "" {
		return
	}
	fi, err := os.Stat(p.o.ApkDB)
	if err != nil {
		return
	}
	if p.apkStat != nil && fi.ModTime().Equal(p.apkStat.ModTime()) && fi.Size() == p.apkStat.Size() {
		return
	}
	data, err := os.ReadFile(p.o.ApkDB)
	if err != nil {
		return
	}
	cur := ParseApkInstalled(data)
	if p.apkDB != nil {
		for _, c := range DiffApk(p.apkDB, cur, now) {
			emit(c)
		}
	}
	p.apkDB, p.apkStat = cur, fi
}
