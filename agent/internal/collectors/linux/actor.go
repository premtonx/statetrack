// Package linux contains the Linux collectors: process attribution (this
// file), filesystem (fs), systemd services and package managers.
//
// Attribution sources, best first:
//   - Audit netlink multicast (AUDIT_SYSCALL/EXECVE/PATH/CWD records): PID,
//     PPID, UID, loginuid and exe captured by the kernel at syscall time.
//   - Proc connector (PROC_EVENT_EXEC): snapshots /proc/<pid> the moment a
//     process execs, before short-lived tools like sed, mv or cp exit.
//   - fanotify FAN_CLOSE_WRITE: the exact writer PID of each file.
//   - Unprivileged fallback: on the first sign of activity in a directory
//     (e.g. sed's temp file, vim's 4913 probe), /proc is scanned for
//     processes whose arguments reference that directory, which are then
//     snapshotted while still alive.
//
// All sources feed one Resolver: a thread-safe PID -> process cache with a
// TTL that outlives the processes themselves.
package linux

import (
	"bufio"
	"bytes"
	"net/netip"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/statetrack/statetrack/agent/internal/limiter"
	pb "github.com/statetrack/statetrack/pkg/pb/statetrackv1"
)

// NoLoginUID is the kernel's "unset" audit login UID ((uid_t)-1).
const NoLoginUID = 4294967295

const (
	DefaultCacheTTL     = 30 * time.Second
	DefaultScanInterval = 200 * time.Millisecond
	// writerNoteTTL bounds how long a fanotify/audit write observation is
	// used to attribute later path events.
	writerNoteTTL = 5 * time.Second
	maxDepth      = 64
	maxCmdline    = 4096
	maxEnviron    = 256 << 10
)

// Process attribution methods reported in event metadata.
const (
	AttrWriter  = "writer"     // fanotify/audit saw this PID write the path
	AttrCmdline = "cmdline"    // process arguments reference the path
	AttrTool    = "tool"       // a known tool for this file (useradd, visudo, ...)
	AttrDir     = "dir_writer" // PID recently wrote in the same directory
	AttrUnknown = "unattributed"
)

// ProcInfo is a snapshot of one process.
type ProcInfo struct {
	PID, PPID uint32
	UID       uint32 // effective UID
	LoginUID  uint32 // NoLoginUID when unset
	Name      string // kernel comm (15 chars max)
	Exe       string
	Args      []string
	Cwd       string
	StartTime uint64 // clock ticks after boot; detects PID reuse
	RemoteIP  string // from SSH_CONNECTION/SSH_CLIENT in this process's environ
	Source    string // proc, audit, connector

	seen time.Time
}

// Cmdline returns the arguments joined by spaces.
func (p *ProcInfo) Cmdline() string { return strings.Join(p.Args, " ") }

// ResolverOptions configures a Resolver.
type ResolverOptions struct {
	ProcRoot     string // default /proc
	PasswdPath   string // default /etc/passwd
	TTL          time.Duration
	ScanInterval time.Duration
	Now          func() time.Time
	// Scrub redacts secrets from command lines before they leave the agent.
	Scrub func(string) string
	// SelfPID is excluded from attribution (default os.Getpid()).
	SelfPID uint32
}

// Resolver attributes file changes to processes. It is safe for concurrent
// use.
type Resolver struct {
	o     ResolverOptions
	users *UserDB

	mu       sync.Mutex
	cache    map[uint32]*ProcInfo
	notes    map[string]writerNote // exact path or "dir:" + directory
	lastScan time.Time
}

type writerNote struct {
	pid uint32
	at  time.Time
}

// NewResolver creates a Resolver.
func NewResolver(o ResolverOptions) *Resolver {
	if o.ProcRoot == "" {
		o.ProcRoot = "/proc"
	}
	if o.PasswdPath == "" {
		o.PasswdPath = "/etc/passwd"
	}
	if o.TTL <= 0 {
		o.TTL = DefaultCacheTTL
	}
	if o.ScanInterval <= 0 {
		o.ScanInterval = DefaultScanInterval
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.SelfPID == 0 {
		o.SelfPID = uint32(os.Getpid())
	}
	return &Resolver{o: o, users: NewUserDB(o.PasswdPath), cache: make(map[uint32]*ProcInfo),
		notes: make(map[string]writerNote)}
}

// Users returns the resolver's passwd cache.
func (r *Resolver) Users() *UserDB { return r.users }

// Remember snapshots pid and its ancestors now. Call it as early as
// possible (on exec, on a fanotify event) so the process is known after it
// exits.
func (r *Resolver) Remember(pid uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.chainLocked(pid)
}

// RememberInfo merges externally captured process facts (audit records)
// into the cache, then snapshots whatever /proc still has.
func (r *Resolver) RememberInfo(p ProcInfo) {
	if p.PID == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.o.Now()
	live := r.readProc(p.PID)
	cur := r.cache[p.PID]
	switch {
	case live != nil && (cur == nil || cur.StartTime != live.StartTime):
		cur = live
	case cur == nil:
		c := p
		cur = &c
	}
	// Syscall-time kernel facts win over later /proc reads.
	if p.PPID != 0 {
		cur.PPID = p.PPID
	}
	if p.Source != "" {
		cur.UID, cur.LoginUID, cur.Source = p.UID, p.LoginUID, p.Source
	}
	if p.Exe != "" {
		cur.Exe = p.Exe
	}
	if p.Name != "" && cur.Name == "" {
		cur.Name = p.Name
	}
	if len(p.Args) > 0 {
		cur.Args = p.Args
	}
	if p.Cwd != "" {
		cur.Cwd = p.Cwd
	}
	cur.seen = now
	r.cache[p.PID] = cur
	if cur.PPID > 1 {
		r.chainLocked(cur.PPID)
	}
}

// NoteWriter records that pid wrote path (from fanotify or audit).
func (r *Resolver) NoteWriter(p string, pid uint32) {
	if pid == 0 || pid == r.o.SelfPID {
		return
	}
	now := r.o.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notes[p] = writerNote{pid, now}
	r.notes["dir:"+path.Dir(p)] = writerNote{pid, now}
	if len(r.chainLocked(pid)) == 0 {
		// Reaped before it could be read: fall back to the processes
		// (e.g. a still-running "sh -c '... > path'") that reference dir.
		r.scanLocked(now, path.Dir(p))
	}
}

// Activity signals that something changed in dir. Unless a scan ran within
// the scan interval, /proc is scanned for processes that reference dir in
// their arguments (or are known writers of files there) and they are
// snapshotted while still alive.
func (r *Resolver) Activity(dir string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanLocked(r.o.Now(), dir)
}

func (r *Resolver) scanLocked(now time.Time, dir string) {
	if now.Sub(r.lastScan) < r.o.ScanInterval {
		return
	}
	r.lastScan = now
	entries, err := os.ReadDir(r.o.ProcRoot)
	if err != nil {
		return
	}
	for _, e := range entries {
		n, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil || uint32(n) == r.o.SelfPID {
			continue
		}
		pid := uint32(n)
		base := path.Join(r.o.ProcRoot, e.Name())
		args := readArgs(path.Join(base, "cmdline"))
		if len(args) == 0 {
			continue
		}
		comm := ""
		if b, err := os.ReadFile(path.Join(base, "comm")); err == nil {
			comm = strings.TrimSpace(string(b))
		}
		cwd, _ := os.Readlink(path.Join(base, "cwd"))
		if !argsTouchDir(args, cwd, dir) && !isKnownWriter(comm) {
			continue
		}
		if c := r.cache[pid]; c != nil && c.Cmdline() == strings.Join(args, " ") {
			c.seen = now
			continue
		}
		r.chainLocked(pid)
	}
}

// Attribute picks the process most likely responsible for a change to p.
func (r *Resolver) Attribute(p string) (pid uint32, method string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.o.Now()
	if n, ok := r.notes[p]; ok && now.Sub(n.at) <= writerNoteTTL && r.knownLocked(n.pid) {
		return n.pid, AttrWriter
	}
	var best *ProcInfo
	bestMethod := ""
	for _, c := range r.cache {
		if c.PID == r.o.SelfPID || now.Sub(c.seen) > r.o.TTL {
			continue
		}
		m := ""
		switch {
		case argsReference(c.Args, c.Cwd, p):
			m = AttrCmdline
		case toolWrites(c.Name, p):
			m = AttrTool
		default:
			continue
		}
		if best == nil || r.preferLocked(c, best) {
			best, bestMethod = c, m
		}
	}
	if best != nil {
		return best.PID, bestMethod
	}
	if n, ok := r.notes["dir:"+path.Dir(p)]; ok && now.Sub(n.at) <= writerNoteTTL && r.knownLocked(n.pid) {
		return n.pid, AttrDir
	}
	return 0, AttrUnknown
}

// knownLocked reports whether pid can still be resolved (cached or alive);
// a writer reaped before it could be snapshotted is useless.
func (r *Resolver) knownLocked(pid uint32) bool {
	if _, ok := r.cache[pid]; ok {
		return true
	}
	_, alive := r.startTime(pid)
	return alive
}

// preferLocked reports whether candidate c is a better match than best: a
// descendant beats its ancestor (vim over the sudo that runs it), then the
// later start wins. Start times tick at 10 ms, so PIDs break ties.
func (r *Resolver) preferLocked(c, best *ProcInfo) bool {
	switch {
	case r.descendsLocked(c, best.PID):
		return true
	case r.descendsLocked(best, c.PID):
		return false
	case c.StartTime != best.StartTime:
		return c.StartTime > best.StartTime
	}
	return c.PID > best.PID
}

func (r *Resolver) descendsLocked(p *ProcInfo, ancestor uint32) bool {
	for i := 0; i < maxDepth && p != nil && p.PPID > 1; i++ {
		if p.PPID == ancestor {
			return true
		}
		p = r.cache[p.PPID]
	}
	return false
}

// Actor builds the actor context and ancestry (acting process first, up to
// but excluding init) for pid. It returns nil, nil when pid is unknown.
func (r *Resolver) Actor(pid uint32) (*pb.ActorContext, []limiter.Process) {
	if pid == 0 {
		return nil, nil
	}
	r.mu.Lock()
	chain := r.chainLocked(pid)
	remoteIP := ""
	for _, p := range chain {
		if remoteIP == "" && p.RemoteIP != "" {
			remoteIP = p.RemoteIP
		}
	}
	r.mu.Unlock()
	if len(chain) == 0 {
		return nil, nil
	}

	leaf := chain[0]
	ancestry := make([]limiter.Process, 0, len(chain))
	lineage := make([]string, 0, len(chain))
	for i := len(chain) - 1; i >= 0; i-- {
		if n := len(lineage); n == 0 || lineage[n-1] != chain[i].Name {
			lineage = append(lineage, chain[i].Name)
		}
	}
	for _, p := range chain {
		ancestry = append(ancestry, limiter.Process{PID: p.PID, Name: p.Name, Cmdline: p.Cmdline()})
	}
	cmd := leaf.Cmdline()
	if len(cmd) > maxCmdline {
		cmd = cmd[:maxCmdline]
	}
	if r.o.Scrub != nil {
		cmd = r.o.Scrub(cmd)
	}
	a := &pb.ActorContext{
		Username:       r.users.Name(leaf.UID),
		UidOrSid:       strconv.FormatUint(uint64(leaf.UID), 10),
		Pid:            leaf.PID,
		Ppid:           leaf.PPID,
		ProcessName:    leaf.Name,
		Cmdline:        cmd,
		ProcessLineage: lineage,
		RemoteIp:       remoteIP,
	}
	// loginuid is inherited across fork; a writer that exited before its
	// loginuid could be read shares its session ancestors' value.
	login := uint32(NoLoginUID)
	for _, p := range chain {
		if p.LoginUID != NoLoginUID {
			login = p.LoginUID
			break
		}
	}
	if login != NoLoginUID {
		a.LoginUid = strconv.FormatUint(uint64(login), 10)
		a.LoginUsername = r.users.Name(login)
	}
	return a, ancestry
}

// Exited marks pid as gone (proc connector EXIT); it stays cached for the
// TTL so late events can still be attributed.
func (r *Resolver) Exited(pid uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c := r.cache[pid]; c != nil {
		c.seen = r.o.Now()
	}
}

// Sweep evicts cache entries and writer notes past their TTL.
func (r *Resolver) Sweep() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.o.Now()
	for pid, c := range r.cache {
		if now.Sub(c.seen) > r.o.TTL {
			delete(r.cache, pid)
		}
	}
	for k, n := range r.notes {
		if now.Sub(n.at) > writerNoteTTL {
			delete(r.notes, k)
		}
	}
}

// Len returns the number of cached processes.
func (r *Resolver) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.cache)
}

// chainLocked returns pid's cached-or-live snapshot followed by its
// ancestors, stopping before PID 1 (and kthreadd).
func (r *Resolver) chainLocked(pid uint32) []*ProcInfo {
	var chain []*ProcInfo
	seen := map[uint32]bool{}
	for p := pid; p > 2 && !seen[p] && len(chain) < maxDepth; {
		seen[p] = true
		info := r.lookupLocked(p)
		if info == nil {
			break
		}
		chain = append(chain, info)
		p = info.PPID
	}
	return chain
}

func (r *Resolver) lookupLocked(pid uint32) *ProcInfo {
	now := r.o.Now()
	cur := r.cache[pid]
	if st, alive := r.startTime(pid); alive {
		if cur == nil || cur.StartTime != st {
			// New process, or the PID was reused since it was cached.
			cur = r.readProc(pid)
		}
	} else if cur != nil && now.Sub(cur.seen) > r.o.TTL {
		cur = nil
	}
	if cur == nil {
		delete(r.cache, pid)
		return nil
	}
	cur.seen = now
	r.cache[pid] = cur
	return cur
}

func (r *Resolver) startTime(pid uint32) (uint64, bool) {
	b, err := os.ReadFile(path.Join(r.o.ProcRoot, strconv.FormatUint(uint64(pid), 10), "stat"))
	if err != nil {
		return 0, false
	}
	_, _, st, ok := parseStat(b)
	return st, ok
}

// readProc snapshots /proc/<pid>; nil if the process is gone.
func (r *Resolver) readProc(pid uint32) *ProcInfo {
	base := path.Join(r.o.ProcRoot, strconv.FormatUint(uint64(pid), 10))
	stat, err := os.ReadFile(path.Join(base, "stat"))
	if err != nil {
		return nil
	}
	comm, ppid, st, ok := parseStat(stat)
	if !ok {
		return nil
	}
	p := &ProcInfo{PID: pid, PPID: ppid, Name: comm, StartTime: st, LoginUID: NoLoginUID, Source: "proc"}
	if b, err := os.ReadFile(path.Join(base, "status")); err == nil {
		parseStatus(b, p)
	}
	if b, err := os.ReadFile(path.Join(base, "loginuid")); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32); err == nil {
			p.LoginUID = uint32(v)
		}
	}
	p.Args = readArgs(path.Join(base, "cmdline"))
	p.Exe, _ = os.Readlink(path.Join(base, "exe"))
	p.Cwd, _ = os.Readlink(path.Join(base, "cwd"))
	// Read now: the session's shells may be gone by the time the change
	// is attributed.
	p.RemoteIP = r.readRemoteIP(p)
	return p
}

func (r *Resolver) readRemoteIP(p *ProcInfo) string {
	f, err := os.Open(path.Join(r.o.ProcRoot, strconv.FormatUint(uint64(p.PID), 10), "environ"))
	if err != nil {
		return ""
	}
	defer f.Close()
	b := make([]byte, maxEnviron)
	n, _ := f.Read(b)
	return RemoteIPFromEnviron(b[:n])
}

// RemoteIPFromEnviron extracts the SSH client address from a NUL-separated
// environment block.
func RemoteIPFromEnviron(env []byte) string {
	var conn, client string
	for _, kv := range bytes.Split(env, []byte{0}) {
		switch {
		case bytes.HasPrefix(kv, []byte("SSH_CONNECTION=")):
			conn = string(kv[len("SSH_CONNECTION="):])
		case bytes.HasPrefix(kv, []byte("SSH_CLIENT=")):
			client = string(kv[len("SSH_CLIENT="):])
		}
	}
	for _, v := range []string{conn, client} {
		if f := strings.Fields(v); len(f) > 0 {
			if a, err := netip.ParseAddr(f[0]); err == nil {
				return a.Unmap().String()
			}
		}
	}
	return ""
}

// parseStat extracts comm, ppid and starttime from /proc/<pid>/stat. comm
// may contain spaces and parentheses, so it is delimited by the last ')'.
func parseStat(b []byte) (comm string, ppid uint32, start uint64, ok bool) {
	open, end := bytes.IndexByte(b, '('), bytes.LastIndexByte(b, ')')
	if open < 0 || end < open {
		return "", 0, 0, false
	}
	comm = string(b[open+1 : end])
	f := strings.Fields(string(b[end+1:]))
	// f[0] is field 3 (state); ppid is field 4, starttime field 22.
	if len(f) < 20 {
		return "", 0, 0, false
	}
	pp, err1 := strconv.ParseUint(f[1], 10, 32)
	st, err2 := strconv.ParseUint(f[19], 10, 64)
	if err1 != nil || err2 != nil {
		return "", 0, 0, false
	}
	return comm, uint32(pp), st, true
}

func parseStatus(b []byte, p *ProcInfo) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Name":
			p.Name = v
		case "PPid":
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				p.PPID = uint32(n)
			}
		case "Uid":
			// real, effective, saved, filesystem
			if f := strings.Fields(v); len(f) >= 2 {
				if n, err := strconv.ParseUint(f[1], 10, 32); err == nil {
					p.UID = uint32(n)
				}
			}
		}
	}
}

func readArgs(p string) []string {
	b, err := os.ReadFile(p)
	if err != nil || len(b) == 0 {
		return nil
	}
	if len(b) > maxCmdline {
		b = b[:maxCmdline]
	}
	b = bytes.TrimRight(b, "\x00")
	parts := bytes.Split(b, []byte{0})
	args := make([]string, len(parts))
	for i, a := range parts {
		args[i] = string(a)
	}
	return args
}

// argPaths yields the absolute paths an argument list may refer to.
// Arguments holding shell code (sh -c '... | tee /etc/x') are tokenized
// and their absolute paths considered too.
func argPaths(args []string, cwd string, fn func(string) bool) bool {
	for i, a := range args {
		if i == 0 || a == "" {
			continue
		}
		if strings.ContainsAny(a, " \t\n;|&><") {
			if strings.HasPrefix(a, "/") && fn(path.Clean(a)) {
				return true
			}
			for _, tok := range strings.FieldsFunc(a, isShellDelim) {
				if strings.HasPrefix(tok, "/") && len(tok) > 1 && fn(path.Clean(tok)) {
					return true
				}
			}
			continue
		}
		if _, v, ok := strings.Cut(a, "="); ok && strings.HasPrefix(a, "-") {
			a = v
		}
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		if !strings.HasPrefix(a, "/") {
			if cwd == "" {
				continue
			}
			a = path.Join(cwd, a)
		}
		if fn(path.Clean(a)) {
			return true
		}
	}
	return false
}

func isShellDelim(r rune) bool {
	switch r {
	case ' ', '\t', '\n', ';', '|', '&', '>', '<', '\'', '"', '(', ')', '`':
		return true
	}
	return false
}

// argsReference reports whether an argument names p or a directory
// containing it (cp -r src /etc/app).
func argsReference(args []string, cwd, p string) bool {
	return argPaths(args, cwd, func(a string) bool {
		return a == p || (a != "/" && strings.HasPrefix(p, a+"/"))
	})
}

// argsTouchDir reports whether an argument lies in dir or names an
// ancestor directory of it.
func argsTouchDir(args []string, cwd, dir string) bool {
	return argPaths(args, cwd, func(a string) bool {
		return a == dir || path.Dir(a) == dir || (a != "/" && strings.HasPrefix(dir, a+"/"))
	})
}

// knownWriters maps tools that rewrite files without naming them on the
// command line to the files they write.
var knownWriters = []struct {
	tools []string
	files *limiter.Matcher
}{
	{[]string{"useradd", "usermod", "userdel", "groupadd", "groupmod", "groupdel", "adduser", "deluser",
		"addgroup", "delgroup", "passwd", "chpasswd", "chsh", "chfn", "chage", "gpasswd", "newusers",
		"vipw", "vigr", "pwconv", "grpconv"},
		limiter.MustMatcher("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/subuid", "/etc/subgid",
			"/home/*/.ssh/**", "/etc/skel/**")},
	{[]string{"visudo"}, limiter.MustMatcher("/etc/sudoers", "/etc/sudoers.d/**")},
	{[]string{"crontab"}, limiter.MustMatcher("/var/spool/cron/**")},
	{[]string{"ssh-keygen", "ssh-copy-id"}, limiter.MustMatcher("**/.ssh/**", "/etc/ssh/**")},
	{[]string{"hostnamectl"}, limiter.MustMatcher("/etc/hostname", "/etc/machine-info")},
	{[]string{"timedatectl"}, limiter.MustMatcher("/etc/localtime", "/etc/timezone")},
	{[]string{"systemctl"}, limiter.MustMatcher("/etc/systemd/**")},
	{[]string{"update-alternatives"}, limiter.MustMatcher("/etc/alternatives/**")},
	// Package managers write files named only inside their packages.
	{[]string{"dpkg", "apt", "apt-get", "aptitude", "unattended-upgr", "rpm", "dnf", "yum", "zypper", "apk"},
		limiter.MustMatcher("/**")},
}

func toolWrites(name, p string) bool {
	for _, w := range knownWriters {
		for _, t := range w.tools {
			if t == name {
				return w.files.Match(p)
			}
		}
	}
	return false
}

// isKnownWriter reports whether name is one of the knownWriters tools; they
// are snapshotted on any activity because their targets are implicit.
func isKnownWriter(name string) bool {
	for _, w := range knownWriters {
		for _, t := range w.tools {
			if t == name {
				return true
			}
		}
	}
	return false
}

// UserDB maps UIDs to names from a passwd file, reloading it when it
// changes. It is safe for concurrent use.
type UserDB struct {
	path string

	mu      sync.Mutex
	checked time.Time
	modTime time.Time
	size    int64
	byUID   map[uint32]string
}

// NewUserDB creates a UserDB for the passwd file at p.
func NewUserDB(p string) *UserDB { return &UserDB{path: p} }

// Name returns the user name for uid, or the decimal UID if unknown.
func (u *UserDB) Name(uid uint32) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if now := time.Now(); now.Sub(u.checked) > time.Second || u.byUID == nil {
		u.checked = now
		if fi, err := os.Stat(u.path); err == nil && (u.byUID == nil || !fi.ModTime().Equal(u.modTime) || fi.Size() != u.size) {
			u.modTime, u.size = fi.ModTime(), fi.Size()
			u.byUID = parsePasswd(u.path)
		}
	}
	if n, ok := u.byUID[uid]; ok {
		return n
	}
	return strconv.FormatUint(uint64(uid), 10)
}

// Invalidate forces a reload on the next lookup (the file just changed).
func (u *UserDB) Invalidate() {
	u.mu.Lock()
	u.checked = time.Time{}
	u.mu.Unlock()
}

func parsePasswd(p string) map[uint32]string {
	m := make(map[uint32]string)
	b, err := os.ReadFile(p)
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 3 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if uid, err := strconv.ParseUint(f[2], 10, 32); err == nil {
			if _, dup := m[uint32(uid)]; !dup {
				m[uint32(uid)] = f[0]
			}
		}
	}
	return m
}

// sortedPIDs is used by tests and diagnostics.
func (r *Resolver) sortedPIDs() []uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]uint32, 0, len(r.cache))
	for pid := range r.cache {
		out = append(out, pid)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
