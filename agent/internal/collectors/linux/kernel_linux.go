//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// netlinkSocket is a blocking netlink socket whose reads time out so the
// reader can observe cancellation.
type netlinkSocket struct{ fd int }

func openNetlink(proto, groups int) (*netlinkSocket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: uint32(groups)}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	tv := unix.NsecToTimeval(int64(250 * time.Millisecond))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// A large receive buffer absorbs exec bursts (e.g. a package install).
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	return &netlinkSocket{fd: fd}, nil
}

func (s *netlinkSocket) Close() error { return unix.Close(s.fd) }

// loop reads netlink messages until ctx is done, passing each to fn.
func (s *netlinkSocket) loop(ctx context.Context, log *slog.Logger, name string, fn func(syscall.NetlinkMessage)) {
	buf := make([]byte, 64<<10)
	for ctx.Err() == nil {
		n, _, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.ENOBUFS) {
				log.Warn("netlink receive buffer overrun; some attributions may be missing", "source", name)
				continue
			}
			log.Error("netlink read failed; source stopped", "source", name, "err", err)
			return
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			continue
		}
		for _, m := range msgs {
			fn(m)
		}
	}
}

// AttributionStatus reports which kernel attribution sources are active.
type AttributionStatus struct {
	Audit     bool
	Connector bool
	Fanotify  bool
}

// startAudit listens passively on the audit multicast group (alongside
// auditd, if any). It needs CAP_AUDIT_READ and only yields records for
// syscalls matched by the host's audit rules.
func startAudit(ctx context.Context, wg *sync.WaitGroup, r *Resolver, log *slog.Logger) error {
	const auditNlgrpReadlog = 1
	s, err := openNetlink(unix.NETLINK_AUDIT, auditNlgrpReadlog)
	if err != nil {
		return err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer s.Close()
		var asm AuditAssembler
		s.loop(ctx, log, "audit", func(m syscall.NetlinkMessage) {
			ev := asm.Feed(m.Header.Type, m.Data)
			if ev == nil || ev.PID == 0 {
				return
			}
			r.RememberInfo(ev.ProcInfo())
			if ev.Success {
				for _, p := range ev.Paths {
					r.NoteWriter(p, ev.PID)
				}
			}
		})
	}()
	return nil
}

// startConnector subscribes to proc connector exec/exit events. It needs
// CAP_NET_ADMIN, the initial network namespace and CONFIG_PROC_EVENTS.
func startConnector(ctx context.Context, wg *sync.WaitGroup, r *Resolver, log *slog.Logger) error {
	const cnIdxProc, cnValProc, procCnMcastListen = 1, 1, 1
	s, err := openNetlink(unix.NETLINK_CONNECTOR, cnIdxProc)
	if err != nil {
		return err
	}
	msg := make([]byte, unix.NLMSG_HDRLEN+20+4)
	binary.NativeEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:], unix.NLMSG_DONE)
	binary.NativeEndian.PutUint32(msg[12:], uint32(os.Getpid()))
	binary.NativeEndian.PutUint32(msg[16:], cnIdxProc)
	binary.NativeEndian.PutUint32(msg[20:], cnValProc)
	binary.NativeEndian.PutUint16(msg[32:], 4)
	binary.NativeEndian.PutUint32(msg[36:], procCnMcastListen)
	if err := unix.Sendto(s.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		s.Close()
		return err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer s.Close()
		s.loop(ctx, log, "proc_connector", func(m syscall.NetlinkMessage) {
			ev, ok := ParseConnector(m.Data)
			switch {
			case !ok:
			case ev.Exec:
				r.Remember(ev.PID)
			case ev.Exit:
				r.Exited(ev.PID)
			}
		})
	}()
	return nil
}

// StartAttribution starts the kernel attribution sources that the current
// privileges allow and reports which are active.
func StartAttribution(ctx context.Context, wg *sync.WaitGroup, r *Resolver, log *slog.Logger) AttributionStatus {
	var st AttributionStatus
	if err := startAudit(ctx, wg, r, log); err != nil {
		log.Info("audit attribution unavailable", "err", err)
	} else {
		st.Audit = true
	}
	if err := startConnector(ctx, wg, r, log); err != nil {
		log.Info("proc connector attribution unavailable", "err", err)
	} else {
		st.Connector = true
	}
	return st
}

// fanotifyWatcher reports the PID of every process that closes a written
// file in a marked directory. It needs CAP_SYS_ADMIN.
type fanotifyWatcher struct {
	fd  int
	mu  sync.Mutex
	dir map[string]bool
}

func newFanotify() (*fanotifyWatcher, error) {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK,
		unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &fanotifyWatcher{fd: fd, dir: make(map[string]bool)}, nil
}

// FAN_MODIFY fires at write() time while the writer is still running (the
// kernel merges repeats); FAN_CLOSE_WRITE covers writers seen only at close.
const fanMask = unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_EVENT_ON_CHILD

func (f *fanotifyWatcher) Add(dir string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dir[dir] {
		return nil
	}
	if err := unix.FanotifyMark(f.fd, unix.FAN_MARK_ADD|unix.FAN_MARK_ONLYDIR, fanMask, unix.AT_FDCWD, dir); err != nil {
		return fmt.Errorf("fanotify mark %s: %w", dir, err)
	}
	f.dir[dir] = true
	return nil
}

func (f *fanotifyWatcher) Remove(dir string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dir[dir] {
		_ = unix.FanotifyMark(f.fd, unix.FAN_MARK_REMOVE|unix.FAN_MARK_ONLYDIR, fanMask, unix.AT_FDCWD, dir)
		delete(f.dir, dir)
	}
}

// Run delivers (path, pid) pairs until ctx is done, then closes the group.
func (f *fanotifyWatcher) Run(ctx context.Context, fn func(path string, pid uint32)) {
	defer unix.Close(f.fd)
	buf := make([]byte, 64<<10)
	metaLen := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	pfd := []unix.PollFd{{Fd: int32(f.fd), Events: unix.POLLIN}}
	for ctx.Err() == nil {
		if n, err := unix.Poll(pfd, 250); err != nil || n == 0 {
			continue
		}
		n, err := unix.Read(f.fd, buf)
		if err != nil || n < metaLen {
			continue
		}
		for off := 0; off+metaLen <= n; {
			m := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[off]))
			if m.Event_len < uint32(metaLen) {
				break
			}
			if m.Fd >= 0 {
				p, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(m.Fd)))
				unix.Close(int(m.Fd))
				if err == nil && m.Pid > 0 {
					fn(p, uint32(m.Pid))
				}
			}
			off += int(m.Event_len)
		}
	}
}
