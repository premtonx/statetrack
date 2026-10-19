//go:build windows

package windows

import (
	"context"
	"errors"
	"log/slog"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// EvtSubscribe/EvtRender flags (wevtapi.dll is not bound by x/sys).
const (
	evtSubscribeToFutureEvents = 1
	evtRenderEventXML          = 1
)

var (
	modWevtapi       = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe = modWevtapi.NewProc("EvtSubscribe")
	procEvtNext      = modWevtapi.NewProc("EvtNext")
	procEvtRender    = modWevtapi.NewProc("EvtRender")
	procEvtClose     = modWevtapi.NewProc("EvtClose")
)

// errNoEvents is returned by evtNext when the poll timeout expired without
// a matching event (ERROR_NO_MORE_ITEMS).
var errNoEvents = windows.ERROR_NO_MORE_ITEMS

// subscription is one EvtSubscribe handle.
type subscription struct {
	handle windows.Handle
}

// newSubscription opens a pull subscription over channel with the XPath
// query, starting from the newest matching event.
func newSubscription(channel, query string) (*subscription, error) {
	var ch *uint16
	if channel != "" {
		var err error
		ch, err = windows.UTF16PtrFromString(channel)
		if err != nil {
			return nil, err
		}
	}
	q, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return nil, err
	}
	r1, _, e1 := procEvtSubscribe.Call(
		0, // Session (local)
		0, // SignalEvent
		uintptr(unsafe.Pointer(ch)),
		uintptr(unsafe.Pointer(q)),
		0, // Bookmark
		0, // Context
		0, // Callback (pull mode)
		evtSubscribeToFutureEvents,
	)
	if r1 == 0 {
		return nil, e1
	}
	return &subscription{handle: windows.Handle(r1)}, nil
}

func (s *subscription) close() {
	if s == nil || s.handle == 0 {
		return
	}
	procEvtClose.Call(uintptr(s.handle))
	s.handle = 0
}

// next blocks up to ~1s for one event, then renders it as XML.
func (s *subscription) next() (string, error) {
	var ev windows.Handle
	r1, _, e1 := procEvtNext.Call(uintptr(s.handle), 1, uintptr(unsafe.Pointer(&ev)), 1000, 0, 0)
	if r1 == 0 {
		if errno, ok := e1.(syscall.Errno); ok && errno == windows.ERROR_NO_MORE_ITEMS {
			return "", errNoEvents
		}
		return "", e1
	}
	defer procEvtClose.Call(uintptr(ev))
	return evtRenderXML(ev)
}

// evtRenderXML renders one event handle to its EvtRender XML form.
func evtRenderXML(ev windows.Handle) (string, error) {
	var used, propCount uint32
	// Sizing call: NULL buffer returns the required byte count.
	procEvtRender.Call(0, uintptr(ev), evtRenderEventXML, 0, 0,
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&propCount)))
	if used == 0 {
		return "", errors.New("evt: empty render")
	}
	buf := make([]uint16, used/2+1)
	r1, _, e1 := procEvtRender.Call(0, uintptr(ev), evtRenderEventXML, uintptr(len(buf))*2,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&propCount)))
	if r1 == 0 {
		return "", e1
	}
	return windows.UTF16ToString(buf), nil
}

// Subscriber tails one channel+query, delivering parsed events to onEvent.
type Subscriber struct {
	Channel string
	Query   string
	onEvent func(Event)
}

// run blocks until ctx is done. onEvent is called on this goroutine.
func (s Subscriber) run(ctx context.Context, log *slog.Logger) {
	sub, err := newSubscription(s.Channel, s.Query)
	if err != nil {
		log.Error("event log subscription failed", "channel", s.Channel, "err", err)
		return
	}
	defer sub.close()
	log.Info("event log subscription active", "channel", s.Channel)
	for {
		if ctx.Err() != nil {
			return
		}
		xml, err := sub.next()
		if errors.Is(err, errNoEvents) {
			continue
		}
		if err != nil {
			// Transient read errors are logged but not fatal.
			log.Warn("event log read", "channel", s.Channel, "err", err)
			continue
		}
		ev, err := ParseEvent(xml)
		if err != nil {
			log.Warn("event log parse", "channel", s.Channel, "err", err)
			continue
		}
		s.onEvent(ev)
	}
}
