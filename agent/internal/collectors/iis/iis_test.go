package iis

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/statetrack/statetrack/agent/internal/engine"
)

// fixture is a trimmed applicationHost.config with the two pools and one site
// the watcher tests exercise. It is deliberately a real document (with the
// configSections preamble IIS writes) rather than a hand-built struct, so the
// parser is tested against the shape it will actually see.
const fixture = `<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <configSections>
    <sectionGroup name="system.applicationHost">
      <section name="applicationPools" overrideModeDefault="Deny" />
      <section name="sites" overrideModeDefault="Deny" />
    </sectionGroup>
  </configSections>
  <system.applicationHost>
    <applicationPools>
      <add name="CheckoutAppPool" autoStart="true" managedRuntimeVersion="v4.0"
           managedPipelineMode="Integrated" enable32BitAppOnWin64="false"
           queueLength="1000" startMode="AlwaysRunning">
        <processModel identityType="ApplicationPoolIdentity" idleTimeout="00:20:00"
                      maxProcesses="1" loadUserProfile="true" pingingEnabled="true" />
        <recycling logEventOnRecycle="Time,Requests">
          <periodicRestart time="00:00:00">
            <schedule>
              <add value="02:00:00" />
              <add value="14:00:00" />
            </schedule>
          </periodicRestart>
        </recycling>
        <failure rapidFailProtection="true" rapidFailProtectionInterval="00:05:00"
                 rapidFailProtectionMaxCrashes="5" />
      </add>
      <add name="BillingAppPool" autoStart="true" managedRuntimeVersion=""
           managedPipelineMode="Integrated">
        <processModel identityType="SpecificUser" userName="CORP\svc_billing"
                      password="Sup3rS3cret!" idleTimeout="00:20:00" maxProcesses="2" />
      </add>
    </applicationPools>
    <sites>
      <site name="Checkout" id="1" serverAutoStart="true">
        <bindings>
          <binding protocol="https" bindingInformation="*:443:checkout.example.com"
                   certificateHash="a1b2c3d4e5" sslStoreName="My" />
        </bindings>
        <application path="/" applicationPool="CheckoutAppPool" enabledProtocols="https">
          <virtualDirectory path="/" physicalPath="C:\inetpub\wwwroot\checkout" />
        </application>
        <logFile directory="C:\inetpub\logs\LogFiles" />
      </site>
    </sites>
  </system.applicationHost>
</configuration>`

func TestParseConfigReadsPoolsSitesAndDefaults(t *testing.T) {
	cfg, err := ParseConfig([]byte(fixture))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if len(cfg.Pools) != 2 {
		t.Fatalf("pools = %d, want 2", len(cfg.Pools))
	}
	// Sorted by name, so the document order is not the file order.
	billing, checkout := cfg.Pools[0], cfg.Pools[1]
	if billing.Name != "BillingAppPool" || checkout.Name != "CheckoutAppPool" {
		t.Fatalf("pools not sorted: %q, %q", billing.Name, checkout.Name)
	}
	if checkout.State != stateUnknown {
		t.Errorf("state = %q before a runtime query, want %q", checkout.State, stateUnknown)
	}
	if !checkout.AutoStart || checkout.ManagedRuntimeVersion != "v4.0" {
		t.Errorf("checkout pool attributes lost: %+v", checkout)
	}
	if checkout.ProcessModel.IdentityType != "ApplicationPoolIdentity" {
		t.Errorf("identity = %q", checkout.ProcessModel.IdentityType)
	}
	if !checkout.ProcessModel.LoadUserProfile || !checkout.ProcessModel.PingingEnabled {
		t.Errorf("process model defaults lost: %+v", checkout.ProcessModel)
	}
	if !checkout.RapidFailProtection.Enabled || checkout.RapidFailProtection.MaximumFailures != 5 {
		t.Errorf("rapid fail protection lost: %+v", checkout.RapidFailProtection)
	}
	if got := strings.Join(checkout.Recycling.Schedule, ","); got != "02:00:00,14:00:00" {
		t.Errorf("schedule = %q", got)
	}
	// An empty managedRuntimeVersion means "No Managed Code" to IIS; rendering
	// the empty string would make the document ambiguous.
	if billing.ManagedRuntimeVersion != "No Managed Code" {
		t.Errorf("empty runtime version = %q, want the IIS label", billing.ManagedRuntimeVersion)
	}

	if len(cfg.Sites) != 1 {
		t.Fatalf("sites = %d, want 1", len(cfg.Sites))
	}
	site := cfg.Sites[0]
	if site.Name != "Checkout" || len(site.Bindings) != 1 {
		t.Fatalf("site = %+v", site)
	}
	b := site.Bindings[0]
	if b.Protocol != "https" || b.Port != 443 || b.HostHeader != "checkout.example.com" {
		t.Errorf("binding parsed wrong: %+v", b)
	}
	if b.SSLThumbprint != "A1B2C3D4E5" {
		t.Errorf("thumbprint = %q, want upper-cased", b.SSLThumbprint)
	}
	if len(site.Applications) != 1 || site.Applications[0].PhysicalPath != `C:\inetpub\wwwroot\checkout` {
		t.Errorf("application parsed wrong: %+v", site.Applications)
	}
}

func TestRenderPoolScrubsPasswordAndIsStable(t *testing.T) {
	cfg, err := ParseConfig([]byte(fixture))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	var billing Pool
	for _, p := range cfg.Pools {
		if p.Name == "BillingAppPool" {
			billing = p
		}
	}
	scrub := func(string) string { return "[REDACTED:sha256:deadbeef]" }
	first := renderPool(billing, scrub)
	second := renderPool(billing, scrub)

	if string(first) != string(second) {
		t.Fatal("render is not deterministic; the shadow cache would report a change every poll")
	}
	if strings.Contains(string(first), "Sup3rS3cret!") {
		t.Fatal("cleartext password reached the rendered document")
	}
	if !strings.Contains(string(first), "[REDACTED:sha256:deadbeef]") {
		t.Error("scrubbed password marker missing from document")
	}

	var doc poolDoc
	if err := yaml.Unmarshal(first, &doc); err != nil {
		t.Fatalf("rendered document is not valid YAML: %v\n%s", err, first)
	}
	if doc.Kind != "iis_apppool" || doc.Name != "BillingAppPool" {
		t.Errorf("document header = %+v", doc)
	}
	if doc.Identities.Type != "SpecificUser" || doc.Identities.UserName != `CORP\svc_billing` {
		t.Errorf("identity lost: %+v", doc.Identities)
	}
}

func TestRenderPoolOmitsPasswordWhenUnset(t *testing.T) {
	// A pool on ApplicationPoolIdentity has no password; writing a redaction
	// marker would claim a credential is configured.
	doc := renderPool(Pool{Name: "AppPool", State: "Started"}, nil)
	if strings.Contains(string(doc), "password:") {
		t.Errorf("unexpected password field:\n%s", doc)
	}
}

func TestPoolSummaryDescribesTheChange(t *testing.T) {
	before := Pool{Name: "CheckoutAppPool", State: "Started",
		ProcessModel: ProcessModel{IdentityType: "ApplicationPoolIdentity"}}
	stopped := before
	stopped.State = "Stopped"
	if got := PoolSummary(PoolPath("CheckoutAppPool"), before, stopped); !strings.Contains(got, "stopped") {
		t.Errorf("summary = %q, want it to say the pool stopped", got)
	}

	reidentified := before
	reidentified.ProcessModel = ProcessModel{IdentityType: "SpecificUser", UserName: `CORP\svc_checkout`}
	if got := PoolSummary(PoolPath("CheckoutAppPool"), before, reidentified); !strings.Contains(got, "identity changed") {
		t.Errorf("summary = %q, want the identity change", got)
	}
	if !PoolIdentityChanged(before, reidentified) {
		t.Error("PoolIdentityChanged = false for a changed identity")
	}
	if !PoolChangedToStopped(before, stopped) {
		t.Error("PoolChangedToStopped = false for a Started -> Stopped transition")
	}
}

func TestPathHelpersAcceptEverySpelling(t *testing.T) {
	for _, in := range []string{"CheckoutAppPool", "iis://apppool/CheckoutAppPool", "apppool/CheckoutAppPool"} {
		if got := PoolPath(in); got != "iis://apppool/CheckoutAppPool" {
			t.Errorf("PoolPath(%q) = %q", in, got)
		}
	}
	if got := SitePath("iis://site/Checkout"); got != "iis://site/Checkout" {
		t.Errorf("SitePath = %q", got)
	}
	if !IsPoolPath("iis://apppool/X") || IsSitePath("iis://apppool/X") {
		t.Error("IsPoolPath/IsSitePath disagree")
	}
	if got := NameFromPath("iis://site/Checkout"); got != "Checkout" {
		t.Errorf("NameFromPath = %q", got)
	}
}

// ---------------------------------------------------------------------------
// Collector behaviour against fixtures
// ---------------------------------------------------------------------------

type harness struct {
	mu      sync.Mutex
	seeded  map[string]string
	handled []engine.DocEvent
}

func (h *harness) seed(_ context.Context, path, _ string, content []byte, _ time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seeded[path] = string(content)
	return nil
}

func (h *harness) handle(_ context.Context, de engine.DocEvent) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handled = append(h.handled, de)
	return nil
}

func (h *harness) known(path string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.seeded[path]
	return ok
}

func newTestCollector(t *testing.T, states map[string]string) (*Collector, *harness, func(map[string]string)) {
	t.Helper()
	h := &harness{seeded: map[string]string{}}
	mutex := &sync.Mutex{}
	current := states
	col := New(Options{
		ConfigPath: "applicationHost.config",
		Pools:      []string{"CheckoutAppPool"},
		Sites:      []string{"Checkout"},
		Interval:   time.Hour,
		ReadConfig: func(string) ([]byte, time.Time, error) {
			return []byte(fixture), time.Now(), nil
		},
		States: func(context.Context) (map[string]string, error) {
			mutex.Lock()
			defer mutex.Unlock()
			out := make(map[string]string, len(current))
			for k, v := range current {
				out[k] = v
			}
			return out, nil
		},
		Handle: h.handle,
		Seed:   h.seed,
		Known:  func(_ context.Context, path string) bool { return h.known(path) },
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	set := func(next map[string]string) {
		mutex.Lock()
		defer mutex.Unlock()
		current = next
	}
	return col, h, set
}

func TestCollectorSeedsBaselineWithoutEvent(t *testing.T) {
	col, h, _ := newTestCollector(t, map[string]string{"CheckoutAppPool": "Started", "Checkout": "Started"})
	col.Poll(context.Background())

	if len(h.handled) != 0 {
		t.Fatalf("baseline emitted %d events, want 0", len(h.handled))
	}
	if _, ok := h.seeded["iis://apppool/CheckoutAppPool"]; !ok {
		t.Fatal("pool baseline not seeded")
	}
	if _, ok := h.seeded["iis://site/Checkout"]; !ok {
		t.Fatal("site baseline not seeded")
	}
	if !strings.Contains(h.seeded["iis://apppool/CheckoutAppPool"], "state: Started") {
		t.Errorf("baseline does not carry the runtime state:\n%s", h.seeded["iis://apppool/CheckoutAppPool"])
	}
}

func TestCollectorEmitsStoppedPool(t *testing.T) {
	col, h, set := newTestCollector(t, map[string]string{"CheckoutAppPool": "Started", "Checkout": "Started"})
	col.Poll(context.Background())

	set(map[string]string{"CheckoutAppPool": "Stopped", "Checkout": "Started"})
	col.Poll(context.Background())

	if len(h.handled) != 1 {
		t.Fatalf("events = %d, want exactly the pool transition", len(h.handled))
	}
	de := h.handled[0]
	if de.Path != "iis://apppool/CheckoutAppPool" || de.TargetType != TargetPool {
		t.Fatalf("event target = %s/%s", de.TargetType, de.Path)
	}
	if !strings.Contains(string(de.Content), "state: Stopped") {
		t.Errorf("event content does not show the stopped state:\n%s", de.Content)
	}
}

func TestCollectorIgnoresUnchangedPoll(t *testing.T) {
	col, h, _ := newTestCollector(t, map[string]string{"CheckoutAppPool": "Started", "Checkout": "Started"})
	col.Poll(context.Background())
	col.Poll(context.Background())
	col.Poll(context.Background())
	if len(h.handled) != 0 {
		t.Fatalf("unchanged polls emitted %d events", len(h.handled))
	}
}

func TestCollectorReportsRemovedPoolOnce(t *testing.T) {
	col, h, _ := newTestCollector(t, map[string]string{"CheckoutAppPool": "Started", "Checkout": "Started"})
	col.Poll(context.Background())

	// The pool disappears from configuration: the collector still sees the
	// document in its last-poll map and must report a deletion exactly once.
	col.o.Pools = nil
	col.o.Sites = nil
	col.Poll(context.Background())
	col.Poll(context.Background())

	if len(h.handled) != 2 {
		t.Fatalf("events = %d, want one deletion per document", len(h.handled))
	}
	for _, de := range h.handled {
		if de.Content != nil {
			t.Errorf("deletion event carried content for %s", de.Path)
		}
	}
}

func TestCollectorDynamicTargetsStartWatchingWithoutRestart(t *testing.T) {
	var mu sync.Mutex
	dynamic := []string(nil)
	states := map[string]string{"CheckoutAppPool": "Started", "BillingAppPool": "Started"}
	h := &harness{seeded: map[string]string{}}
	col := New(Options{
		ConfigPath: "applicationHost.config",
		Interval:   time.Hour,
		// The console has pushed no rule yet.
		DynamicTargets: func() ([]string, []string) {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), dynamic...), nil
		},
		ReadConfig: func(string) ([]byte, time.Time, error) { return []byte(fixture), time.Now(), nil },
		States:     func(context.Context) (map[string]string, error) { return states, nil },
		Handle:     h.handle,
		Seed:       h.seed,
		Known:      func(_ context.Context, path string) bool { return h.known(path) },
		Logger:     slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})

	col.Poll(context.Background())
	if len(h.seeded) != 0 {
		t.Fatalf("watched %d targets with no rule pushed", len(h.seeded))
	}

	// A rule authored in the console arrives on the next heartbeat.
	mu.Lock()
	dynamic = []string{"iis://apppool/BillingAppPool"}
	mu.Unlock()

	col.Poll(context.Background())
	if _, ok := h.seeded["iis://apppool/BillingAppPool"]; !ok {
		t.Fatal("console-pushed pool was not picked up by the running collector")
	}
}

func TestCollectorSkipsUnreadableConfig(t *testing.T) {
	h := &harness{seeded: map[string]string{}}
	col := New(Options{
		ConfigPath: "missing.config",
		Pools:      []string{"CheckoutAppPool"},
		Interval:   time.Hour,
		ReadConfig: func(string) ([]byte, time.Time, error) { return nil, time.Time{}, os.ErrNotExist },
		Handle:     h.handle,
		Seed:       h.seed,
		Known:      func(context.Context, string) bool { return false },
		Logger:     slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	col.Poll(context.Background())
	if len(h.seeded) != 0 || len(h.handled) != 0 {
		t.Fatal("a host without IIS produced events")
	}
}
