package storage

import (
	"strings"
	"testing"
)

// A watch rule that reaches the agent with a bad pattern becomes a classifier
// that silently matches nothing: the console would show a watched target that is
// not actually watched, which is the worst failure mode for this feature. These
// tests pin the validation that prevents it.
func TestWatchRuleInputValidateAccepts(t *testing.T) {
	cases := []struct {
		name       string
		in         WatchRuleInput
		wantName   string
		wantTarget string
	}{
		{
			name: "iis app pool",
			in: WatchRuleInput{
				HostScope: "win-app-02", TargetType: "iis_apppool",
				Pattern: "iis://apppool/CheckoutAppPool", Level: 1,
			},
			wantName: "CheckoutAppPool", wantTarget: WatchTypeIISPool,
		},
		{
			name: "database table",
			in: WatchRuleInput{
				HostScope: "*", TargetType: "database_table",
				Pattern: "db://postgres/settings_db/tables/public.app_settings", Level: 1,
			},
			wantName: "public.app_settings", wantTarget: WatchTypeDBTable,
		},
		{
			name: "windows file",
			in: WatchRuleInput{
				HostScope: "win-app-02", TargetType: "file",
				Pattern: `C:\inetpub\wwwroot\checkout\web.config`, Level: 1,
			},
			wantName: "web.config", wantTarget: WatchTypeFile,
		},
		{
			name: "directory glob, drift only",
			in: WatchRuleInput{
				HostScope: "prod-web-01", TargetType: "directory",
				Pattern: `D:\Apps\Billing\Config\**`, Level: 3,
			},
			wantName: "**", wantTarget: WatchTypeDirectory,
		},
		{
			name: "registry key",
			in: WatchRuleInput{
				HostScope: "win-app-02", TargetType: "registry",
				Pattern: `HKLM\Software\Company\App\**`, Level: 1,
			},
			wantName: "**", wantTarget: WatchTypeRegistry,
		},
		{
			name: "kubernetes object",
			in: WatchRuleInput{
				HostScope: "prod-k8s-01", TargetType: "k8s_object",
				Pattern: "/k8s/prod-k8s-01/production/configmaps/checkout-config", Level: 1,
			},
			wantName: "checkout-config", wantTarget: WatchTypeK8sObject,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := c.in
			if err := in.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if in.Name != c.wantName {
				t.Errorf("name = %q, want %q", in.Name, c.wantName)
			}
			if in.TargetType != c.wantTarget {
				t.Errorf("target type = %q, want %q", in.TargetType, c.wantTarget)
			}
		})
	}
}

func TestWatchRuleInputValidateDefaultsHostToFleet(t *testing.T) {
	in := WatchRuleInput{TargetType: "service", Pattern: "W3SVC", Level: 1}
	if err := in.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if in.HostScope != FleetScope {
		t.Errorf("host scope = %q, want %q", in.HostScope, FleetScope)
	}
}

func TestWatchRuleInputValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		in   WatchRuleInput
		want string
	}{
		{
			name: "database table that is not a db path",
			in:   WatchRuleInput{TargetType: "database_table", Pattern: "public.app_settings", Level: 1},
			want: "db://",
		},
		{
			name: "database table without a table segment",
			in:   WatchRuleInput{TargetType: "database_table", Pattern: "db://postgres/settings_db", Level: 1},
			want: "/tables/",
		},
		{
			name: "registry key without a hive",
			in:   WatchRuleInput{TargetType: "registry", Pattern: `Software\Company\App`, Level: 1},
			want: "hive",
		},
		{
			name: "kubernetes object without a leading slash",
			in:   WatchRuleInput{TargetType: "k8s_object", Pattern: "production/configmaps/x", Level: 1},
			want: "absolute",
		},
		{
			name: "unknown target type",
			in:   WatchRuleInput{TargetType: "printer", Pattern: "x", Level: 1},
			want: "unsupported target type",
		},
		{
			name: "empty pattern",
			in:   WatchRuleInput{TargetType: "file", Pattern: "   ", Level: 1},
			want: "pattern is required",
		},
		{
			name: "level zero would drop every event",
			in:   WatchRuleInput{TargetType: "file", Pattern: `/etc/app.conf`, Level: 0},
			want: "impact level",
		},
		{
			name: "level above the range",
			in:   WatchRuleInput{TargetType: "file", Pattern: `/etc/app.conf`, Level: 9},
			want: "impact level",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := c.in
			err := in.Validate()
			if err == nil {
				t.Fatalf("Validate(%+v) = nil, want a rejection", c.in)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %q, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestWatchRuleInputNormalisesTypeCase(t *testing.T) {
	in := WatchRuleInput{TargetType: "  IIS_AppPool ", Pattern: "CheckoutAppPool", Level: 1}
	if err := in.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if in.TargetType != WatchTypeIISPool {
		t.Errorf("target type = %q, want %q", in.TargetType, WatchTypeIISPool)
	}
	// A bare pool name is what an operator types; the agent normalises it to the
	// iis:// URI, so validation must not demand the URI form.
	if in.Pattern != "CheckoutAppPool" {
		t.Errorf("pattern = %q", in.Pattern)
	}
}

// The diff flag is a pointer in the input so "not sent" can default to on while
// an explicit false still means hash-only.
func TestWatchRuleDiffDefaultsOn(t *testing.T) {
	in := WatchRuleInput{TargetType: "file", Pattern: "/etc/app.conf", Level: 1}
	if err := in.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if in.Diff != nil {
		t.Error("Validate invented a diff value; the default belongs to the store")
	}
}
