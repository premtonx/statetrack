package migrations

import (
	"strings"
	"testing"
)

// Every embedded migration must be free of a leading byte-order mark.
//
// Postgres fails the whole boot on one ("syntax error at or near \ufeff"), and
// the server exits, so a single file saved by an editor that adds a BOM would
// break `docker compose up` on a fresh volume. Files() strips one defensively;
// this test keeps the source honest as well.
func TestNoMigrationStartsWithBOM(t *testing.T) {
	files, err := Files()
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no migrations embedded")
	}
	for _, f := range files {
		if strings.HasPrefix(f.SQL, "\ufeff") {
			t.Errorf("%s begins with a UTF-8 BOM; save it as UTF-8 without BOM", f.Name)
		}
		if strings.TrimSpace(f.SQL) == "" {
			t.Errorf("%s is empty", f.Name)
		}
	}
}

func TestFilesAreOrderedAndNamed(t *testing.T) {
	files, err := Files()
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	for i, f := range files {
		if f.Name == "" || f.Version == "" {
			t.Fatalf("migration %d has an empty name or version", i)
		}
		if i > 0 && files[i-1].Version >= f.Version {
			t.Fatalf("migrations are not sorted: %q before %q", files[i-1].Version, f.Version)
		}
	}
}

func TestTrimBOM(t *testing.T) {
	cases := map[string]string{
		"\ufeffCREATE TABLE t ();": "CREATE TABLE t ();",
		"CREATE TABLE t ();":       "CREATE TABLE t ();",
		"":                         "",
		// Only a *leading* BOM is stripped; an interior one is the author's
		// content (or a bug worth failing on), not an encoding artefact.
		"SELECT '\ufeff';": "SELECT '\ufeff';",
	}
	for in, want := range cases {
		if got := trimBOM(in); got != want {
			t.Errorf("trimBOM(%q) = %q, want %q", in, got, want)
		}
	}
}
