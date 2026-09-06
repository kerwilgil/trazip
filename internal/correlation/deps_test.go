package correlation

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenImports are every package layer that must never depend on
// internal/correlation (Phase E.0: "correlation nunca importa capas
// superiores. Todo lo superior puede importar correlation."). Checked by
// prefix so a future subpackage (e.g. trazip/internal/api/something) is
// caught too.
var forbiddenImports = []string{
	"trazip/internal/api",
	"trazip/internal/diagnosis",
	"trazip/internal/monitor",
	"trazip/internal/voip",
	"trazip/internal/report",
	"trazip/internal/session",
	"trazip/internal/investigation",
}

// TestPackageIsLeaf structurally enforces internal/correlation's own
// dependency contract by parsing every non-test .go file's own import
// list — a plain code-review comment is easy to drift from; this fails CI
// the moment it does. Uses go/parser (stdlib) rather than go/packages to
// avoid needing a full type-check/build, matching the "preferir stdlib
// go/parser" guidance and keeping this test fast and dependency-free.
func TestPackageIsLeaf(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no .go files found in internal/correlation — glob pattern broken?")
	}

	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue // test files may import anything they need for fixtures
		}
		astFile, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", f, err)
		}
		for _, imp := range astFile.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, forbidden := range forbiddenImports {
				if path == forbidden || strings.HasPrefix(path, forbidden+"/") {
					t.Errorf("%s imports %q — internal/correlation must stay a leaf package (stdlib + internal/model only)", f, path)
				}
			}
			if path != "trazip/internal/model" && strings.HasPrefix(path, "trazip/") {
				t.Errorf("%s imports %q — internal/correlation may only import trazip/internal/model besides the standard library", f, path)
			}
		}
	}
}
