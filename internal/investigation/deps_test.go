package investigation

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenImports mirrors internal/correlation's own deps_test.go — the
// packages investigation must never depend on, so a future Investigation
// UI/CLI can only ever reach a module's rich result through that module's
// own Phase E.0 adapter, never by importing the module (or internal/api)
// directly (Phase E: "investigation → api PROHIBIDO").
var forbiddenImports = []string{
	"trazip/internal/api",
	"trazip/internal/diagnosis",
	"trazip/internal/monitor",
	"trazip/internal/voip",
	"trazip/internal/session",
}

func TestPackageDoesNotImportForbiddenLayers(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no .go files found in internal/investigation — glob pattern broken?")
	}

	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		astFile, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", f, err)
		}
		for _, imp := range astFile.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, forbidden := range forbiddenImports {
				if path == forbidden || strings.HasPrefix(path, forbidden+"/") {
					t.Errorf("%s imports %q — internal/investigation must never depend on it (see this package's own doc comment)", f, path)
				}
			}
		}
	}
}
