package tracemap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/locktivity/epack/internal/procexec"
)

// program is a collector's own packages, parsed and type-checked from
// source, with their imports from outside the module read from the export
// data `go list -export` builds.
type program struct {
	fset   *token.FileSet
	root   string
	module string
	pkgs   []*sourcePackage
}

type sourcePackage struct {
	path  string
	files []*ast.File
	info  *types.Info
}

// listedPackage is what `go list -json` says about one package.
type listedPackage struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	Export     string
	Module     *struct {
		Path string
		Dir  string
		Main bool
	}
	Error *struct{ Err string }
}

// loadProgram loads the packages of the module whose root is dir.
func loadProgram(ctx context.Context, dir string) (*program, error) {
	var stderr bytes.Buffer
	out, err := procexec.Output(ctx, procexec.Spec{
		Path:   "go",
		Args:   []string{"list", "-e", "-deps", "-export", "-json=ImportPath,Dir,GoFiles,Export,Module,Error", "./..."},
		Dir:    dir,
		Stderr: &stderr,
	})
	if err != nil {
		return nil, fmt.Errorf("go list: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	exports := map[string]string{}
	var mains []listedPackage
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listedPackage
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("reading go list: %w", err)
		}
		if p.Module != nil && p.Module.Main {
			if p.Error != nil {
				return nil, fmt.Errorf("package %s: %s", p.ImportPath, p.Error.Err)
			}
			mains = append(mains, p)
			continue
		}
		exports[p.ImportPath] = p.Export
	}
	if len(mains) == 0 {
		return nil, fmt.Errorf("no packages of the main module under %s", dir)
	}
	prog := &program{fset: token.NewFileSet(), root: mains[0].Module.Dir, module: mains[0].Module.Path}
	fromExport := importer.ForCompiler(prog.fset, "gc", func(path string) (io.ReadCloser, error) {
		file := exports[path]
		if file == "" {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(file)
	})
	checked := map[string]*types.Package{}
	imp := importerFunc(func(path string) (*types.Package, error) {
		if p, ok := checked[path]; ok {
			return p, nil
		}
		return fromExport.Import(path)
	})
	// With one context for every package, a generic type instantiated with the
	// same type arguments in two packages is one type, so its fields are the
	// same variables in both.
	ctxt := types.NewContext()
	// go list -deps lists each package after the packages it imports, so the
	// module's own imports are checked before the packages that need them.
	for _, lp := range mains {
		sp := &sourcePackage{path: lp.ImportPath, info: &types.Info{
			Types:      map[ast.Expr]types.TypeAndValue{},
			Defs:       map[*ast.Ident]types.Object{},
			Uses:       map[*ast.Ident]types.Object{},
			Selections: map[*ast.SelectorExpr]*types.Selection{},
		}}
		for _, name := range lp.GoFiles {
			f, err := parser.ParseFile(prog.fset, filepath.Join(lp.Dir, name), nil, parser.SkipObjectResolution)
			if err != nil {
				return nil, err
			}
			sp.files = append(sp.files, f)
		}
		var typeErrs []error
		conf := types.Config{Context: ctxt, Importer: imp, Error: func(err error) { typeErrs = append(typeErrs, err) }}
		pkg, _ := conf.Check(lp.ImportPath, prog.fset, sp.files, sp.info)
		if len(typeErrs) > 0 {
			return nil, fmt.Errorf("type-checking %s: %w", lp.ImportPath, typeErrs[0])
		}
		checked[lp.ImportPath] = pkg
		prog.pkgs = append(prog.pkgs, sp)
	}
	return prog, nil
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }

// relative returns a position's file relative to the module root and its
// line, as file:line.
func (p *program) relative(pos token.Pos) (string, int, bool) {
	position := p.fset.Position(pos)
	if !position.IsValid() {
		return "", 0, false
	}
	rel, err := filepath.Rel(p.root, position.Filename)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", 0, false
	}
	return filepath.ToSlash(rel), position.Line, true
}
