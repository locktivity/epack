package componentsdk

import (
	"path"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
)

// gapHelpers holds the functions marked with Recorder.Helper, by name.
var gapHelpers sync.Map

// Helper marks the calling function as one the collector records gaps
// through, as testing.T.Helper marks a test helper. A gap's Source then
// names the line that called the function rather than a line inside it.
func (r *Recorder) Helper() {
	var pc [1]uintptr
	if runtime.Callers(2, pc[:]) == 0 {
		return
	}
	frame, _ := runtime.CallersFrames(pc[:]).Next()
	if frame.Function != "" {
		gapHelpers.Store(frame.Function, true)
	}
}

// sdkPackage is this package's import path, whose frames gapSource skips.
var sdkPackage = reflect.TypeFor[Recorder]().PkgPath()

// mainModule is the path of the module the binary was built from, such as
// github.com/locktivity/epack-collector-okta, and its main package's path.
var mainModule = sync.OnceValues(func() (string, string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", ""
	}
	return info.Main.Path, info.Path
})

// gapSource returns the first line on the stack in the collector's own code
// that is not in a function marked with Helper, or "" when there is none.
// Frames in this package, other than its tests, and frames outside the main
// module, such as a vendor SDK's, are passed over.
func gapSource() string {
	var pcs [64]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		if frame.Function != "" && !sdkFrame(frame) {
			if _, helper := gapHelpers.Load(frame.Function); !helper {
				if src, ok := moduleSource(frame); ok {
					return src
				}
			}
		}
		if !more {
			return ""
		}
	}
}

func sdkFrame(frame runtime.Frame) bool {
	return strings.HasPrefix(frame.Function, sdkPackage+".") && !strings.HasSuffix(frame.File, "_test.go")
}

// moduleSource returns frame's file and line relative to the main module's
// root, or false for a frame outside the main module. The directory comes
// from the frame's package, so the path is the same whether or not the
// binary was built with -trimpath.
func moduleSource(frame runtime.Frame) (string, bool) {
	module, mainPkg := mainModule()
	if module == "" {
		return "", false
	}
	pkg := functionPackage(frame.Function)
	if pkg == "main" {
		pkg = mainPkg
	}
	pkg = strings.TrimSuffix(pkg, "_test")
	var dir string
	switch {
	case pkg == module:
	case strings.HasPrefix(pkg, module+"/"):
		dir = pkg[len(module)+1:]
	default:
		return "", false
	}
	file := path.Base(strings.ReplaceAll(frame.File, `\`, "/"))
	return path.Join(dir, file) + ":" + strconv.Itoa(frame.Line), true
}

// functionPackage returns the import path of the package a function name,
// as runtime.Frame gives it, belongs to: the name up to the first dot after
// its last slash. The linker writes a dot in that last element as %2e.
func functionPackage(fn string) string {
	slash := strings.LastIndexByte(fn, '/')
	dot := strings.IndexByte(fn[slash+1:], '.')
	if dot < 0 {
		return ""
	}
	return strings.ReplaceAll(fn[:slash+1+dot], "%2e", ".")
}
