package tracemap

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"reflect"
	"sort"
	"strings"
)

// sdkPackage is the SDK collectors emit their artifacts through.
const sdkPackage = "github.com/locktivity/epack/componentsdk"

// Bounds on the lines one field lists: how many hops from the assignment
// the inputs may be, and how many lines in all.
const (
	maxDepth = 4
	maxLines = 40
)

// analysis finds the source lines behind each field of a collector's
// artifacts. It is a guide for reading the source rather than a proof: it
// follows the assignments to a field, the variables and fields its value is
// computed from, the conditions those lines sit under, and the module's own
// functions the assignment calls, within bounds.
type analysis struct {
	prog *program
	// roots holds the Go types emitted at each artifact path, and
	// rootsBySchema those emitted with a schema but no constant path.
	roots         map[string][]types.Type
	rootsBySchema map[string][]types.Type
	sites         map[*types.Var][]*site
	funcs         map[*types.Func]*ast.FuncDecl
}

// site is one place that writes a variable or field: a statement, a
// composite literal's element, or a range clause.
type site struct {
	node  ast.Node
	value ast.Expr
	info  *types.Info
	// stack holds the node's ancestors, outermost first.
	stack []ast.Node
}

func newAnalysis(prog *program) *analysis {
	a := &analysis{
		prog:          prog,
		roots:         map[string][]types.Type{},
		rootsBySchema: map[string][]types.Type{},
		sites:         map[*types.Var][]*site{},
		funcs:         map[*types.Func]*ast.FuncDecl{},
	}
	for _, p := range prog.pkgs {
		for _, f := range p.files {
			var stack []ast.Node
			ast.Inspect(f, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				a.visit(p.info, n, stack)
				stack = append(stack, n)
				return true
			})
		}
	}
	return a
}

func (a *analysis) addSite(v *types.Var, s *site) {
	if v != nil {
		a.sites[v] = append(a.sites[v], s)
	}
}

func (a *analysis) visit(info *types.Info, n ast.Node, stack []ast.Node) {
	at := func(node ast.Node, value ast.Expr) *site {
		return &site{node: node, value: value, info: info, stack: append([]ast.Node(nil), stack...)}
	}
	switch n := n.(type) {
	case *ast.FuncDecl:
		if fn, ok := info.Defs[n.Name].(*types.Func); ok && n.Body != nil {
			a.funcs[fn] = n
		}
	case *ast.AssignStmt:
		for i, lhs := range n.Lhs {
			value := n.Rhs[0]
			if len(n.Rhs) == len(n.Lhs) {
				value = n.Rhs[i]
			}
			a.addSite(written(info, lhs), at(n, value))
		}
	case *ast.IncDecStmt:
		a.addSite(written(info, n.X), at(n, n.X))
	case *ast.ValueSpec:
		for i, name := range n.Names {
			var value ast.Expr
			switch {
			case len(n.Values) == len(n.Names):
				value = n.Values[i]
			case len(n.Values) > 0:
				value = n.Values[0]
			}
			v, _ := info.Defs[name].(*types.Var)
			a.addSite(v, at(n, value))
		}
	case *ast.RangeStmt:
		for _, e := range []ast.Expr{n.Key, n.Value} {
			if e != nil {
				a.addSite(written(info, e), at(n, n.X))
			}
		}
	case *ast.CompositeLit:
		a.compositeSites(info, n, at)
		if isSDKType(info.TypeOf(n), "CollectedArtifact") {
			a.addRoot(info, keyed(n, "Path"), keyed(n, "Schema"), keyed(n, "Data"))
		}
	case *ast.CallExpr:
		if fn := callee(info, n); fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == sdkPackage && fn.Name() == "JSONArtifact" && len(n.Args) == 3 {
			var schema ast.Expr
			if meta, ok := ast.Unparen(n.Args[2]).(*ast.CompositeLit); ok {
				schema = keyed(meta, "Schema")
			}
			a.addRoot(info, n.Args[0], schema, n.Args[1])
		}
	}
}

// compositeSites records each field a struct literal sets.
func (a *analysis) compositeSites(info *types.Info, lit *ast.CompositeLit, at func(ast.Node, ast.Expr) *site) {
	st, ok := deref(info.TypeOf(lit)).Underlying().(*types.Struct)
	if !ok {
		return
	}
	for i, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if key, ok := kv.Key.(*ast.Ident); ok {
				v, _ := info.Uses[key].(*types.Var)
				a.addSite(v, at(kv, kv.Value))
			}
			continue
		}
		if i < st.NumFields() {
			a.addSite(st.Field(i), at(elt, elt))
		}
	}
}

func (a *analysis) addRoot(info *types.Info, path, schema, data ast.Expr) {
	if data == nil {
		return
	}
	t := info.TypeOf(data)
	if t == nil {
		return
	}
	if p, ok := constString(info, path); ok {
		a.roots[p] = append(a.roots[p], t)
	} else if s, ok := constString(info, schema); ok {
		a.rootsBySchema[s] = append(a.rootsBySchema[s], t)
	}
}

func constString(info *types.Info, e ast.Expr) (string, bool) {
	if e == nil {
		return "", false
	}
	tv, ok := info.Types[e]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(tv.Value), true
}

func keyed(lit *ast.CompositeLit, name string) ast.Expr {
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == name {
				return kv.Value
			}
		}
	}
	return nil
}

func isSDKType(t types.Type, name string) bool {
	named, ok := deref(t).(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == sdkPackage && named.Obj().Name() == name
}

// written returns the variable or field an assignment to e writes, or nil.
// Writing an element of a map or slice writes the map or slice.
func written(info *types.Info, e ast.Expr) *types.Var {
	switch e := ast.Unparen(e).(type) {
	case *ast.Ident:
		v, _ := info.ObjectOf(e).(*types.Var)
		return v
	case *ast.SelectorExpr:
		if sel := info.Selections[e]; sel != nil {
			v, _ := sel.Obj().(*types.Var)
			return v
		}
		v, _ := info.Uses[e.Sel].(*types.Var)
		return v
	case *ast.IndexExpr:
		return written(info, e.X)
	case *ast.StarExpr:
		return written(info, e.X)
	}
	return nil
}

// callee returns the function or method a call names, or nil for a call of
// a function value, a conversion, or a builtin.
func callee(info *types.Info, call *ast.CallExpr) *types.Func {
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		fn, _ := info.Uses[fun].(*types.Func)
		return fn
	case *ast.SelectorExpr:
		fn, _ := info.Uses[fun.Sel].(*types.Func)
		return fn
	case *ast.IndexExpr:
		if id, ok := ast.Unparen(fun.X).(*ast.Ident); ok {
			fn, _ := info.Uses[id].(*types.Func)
			return fn
		}
	}
	return nil
}

func deref(t types.Type) types.Type {
	for {
		p, ok := t.(*types.Pointer)
		if !ok {
			return t
		}
		t = p.Elem()
	}
}

// fieldAt returns the deepest struct field the pointer pattern passes
// through from the root type, or nil when the pattern leaves the types the
// analysis can follow: an interface, a type with its own MarshalJSON, or a
// name no field encodes as.
func fieldAt(root types.Type, pattern string) *types.Var {
	if pattern == "" {
		return nil
	}
	var last *types.Var
	t := root
	for _, token := range strings.Split(pattern[1:], "/") {
		t = deref(t)
		if marshalsItself(t) {
			return nil
		}
		switch u := t.Underlying().(type) {
		case *types.Struct:
			f := jsonField(u, unescapeToken(token))
			if f == nil {
				return nil
			}
			last, t = f, f.Type()
		case *types.Slice:
			if token != "*" {
				return nil
			}
			t = u.Elem()
		case *types.Array:
			if token != "*" {
				return nil
			}
			t = u.Elem()
		case *types.Map:
			t = u.Elem()
		default:
			return nil
		}
	}
	return last
}

func unescapeToken(t string) string {
	return strings.ReplaceAll(strings.ReplaceAll(t, "~1", "/"), "~0", "~")
}

// marshalsItself reports whether t, or a pointer to it, encodes itself, so
// its JSON shape is not its fields'.
func marshalsItself(t types.Type) bool {
	if _, ok := t.Underlying().(*types.Interface); ok {
		return true
	}
	for _, m := range []string{"MarshalJSON", "MarshalText"} {
		if obj, _, _ := types.LookupFieldOrMethod(types.NewPointer(t), true, nil, m); obj != nil {
			if _, ok := obj.(*types.Func); ok {
				return true
			}
		}
	}
	return false
}

// jsonField returns the field of st that encoding/json writes under name,
// looking into embedded structs without a name of their own.
func jsonField(st *types.Struct, name string) *types.Var {
	for i := range st.NumFields() {
		f := st.Field(i)
		tag, _, _ := strings.Cut(reflect.StructTag(st.Tag(i)).Get("json"), ",")
		if tag == "-" {
			continue
		}
		if f.Embedded() && tag == "" {
			if inner, ok := deref(f.Type()).Underlying().(*types.Struct); ok {
				if found := jsonField(inner, name); found != nil {
					return found
				}
				continue
			}
		}
		if !f.Exported() {
			continue
		}
		if tag == "" {
			tag = f.Name()
		}
		if tag == name {
			return f
		}
	}
	return nil
}

// codeLines names the lines the analysis finds for a field and adds their
// text to lines.
func codeLines(a *analysis, src *source, lines Lines, path, schema, pattern string) ([]CodeLine, error) {
	var out []CodeLine
	for _, l := range a.fieldLines(path, schema, pattern) {
		file, line, ok := a.prog.relative(l.pos)
		if !ok {
			continue
		}
		cl := CodeLine{Role: l.role, Line: LineRef(file, line)}
		last := line
		if l.end.IsValid() {
			_, end, ok := a.prog.relative(l.end)
			if ok && end > line {
				cl.End, last = end, end
			}
		}
		for n := line; n <= last; n++ {
			ref := LineRef(file, n)
			text, err := src.line(ref)
			if err != nil {
				return nil, err
			}
			lines[ref] = text
		}
		out = append(out, cl)
	}
	sort.SliceStable(out, func(i, j int) bool { return lineLess(out[i].Line, out[j].Line) })
	return out, nil
}

// tracedLine is one line a field lists, before it is named relative to the
// module root.
type tracedLine struct {
	role     string
	pos, end token.Pos
}

// rolePrecedence orders the roles a line can have: a line listed twice keeps
// the earlier role.
var rolePrecedence = map[string]int{RoleAssign: 0, RoleHelper: 1, RoleInput: 2, RoleCondition: 3}

// fieldLines finds the lines behind the field at pattern in the artifact at
// path, which the clean run emitted with the given schema.
func (a *analysis) fieldLines(path, schema, pattern string) []tracedLine {
	roots := a.roots[path]
	if len(roots) == 0 && schema != "" {
		roots = a.rootsBySchema[schema]
	}
	var targets []*types.Var
	for _, r := range roots {
		if f := fieldAt(r, pattern); f != nil {
			targets = append(targets, f)
		}
	}
	if len(targets) == 0 {
		return nil
	}
	t := &trace{a: a, lines: map[lineKey]tracedLine{}, seen: map[*types.Var]bool{}}
	for _, f := range targets {
		t.seen[f] = true
		t.queue = append(t.queue, queued{v: f, depth: 0})
	}
	t.run()
	out := make([]tracedLine, 0, len(t.lines))
	for _, l := range t.lines {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pos < out[j].pos })
	return out
}

type queued struct {
	v     *types.Var
	depth int
}

// trace is one field's walk, breadth first, so the lines nearest the
// assignment are kept when a field reaches maxLines.
type trace struct {
	a     *analysis
	lines map[lineKey]tracedLine
	seen  map[*types.Var]bool
	queue []queued
}

// lineKey names a source line by its file and line number.
type lineKey struct {
	file string
	line int
}

func (t *trace) run() {
	for len(t.queue) > 0 && len(t.lines) < maxLines {
		q := t.queue[0]
		t.queue = t.queue[1:]
		for _, s := range t.a.sites[q.v] {
			role := RoleInput
			switch {
			case q.depth == 0:
				role = RoleAssign
			case s.inCondition():
				role = RoleCondition
			}
			t.add(role, s.node.Pos(), 0)
			if q.depth == 0 {
				t.helpers(s)
			}
			t.follow(s.info, s.value, q.depth+1)
			t.conditions(s, q.depth+1)
		}
	}
}

// inCondition reports whether a site is part of a condition: a range
// clause, which defines its variables as it loops, or the statement an if,
// switch, or for runs before its test.
func (s *site) inCondition() bool {
	if _, ok := s.node.(*ast.RangeStmt); ok {
		return true
	}
	if len(s.stack) == 0 {
		return false
	}
	switch parent := s.stack[len(s.stack)-1].(type) {
	case *ast.IfStmt:
		return parent.Init == s.node
	case *ast.SwitchStmt:
		return parent.Init == s.node
	case *ast.TypeSwitchStmt:
		return parent.Init == s.node || parent.Assign == s.node
	case *ast.ForStmt:
		return parent.Init == s.node || parent.Post == s.node
	}
	return false
}

// add lists a line once, with the first of its roles in rolePrecedence.
func (t *trace) add(role string, pos, end token.Pos) {
	if !pos.IsValid() {
		return
	}
	at := t.a.prog.fset.Position(pos)
	key := lineKey{file: at.Filename, line: at.Line}
	if have, ok := t.lines[key]; ok {
		if rolePrecedence[role] < rolePrecedence[have.role] {
			t.lines[key] = tracedLine{role: role, pos: have.pos, end: end}
		}
		return
	}
	if len(t.lines) < maxLines {
		t.lines[key] = tracedLine{role: role, pos: pos, end: end}
	}
}

// follow queues the variables and fields e reads, at depth.
func (t *trace) follow(info *types.Info, e ast.Expr, depth int) {
	if e == nil || depth > maxDepth {
		return
	}
	ast.Inspect(e, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.SelectorExpr:
			// A field is followed and not the value it is read from, which
			// says where the field is rather than what it holds.
			if sel := info.Selections[n]; sel != nil && sel.Kind() == types.FieldVal {
				t.enqueue(sel.Obj().(*types.Var), depth)
				return false
			}
			if v, ok := info.Uses[n.Sel].(*types.Var); ok {
				t.enqueue(v, depth)
			}
			return false
		case *ast.Ident:
			if v, ok := info.Uses[n].(*types.Var); ok && !v.IsField() {
				t.enqueue(v, depth)
			}
		}
		return true
	})
}

func (t *trace) enqueue(v *types.Var, depth int) {
	if t.seen[v] || len(t.a.sites[v]) == 0 {
		return
	}
	t.seen[v] = true
	t.queue = append(t.queue, queued{v: v, depth: depth})
}

// helpers adds each function of the module an assignment's value calls.
func (t *trace) helpers(s *site) {
	if s.value == nil {
		return
	}
	ast.Inspect(s.value, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if fn := callee(s.info, call); fn != nil {
				if decl := t.a.funcs[fn]; decl != nil {
					t.add(RoleHelper, decl.Pos(), decl.End())
				}
			}
		}
		return true
	})
}

// conditions adds the tests a site sits under: the if, loop, switch, and
// case it is inside, whose variables are queued at depth, and each check
// before it in an enclosing block that returns, continues, or breaks out
// early, such as one that skips an item.
func (t *trace) conditions(s *site, depth int) {
	child := s.node
	for i := len(s.stack) - 1; i >= 0; i-- {
		switch n := s.stack[i].(type) {
		case *ast.FuncDecl:
			return
		case *ast.IfStmt:
			if child == n.Body || child == n.Else {
				t.condition(s.info, n.Pos(), n.Cond, depth)
			}
		case *ast.ForStmt:
			if child == n.Body {
				t.condition(s.info, n.Pos(), n.Cond, depth)
			}
		case *ast.RangeStmt:
			if child == n.Body {
				t.condition(s.info, n.Pos(), n.X, depth)
			}
		case *ast.SwitchStmt:
			t.condition(s.info, n.Pos(), n.Tag, depth)
		case *ast.TypeSwitchStmt:
			t.condition(s.info, n.Pos(), nil, depth)
		case *ast.CaseClause:
			t.condition(s.info, n.Pos(), nil, depth)
			for _, e := range n.List {
				t.follow(s.info, e, depth)
			}
			t.guards(n.Body, child)
		case *ast.CommClause:
			t.condition(s.info, n.Pos(), nil, depth)
			t.guards(n.Body, child)
		case *ast.BlockStmt:
			t.guards(n.List, child)
		}
		child = s.stack[i]
	}
}

func (t *trace) condition(info *types.Info, pos token.Pos, e ast.Expr, depth int) {
	t.add(RoleCondition, pos, 0)
	t.follow(info, e, depth)
}

// guards adds each if statement before child in list whose body ends by
// leaving early. What a guard tests is not followed further: most guards
// near the top of a function check an error or the configuration, which
// every line after them sits behind.
func (t *trace) guards(list []ast.Stmt, child ast.Node) {
	for _, stmt := range list {
		if stmt == child {
			return
		}
		if guard, ok := stmt.(*ast.IfStmt); ok && guard.Else == nil && leavesEarly(guard.Body) {
			t.add(RoleCondition, guard.Pos(), 0)
		}
	}
}

// leavesEarly reports whether a block ends with a return, a branch such as
// continue, or a call to panic.
func leavesEarly(b *ast.BlockStmt) bool {
	if b == nil || len(b.List) == 0 {
		return false
	}
	switch last := b.List[len(b.List)-1].(type) {
	case *ast.ReturnStmt, *ast.BranchStmt:
		return true
	case *ast.ExprStmt:
		call, ok := last.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		id, ok := call.Fun.(*ast.Ident)
		return ok && id.Name == "panic"
	}
	return false
}
