package collectortest

import "github.com/locktivity/epack/componentsdk"

// checkPermissions checks that each gap's missing permission matches the one
// its operation declares in componentsdk.Operation.Permission. The customer
// is then told to grant the permission the call needs, and that permission
// is declared once, with the call.
func (k *kit) checkPermissions(check, name string, res componentsdk.InProcessResult) {
	if res.Result == nil {
		return
	}
	declared := map[string]string{}
	for _, op := range res.Operations {
		if op.Permission != "" {
			declared[op.Name] = op.Permission
		}
	}
	for _, g := range res.Result.Gaps {
		want := declared[g.Operation]
		if g.MissingPermission == "" || want == "" || g.MissingPermission == want {
			continue
		}
		k.violate("permissions", name, "the gap at %s %s has missing permission %s, but %s declares %s in Operation.Permission. "+
			"Put the permission the call needs in Operation.Permission, and leave MissingPermission off the call's gaps", g.Path, pointerLabel(g.Pointer), g.MissingPermission, g.Operation, want)
	}
}
