package componentsdk

import "context"

// Step is a named part of a collector's run, such as reading users and
// their sign-in methods. The calls made with the context StartStep returns
// belong to the step, and the result artifact lists each step with its
// times and counts, at every level. A step's name is part of the
// collector's contract, as an operation's name is.
type Step struct {
	run   *run
	state *stepState
}

// stepState is a step as the ledger keeps it. The ledger's mutex guards it.
type stepState struct {
	name, title    string
	startMS, endMS int64
	ended          bool
	requests       int
	calls          int
	retries        int
	failed         int
	ops            []StepOperation
}

// ResultStep is one step in the result artifact. Requests, Calls, Retries,
// and Failed count every request made in the step, including rows left out
// past the limit: the requests sent, the calls they belong to, the retries
// among them, and the attempts that failed.
type ResultStep struct {
	Name       string          `json:"name"`
	Title      string          `json:"title"`
	StartMS    int64           `json:"start_ms"`
	EndMS      int64           `json:"end_ms"`
	Requests   int             `json:"requests"`
	Calls      int             `json:"calls"`
	Retries    int             `json:"retries"`
	Failed     int             `json:"failed"`
	Operations []StepOperation `json:"operations,omitempty"`
}

// StepOperation counts one operation's calls in a step.
type StepOperation struct {
	Name  string `json:"name"`
	Calls int    `json:"calls"`
}

type stepKey struct{}

// StartStep opens a step named name, such as "people", and prints title,
// such as "People and sign-in methods", as a status line. It returns a copy
// of ctx whose calls belong to the step; ctx must come from the run's
// CollectorContext.Context. Call End when the step's work is done. A step
// still open when the collector emits ends then.
//
// Steps can overlap when a collector works on several things at once. They
// do not nest: a step opened with the context of another takes over the
// calls made with its own context, and the result lists the two side by
// side. A call made outside every step belongs to none. With a context the
// SDK did not create, StartStep returns ctx and a step that records nothing.
func StartStep(ctx context.Context, name, title string) (context.Context, *Step) {
	r := runFrom(ctx)
	if r == nil {
		return ctx, &Step{}
	}
	if name == "" {
		name = UnnamedOperation
	}
	if title == "" {
		title = name
	}
	s := &Step{run: r, state: r.calls.startStep(name, title, r.sinceStart(r.now()))}
	if r.status != nil {
		r.status(title)
	}
	return context.WithValue(ctx, stepKey{}, s), s
}

// StartCollectorStep opens a step as StartStep does, with ctx's Context, and
// returns a copy of ctx whose Context carries the step. A helper that
// records gaps, reports progress, or reads the level, and makes the step's
// calls, then takes the one context. With a context the SDK did not create,
// it returns ctx and a step that records nothing.
func StartCollectorStep(ctx CollectorContext, name, title string) (CollectorContext, *Step) {
	stepCtx, s := StartStep(ctx.Context(), name, title)
	var c *collectorContext
	switch sdk := ctx.(type) {
	case *collectorContext:
		c = sdk
	case *steppedContext:
		c = sdk.collectorContext
	default:
		return ctx, s
	}
	return &steppedContext{collectorContext: c, stepCtx: stepCtx}, s
}

// steppedContext is a collector's context whose Context carries a step.
type steppedContext struct {
	*collectorContext
	stepCtx context.Context
}

var (
	_ CollectorContext = (*steppedContext)(nil)
	_ StagingContext   = (*steppedContext)(nil)
)

func (s *steppedContext) Context() context.Context { return s.stepCtx }

// End closes the step. Calling it again does nothing.
func (s *Step) End() {
	if s == nil || s.run == nil {
		return
	}
	s.run.calls.endStep(s.state, s.run.sinceStart(s.run.now()))
}

// stepIn returns the step ctx carries when it belongs to r.
func stepIn(ctx context.Context, r *run) *stepState {
	s, _ := ctx.Value(stepKey{}).(*Step)
	if s == nil || s.run != r {
		return nil
	}
	return s.state
}

func stepName(st *stepState) string {
	if st == nil {
		return ""
	}
	return st.name
}

func (l *ledger) startStep(name, title string, startMS int64) *stepState {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := &stepState{name: name, title: title, startMS: startMS}
	l.steps = append(l.steps, st)
	return st
}

func (l *ledger) endStep(st *stepState, endMS int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st.end(endMS)
}

// endOpenSteps ends each step still open at endMS.
func (l *ledger) endOpenSteps(endMS int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, st := range l.steps {
		st.end(endMS)
	}
}

// end closes the step at endMS, or at its start if endMS is earlier, unless
// it has ended already. The ledger's mutex guards it.
func (st *stepState) end(endMS int64) {
	if !st.ended {
		st.ended, st.endMS = true, max(endMS, st.startMS)
	}
}

// count adds a row to its step's counts. The caller holds l.mu.
func (l *ledger) count(st *stepState, row CallRow) {
	if st == nil {
		return
	}
	st.requests++
	if row.Attempt > 1 {
		st.retries++
	} else {
		st.calls++
		st.countCall(row.Operation)
	}
	if row.failed() {
		st.failed++
	}
}

func (st *stepState) countCall(op string) {
	for i := range st.ops {
		if st.ops[i].Name == op {
			st.ops[i].Calls++
			return
		}
	}
	st.ops = append(st.ops, StepOperation{Name: op, Calls: 1})
}

// resultSteps lists the steps in the order they started.
func (l *ledger) resultSteps() []ResultStep {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]ResultStep, 0, len(l.steps))
	for _, st := range l.steps {
		out = append(out, ResultStep{
			Name:       st.name,
			Title:      st.title,
			StartMS:    st.startMS,
			EndMS:      st.endMS,
			Requests:   st.requests,
			Calls:      st.calls,
			Retries:    st.retries,
			Failed:     st.failed,
			Operations: append([]StepOperation(nil), st.ops...),
		})
	}
	return out
}
