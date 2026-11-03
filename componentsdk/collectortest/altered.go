package collectortest

import (
	"fmt"

	"github.com/locktivity/epack/componentsdk"
)

// The perturbation checks run the clean scenario again with one
// operation's answers changed, and judge each run against the clean one.
// The sensitivity, order, and fields checks change the answers' bodies. The
// pages and faults checks wrap the run's network instead. pickOps picks the
// operations a check changes, and a perturber makes each change and runs
// it. alter builds a scenario with changed bodies, and transformBody changes
// one body through the suite's codec.

// readBody returns a canned response's body as text the checks can read and
// change. The text is the JSON the codec decodes the body to, or the body
// itself. encoded is true when the codec decoded the body, and a changed body
// is then encoded again. cbor is true for a CBOR body the codec did not
// decode. The text checks cannot read that body.
func (k *kit) readBody(op string, r Response) (text string, encoded, cbor bool, err error) {
	if r.decoded {
		return r.Body, false, false, nil
	}
	decoded, err := decodeResponse(k.suite.Codec, op, r.Header, []byte(r.Body))
	if err == nil && decoded != nil {
		return string(decoded), true, false, nil
	}
	return r.Body, false, isCBOR(r.Header.Get("Content-Type")), err
}

// textOf returns a canned response's body as the checks read it. That is the
// JSON the codec decodes it to, or the body itself. It returns "" for a CBOR
// body the codec did not decode.
func (k *kit) textOf(op string, r Response) string {
	text, _, cbor, _ := k.readBody(op, r)
	if cbor {
		return ""
	}
	return text
}

// transformBody changes a canned response's body as text with change and
// returns the new body. change reports whether it changed anything. When the
// suite's codec decoded the body, the new body is encoded again with it. A
// CBOR body the codec did not decode goes to cbor instead. If cbor is nil,
// transformBody returns that body as it is and reports no change. It returns
// an error when the codec cannot decode the body or cannot encode the
// changed body.
func (k *kit) transformBody(op string, r Response, change, cbor func(string) (string, bool)) (string, bool, error) {
	text, encoded, isCBORBody, err := k.readBody(op, r)
	switch {
	case err != nil:
		return "", false, err
	case isCBORBody && cbor == nil:
		return r.Body, false, nil
	case isCBORBody:
		body, ok := cbor(text)
		return body, ok, nil
	}
	body, ok := change(text)
	if !ok || !encoded {
		return body, ok, nil
	}
	out, err := k.suite.Codec.EncodeResponse(op, r.Header, []byte(body))
	if err != nil {
		return "", false, fmt.Errorf("the codec could not encode the changed body: %w", err)
	}
	return string(out), true, nil
}

// alter returns the clean scenario with change applied to each response op
// consumed in the clean run. change gets the response's index. alter
// reports whether change changed any response.
func (k *kit) alter(op string, change func(i int, r Response) (string, bool)) (Scenario, bool) {
	consumed := k.consumedBy()
	sc := k.suite.Scenarios[0]
	sc.Responses = append([]Response(nil), sc.Responses...)
	touched := false
	for i, r := range sc.Responses {
		if !containsString(consumed[i], op) {
			continue
		}
		if body, ok := change(i, r); ok {
			sc.Responses[i].Body = body
			touched = true
		}
	}
	return sc, touched
}

// opPick says which of the clean run's operations a check changes. Every
// check leaves out calls with no operation name. The zero opPick keeps the
// HTTP operations the kit counted calls for in the clean run.
type opPick struct {
	// fromResult takes the operations from the result artifact's call
	// counts instead of the kit's own.
	fromResult bool
	// uncalled keeps operations with no calls.
	uncalled bool
	// anyKind keeps operations the run made through DNS or a dialed
	// endpoint as well as HTTP ones.
	anyKind bool
	// skipInsensitive leaves out the operations in Suite.Insensitive.
	skipInsensitive bool
	// exempt lists more operations to leave out, such as Suite.Ordered.
	exempt []string
}

// pickOps returns the clean run's operations that p keeps, in the order
// the run counted them.
func (k *kit) pickOps(p opPick) []componentsdk.OperationCalls {
	from := k.baseline.Operations
	if p.fromResult {
		from = k.baseline.Result.Calls.Operations
	}
	var out []componentsdk.OperationCalls
	for _, op := range from {
		switch {
		case op.Name == componentsdk.UnnamedOperation,
			op.Calls == 0 && !p.uncalled,
			!p.anyKind && k.baselineNet.kindOf(op.Name) != kindHTTP,
			p.skipInsensitive && k.insensitive(op.Name),
			containsString(p.exempt, op.Name):
			continue
		}
		out = append(out, op)
	}
	return out
}

// consumedBy maps the index of each of the clean scenario's responses to
// the operations that consumed it in the clean run.
func (k *kit) consumedBy() map[int][]string {
	if k.baselineOps == nil {
		k.baselineOps = k.baselineNet.replay.operationsFor()
	}
	return k.baselineOps
}

// perturber makes one check's changes to the clean run and runs each. Its
// hooks hold what the checks do differently when a change cannot be made.
type perturber struct {
	k     *kit
	check string
	// unapplied handles a change that reached none of the operation's
	// answers. Nil skips it without a word.
	unapplied func(label, op string)
	// unreadable handles an answer the change cannot read or write, such as
	// one the codec cannot decode. The run is then not made. Nil skips that
	// answer and changes the rest.
	unreadable func(label, op string, err error)
}

// perturbation is one change a perturber makes to the clean run.
type perturbation struct {
	// label names the run in reports, and op is the operation it changes.
	label, op string
	// text changes the text of each of op's answers, and cbor changes a CBOR
	// body the codec did not decode, as transformBody describes. Nil text
	// leaves the bodies as they are.
	text, cbor func(string) (string, bool)
	// wrap installs a transport around the run's network.
	wrap func(*network)
	// reached reports, after the run, whether wrap's change reached a call.
	reached func() bool
}

// run makes c and runs the clean scenario with it. It returns false when
// the change was not made or reached no call, after calling the hook that
// applies.
func (p perturber) run(c perturbation) (alteredRun, bool) {
	sc := p.k.suite.Scenarios[0]
	if c.text != nil {
		var changed bool
		var failure error
		sc, changed = p.k.alter(c.op, func(i int, r Response) (string, bool) {
			if failure != nil {
				return "", false
			}
			body, ok, err := p.k.transformBody(c.op, r, c.text, c.cbor)
			if err != nil && p.unreadable != nil {
				failure = fmt.Errorf("response %d: %w", i, err)
			}
			return body, ok
		})
		switch {
		case failure != nil:
			p.unreadable(c.label, c.op, failure)
			return alteredRun{}, false
		case !changed:
			p.skip(c)
			return alteredRun{}, false
		}
	}
	res, n := p.k.runOnce(p.check, c.label, sc, c.wrap)
	if c.reached != nil && !c.reached() {
		p.skip(c)
		return alteredRun{}, false
	}
	return alteredRun{res: res, unanswered: len(n.unmatched()) > 0}, true
}

func (p perturber) skip(c perturbation) {
	if p.unapplied != nil {
		p.unapplied(c.label, c.op)
	}
}

// alteredRun is the result of running an altered scenario.
type alteredRun struct {
	res componentsdk.InProcessResult
	// unanswered is true when the run made a request the scenario has no
	// response for. A follow-up whose body lists IDs in the order the
	// collector got them is one example. Such a run proves nothing about the
	// values.
	unanswered bool
}

// failed reports whether the run failed.
func (a alteredRun) failed() bool { return a.res.ExitCode != 0 }

// moved lists each value in run's output that differs from the clean run's.
// Every list is sorted before the comparison. It returns nil for a run that
// failed or is unanswered.
func (k *kit) moved(run alteredRun) []string {
	if run.unanswered || run.failed() {
		return nil
	}
	if k.cleanSorted == nil {
		k.cleanSorted = sortedArtifacts(k.baseline.Artifacts)
	}
	return diffSorted(k.cleanSorted, sortedArtifacts(run.res.Artifacts), k.ignore)
}
