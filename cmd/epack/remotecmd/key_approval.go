//go:build components

package remotecmd

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"time"

	"github.com/locktivity/epack/internal/cli/browser"
	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/remote"
)

const defaultApprovalInterval = 5 * time.Second

// maxApprovalWait bounds the wait for an approval whatever the remote says,
// and is the wait when it names no deadline.
const maxApprovalWait = 30 * time.Minute

// Tests replace these so a wait runs without real time passing or a browser.
var (
	approvalNow      = time.Now
	approvalSleep    = sleepContext
	openApprovalPage = browser.Open
)

// KeyLister lists the keys a configuration accepts, as *remote.Executor does.
type KeyLister interface {
	KeyList(ctx context.Context, config string) (*remote.KeyListResponse, error)
}

// PendingKey is a key the remote holds until a person approves it.
type PendingKey struct {
	Remote string
	Config string
	// Key is the key as key.register returned it, with its Approval.
	Key    remote.SigningKey
	Lister KeyLister
	// NoBrowser prints the approval link without opening it.
	NoBrowser bool
	// Resume says how to pick the request up again after Ctrl-C, as in
	// "run 'epack key create' again".
	Resume string
}

// AwaitKeyApproval shows the code and link that approve a pending key, opens
// the link unless NoBrowser, and checks the remote until the key leaves
// pending. It returns the status the key ended with, lapsed when the window
// closed first. Ctrl-C stops the wait and leaves the request open.
func AwaitKeyApproval(ctx context.Context, out *output.Writer, pending PendingKey) (string, error) {
	approval := pending.Key.Approval
	if approval == nil || approval.Code == "" || approval.URL == "" {
		return "", exitError("the %s adapter did not return an approval code and link", pending.Remote)
	}
	opened := false
	if !pending.NoBrowser {
		switch err := openApprovalPage(ctx, approval.URL); {
		case err == nil:
			opened = true
		case errors.Is(err, browser.ErrUnsupportedURL):
			out.Warning("the approval link is not an http or https URL, so it was not opened")
		}
	}
	printApprovalInstructions(out, pending.Remote, approval, opened)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	spinner := out.StartSpinner("Waiting for approval")
	status, err := waitForApproval(ctx, pending.Lister, pending.Config, pending.Key.ID, approval)
	switch {
	case err != nil && ctx.Err() != nil:
		spinner.Fail("Stopped waiting")
		until := ""
		if expires, err := time.Parse(time.RFC3339, approval.ExpiresAt); err == nil {
			until = " until " + expires.Local().Format("15:04")
		}
		return "", exitError("stopped waiting for approval. The request stays open%s; %s to resume", until, pending.Resume)
	case err != nil:
		spinner.Fail("Could not check on the key")
		return "", exitError("checking whether the key was approved: %v", adapterMessage(err))
	case status == remote.KeyStatusUsable:
		spinner.Success("Approved")
	case status == remote.KeyStatusDenied:
		spinner.Fail("Denied")
	case status == remote.KeyStatusLapsed:
		spinner.Fail("Not approved in time")
	default:
		spinner.Fail("Not approved")
	}
	return status, nil
}

// printApprovalInstructions tells the person where to approve the key and
// with which code. The code shows even with --quiet, since the page asks
// for it; under --json it goes to stderr so stdout carries only the result.
func printApprovalInstructions(out *output.Writer, remoteName string, approval *remote.KeyApproval, opened bool) {
	write := out.PrintAlways
	if out.IsJSON() {
		write = out.Notice
	}
	p := out.Palette()
	write("\nApprove the key on %s\n", p.Bold(remoteName))
	write("  Code: %s\n", p.Bold(output.Printable(approval.Code)))
	if opened {
		write("  Your browser is open. Enter the code there to approve the key.\n")
		write("  If it didn't open, open this link in your browser:\n")
	} else {
		write("  Open this link in your browser and enter the code to approve the key:\n")
	}
	write("  %s\n", output.Printable(approval.URL))
}

// waitForApproval checks the key every interval until it leaves pending or
// the approval window closes, and returns the status it ended with: lapsed
// when the window closed first. A check the remote says to retry is retried.
func waitForApproval(ctx context.Context, lister KeyLister, config, id string, approval *remote.KeyApproval) (string, error) {
	interval := time.Duration(approval.Interval) * time.Second
	if interval <= 0 {
		interval = defaultApprovalInterval
	}
	deadline := approvalNow().Add(maxApprovalWait)
	if expires, err := time.Parse(time.RFC3339, approval.ExpiresAt); err == nil && expires.Before(deadline) {
		deadline = expires
	}
	for {
		if err := approvalSleep(ctx, min(interval, deadline.Sub(approvalNow()))); err != nil {
			return "", err
		}
		list, err := lister.KeyList(ctx, config)
		var adapterErr *remote.AdapterError
		switch {
		case err == nil:
			if status := keyStatus(list.Keys, id); status != remote.KeyStatusPending {
				return status, nil
			}
		case !errors.As(err, &adapterErr) || !adapterErr.IsRetryable():
			return "", err
		}
		if !approvalNow().Before(deadline) {
			return remote.KeyStatusLapsed, nil
		}
	}
}

func keyStatus(keys []remote.SigningKey, id string) string {
	for _, key := range keys {
		if key.ID == id {
			return key.Status
		}
	}
	return ""
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
