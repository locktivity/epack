package credentials

import (
	"fmt"
	"io"
	"os"

	"github.com/locktivity/epack/internal/broker"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
)

// BrokerOverridePolicy describes how a runtime should report use of a custom
// credential broker when Locktivity-managed credentials are active.
type BrokerOverridePolicy struct {
	StrictProductionComponent string
	AuditComponent            string
	AuditName                 string
	AuditDescription          string
}

// UsesManagedCredentials reports whether the component has any Locktivity-managed
// credential refs configured.
func UsesManagedCredentials(refs []string) bool {
	return len(refs) > 0
}

// ValidateManagedCredentialBrokerOverride enforces the custom credential broker
// policy only when Locktivity-managed credentials are actually in use.
func ValidateManagedCredentialBrokerOverride(stderr io.Writer, refs []string, policy BrokerOverridePolicy) error {
	if !UsesManagedCredentials(refs) {
		return nil
	}

	customBrokerURL, customBrokerActive, err := broker.ResolveCustomCredentialBrokerURL(os.Getenv)
	if err != nil {
		return err
	}
	if !customBrokerActive {
		return nil
	}

	if stderr != nil {
		_, _ = fmt.Fprintf(stderr, "WARNING: Running with custom credential broker %s. GitHub Actions OIDC tokens will be sent to this endpoint.\n", customBrokerURL)
	}

	if err := securitypolicy.EnforceStrictProduction(policy.StrictProductionComponent, true); err != nil {
		return err
	}

	securityaudit.Emit(securityaudit.Event{
		Type:        securityaudit.EventInsecureBypass,
		Component:   policy.AuditComponent,
		Name:        policy.AuditName,
		Description: policy.AuditDescription,
		Attrs:       broker.CustomCredentialBrokerAuditAttrs(customBrokerURL),
	})
	return nil
}
