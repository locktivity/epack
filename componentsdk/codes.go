package componentsdk

import "github.com/locktivity/epack/internal/componenttypes"

// Code says why a value could not be collected. Every collector uses the same
// thirteen codes, so a reader can tell whose move it is without knowing the
// collector.
type Code string

const (
	// CodeAuthFailed means the credentials were rejected or have expired.
	CodeAuthFailed Code = "auth_failed"
	// CodePermissionDenied means the sign-in worked but a scope, role, or
	// grant is missing.
	CodePermissionDenied Code = "permission_denied"
	// CodeConfigInvalid means the collector's configuration is wrong.
	CodeConfigInvalid Code = "config_invalid"
	// CodeNotLicensed means the vendor plan or edition lacks the feature.
	CodeNotLicensed Code = "not_licensed"
	// CodeUnsupported means the vendor does not report the value at all, so
	// no run of the collector can read it. It does not make a run partial.
	CodeUnsupported Code = "unsupported"
	// CodeNotRead means the vendor reports the value but the collector does
	// not read it, such as a value behind a call the collector does not make.
	// Its publisher can add it. It does not make a run partial.
	CodeNotRead Code = "not_read"
	// CodeRateLimited means the vendor was still throttling after retries.
	CodeRateLimited Code = "rate_limited"
	// CodeVendorError means the vendor kept failing, such as 5xx responses or
	// dropped connections, after retries.
	CodeVendorError Code = "vendor_error"
	// CodeTimeout means no answer came within the time budget.
	CodeTimeout Code = "timeout"
	// CodeInvalidResponse means the response did not have the shape the
	// collector expects.
	CodeInvalidResponse Code = "invalid_response"
	// CodeTooLarge means the vendor holds more than the collector reads,
	// such as an audit log past the number of events the collector reads.
	CodeTooLarge Code = "too_large"
	// CodeInternal means a bug in the collector.
	CodeInternal Code = "internal"
	// CodeNotShared means the customer left the value out of this pack with
	// the collect config key. Only the SDK records it, and it never fails
	// a run.
	CodeNotShared Code = "not_shared"
)

// Owner is the party that can act on a code.
type Owner string

const (
	// OwnerCustomer is whoever runs the collector against their own account.
	OwnerCustomer Owner = "customer"
	// OwnerNobody marks an expected gap, such as a feature the plan lacks.
	OwnerNobody Owner = "nobody"
	// OwnerVendor is the provider whose API the collector calls.
	OwnerVendor Owner = "vendor"
	// OwnerVendorOrRunner covers timeouts, which a slow API or the runner's
	// network can cause.
	OwnerVendorOrRunner Owner = "vendor_or_runner"
	// OwnerPublisher is whoever publishes the collector.
	OwnerPublisher Owner = "publisher"
)

var codeOwners = map[Code]Owner{
	CodeAuthFailed:       OwnerCustomer,
	CodePermissionDenied: OwnerCustomer,
	CodeConfigInvalid:    OwnerCustomer,
	CodeNotLicensed:      OwnerNobody,
	CodeUnsupported:      OwnerNobody,
	CodeNotRead:          OwnerPublisher,
	CodeRateLimited:      OwnerVendor,
	CodeVendorError:      OwnerVendor,
	CodeTimeout:          OwnerVendorOrRunner,
	CodeInvalidResponse:  OwnerPublisher,
	CodeTooLarge:         OwnerPublisher,
	CodeInternal:         OwnerPublisher,
	CodeNotShared:        OwnerNobody,
}

// Codes lists every code, in the order the protocol documents them.
func Codes() []Code {
	return []Code{
		CodeAuthFailed, CodePermissionDenied, CodeConfigInvalid, CodeNotLicensed, CodeUnsupported, CodeNotRead,
		CodeRateLimited, CodeVendorError, CodeTimeout, CodeInvalidResponse, CodeTooLarge, CodeInternal, CodeNotShared,
	}
}

// Valid reports whether c is one of the thirteen codes.
func (c Code) Valid() bool {
	_, ok := codeOwners[c]
	return ok
}

// Owner returns the party that can act on c. An unknown code belongs to the
// publisher, since only a collector bug produces one.
func (c Code) Owner() Owner {
	if owner, ok := codeOwners[c]; ok {
		return owner
	}
	return OwnerPublisher
}

// makesPartial reports whether a gap with code c makes a run partial. Every
// code does except not_shared, which the customer chose, unsupported, which
// no run could avoid, and not_read, which every run of the collector has.
func (c Code) makesPartial() bool {
	return c != CodeNotShared && c != CodeUnsupported && c != CodeNotRead
}

// ExitCode is the exit code for a run that c stops entirely: 2 for
// configuration, 3 for sign-in and permissions, 4 for the vendor or network,
// and 1 otherwise.
func (c Code) ExitCode() int {
	switch c {
	case CodeConfigInvalid:
		return componenttypes.ExitConfigError
	case CodeAuthFailed, CodePermissionDenied:
		return componenttypes.ExitAuthError
	case CodeRateLimited, CodeVendorError, CodeTimeout:
		return componenttypes.ExitNetworkError
	default:
		return 1
	}
}
