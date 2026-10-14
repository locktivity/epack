// Package secrets resolves the variables a configuration lists under
// secrets: from the environment first and then from a secret store, the
// operating system keychain by default. Stored values are scoped to one
// configuration on one remote and approved for the components that read
// them; a revision that changes a reader needs a fresh approval before the
// value is used again. Nothing here prompts: the commands that may interact
// pass interactive explicitly, and a run, a check, and a fetch summary never
// do.
package secrets
