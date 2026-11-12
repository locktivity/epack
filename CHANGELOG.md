# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### BUG FIXES

- The release workflow `epack sdk new` writes for a tool, remote or utility
  creates the GitHub release once, in its release job. Each platform's SLSA
  build created it too, so builds that finished together failed with
  `already_exists` or left two releases for one tag. The release still
  carries each `.intoto.jsonl` next to its `.sigstore.json` copy. Collector
  scaffolds already worked this way
- A recording keeps OData's control information keys, such as
  `inheritsPermissionsFrom@odata.context` or `members@odata.nextLink`. The
  scrubber read them as email addresses and replaced them with fakes, which
  broke the structure of Microsoft Graph recordings. An address at a domain
  such as `odata.org` is still replaced

## [0.11.1] - 2026-11-12

### ENHANCEMENTS

- Every field of the eight normalized schemas has a written definition.
  The endpoint-posture device rows, the tls certificate details and the
  schema_version and collected_at fields of every schema now say what they
  hold, and the access-posture and vuln-scanning counts that only repeated
  their label now say what they count. The definitions also state which
  roles make a user privileged or an admin, which accounts are members or
  credentials, that network ACLs don't change the SSH and RDP values, that
  a remembered device doesn't make a sign-in uncovered, and how an unknown
  device reading affects an endpoint percentage
- roster.Derive follows two of those definitions. An account with
  signs_in_through signs in through another identity provider, so the MFA
  values over users, and over admins when one of them does, are left out.
  A vcs block's base_permission is the permission every member gets, and
  when it maps to admin in terms.roles, every member but no outside
  collaborator is an admin

## [0.11.0] - 2026-11-12

### ENHANCEMENTS

- `roster.Derive` gives a value for every field of the eight normalized
  schemas, apart from the time of the run and the free text a schema leaves
  to the collector, such as issue and error messages. New roster blocks
  describe the rest of a tenant: `directory` for its domain, account states,
  passwords, app provisioning and session limits, `cloud` for its cloud
  accounts, databases, audit logs, backups, threat detection, local users
  and machine credentials, and `endpoint`, `scanning`, `vcs`, `tls` and
  `email_dns` for its devices, vulnerability scanners, repositories, TLS
  endpoints and mail domains. `providers` gives each schema's provider. A
  roster without a block derives what it did before
- A roster with a `vcs` block gives a code host's whole access-posture
  artifact. Its accounts are the organization's members, outside
  collaborators and bots, its roles the organization roles, and its apps
  the installed apps. The block adds the organization's single sign-on,
  SCIM provisioning, IP allow list and machine credentials, such as tokens
  and deploy keys, each belonging to the organization or to repositories.
  A repository with `collector_access` false, such as one a GitHub App
  isn't installed on, is out of the scan. Such a roster gives no
  idp-posture values
- `roster.AboveLevel` reports whether a run at a level leaves out a value,
  so a test can drop the audit-level values Derive gives when it compares
  them with a trust run. `roster.Align` also takes `Settle`'s values
- `roster.Uncovered` lists the fields an artifact writes that Derive has no
  value for, so a test that compares a collector's output with a roster can
  fail on what the comparison doesn't reach. `roster.Unanswered` lists the
  fields of a schema no roster's values hold, `roster.NotDerived` the fields
  Derive never gives with the reason for each, and `roster.Align` matches
  Derive's list entries to an artifact's by the fields that identify them,
  such as a TLS endpoint's host and port
- Derive gives percentages in every entry of a list, and the `all_*`
  booleans in tls and email-dns, true when every endpoint or domain counts
  and null over none. `Expect` compares lists and objects by their JSON
  encoding, so a derived list or count by name matches one read from an
  artifact
- `componentsdk/collectortest/simulate` builds a vendor simulator from a
  roster and checks a collector against the values `roster.Derive` gives.
  A simulator lists each endpoint with the recorded operation it mirrors,
  what it needs, and how the vendor pages it: a next link in the body, a
  Link header, a cursor, or an offset. It builds each item from a copy of
  one the sandbox's recording holds, so its answers keep the vendor's
  nulls, optional fields and envelopes. The kit answers a call the
  credential or the plan can't make with the vendor's refusal, and gives
  stable IDs. Its harness checks every simulated answer's shape against
  the recording, and fails on a field, type, operation or status the
  recording doesn't hold unless the simulator lists it with why. It lines
  a collector's normalized values up with the derived ones, fails on a
  difference no verdict lists and on a listed one that matches again, and
  runs a matrix of roster variants, rules on random rosters, and a
  comparison with the recording's values
- `simulate.Harness.Coverage` turns on a coverage check: `Tenants` also
  fails on a field a collector writes that the roster gives no value for,
  as `roster.Uncovered` finds it, unless `Harness.Uncompared` lists the
  field with why, and on a listing every scenario now compares
- A roster's sign-in policies can name a `first_match` set and a
  `priority`, for a vendor such as Okta that applies the first policy and
  rule that match a sign-in. `blocks` can be `all`, for a rule that denies
  every sign-in
- `Suite.FieldFaults` turns on the test kit's `field_faults` check, which
  holds that a missing or unreadable field never lowers a count. For each
  field the collector reads in an operation's answers, it runs the clean
  scenario with the field set to null, dropped, and, for a list, emptied.
  Every number and boolean in the output must keep its clean value or be
  left out under a gap, which must name the operation when
  `Suite.GapOperations` is on. An XML element is dropped or, for a list,
  emptied. Paging fields are left alone. A change to an object is reported
  only where no field inside it explains the same values, so a finding
  names the field the collector reads. It would have caught Microsoft
  v0.2.4's Global Administrator count of 0 from roles Graph sends with
  `isPrivileged` null, and its soft delete share of 0 from vaults listed
  without their security settings
- `Suite.Populations` declares a list whose emptying is a real answer, such
  as a users list, and `Suite.Omissions` a field the vendor leaves out, or
  sends as null, to mean a value. Each entry names one operation's list or
  field and says why. A `*` in an entry matches any one key, such as each
  of a resource's tags. The `field_faults` check reports an entry it never
  used

## [0.10.6] - 2026-11-11

### ENHANCEMENTS

- `evidencepack/cloud-posture@v1`'s `storage` object has
  `network_restricted_pct` and its audit-level count: the storage resources
  that refuse traffic from the public internet, because public network access
  is off or only listed networks and private endpoints may connect
- `storage.encryption_pct` says it counts encryption at rest with any key,
  the provider's own or the customer's, and `storage.public_access_blocked_pct`
  says it counts anonymous access to the data, not whether the internet can
  reach the resource. Each points at the other field for the other question
- `evidencepack/idp-posture@v1`'s `policy.mfa_required` says enforced
  policies combine: between them they must require MFA of every user on
  every sign-in, or block it, whatever the app, client type, device,
  location or risk. Exceptions a policy names, such as break-glass
  accounts, don't make it false. It said every user must use MFA, which no
  tenant with a break-glass account meets. `mfa_required_user_count` counts
  the users whose every sign-in requires MFA or is blocked, so an excluded
  user counts as not covered, and `legacy_auth_blocked` combines policies
  the same way
- `user_security.user_count` says it counts enabled accounts of people in
  the organization, leaving out guests from other organizations, as the
  collectors already did. `privileged_users_count` says it counts users with
  a role that can change who has access, reset another user's credentials,
  or change sign-in or security settings, and not roles that only read
- `evidencepack/access-posture@v1`'s members are people with an account in
  the system or a role anywhere in it, such as on one resource group, and
  its admins are members who can change who has access or change or delete
  any resource. In a scope, an admin's role covers the whole account or
  subscription
- `evidencepack/cloud-posture@v1`'s SSH and RDP fields count a security
  group as open when its rules, applied as the cloud applies them, let a
  connection in from any address. A deny rule processed first closes the
  port
- `componentsdk/collectortest/roster` reads a roster: a tenant's accounts,
  roles, sign-in policies, apps and cloud resources in the vendor's terms,
  with a block that maps each term to a normalized one. `roster.Derive`
  gives the normalized values the roster determines, following the
  schemas' definitions, so a collector's simulated or sandbox output can be
  checked against values worked out apart from its code. `OneAtATime`,
  `Pairwise` and `Build` make roster variants that change one setting at a
  time or every pair of settings. `Roster.Applies` says whether a sign-in
  policy applies to one account's sign-in to an app, and `Roster.Outcome`
  what the enforced policies that apply ask of it, so a vendor's own policy
  evaluation can be checked against the roster's reading
- `collectortest.CompareResponses` reports where a simulator's responses
  differ from a recording: fields, JSON types, list lengths, status codes
  and enum spellings

## [0.10.5] - 2026-11-10

### ENHANCEMENTS

- The schema check skips a required property that the schema places above
  the run's level with `x-epack-level`, on the property or on a value that
  holds it. A collector can gate an identifier to `audit` and keep it
  required for the runs that write it. `outputcheck.ValidateAt` runs the
  check, and the collectortest kit uses it as well
- `Recorder.Targets` declares what a run was pointed at: its container and
  the resources it assessed, each kind with how it was chosen and where its
  targets sit in the pack. The result artifact writes the declarations as
  `targets`, pointing into the artifacts so names follow their own levels,
  with the SDK's `count` from the audit level and `complete` at every level.
  A declaration the artifacts don't bear out is a `targets` check finding.
  A choice says when the credential was given only some targets (`granted`,
  `granted_filtered`) or the collector picked them itself (`collector`),
  `For` narrows a declaration to the values read in fewer targets, such as
  security services read in one region, and a container the artifact
  describes is declared at the whole artifact, so its label can sit beside
  its ID
- The collect protocol says which identifiers each level may hold: account,
  tenant, and workspace identifiers sit at `audit` and above, and names the
  company publishes stay at every level

## [0.10.4] - 2026-11-06

### ENHANCEMENTS

- `x-epack-replaced-by` has a `reason`, one sentence on why the field moved,
  for a profile editor to show beside a test on it. A field with no reason of
  its own takes the nearest enclosing block's. The blocks epack v0.10.0 moved
  out of cloud-posture and vcs-posture each have one, and so do the
  `cloudtrail_enabled` and `cloudtrail_multiregion` aliases

### BUG FIXES

- The collect protocol said a profile test could move to a field marked
  `same` as it is. That holds only within one schema. A test moved to another
  schema reads that schema's artifacts from every system, such as every
  system's `access-posture`, so it checks more than the old test did

## [0.10.3] - 2026-11-06

### ENHANCEMENTS

- Each deprecated field in the normalized schemas has `x-epack-replaced-by`,
  naming the schema and field that hold its value now. `same` marks a new
  field that holds the same value, so a profile test can move to it as it
  is. A profile editor can then show a test on a deprecated field what to
  test instead, from the schema alone. That covers the blocks epack v0.10.0
  moved out of cloud-posture and vcs-posture, and cloud-posture's
  `cloudtrail_enabled` and `cloudtrail_multiregion` aliases

## [0.10.2] - 2026-11-06

### ENHANCEMENTS

- `Recorder.Moved` records a value that sits in a block epack moved to
  another kind, such as a deprecated block written beside its new fields.
  When the collect config key leaves that kind out, `Emit` removes the value
  with a `not_shared` gap, and drops the gaps inside it. Use it for a block
  that is not a copy of one value in the new kind, such as an AWS account's
  `iam` block, which access-posture rolls up across accounts

### BUG FIXES

- A value `Recorder.Mirror` copied from a kind the collect config key leaves
  out is removed with a `not_shared` gap when the collector never passed that
  kind to `Emit`. A collector that checks `Selected` skips building a kind
  left out, so the copy stayed in the pack. For example, a deprecated field
  copied from access-posture showed in a pack that left access-posture out

## [0.10.1] - 2026-11-05

### ENHANCEMENTS

- The shared collector CI workflow takes `test-timeout`, the timeout for
  `go test`. It defaults to 10m, Go's own default, for a collector whose test
  kit runs longer under the race detector
- cloud-posture declares `iam`, `vuln_scanning` and `workforce_sign_in`
  again, and vcs-posture declares `org_security` and `security_features`.
  These are the blocks epack v0.10.0 moved to access-posture and
  vuln-scanning, and each is marked deprecated. A collector can write them
  beside the new fields, so profiles written before v0.10.0 keep grading the
  same. They keep their v0.9.9 definitions, so they are written at the trust
  level. A later release removes them
- `epack shadow` is in the command list `epack` prints with no command.
  Without a collector name, it prints its usage and examples, like
  `epack sign` and `epack push`

### BUG FIXES

- In plain progress output, which CI uses, each status line names the
  collector that sent it. With collectors running in parallel, a line could
  carry the name of whichever collector started last
- `epack run` numbered collectors from 2, so the first of five showed as
  `(2/5)`. They are numbered from 1 now, in the terminal and in the
  progress sent to the remote
- `epack shadow` with neither `--version` nor `--binary` said "not both".
  The message names the two flags now

## [0.10.0] - 2026-11-05

### ENHANCEMENTS

- The test kit's new `redaction` check reports a run of letters and digits
  that redaction hid as a possible secret from a gap, its advice, a run
  warning, or a failure message. In a scenario such a run is almost always an
  identifier the reader needs, such as an API error code. A run inside a URL
  is left out. `InProcessResult.Redacted` lists the runs
- A collector's schema can describe how the collector measures a value with
  `x-epack-method`, one plain sentence such as "Reads each S3 bucket's
  default encryption setting." The test kit's new `methods` check asks for
  one on every number and true-or-false value in a normalized artifact. A
  value copied from the detailed artifact with `Recorder.Mirror` uses the
  method of the value it copies. The check also asks for one on each such
  value a trust run writes in a detailed artifact, since profiles test the
  detailed fields of collectors with no normalized artifact. It finds a
  copied value's method in the detailed artifact's schema, so it holds when
  that artifact is not written
- A new reserved config key, `collect`, lists the kinds of evidence a
  collector collects, such as `[cloud-posture, details]`, at every level.
  A collector's own detailed file is the kind `details`. Without the
  key, a collector collects every kind its level allows. A key that is not a
  list of kinds fails the run with `config_invalid`. Each kind it leaves out
  gets a gap with the new code `not_shared`, and the collector result's new
  `collect` records what the key listed, what it left out, and any kind the
  run never wrote. Leaving out a normalized kind also removes the values
  `Recorder.Mirror` copied from it. A `not_shared` gap does not make a run
  partial. `componentsdk.Selected` tells a collector whether to collect a
  kind, and `Emit` leaves out what it rules out
- `CollectorSpec.Writes` lists the schema IDs a collector can write. SDK
  collectors publish it in `--capabilities` and the build file, and the new
  `writes` kit check fails a collector that writes a schema ID it does not
  list. `epack collect` and `epack run` warn when a collector's `collect`
  list names a kind the run never wrote, from the result's `unmatched`
  list
- `epack shadow <collector>` previews what a new collector version would
  change before you upgrade. It runs the locked version, the candidate, and
  the locked version again. A field or gap that differs between the two
  locked runs is noise, which the report lists apart from its changes.
  The candidate is a release (`--version`) or a local build (`--binary`),
  locked and verified in a throwaway project. Strict production mode
  refuses a local build, as it refuses an unpinned binary in
  `epack collect`, and a custom credential broker gets the same check as
  in `collect`. The report lists changed fields by pattern, gaps by code
  and missing permission, API operations, call counts as ranges, and each
  control whose result would change, from the project's validate tool run
  on a pack from each run. It names a file only by a path a build file
  declares, a schema ID, or the collector's own name, and holds no value
  from the account. At a terminal outside CI, the report shows the values
  behind each change. `--values` writes them to a private file
- `x-epack-level` at a schema's root marks the whole artifact. The SDK
  leaves it out of a run below that level and drops the gaps inside it. A
  collector whose normalized artifact carries what profiles read can mark
  its detailed schema `audit` so trust packs leave that file out
- The collector result's `run.level` records the level the run collected
  at, at every level, for every artifact the run wrote
- `Emit` leaves out each value a collector writes that its schema marks
  above the run's level, as the result leaves out its own. The result lists
  each one as a `levels` check finding, which the test kit reports
- Below the audit level, the collector result leaves out what grows with the
  account's size or names it:
  - `signed_in_as.tenant_id`
  - each operation's `calls`, `attempts`, `retries`, `statuses`, and `errors`
  - each step's `start_ms`, `end_ms`, `requests`, `calls`, `retries`, and
    `failed`, and its operations' calls
  - a gap's `call` and `unmeasured`

  At every level, operations gain `retried`, `status_codes`, and
  `error_codes`, and steps gain `any_failed`, so a trust result still says
  which calls failed or were retried. The schema marks each field left out
  with `x-epack-level: audit`. The SDK leaves out exactly the fields the
  schema marks
- `evidencepack/cloud-posture@v1` marks `account_id`, `accounts_expected`,
  and the counts behind its percentages as audit-level. It adds
  `all_accounts_collected`. An account no longer requires `account_id`
- `InProcessResult.Operations` counts each operation's calls at every level.
  The test kit's fault matrix and credential checks read it, so they work for
  a suite that runs at the trust level
- epack-conformance COL-080 fails a trust result that holds any value the
  result schema marks for a higher level, such as the tenant, call or step
  counts or times, or a gap's call number or unmeasured count. The schema is
  the only list, so a field marked later is checked without a change to
  COL-080. A result from an SDK that counted calls at every level still
  passes with those counts. Its operations do not carry `retried`
- `epack verify --insecure-skip-tlog`, with `--public-key`, accepts a key
  signature that has no transparency log entry, such as one made with
  `epack sign --no-tlog`. Certificate signatures still need their entry. A
  verification that accepts only such key signatures fetches no Sigstore
  trust root, so it makes no network calls
- Every percentage in the normalized schemas sets its rounding with
  `x-epack-rounding`. A percentage where more is better, such as MFA
  coverage, rounds down (`floor`). A percentage where more is worse, such as
  rules open to the world or endpoints that still accept a legacy protocol,
  rounds up (`ceil`). This way a percentage short of 100 never rounds up to
  100, and one above 0 never rounds down to 0
- The `tls` and `email-dns` summary percentages, and their every-endpoint
  and every-domain booleans, point to their counts with `x-epack-numerator`
  and `x-epack-denominator`. The `ratios` check recomputes them from those
  counts
- `idp-posture`'s privileged MFA percentages point to the count they are
  taken over. The `population` check reports one that is set when that
  count is 0
- The `x-epack-present` annotation points to a boolean field that is true
  when a value's population has any members. The `population` and `nulls`
  checks treat a false flag like a denominator of 0. At the trust level,
  the normalized schemas leave out their counts, and the checks use the flag
  instead
- The `population` check reports a value that is set although its
  denominator or `x-epack-present` flag was not read. A denominator or flag
  was not read when it is null or left out with a gap. A count or
  percentage over a population the collector could not read must be left
  out too. The `nulls` check accepts a null value whose denominator was not
  read
- `componentsdk.NextLink(resp)` returns the next page from a response's
  `Link` headers, parsed as RFC 8288 defines them. It reads every header
  line and every link on each line. Okta sends self and next on separate
  lines, and GitHub lists several links on one line
- The test kit's `pages` check reports a next page that a scenario's answer
  offered and the run never requested. The next page can come from a `Link`
  header, a body field such as `next` or `@odata.nextLink`, a token such as
  `NextToken` or `next_cursor`, or a GraphQL `pageInfo`. For each operation
  that pages by `Link` header or body field, the check also adds a next page
  to the operation's last answer and checks that the run requests it.
  `Suite.Capped` exempts lists cut short on purpose and polling APIs.
  `Suite.Paged` lists operations that page by `Link` header where the
  scenarios do not show it
- The test kit's `order` check runs the clean scenario once for each
  operation, with every list in that operation's answers reversed. Lists
  are JSON arrays and repeated XML elements. The check compares the results
  with every list sorted and reports a value that changes. `Suite.Ordered`
  exempts answers whose order the vendor documents
- `Suite.Variants` runs the clean scenario as another deployment of the
  vendor, such as AWS GovCloud, would answer it. It rewrites the scenario's
  canned answers, config, and env with old, new pairs. The `variants` check
  reports a value that does not follow the rewrite, such as an ARN prefix
  the collector hard-codes. It also reports a request the rewritten scenario
  cannot answer, such as one to a hard-coded host
- `componentsdk.Operation.Permission` declares the permission a call needs,
  in the vendor's terms. The collector result lists it with the operation as
  `permission` at every level. A `permission_denied` gap recorded from the
  call's error records it as `missing_permission`, with no option needed.
  `HTTPOptions.NamesPermission` lets a collector leave the permission off a
  denial that granting it would not fix, such as AWS's explicit deny or a
  denial with no message. The test kit's `permissions` check reports a gap
  whose missing permission differs from the one its operation declares
- The SDK has a normalized schema for `evidencepack/endpoint-posture@v1`,
  based on the JumpCloud collector's schema. Emit checks artifacts of that
  type against it. It covers the fleet, compliance, hardening, patching, and
  protection. The fleet counts, `metric_coverage`,
  and device rows are audit-level. Local admin accounts are internal-level.
  At the trust level, an artifact has `fleet.devices_present` and no counts.
  The schema adds `fleet.mdm_enrolled_pct`, the percentage of
  `fleet.device_count` enrolled in MDM. Every percentage and count allows
  null, for a fleet with no devices. Every percentage rounds down and
  requires `devices_present` to be true
- A schema can give each value a label and a summary for readers of the
  pack with `x-epack-label`, a few words such as "Disk encryption", and
  `x-epack-summary`, one or two plain sentences on what the value counts or
  says. `x-epack-goal` is the better value where one is better. It is
  `true` or `false` on a true-or-false value, and `higher` or `lower` on a
  count. A percentage takes its direction from `x-epack-rounding`. The schemas ship
  in the build file, so the labels travel with each build. Every field in
  the SDK's normalized schemas has a label, and every number and
  true-or-false value has a summary
- The test kit's new `labels` check reports each number and true-or-false
  value the clean scenario writes that has no `x-epack-label` or no
  `x-epack-summary`, and a goal that does not fit its value. A normalized
  artifact passes with the SDK's own labels. New scaffolds label their
  example schema
- Every data artifact a collector writes sits at
  `artifacts/<collector>.<kind>.json`, where the kind is the name in its
  schema ID, or `details` for the collector's own detailed file.
  `componentsdk.ArtifactPath(collector, schemaID)` gives the path. A run
  configured under another name in `epack.yaml` writes its files under
  that name, and the SDK moves every path in the output to match, so two
  runs of one collector in a pack no longer collide.
  `componentsdk.RunPath` gives the path a run writes. The test kit's new
  `paths` check reports an artifact written anywhere else
- Two new gap codes. `unsupported` marks a value the vendor does not report
  at all, such as a normalized field it has no data for. Its owner is
  `nobody`, and it does not make a run partial. `too_large` marks a value
  the collector's own read limit cut short, such as an audit log longer
  than the collector reads. Its owner is `publisher`
- `x-epack-rollup` takes `among`, a list of conditions that pick the rows a
  rollup covers. Each is `{"where": pointer, "equals": value}` or
  `{"where": pointer, "not_equals": value}`. A count or percentage over
  active apps only, for example, can now be checked against its rows
- `HTTPOptions.ThrottleWait` sets the wait before retrying a throttled
  response that still has requests left in its rate limit. GitHub answers
  this way over a secondary rate limit and asks for a minute's wait. Without
  it, such a response waits only as long as the primary limit's reset
  header says, or backs off for at most 8 seconds
- `CollectorSpec.Methods` gives a collector's `x-epack-method` sentences
  for a normalized artifact, keyed by schema ID and then by field, with `*`
  for any array index. Emit checks the artifact against the SDK's schema
  with the sentences added, and the build file carries that schema. A
  collector no longer copies a normalized schema to describe how it
  measures it. `CollectorSpec.ArtifactSchemas` returns the schemas Emit
  uses, and `NormalizedSchemaWithMethods` returns one type's
- The test kit's new `normalized` check reports a copy of a normalized
  schema in `CollectorSpec.Schemas`, which replaces the SDK's and falls
  behind it. It also reports a `Methods` entry it cannot place on a field
- The gap code `not_read` means the vendor reports a value but the collector
  does not read it, such as a value behind a call the collector does not
  make. Its owner is the publisher, who can add the read. Like
  `unsupported`, it does not make a run partial. `unsupported` keeps its
  meaning, a value the vendor never reports
- The SDK has normalized schemas for `evidencepack/access-posture@v1` and
  `evidencepack/vuln-scanning@v1`, and Emit checks artifacts of those types
  against them. `access-posture` covers who can get into one system and how
  they sign in. It has sections for sign-in rules, members, admins, root
  accounts, machine credentials, and connected apps. A collector writes one
  for each system it reads, such as GitHub, AWS, or ClickHouse. Its
  `system_type` says what kind of system it is, such as `code_host` or
  `saas`. `vuln-scanning` lists each scanner a system runs, with its
  coverage and its open findings by severity. In both, the counts and the
  per-account `scopes` are audit-level, and the `*_present` flags are
  written at every level
- `evidencepack/idp-posture@v1` accepts `jumpcloud` as a provider
- `CollectorSpec.ConfigSchema` is a JSON Schema for the collector's config.
  The SDK checks the config against it before the handler runs, and skips
  the keys it reads itself, such as `level`. A config that does not match
  fails the run with `config_invalid`. The error gives each bad value's JSON
  pointer. This keeps a malformed value from being read in as a default
- A scaffolded collector declares its config schema in
  `docs/schema/config.json`, and its spec passes that file as
  `ConfigSchema`. It declares the permission each call needs with
  `Operation.Permission`, so its gaps record the missing permission without
  an option
- `componentsdk.Vocabulary` holds the values a vendor's field can take. They
  come from a file that is refreshed from the vendor's catalog. `Must`
  panics at startup on a constant the vocabulary lacks, such as a misspelled
  event type. `Seen` adds a value that the vendor sent and the vocabulary
  lacks to the collector result's `unrecognized` list. The list has a count
  at every level and the values at the audit level. The test kit's
  `vocabulary` check reports a scenario whose answers contain such a value
- `Suite.FieldSensitivity` turns on the test kit's `fields` check. The check
  changes one state field at a time in each operation's answers, such as a
  status, an enabled flag, an operator, or conditions. It reports a field
  whose change leaves every value the same in an object the collector reads.
  `Suite.IgnoredFields` exempts a field the collector may ignore. On Okta's
  recording, the check finds policy rule conditions the collector never
  reads
- `Suite.ResponseSchemas` maps an operation to the JSON Schema of its
  successful answer, as the vendor's API spec defines it. The test kit's
  `responses` check validates every scenario's canned answers against that
  schema and reports any field the schema does not define. Okta's
  hand-written token answers carry a status field that Okta never sends. The
  check reports it against Okta's published ApiToken schema
- `evidencepack/cloud-posture@v1` has a `database` object with
  `encryption_pct`, `public_access_blocked_pct`, and `multi_az_pct`.
  `multi_az_pct` and the counts behind the percentages are audit-level, and
  `databases_present` is written at every level. The schema also has
  `threat_detection.enabled`, which is true when threat detection is on in
  every enabled region. `backup.retention_days_min` is null when no resource
  has backups enabled
- The descriptions of `cloud-posture`'s `ssh_open_to_world_pct` and
  `rdp_open_to_world_pct` match what the collectors count. They count
  security groups or network security groups with a rule open to any
  address. On Google Cloud they count firewall rules open to any address
- A percentage over an empty population is null in a normalized artifact,
  as it is in a collector's own artifacts. A left-out percentage therefore
  means a failed read. The `population` check reports a percentage left out
  with no gap when its denominator is 0 or its `x-epack-present` flag is
  false
- Every percentage in the `idp-posture`, `vcs-posture`, and `cloud-posture`
  schemas points to the counts it is taken from, and the `ratios` and
  `population` checks run on them. Each percentage has a numerator count at
  the audit level. A percentage that had no denominator has one at the
  audit level, with a present flag at every level. These denominators and
  flags are:
  - `user_security.user_count` and `users_present`
  - `app_security.app_count` and `apps_present`
  - `lifecycle.account_count` and `accounts_present`
  - the top-level `repository_count`, `scanned_repository_count`, and
    `repositories_present`
  - `storage_resource_count`, `security_group_count`, and
    `scanned_resource_count`, each with its present flag

  The privileged percentages keep `privileged_users_count` as their
  denominator. `policy.mfa_required_coverage_pct` is taken over
  `user_security.user_count`
- `evidencepack/idp-posture@v1` marks `privileged_users_count`,
  `super_admin_count`, `standing_privileged_users_count`, and
  `authorized_third_party_apps_count` as audit-level. It adds
  `privileged_users_present` and `standing_privileged_users_present` at
  every level. The privileged percentages are null when
  `privileged_users_present` is false
- A gap can carry collection guidance from `componentsdk.Fix`, `NoAction`,
  or `Decide`. A gap holds at most one of them, and it is written at every
  level. Below the audit level, the SDK redacts from it the principal's ID
  and tenant and the identifiers in the run's scopes and config. When it
  redacts any, the test kit's `guidance` check reads the advice from an
  audit run. The scope set with `componentsdk.Scope` is written from the audit level, like the
  gap's warning. A second piece of advice on one gap is a `guidance` check
  finding, and the gap keeps the first. A choice with fewer than two options
  is also a finding
- `Recorder.Warn` records a warning about the whole run in the collector
  result's `warnings` list. It takes the same advice options as a gap, and
  a missing permission. The advice and missing permission are written at
  every level, and the message and scope from the audit level
- The test kit's `guidance` check reports advice that contains a value from
  the scenario's answers or config that identifies a resource, person, or
  account. The check recognizes such a value by its field's name. It also
  recognizes the fakes that a recording's scrubbing writes for an email
  address, GUID, or AWS account number, wherever they appear, such as an
  account number inside an ARN
- `componentsdk.Recorder.Warnings()` returns the run warnings recorded so
  far, as `Gaps()` does for gaps. It is for tests that run a collector's
  code without `RunInProcess`
- `collectortest.CheckNames()` returns the names of the test kit's checks.
  `Suite.SkipChecks` takes these names, and `Violation.Check` holds one
- `componentsdk.Percent(count, total, rounding)` returns a whole percentage
  rounded with `RoundDown`, `RoundUp`, or `RoundNearest`. It returns nil
  when there is nothing to count

### BUG FIXES

- Redaction no longer hides a long run that reads as words, such as the AWS
  error code `ServerSideEncryptionConfigurationNotFoundError` or the
  Microsoft Graph path `/reports/authenticationMethods/userRegistrationDetails`.
  A gap's detail showed such a run as `[REDACTED]`, which hid the call or
  error to act on. A run with digits, `+`, or `=` that does not read as words
  is still hidden
- `Recorder.Mirror` no longer copies the `not_shared` gap of an artifact the
  `collect` key left out onto the value it copies. A collector that called
  `Selected` on its detailed artifact before mirroring from it failed in
  `Emit`, with the copied value written and a gap on it

- `CollectorSpec.Methods` places a sentence on a map's values, through the
  map's `additionalProperties`, with `*` or any key as the last token, such
  as `/fleet/devices_by_os/*`

- `epack sdk map` finds the code behind an artifact whose path comes from
  `componentsdk.ArtifactPath`, called in place or through a package-level
  variable. It used to find code only for a path written as a constant, so
  a detailed artifact named that way had no code lines in its trace map

- `componentsdk.NextLink`, and the test kit's `pages` check with it, skip a
  next link marked `results="false"`. Sentry's API marks its last page that
  way, so a Sentry list stops there

- The test kit's `tracemap` check now reports a committed map whose source
  lines no longer match the collector's code, and a gap line the map does
  not list. It used to miss stale line numbers that `epack sdk map --check`
  caught
- Two suites in one package that share a name no longer overwrite each
  other's output under `COLLECTORTEST_OUT`. The second is an `export`
  violation that asks for a `Suite.Name` of its own

### UPGRADE NOTES

- A collector that writes a normalized artifact fails the test kit's
  `methods` check until each number and true-or-false value in it has an
  `x-epack-method`, in the collector's schema or on the detailed value it
  copies. A collector also fails it until each such value a trust run writes
  in its detailed artifact has one. Mark the detailed schema `audit` at its
  root when a normalized artifact carries what profiles read
- A collector that writes an artifact with a schema ID fails the test kit's
  `writes` check until `CollectorSpec.Writes` lists it
- A reader of collector results finds the new gap codes `not_shared` and
  `not_read` and the new `collect` object. A `not_read` gap names a value the
  collector could read in a later release, so a page can say so instead of
  saying the vendor doesn't report it. A `not_shared` gap is the customer's choice, so it
  needs no fix and does not count against collector health
- A collector that writes `evidencepack/cloud-posture@v1` fails the test
  kit's `levels` check at the trust level until it leaves out the fields the
  schema marks audit. Write the present flags, such as
  `storage_resources_present`, beside the counts
- `evidencepack/cloud-posture@v1` no longer has `iam`, `vuln_scanning`, or
  `workforce_sign_in`. `evidencepack/vcs-posture@v1` no longer has
  `org_security` or `security_features`. Sign-in, members, admins, root
  accounts, and machine credentials are in `evidencepack/access-posture@v1`,
  and scanner coverage is in `evidencepack/vuln-scanning@v1`. A collector
  writes those files instead. A profile or field guide that reads an old
  field reads its new one. Each field moves as follows
  - cloud-posture's `accounts[*].iam` `users_present`, `user_count`,
    `mfa_user_count`, and `mfa_coverage_pct` move to access-posture's
    `members.local_members_present`, `local_member_count`,
    `local_mfa_member_count`, and `local_mfa_coverage_pct`
  - `iam.root_mfa_enabled` moves to `root.root_mfa_coverage_pct`.
    `iam.root_access_protected` is now `root_mfa_coverage_pct` at 100 with
    `root_access_keys_present` false
  - `iam.access_keys_present` and `access_key_user_count` move to
    `credentials.credentials_present` and `credential_count`
  - `iam.access_key_rotation_compliant_pct` and
    `rotation_compliant_user_count` move to `credentials.rotation_overdue_pct`
    and `rotation_overdue_credential_count`, which count the keys that are
    not rotated in time
  - `iam.saml_providers_present` and `workforce_sign_in.in_use` move to
    `sign_in.sso_configured`. `iam.saml_provider_count` has no new field.
    `workforce_sign_in.user_count` moves to `members.sso_member_count`.
    `workforce_sign_in.mfa_source` has no new field, since idp-posture holds
    MFA for sign-ins through an identity provider
  - cloud-posture's `vuln_scanning` moves to a vuln-scanning scanner entry.
    `enabled` becomes the entry's `enabled`, `scanned_resources_present` its
    `resources_present`, and `scanned_resource_count` its
    `scanned_resource_count`. `unpatched_resource_count` and `unpatched_pct`
    have no new field. The entry's open findings by severity, and
    `overdue_present`, take their place
  - vcs-posture's `org_security.two_factor_required` moves to
    access-posture's `sign_in.mfa_required`
  - vcs-posture's `security_features` moves to vuln-scanning entries for
    Dependabot, secret scanning, and code scanning. Each `*_pct` becomes the
    entry's `coverage_pct`, and each `*_repository_count` its
    `scanned_resource_count`, with the repositories collected as its
    `resource_count`
  - A system with several accounts or subscriptions lists each one in
    access-posture's and vuln-scanning's `scopes`, at the audit level
- In `evidencepack/access-posture@v1`, a member or admin is local when they
  can sign in without SSO, even if their account is linked to SSO. Local and
  SSO members can overlap when the system doesn't require SSO. A credential
  is unrestricted when it has neither an IP limit nor a scope narrower than
  full access. A credential limited to chosen permissions or resources has a
  narrower scope. With scopes, each top-level `sign_in` value is false when
  any scope's is false, null when any other is null, and true otherwise
- A member of `evidencepack/access-posture@v1` or a user of
  `evidencepack/idp-posture@v1` is inactive with no sign-in or other recorded
  activity in the last 90 days. access-posture leaves out the rotation counts
  with a gap when the system doesn't record when a credential was created
- In `evidencepack/vuln-scanning@v1`, a scanner turned on per resource, such
  as per repository, is `enabled` when it is on for at least one resource.
  `coverage_pct` gives the share it covers
- `evidencepack/endpoint-posture@v1`'s `scope.discovery_complete` may be
  null, so a collector that can't tell writes null with a gap
- `evidencepack/endpoint-posture@v1`'s `availability` reasons include
  `not_read`, for a metric the vendor reports but the collector doesn't read
- A reader of trust-level collector results finds operations without
  `calls`, `attempts`, or `retries` and steps without times or counts. Read
  `retried`, `status_codes`, `error_codes`, and `any_failed` instead
- A collector fails the test kit's `pages` check when its scenarios offer a
  next page that it never requests. Read every page, or list a polling API
  or a deliberate cap in `Suite.Capped`. For example, Okta's recording
  offers a System Log page that its collector does not read
- A collector fails the test kit's `order` check when its values depend on
  the order a vendor lists things in. For example, the AWS collector judges
  a trail bucket's retention by whichever trail DescribeTrails lists first
- `evidencepack/email-dns@v1` follows RFC 9989, which replaces RFC 7489 for
  DMARC. `enforced` and the summary's enforced values count a domain as
  enforced when the policy that applies to it rejects failing mail. That is
  p=reject on the domain's own record, or a subdomain policy of reject on
  the record the DNS tree walk finds above the domain. The subdomain policy
  is sp, or p when the record has no sp. In either case the record must not
  set t=y. A legacy pct tag does not affect these values. `has_reporting`
  and the reporting values need a valid rua URI, so an address without
  mailto: does not count. `policy` is none for a record that lists a valid
  rua URI but has no valid p tag. An email-dns collector changes its values
  to match and lists each changed value in its changelog
- A collector that writes `evidencepack/endpoint-posture@v1` fails the test
  kit's `levels` check at the trust level until it leaves out the fleet
  counts, `scope.observed_device_count`, and `metric_coverage`. It must
  also write `fleet.devices_present`
- `evidencepack/endpoint-posture@v1` has no `policies`, `threat_events`,
  `device_actions`, `history`, or `inventories`, and a device row has no
  `prohibited_apps`. A collector keeps these in its own file. Counts use the
  same names as the other normalized schemas, so `fleet.devices_count` is
  `fleet.device_count`. The others are `scope.observed_device_count`,
  `fleet.managed_device_count`, `fleet.mdm_enrolled_device_count`, and the
  `metric_coverage` counts such as `passing_device_count`. The JumpCloud
  collector writes the old names and these sections until it updates to
  this SDK. A profile or field guide that reads them needs the new names
- `email-dns`'s `with_dmarc_count` and `with_all_three_count` count a domain
  when a DMARC record applies to it. That record is the domain's own or the
  one the DNS tree walk finds above it. `enforced` uses the same record
- A collector that leaves out a percentage over an empty population fails
  the test kit's `population` check until it writes null. For example, the
  Okta and Microsoft Cloud collectors leave out the privileged MFA
  percentages for a tenant with no privileged users
- A collector that writes `idp-posture`, `vcs-posture`, or `cloud-posture`
  writes the counts behind each percentage at the audit level, and the
  present flags at every level. The checks use the counts to recompute its
  percentages, and the flags to recognize an empty population at the trust
  level
- A collector that writes `evidencepack/idp-posture@v1` fails the test kit's
  `levels` check at the trust level until it leaves out the privileged and
  app counts. It must also write `privileged_users_present` and
  `standing_privileged_users_present`. The Okta and Microsoft Cloud
  collectors do not do this yet. A Foundational Controls 1.x profile that
  tests `super_admin_count` on a trust-level stream shows Not collected once
  its collector updates, because the count is written from the audit level
  only
- A collector gets a `ratios` finding when it rounds a normalized percentage
  differently from the schema's `x-epack-rounding` and the schema points to
  the percentage's counts. The TLS and email-dns summaries point to their
  counts. For example, rounding a TLS `expiring_soon_pct` or
  `legacy_protocol_supported_pct` down is a finding
- `componentsdk.Gap` gets its `Schema`, `Path`, and `Pointer` fields from an
  embedded `Location`. It reads and writes them as JSON the same way as
  before. A `Gap` literal that sets those fields, as tests do, must set them
  in `Location`, as in `Gap{Location: Location{Path: p, Pointer: "/users"}}`.
  Go 1.27 accepts the old form too. The Microsoft Cloud and Sentry
  collectors' tests build such literals
- A reader that takes the level from an artifact's `collected_at_level`
  should read the collector result's `run.level`, and fall back to
  `collected_at_level` for older collectors. A collector's own file can be
  missing at a level, as GitHub's is at trust. The normalized schemas do not
  declare `collected_at_level`, `endpoint-posture` rejects it, and new
  scaffolds do not write it
- A collector fails the test kit's `labels` check until each number and
  true-or-false value in its own artifacts has an `x-epack-label` and an
  `x-epack-summary`. `SkipChecks: []string{"labels"}` turns the check off
- A collector whose `CollectorSpec.Schemas` holds its own copy of a
  normalized schema fails the `normalized` check. Move its `x-epack-method`
  sentences into `CollectorSpec.Methods` and drop the copy.
  `SkipChecks: []string{"normalized"}` turns the check off
- A collector fails the test kit's `paths` check until each data artifact
  sits at `componentsdk.ArtifactPath(collector, schemaID)`. Its detailed
  file moves from `artifacts/<collector>.json` to
  `artifacts/<collector>.details.json`. A reader that finds artifacts by
  path should find them by kind instead, or follow the new paths
- A reader of collector results should accept the gap codes `unsupported`
  and `too_large`. A run whose only gaps are `unsupported` is `collected`
- `componentsdk.GapOption` is now `componentsdk.AdviceOption`, since run
  warnings take the same options. `GapOption` remains as a deprecated alias,
  so code that names it still compiles

## [0.9.9] - 2026-10-26

### BUG FIXES

- `make lint` in a project from `epack sdk new collector` runs golangci-lint
  under the Go release in go.mod's `toolchain` line, which is the one CI
  installs. With a newer Go installed, such as Go 1.27, golangci-lint v2.9.0
  panicked with "file requires newer Go version"
- epack-conformance fails C-020 and COL-040 when a collector given `--config`
  and `--secret` exits 2 on the run that should collect: it rejected a config
  it should collect with. The failure names the config file and quotes the
  last line of the collector's stderr. The output checks used to skip, and
  the run passed. Without `--secret`, exit 2 still skips them, since a
  collector with no credentials can exit 2 too

### UPGRADE NOTES

- A collector whose credential must parse before it is used, such as a JSON
  key, fails to parse the `--secret` canary. If it reports that as a config
  error (exit 2), it now fails conformance when `--config` is given. As an
  authentication error (exit 3), the output checks skip and COL-043 passes

## [0.9.8] - 2026-10-23

### ENHANCEMENTS

- `epack sdk new collector` writes a collector that can be tagged without
  hand edits:
  - go.mod has a `toolchain` line matching epack's, so CI and release builds
    use that Go release instead of the older one the `go` line names. Tools,
    remotes, and utilities get the same line
  - `release.yaml` creates a draft when the repository variable
    `SANDBOX_RELEASE_CHECK` is `true`. The new `publish.yaml` publishes the
    draft once a passing `sandboxes` commit status arrives from the account
    in `SANDBOX_STATUS_SENDER`. Without the variable, a tag publishes at once
  - `TestRecord/<name>` records the sandbox organization in
    `SANDBOX_<NAME>_ORGANIZATION` to
    `internal/collector/testdata/recordings/<name>.json`, and replaces each
    `SANDBOX_` value and the names in the responses with fakes. The kit runs
    the recording once it exists, and `TestRecordingsScrubbed` checks the
    committed file
  - `TestConformanceListsEveryCredential` fails when `conformance-secrets` in
    ci.yaml or `CONFORMANCE_SECRETS` in the Makefile leaves out a credential
    the kit uses
  - The docs give the source as `<owner>/epack-collector-<name>@^0.1`, taken
    from the module path, and link between pages by full GitHub URL, since
    registry.epack.dev resolves relative links from the repository root
  - The project includes `docs/levels.md` and epack's Apache 2.0 `LICENSE`

### BUG FIXES

- `epack sdk new collector` puts the API client of a collector named
  `collect`, `location`, or `percent` in `internal/api`. Its package used to
  share the name of a function in `internal/collector`, so the scaffold did
  not compile

## [0.9.7] - 2026-10-23

### ENHANCEMENTS

- componentsdk: the normalized cloud-posture schema lists the counts behind
  two of each account's IAM percentages: `user_count` for `mfa_coverage_pct`
  and `access_key_user_count` for `access_key_rotation_compliant_pct`. When a
  count is 0, a collector leaves its percentage out. `saml_provider_count`
  counts the SAML identity providers an account trusts directly for sign-in
- componentsdk: the normalized cloud-posture schema has an optional
  `workforce_sign_in` object for a central sign-in service such as AWS IAM
  Identity Center, with `in_use`, `user_count`, and `mfa_source`
  (`sign_in_service`, `external_idp`, or `unknown`)
- componentsdk: the cloud-posture schema describes
  `access_key_rotation_compliant_pct` as a share of the users
  `access_key_user_count` counts, which is how the AWS collector computes it.
  It used to describe a share of credentials

## [0.9.6] - 2026-10-22

### ENHANCEMENTS

- collectortest: `RecordOptions.Codec` and `Suite.Codec` take a `BodyCodec`
  that turns bodies like a gRPC API's protobuf messages into JSON and back.
  `Record` scrubs the JSON with the same rules as a JSON body, runs the
  scrub check on it, and writes it with `"body_encoding": "codec"`. A body
  the codec cannot decode, or cannot encode after scrubbing, fails the
  recording
- collectortest: the kit's runs encode a recording's codec bodies with
  `Suite.Codec`, so field lengths and gRPC framing match the scrubbed
  values. `RequestBody` matches the JSON the codec decodes a request's body
  to, so calls that differ only in their gRPC request get their own
  answers. `NewReplay` returns an error for a codec recording because it has
  no codec
- collectortest: the sensitivity check changes the bodies `Suite.Codec`
  decodes the same way it changes JSON. It used to list their operations as
  unmutated

## [0.9.5] - 2026-10-22

### ENHANCEMENTS

- componentsdk: a failed dial returns an error that names its call, and so
  does a timeout or reset on a dialed connection. A gap recorded from either
  names the call too, so a collector that dials through the SDK can turn on
  collectortest's `GapOperations` check
- componentsdk: a failed DNS lookup returns an error that names its call, so
  a gap recorded from it names the call too. A name or record that does not
  exist still returns `net.Resolver`'s `*net.DNSError` as it is
- componentsdk: the normalized email-dns schema lists the summary counts
  behind its percentages: `with_mx_count`, `with_spf_count`,
  `with_dmarc_count`, `with_dkim_count`, `with_all_three_count`,
  `enforced_count`, and `with_reporting_count`
- componentsdk: the normalized TLS schema lists the summary counts behind its
  percentages: `reachable_count`, `certificate_valid_count`,
  `hostname_valid_count`, `modern_protocol_count`, `expiring_soon_count`, and
  `legacy_protocol_supported_count`

### UPGRADE NOTES

- A failed lookup or dial returns an error that wraps the `*net.DNSError` or
  `*net.OpError` instead of returning it as is. Get it with `errors.As`
  rather than a type assertion

## [0.9.4] - 2026-10-21

### ENHANCEMENTS

- collectortest: `Record` can record CBOR responses, such as those from AWS
  services on the Smithy RPC v2 CBOR protocol. It decodes each
  `application/cbor` body and scrubs its strings, map keys, and integers with
  the same rules as text bodies. The scrub check reads the decoded body too,
  and a body that does not decode fails the recording
- collectortest: recordings store a body that is not UTF-8 as base64 with
  `"body_encoding": "base64"`. Replays return the same bytes
- collectortest: the sensitivity check changes CBOR responses the same way it
  changes JSON responses. It used to skip them and list the operation as
  unmutated

### BUG FIXES

- epack is built with Go 1.26.10, which fixes GO-2026-6809 in `crypto/x509`

### UPGRADE NOTES

- collectortest imports `github.com/aws/smithy-go`. After bumping epack in a
  collector, `go mod tidy` adds it as an indirect requirement

## [0.9.3] - 2026-10-20

### BUG FIXES

- `epack sdk map` finds the code behind the fields of a type whose
  `MarshalJSON` marshals the value as a local type with the same fields, such
  as `type entry Entry` and then `json.Marshal(entry(e))`. This also works when
  the method deletes keys from the result, or embeds the value in a struct
  that overrides a field's `json` tag to drop `omitempty`

## [0.9.2] - 2026-10-20

### BUG FIXES

- `epack sdk map` finds the code behind a field whose type has a
  `MarshalJSON` of exactly `return json.Marshal(v.Field)`, such as a generic
  `Lookup[T]` that encodes as its record, and behind the fields under it.
  It used to stop at any type with its own `MarshalJSON`
- `epack sdk map` finds a write through a generic type that two of the
  collector's packages instantiate with the same type arguments

### ENHANCEMENTS

- `epack sdk map` prints a warning on stderr for each field that operations
  feed but that has no code. The warning does not change the exit code

## [0.9.1] - 2026-10-20

### BUG FIXES

- `epack verify --json` writes `log_id` as the log's hex-encoded key ID, such
  as Rekor's `c0d23d6a...`, instead of raw bytes

## [0.9.0] - 2026-10-20

### NEW FEATURES

- **Traceable run records** - Collectors on this SDK record enough about each
  run to trace a value to the calls and code behind it:
  - Request rows gain `call`, `step`, `start_ms`, `waited_ms`, and
    `vendor_code`, which the new `HTTPOptions.VendorCode` hook reads. Past
    the first 1,000 rows, up to 1,000 more failed or retried rows are kept,
    and `problem_requests_dropped` counts the ones left out
  - `componentsdk.StartStep` names the steps of a run, and the result lists
    each step's timing, requests, retries, and operations at every level
  - Gaps gain `operation`, `call`, `source`, `missing_permission`, and
    `warning`, with `componentsdk.ResponseError`, the `MissingPermission` and
    `Warning` gap options, and `Recorder.Helper`
  - `signed_in_as` gains `auth_method`, `requested_scopes`, and `read_only`
- **Build file** - Each run adds `artifacts/<collector>.collector-build.json`
  (`evidencepack/collector-build@v1`) with the collector's schemas and trace
  map. Its bytes are the same for every run of one build
- **Trace maps** - `epack sdk map` builds a collector's trace map from its
  collectortest suites and source: for each output field, the operations
  that feed it and the code lines that compute it. `--check` fails on a stale
  map, and collector CI gains a `trace-map` job that runs it
- **Checkable arithmetic** - `x-epack-numerator` and `x-epack-rounding`
  (`floor`, `ceil`, or `nearest`) schema keywords, and a `ratios` output check
  that each percentage matches its numerator and denominator
- **Signature details in `epack verify`** - Each signature's log entry, CI
  run, and source commit, in text output and as `log_index`, `log_id`, and
  `certificate` in `--json`, offline too
- **Conformance checks COL-075 to COL-080** - Run records and build files
  match their schemas and agree with each other, and nothing audit-only
  appears at the trust level. Each check skips what a collector does not
  write, so results from older SDKs pass

### ENHANCEMENTS

- collectortest: `Suite.GapOperations` checks that each fault's gaps name the
  faulted operation, a committed trace map is checked on every suite run, and
  `COLLECTORTEST_MAP` exports the traces `epack sdk map` reads
- The rollups check skips rows the run's level leaves out
- DNS lookups and dials get a call number, start time, and step
- `epack-collector-diff` ignores build files, so moving a line of collector
  code is not an evidence change
- `epack sdk new collector` scaffolds steps, a whole-number percentage with
  its numerator and rounding, the vendor code hook, and a committed trace map
- Suites with a large trace map run faster: the kit validates the build file
  once per suite, and only scenario runs carry the map

### UPGRADE NOTES

- A collector on this SDK adds a build file to every pack. Tests that count
  its artifacts see one more, and tools that list evidence may want to skip
  it, as they skip the collector result
- Errors from the SDK's HTTP transport now wrap their cause, so find it with
  `errors.As` or `errors.Is` rather than a type assertion
- `StartStep` prints the step's title as a status line, so drop status lines
  that repeat it
- Call `Recorder.Helper()` in a collector's own gap-recording helpers, or a
  gap's `source` names the helper instead of its caller

## [0.3.2] - 2026-09-03

### NEW FEATURES

- **Control Mappings** - Seal publisher-authored evidence-to-control mappings
  (`evidencepack/control-mapping@v1`) into packs:
  - `mappings:` section in `epack.yaml` declaring local mapping files
  - Mapping files are locked by digest in `epack.lock.yaml`, drift-checked,
    and verified under `--frozen`
  - `epack collect` seals each mapping into the pack as an ordinary embedded
    artifact (`artifacts/<name>.json`) stamped with the mapping schema; YAML
    input is emitted as deterministic JSON
  - `epack build --mapping <path>` seals a mapping in the core build path
  - Build-time warnings (never failures) for malformed entries, entries citing
    artifacts the pack does not carry, and mappings pinned to a profile digest
    that matches no locked profile
  - `epack inspect` shows a Control Mappings section; the collect summary
    reports sealed mapping entries
  - Lock provenance summaries gain a `mappings` section beside profiles and
    overlays

## [0.3.1] - 2026-08-25

### NEW FEATURES

- **Windows support (core build)** - `epack-core-windows-amd64.exe` and `epack-core-windows-arm64.exe` release binaries with the same SLSA Level 3 provenance as other platforms. Windows covers pack operations (build, sign, verify, inspect, list, extract, merge, diff); collector and tool execution remains macOS/Linux and fails closed on Windows

### ENHANCEMENTS

- Dependency updates for published advisories: sigstore-go v1.2.1 (multi-log threshold bypass GHSA-9vcr-p3rj-q5q6, signing key validity period GHSA-wqqc-jjcq-vfxm) and grpc-go v1.82.1 (GHSA-hrxh-6v49-42gf)
- Path validation rejects rooted paths (`/foo`, `\foo`, `C:foo`) on every platform, closing a Windows-only gap where such paths passed relative-path checks

### BUG FIXES

- Merge, `list --filter`, and `extract --filter` operate on canonical slash paths, fixing broken merges and glob matching on Windows
- Recursive `**` result globbing during push handles Windows drive-letter paths

### UPGRADE NOTES

- Config paths that begin with `/` or `\` or carry a drive prefix are rejected on every platform; use paths relative to the project root

## [0.1.11] - 2026-02-25

### NEW FEATURES

- **Unified Catalog Search** - `epack catalog search` command searches all component types (collectors, tools, remotes, utilities) with optional `--kind` filter
- **Catalog Refresh** - `epack catalog refresh` fetches latest catalog from registry with ETag/Last-Modified caching
- **Global Utility Management** - New `epack utility` command for managing user-installed utilities:
  - `epack utility install <name> <source>` - Install from GitHub releases with Sigstore verification
  - `epack utility list` - List installed utilities with version and signer info
  - `epack utility remove <name>` - Remove installed utilities
- **Utilities Lock** - Global utilities tracked in `~/.epack/utilities.lock` separate from project config

### ENHANCEMENTS

- Catalog schema extended to support all component kinds with backwards-compatible `tools` array
- `CatalogComponent` type replaces `CatalogTool` (alias maintained for compatibility)
- `SearchWithOptions()` method allows filtering search by component kind
- `AllComponents()` and `ComponentsByKind()` methods for flexible catalog queries

### UPGRADE NOTES

- The `epack tool catalog` subcommand is deprecated in favor of the top-level `epack catalog` command
- Catalog JSON format now supports `collectors`, `remotes`, and `utilities` arrays alongside `tools`

## [0.1.0] - 2025-02-18

Initial release.

### NEW FEATURES
- `epack build` command for creating evidence packs
- `epack sign` command with keyless (OIDC) and key-based signing
- `epack verify` command for integrity and attestation verification
- `epack inspect` command for viewing pack contents
- `epack list` command for listing artifacts, attestations, and sources
- `epack extract` command for extracting artifacts
- `epack merge` command for combining multiple packs
- `epack diff` command for comparing pack contents
- JSON output mode for all inspection commands
- Golden file testing infrastructure
- CLI acceptance tests
