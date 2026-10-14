# Rust SDK conformance driver

This separate Cargo package runs actual generated Rust SDK methods. The shared
coordinator owns peers, fixtures, clocks, builds, deadlines and case verdicts.
The driver is not a runtime workspace member; root CI does not test this package.

Rust support is in development and is not yet listed as supported. Results from
this driver are evidence toward that decision, not a support claim.

## Prepare a pinned declaration

The conformance coordinator requires each declaration to carry `driverCommit`,
the full 40-character commit of the driver source, and validates it before
building. The coordinator also fixes every compiler input itself; a declaration
supplies only the tool, the entry path and the feature list. A committed
declaration cannot contain its own commit hash, so `driver.json.template` is
materialized at the root of a temporary source export, beside the runtime's
`Cargo.toml`. This preserves the runtime source and enables its owned Cargo patch.
Do not commit the generated root declaration; it belongs to one run and would
otherwise ship with the source.

From a clean, committed repository root:

```sh
driver_commit="$(git rev-parse HEAD)"
driver_source="$(mktemp -d)"
git archive "$driver_commit" | tar -x -C "$driver_source"
python3 - "$driver_source" "$driver_commit" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
declaration = json.loads((root / "conformance-driver/driver.json.template").read_text())
declaration["driverCommit"] = sys.argv[2]
(root / "driver.json").write_text(json.dumps(declaration, indent=2) + "\n")
PY
# Pass "$driver_source/driver.json" as the coordinator's -driver-declaration.
# Remove "$driver_source" after the coordinator exits.
```

The declaration supplies `tool: cargo`, a relative manifest `entry`, and empty
`features`. The coordinator selects Rust 1.99.0, adds `--features conformance`,
and owns the manifest, target directory, offline caches and executable location.
The package's committed `Cargo.lock` is required by `cargo build --frozen`.
Both generated packages use the fixed `chickinfry-client-plain` and
`chickinfry-client-auth` dependencies, connected through coordinator-owned Cargo
patches. Driver source contains no generated SDK path or environment-selected SDK.

The binary accepts the coordinator's `--plain-sdk PATH --auth-sdk PATH` arguments;
the native SDK binding is compiled in, so those paths do not select or load source.
Standalone diagnostic launches may omit both arguments.

## Protocol and current limitations

Execution specifications, suites and result rows use schema version 3; the
process protocol remains version 1. The coordinator rejects version 2 inputs
and evidence. Each `client.create` must provide `fixture: "plain"` or `"auth"`;
missing, unknown or mistyped selectors return `invalid_args`. Copies retain the
source fixture. Both bridges call the corresponding generated typed SDK.
The driver connects the fixture's probe operations and the auth fixture's
signup, signin, identity, refresh, session and logout operations.

With SDKs and `conformance`, the handshake advertises `client.create`,
`client.copy`, `client.call`, `session.store`, `barrier`, `session.trace` and
`client.transport`. `client.observe` returns the exact eight-field events and
a global sequence watermark, including while SDK calls are pending. Reads are
published from each HTTP exchange; stored-session calls project only the final
exchange's headers and closure at selection time; the first excessive read
is immediately followed by its limit event. The completion event
is emitted once after the generated SDK returns. A watermark selects an interval,
not a promise that the SDK call has completed.

Barriers observe actual runtime entry, original 401 rejection, and both leader
and follower joining the same refresh flight. The follower waits at the runtime
flight join. The leader reports that same actual flight at the transport
response-wait entry, after its refresh request has been sent: the shared
coordinator releases `refresh-joined` only after the peer observes
`refresh-started` (coordinator README, C-09/C-10; `run/concurrent.go:190`).
Holding the leader before sending would prevent that peer observation.
The driver adds no refresh lock
or uncertain-result gate. Session records come from the protected pipe, with
all seven fields checked against the declared origin and credential references.
`session.store.create` also accepts an origin-bound empty store when all three
record/access/refresh references are absent; partial reference groups are invalid.
The driver delegates storage and atomic expected-credential clearing to the
runtime's public `MemorySessionStore`. It adds only revision and trace records
around the runtime store operations; the trace records each actual invocation with `expectedAccessRef`, `expectedRefreshRef` and `removed`.
The driver does not make an extra clear call when the runtime declines deletion.
`input`/`inputRefs` conflicts are rejected even when the literal is null.

SDK errors carry a boolean measured against the actual public error's code or
message in memory; raw exception strings never cross the protocol. Unknown
transport exception messages are reported as `rawTransportDetails: true`, so a
runtime leak fails rather than being hidden by driver sanitization. Tool errors
have null status and outcome, and omit that SDK measurement. Constructor counts
observe entry into HTTP send and resolver functions without making a request.

### Response retention and transport scope

Native transport is pinned to `ureq 3.4.2` and `ureq-proto 0.6.4`. It uses HTTP/1.1
only; there is no HTTP/2 negotiation or receive window. The shared loopback peer
uses plain HTTP. TLS internal retention has not been established: a TLS exchange
reports null retained measurements and an incomplete snapshot, never a passing
retention bound. Remote HTTPS support requires separate verification.

For the plain HTTP path, the body-proportional component is the receiving Vec's
actual capacity, observed immediately after each read. The standard initialized
read sizes, 32-byte growth threshold and Vec allocation pattern are preserved
for Rust 1.99.0, and tested against its `Read::read_to_end` implementation.
The retained sum also includes the fixed library buffers below. No library I/O
buffer is excluded as transient: their combined 262144 bytes exceed 65536.
Header-time redirect rejection allocates no receiving body Vec and drops the
real response immediately. Cancellation is observed after the underlying
transport has been dropped, and reader closure is recorded separately.

| Pinned source | Allocation | Why it does not grow with this response body |
| --- | --- | --- |
| `ureq 3.4.2/src/config.rs:959-960` | input 131072 + output 131072 bytes | Fixed defaults; the driver does not resize them to pass |
| `ureq 3.4.2/src/unversioned/transport/tcp.rs:45-46` | One pair of `LazyBuffers` per TCP transport | Uses those configuration sizes |
| `ureq 3.4.2/src/unversioned/transport/buf.rs:96-101` | Lazy input/output allocations | Resizes to the configured fixed size |
| `ureq 3.4.2/src/unversioned/transport/buf.rs:120-136` | Request scratch reuses input | The shared peer waits for the request; its response cannot accumulate during `Await100` |
| `ureq 3.4.2/src/run.rs:630-707` | Decodes into the supplied receiving slice | Consumes input incrementally; no response-sized intermediate Vec |
| `ureq 3.4.2/src/unversioned/transport/mod.rs:1-8` | HTTP/1.1 transport | No HTTP/2 prebuffer or receive window |

These references describe the measured shared-peer path, not an unverified TLS,
compressed, proxy or unsolicited early-response path. Additional library buffers
on such a path must be measured or proven before using its retention evidence.

Initial credentials arrive only through inherited anonymous pipe fd 3 as JSON
Lines containing exactly string `ref` and `value`. Each line, including LF, is
at most 64 KiB; the whole bootstrap is at most 1 MiB. Registration is unique,
and EOF must be consumed before handshake. A regular file is rejected. There
is no credential environment or file fallback. Control messages carry references;
credentials and exception strings are not written to stdout or stderr.

With SDKs and `conformance`, scoped runtime observations support diagnostic
barriers and store traces. Default builds compile the runtime observation path
out. `--no-default-features --features conformance` omits SDK calls and advertises
neither `client.call`, `barrier` nor `session.trace`. Capabilities do not claim
that a shared case passes. Diagnostic store/refresh process tests use their own
case label and remain separate from shared-case adjudication.

## Checks with owned SDK patches

Prepare plain/auth SDKs through the product's `generate` command, then connect
their package metadata using the same owned patches as the coordinator. Run
these commands in that prepared source copy with the existing Cargo lock:

```sh
RUSTUP_TOOLCHAIN=1.99.0 cargo test --frozen --manifest-path conformance-driver/Cargo.toml --features conformance
RUSTUP_TOOLCHAIN=1.99.0 cargo test --frozen --manifest-path conformance-driver/Cargo.toml
RUSTUP_TOOLCHAIN=1.99.0 cargo test --frozen --manifest-path conformance-driver/Cargo.toml --no-default-features --features conformance
RUSTUP_TOOLCHAIN=1.99.0 cargo clippy --frozen --manifest-path conformance-driver/Cargo.toml --all-targets --features conformance -- -D warnings
RUSTUP_TOOLCHAIN=1.99.0 cargo fmt --all -- --check
RUSTUP_TOOLCHAIN=1.99.0 cargo fmt --manifest-path conformance-driver/Cargo.toml -- --check
```

Repeat clippy with default features off/on as above. The default-off test invokes
the generated SDK, performs actual automatic refresh/retry, and inspects that
debug test's symbols for the absence of runtime conformance observations.
Standalone checks and incomplete coordinator results do not establish customer
support; workerd, PostgreSQL and deployment require separate evidence.
