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

Execution JSON uses schema version 2 and its required `fixture` map; there is no
driver fixture environment variable or argument. The current coordinator creates
a new fixture project and driver process per case, sets its working directory,
and sends only the target in handshake. It does not convey a plain/auth selector
to the driver. Until that contract exists, C-08, C-09 and C-10 explicitly return
`unimplemented`. The auth alias is declared but no fixture is inferred from a store,
working directory, filename or SDK path. Plain `probe.echo` retains its generated
typed call; list and explicit auth operations remain `unimplemented`.
Schema version 3 will select the SDK through `client.create.fixture`
(`plain` or `auth`), as confirmed in decision 6157261468.

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
