# devtools

A single Go binary of small, sharp macOS dev chores. Each chore is a subcommand,
so the toolbox grows without growing a pile of one-off shell scripts.

```
devtools web check <url>              diagnose DNS, TCP, TLS and HTTP in order
devtools ca export                    export TLS-inspection CAs as a PEM bundle
devtools teams away                   set Microsoft Teams presence
devtools launchd install ...          create and manage per-user LaunchAgents
devtools cron add ...                 manage devtools-owned crontab entries
devtools doctor                       check the local prerequisites
```

Every mutating command honours `--dry-run` / `-n`, which prints exactly what
would happen (the AppleScript, the plist, the crontab line) and changes nothing.
Every diagnostic command honours `--json` and sets a meaningful exit code, so it
drops straight into a launchd agent or a cron entry.

## Install

From a [release](https://github.com/neverprepared/devtools/releases) - pick the
archive for your platform, then verify it:

```sh
tar xzf devtools_<version>_darwin_arm64.tar.gz
shasum -a 256 -c checksums.txt --ignore-missing
install -m 755 devtools ~/.local/bin/devtools
```

With Go:

```sh
go install github.com/neverprepared/devtools@latest
```

From source:

```sh
make install              # builds to ~/.local/bin/devtools
make install PREFIX=/usr/local
make check                # go vet + go test
```

Use the **absolute** path (`~/.local/bin/devtools`) in launchd and cron entries:
neither runs with your shell's `PATH`.

### Signing

The darwin binaries in a release are signed with a Developer ID Application
certificate and submitted to Apple's notary service, so a copy downloaded
through a browser is not blocked by Gatekeeper. Check a binary yourself:

```sh
codesign --verify --strict --verbose=2 ./devtools
codesign -dv ./devtools 2>&1 | grep Authority
```

A bare command-line binary cannot carry a stapled notarization ticket -
`xcrun stapler` only handles `.app`, `.pkg` and `.dmg` - so `stapler validate`
reports no ticket and `spctl --assess` says "does not seem to be an app". Both
are expected. The ticket lives on Apple's servers and Gatekeeper checks it
online. Binaries you build yourself, including via `go install`, are unsigned.

### Platform support

`web check` and `cron` are portable. `teams`, `launchd`, and the
keychain-reading side of `ca` drive macOS-only interfaces (osascript,
`launchctl`, `/usr/bin/security`) and exit with a `requires macOS` error
elsewhere - Linux binaries are published, but that subset is what you get.
Run `devtools doctor` to check the local prerequisites.

## `devtools web check` - diagnose an endpoint

Walks the chain in order and names the first link that is broken, instead of
collapsing every possible cause into one opaque error. This replaces the
`dig` + `openssl s_client` + `curl -w` + `jq` pipeline.

```sh
devtools web check example.com                       # bare host implies https
devtools web check https://api.internal/health
devtools web check https://api.internal/health --json | jq .data.tls.days_left
```

What each phase reports:

| Phase | What you learn |
| --- | --- |
| `dns` | the CNAME chain, **which resolver answered**, and the address space of every answer (`private`, `public`, `cgnat`, `loopback`, `link-local`) |
| `tcp <ip>` | reachability of **every** resolved address, so one dead target behind a name is visible |
| `tls` | chain trust and hostname match reported **separately**, plus version and cipher |
| `cert` | CN, issuer, SANs, and days to expiry |
| `http` | status, protocol, the host that actually served it, and the redirect chain |
| `security headers` | advisory only: HSTS, CSP, nosniff, referrer and frame protection |

The split matters. A certificate that is untrusted is a different problem from
one issued for the wrong name, and both are different from one that has expired:

```
FAIL  tls   certificate is not valid for wrong.host.badssl.com: x509: certificate is valid for *.badssl.com, badssl.com, not wrong.host.badssl.com
            SANs: *.badssl.com, badssl.com
ok    cert  CN=*.badssl.com, issuer=YR1, 80 days left (expires 2026-12-28T20:02:55Z)
```

When TLS verification fails the request still runs over the untrusted
connection, so the report can tell you the server itself is fine and only the
certificate is wrong. That distinction is usually the whole answer.

### Private endpoints

The flags that matter for a name that resolves differently depending on where
you are standing:

```sh
# Ask a specific resolver. A private name that NXDOMAINs on the system resolver
# but answers here means the resolver is wrong, not the record.
devtools web check https://app.internal --resolver 10.0.0.2

# Skip DNS entirely and talk to one target, keeping Host and SNI intact.
# Proves whether the ALB or the name is at fault.
devtools web check https://app.internal --resolve-to 10.1.2.3

# Test a vhost before DNS exists.
devtools web check https://1.2.3.4 --host app.internal --sni app.internal
```

A DNS failure stops the chain and says so:

```
FAIL  dns  app.internal.example.com did not resolve via system (10.0.0.53): no such host
           a private name that fails here usually means the wrong resolver, not a missing record:
           retry with --resolver <vpc-resolver-ip>
```

### Assertions

```sh
devtools web check https://api.internal/health \
    --expect-status 200 \
    --expect-body '"status":"ok"' \
    --expect-body '!Exception' \
    --expect-header 'cache-control~no-store' \
    --expect-header '!x-powered-by' \
    --max-ttfb 500ms
```

| Flag | Forms |
| --- | --- |
| `--expect-status` | `200`, `2xx`, `200,204,3xx` |
| `--expect-body` | `text`, `~regex`, `!text` (absence). Repeatable. |
| `--expect-header` | `Name`, `Name=value`, `Name~regex`, `!Name` (absence). Repeatable. |
| `--max-ttfb` | a duration, e.g. `500ms` |

Exit codes, which are the contract for scheduled runs:

| Code | Meaning |
| --- | --- |
| 0 | everything passed (warnings allowed) |
| 1 | the check could not run: bad URL, bad flag |
| 2 | a step or assertion failed |
| 3 | warnings only, and `--strict` was given |

### Scheduling a check

This is where the `launchd` subcommand earns its keep:

```sh
devtools launchd install --name health-api --interval 5m -- \
    ~/.local/bin/devtools web check https://api.internal/health \
        --expect-status 200 --expect-body '"status":"ok"'

devtools launchd logs health-api
```

Other transport flags: `-X/--method`, `-H/--header`, `--timeout`, `-k/--insecure`
(downgrades verification failures to warnings; an expired certificate is still a
failure), `--min-tls`, `--no-follow`, `--max-redirects`, `--max-body`,
`--user-agent`, `--first-ip-only`, `--warn-cert-days`.

Two behaviours worth knowing: the connection is pinned to the exact address the
earlier phases probed, so the report describes one consistent path, and a
redirect elsewhere resolves normally. And because pinning is incompatible with
proxy semantics, the check always connects directly; if `HTTPS_PROXY` is set it
says so, since `curl` would then behave differently.

## `devtools ca` - TLS-inspection (DPI) CA certificates

Behind corporate TLS inspection, the proxy's root CA lands in the macOS
keychain. Every tool that carries its own trust store cannot see it there, so
`pip`, `npm`, `go`, `aws`, `git` and `cargo` all fail with "self-signed
certificate in certificate chain". They want a PEM file. This produces one.

```sh
devtools ca list            # what inspection CAs are installed
devtools ca detect          # is this connection being inspected right now
devtools ca export          # write the bundle
devtools ca env             # the environment variables that use it
```

```
$ devtools ca list
COMMON NAME           SOURCE  CA    EXPIRES             VENDOR / REASON
caadmin.netskope.com  login   true  2043-06-12 (6090d)  known inspection vendor: Netskope
```

Sources scanned: the login keychain (where a user-mode agent installs its
root), the system keychain (where MDM puts one), optional `--from-file` PEMs,
and optionally the live wire via `--from-url`.

### Two bundle shapes, because the tools want different things

This is the part that is easy to get backwards, so `ca env` does it for you:

| | Contents | Who wants it |
| --- | --- | --- |
| `ca export` | the inspection CAs only | `NODE_EXTRA_CA_CERTS`, which **adds** to Node's built-in store |
| `ca export --full-bundle` | inspection CAs **plus every Apple root** | `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `AWS_CA_BUNDLE`, `GIT_SSL_CAINFO`, `PIP_CERT`, `CARGO_HTTP_CAINFO`, which **replace** the trust store |

Hand a replace-style variable the inspection-only file and every public site
stops verifying. Export both, then:

```sh
eval "$(devtools ca env)"                      # this shell
devtools ca env >> ~/.config/shell/env.sh      # permanently
```

`ca env` also prints the `keytool` line for Java, which needs a keystore rather
than a PEM.

Files default to `~/.config/devtools/ca/mitm-ca.pem` and `ca-bundle.pem`.
Each certificate is written under a header giving its subject, issuer, SHA-256
fingerprint, validity and why it was selected, so the bundle is auditable;
`--no-comments` emits bare PEM for a strict parser. Every written bundle is
re-read and loaded into a certificate pool before the command reports success.

### Detecting inspection

```
$ devtools ca detect
CA DETECT  https://example.com

ok    leaf        CN=example.com, issued by CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US
ok    inspection  none: the chain anchors to an Apple-shipped root (SSL.com TLS ECC Root CA 2022)
```

Verification failing is **not** the test. An inspection proxy installs its root
into your keychain precisely so that verification succeeds. So `detect` verifies
the chain and then asks whether the root it anchored to is one **Apple ships**.
A root that is trusted locally but not shipped by Apple was installed on this
machine to sign traffic. When that is the case, the root found on the wire is
ground truth and feeds straight into an export:

```sh
devtools ca export --from-url https://example.com
```

### Unrecognised CAs

27 inspection products are recognised by subject (Netskope, Zscaler,
Palo Alto, Blue Coat, Forcepoint, Fortinet, McAfee, Cisco Umbrella, and the
local interception tools like mitmproxy, Burp, Charles and Fiddler). An internal
corporate CA matches none of them, so it is not exported by default. Find it and
select it explicitly:

```sh
devtools ca list --show-all                           # every certificate, classified
devtools ca export --include 'Example Corp Internal'  # select by subject regexp
devtools ca export --all-non-apple                    # every CA not in Apple's store
```

Expired certificates are dropped unless you pass `--keep-expired`.

## `devtools teams` - presence

Teams exposes no local API for presence, so devtools types the matching slash
command into the Teams command box (`Cmd+E`) with AppleScript.

```sh
devtools teams away
devtools teams busy
devtools teams available          # aliases: active, online, green, free
devtools teams dnd
devtools teams brb
devtools teams offline

devtools teams set dnd            # by name or alias
devtools teams statuses           # list what's available
devtools teams away -n            # print the AppleScript, change nothing
```

Focus is returned to whatever app was frontmost when the presence change
finishes. Pass `--no-restore` to leave Teams in front.

Timeboxed presence, which blocks until the timer elapses:

```sh
devtools teams set dnd --revert-after 45m             # back to available
devtools teams set busy --revert-after 1h --revert-to away
```

Tuning, for when a keystroke races the Electron UI on a cold app:

```sh
devtools teams away --activate-delay 1.5s --key-delay 300ms
devtools teams away --app "Microsoft Teams classic"
```

### One-time setup

AppleScript keystrokes need Accessibility permission for whichever app runs
devtools (your terminal, or `launchd` itself for scheduled runs):

**System Settings > Privacy & Security > Accessibility** -> enable your terminal.

`devtools doctor` tells you whether that is in place. The first scheduled run
may raise its own permission prompt, because launchd is a different requesting
process than your terminal.

## `devtools launchd` - scheduled agents

Writes plists to `~/Library/LaunchAgents` and loads them into your GUI session.
devtools only ever touches labels starting with `com.devtools.`, so your own
agents are left alone.

```sh
# Look busy during working hours, away at the end of the day.
devtools launchd install --name teams-busy --at Mon-Fri@09:00 -- \
    ~/.local/bin/devtools teams busy

devtools launchd install --name teams-away --at Mon-Fri@17:30 -- \
    ~/.local/bin/devtools teams away

devtools launchd list                 # label, loaded, pid, last exit
devtools launchd status teams-busy    # launchctl print output
devtools launchd run teams-busy       # kickstart it now
devtools launchd logs teams-busy      # tail the stdout log
devtools launchd logs teams-busy --stderr
devtools launchd cat teams-busy       # show the plist
devtools launchd uninstall teams-busy
```

Schedules:

| Flag | Meaning |
| --- | --- |
| `--interval 15m` | every 15 minutes (`StartInterval`) |
| `--at 09:00` | daily at 09:00 |
| `--at Mon-Fri@08:45` | weekdays at 08:45 |
| `--at weekdays@17:30` | same (aliases: `weekdays`, `weekends`, `daily`) |
| `--at mon,wed,fri@18:30` | those days |
| `--at '*@*:15'` | every hour at quarter past |

`--at` is repeatable and each spec expands to `StartCalendarInterval` entries.
`--interval` and `--at` are mutually exclusive.

Other flags: `--run-at-load`, `--keep-alive`, `--env KEY=VALUE` (repeatable),
`--workdir`, `--stdout`, `--stderr`, `--nice`, `--no-load`.

Logs default to `~/Library/Logs/devtools/<label>.{out,err}.log`.

launchd execs the program directly with no shell and almost no environment.
devtools resolves a bare program name through `PATH` at install time and refuses
a program that does not exist, so a typo fails at install rather than silently
at 09:00.

## `devtools cron` - crontab entries

```sh
devtools cron add --name teams-away --schedule "30 17 * * 1-5" -- \
    ~/.local/bin/devtools teams away
devtools cron list          # managed entries only
devtools cron list --all    # the whole crontab
devtools cron remove teams-away
devtools cron edit          # plain crontab -e
```

Managed lines carry a trailing `# devtools:<name>` marker. Anything without that
marker is never rewritten or removed, and re-running `add` with the same
`--name` replaces that line in place, so it is safe to run repeatedly.

On macOS, prefer `devtools launchd` for anything user-facing: cron needs Full
Disk Access for `/usr/sbin/cron`, does not run while the machine is asleep, and
does not catch up on missed runs.

## Layout

```
main.go                  signal handling + root command
internal/cli/            cobra command tree (one file per command group)
internal/web/            the DNS -> TCP -> TLS -> HTTP chain walk
internal/castore/        keychain and wire CA extraction, vendor detection, PEM output
internal/check/          shared assertion engine, report rendering, exit codes
internal/teams/          presence states and AppleScript generation
internal/launchd/        plist rendering, schedule parsing, launchctl plumbing
internal/crontab/        marker-scoped crontab editing
internal/osx/            osascript wrapper and app/permission queries
```

Adding a subcommand means a new `internal/cli/<thing>.go` with a
`new<Thing>Cmd()` constructor, registered in `NewRootCmd`, plus a package under
`internal/` holding the actual logic. The logic packages take no cobra
dependency and are unit-tested directly; the `cli` package only parses flags and
prints.
