#!/usr/bin/env bash
#
# Sign and notarize one darwin binary. Invoked by GoReleaser's binary_signs
# hook, once per built darwin artifact, BEFORE archiving - the signature is
# embedded in the Mach-O, so the surrounding tar.gz preserves it.
#
# A bare Mach-O cannot be stapled (xcrun stapler only handles .app/.pkg/.dmg),
# so there is no ticket in the artifact. Notarization still matters: it
# registers this binary's hash with Apple, and Gatekeeper looks the ticket up
# online the first time a quarantined copy is run.
#
# No-ops when the signing environment is absent, so `goreleaser release
# --snapshot` works on a developer machine with no credentials.
set -euo pipefail

binary="${1:?usage: sign-and-notarize.sh <binary>}"

if [[ -z "${MACOS_IDENTITY:-}" ]]; then
  echo "sign: MACOS_IDENTITY unset, skipping signing of ${binary}" >&2
  exit 0
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "sign: codesign requires macOS, refusing to produce an unsigned release" >&2
  exit 1
fi

echo "sign: codesigning ${binary}"
# --options runtime (hardened runtime) and a secure --timestamp are both
# prerequisites for notarization; Apple rejects submissions without them.
codesign --force --timestamp --options runtime \
  --sign "${MACOS_IDENTITY}" "${binary}"
codesign --verify --strict --verbose=2 "${binary}"

if [[ -z "${NOTARY_KEYCHAIN_PROFILE:-}" ]]; then
  echo "sign: NOTARY_KEYCHAIN_PROFILE unset, signed but NOT notarized" >&2
  exit 0
fi

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT
zip="${workdir}/$(basename "${binary}")-notarize.zip"

# notarytool only accepts a container, never a bare executable.
ditto -c -k "${binary}" "${zip}"

echo "sign: submitting $(basename "${binary}") to Apple notary service"
submit_json="${workdir}/submit.json"
notary_args=(--keychain-profile "${NOTARY_KEYCHAIN_PROFILE}")
[[ -n "${NOTARY_KEYCHAIN:-}" ]] && notary_args+=(--keychain "${NOTARY_KEYCHAIN}")

xcrun notarytool submit "${zip}" \
  "${notary_args[@]}" \
  --wait \
  --timeout 30m \
  --output-format json >"${submit_json}"

# Parse with plutil, not python3: plutil ships unconditionally in /usr/bin and
# cannot be shadowed by a Homebrew python whose symlink goes dangling mid-upgrade.
status="$(plutil -extract status raw - <"${submit_json}")"
req_id="$(plutil -extract id raw - <"${submit_json}")"

echo "sign: notarization ${req_id} -> ${status}"

# `--wait` alone is not a gate: assert the verdict explicitly, or an Invalid
# submission ships binaries Gatekeeper refuses while the release looks green.
if [[ "${status}" != "Accepted" ]]; then
  echo "sign: notarization FAILED (${status}); fetching log" >&2
  xcrun notarytool log "${req_id}" "${notary_args[@]}" >&2 || true
  exit 1
fi
