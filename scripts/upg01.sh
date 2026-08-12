#!/usr/bin/env bash
#
# upg01.sh -- UPG-01 upgrade-compatibility harness.
#
# UPG-01 is the guarantee that upgrading a Terraform configuration from the
# v2.3-API provider (module github.com/CheckPointSW/perimeter-81-client-sdk/v2
# @ v2.3.0) to the v3-API provider produces an EMPTY plan: no state
# migration, no resource replacement, no attribute diff.
#
# There is no way to drive this with `ExternalProviders` against the public
# registry: the provider has never been published there (registry.terraform.io
# returns 404 for both the "checkpointsase" and legacy "perimeter81" names),
# and there is no such thing as "provider 2.3.0" in any case -- "v2.3"
# denotes the Harmony SASE *API* version, not a provider release. Provider
# tags stop at v1.8.1, which predates the rebrand and has a different
# package layout.
#
# The real v2.3 baseline is the commit on origin/main tagged in history as
# d4e7810 ("point provider at CheckPointSW SDK module path"): module
# terraform-provider-checkpointsase depending on
# github.com/CheckPointSW/perimeter-81-client-sdk/v2 v2.3.0, which resolves
# cleanly from the Go module proxy (no local `replace`).
#
# This script builds that commit and the current tree as two versions of the
# same provider, publishes both into a project-local Terraform filesystem
# mirror, and drives the real Terraform CLI through:
#
#   1. init + apply pinned to 2.3.0   (creates real objects on the tenant)
#   2. re-pin to 3.0.0, init -upgrade
#   3. plan -detailed-exitcode        (0 = no diff = UPG-01 PASS)
#   4. destroy                        (always, even on failure)
#
# Nothing is written into ~/.terraform.d; everything lives under a
# gitignored work directory inside the repo (override with UPG01_WORK_DIR).
#
# CREDENTIALS
#   Read only from these two environment variables, and only by Terraform's
#   own provider EnvDefaultFunc -- this script never writes them to any file,
#   fixture, CLI config, or log, and never echoes them:
#     CHECKPOINT_SASE_API_KEY   API key for the tenant under test
#     BASE_URL                  Check Point SASE API base URL for that tenant
#   Terraform state under the work directory WILL contain tenant data
#   (that's the point of the test) -- that is exactly why the work directory
#   must stay untracked/gitignored.
#
# USAGE
#   scripts/upg01.sh
#       Full run: builds both provider versions, applies the v2.3 fixture
#       against the real tenant, upgrades the pin, plans, destroys.
#       Requires CHECKPOINT_SASE_API_KEY and BASE_URL.
#
#   UPG01_DRY_RUN=1 scripts/upg01.sh
#       Mechanical-only run: builds both provider versions, writes the CLI
#       config and the v2.3 fixture, runs `terraform init` against the
#       filesystem mirror, then stops. No apply, no plan, no destroy, no
#       credentials required, nothing touches the tenant. Use this to prove
#       the mirror layout and CLI config are correct before ever running the
#       real thing.
#
#   UPG01_WORK_DIR=/some/path scripts/upg01.sh
#       Use a different work directory instead of <repo>/.upg01-work.
#
# EXIT CODES
#   0  UPG-01 PASS (empty plan), or a completed --dry-run
#   1  UPG-01 FAIL (plan reported drift) or a harness/setup error
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Fixed parameters
# ---------------------------------------------------------------------------

BASELINE_SHA="d4e7810"          # v2.3-API baseline commit (origin/main)
BASELINE_VERSION="2.3.0"        # Harmony SASE API version, reused as the
CURRENT_VERSION="3.0.0"         # provider version for this harness's fixture.
BINARY_NAME="terraform-provider-checkpointsase"

# Full source address as Terraform's filesystem mirror expects it, and the
# short form used inside a required_providers block.
MIRROR_INCLUDE="registry.terraform.io/CheckPointSW/checkpointsase"
TF_PROVIDER_SOURCE="CheckPointSW/checkpointsase"

OS_ARCH="$(go env GOOS)_$(go env GOARCH)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"

WORK_DIR="${UPG01_WORK_DIR:-${REPO_ROOT}/.upg01-work}"
MIRROR_DIR="${WORK_DIR}/mirror"
FIXTURE_DIR="${WORK_DIR}/fixture"
CLI_CONFIG_FILE="${WORK_DIR}/cli.tfrc"
BASELINE_WORKTREE="${WORK_DIR}/baseline-worktree"
PLAN_LOG="${WORK_DIR}/upg01-plan.log"

DRY_RUN="${UPG01_DRY_RUN:-0}"

# Set by the main flow; read by cleanup() so a crash after apply still
# attempts to destroy the real objects it created.
APPLIED=0
DESTROYED=0

# ---------------------------------------------------------------------------
# Cleanup: always remove a leftover baseline worktree, and if this run got
# far enough to `apply` against the tenant but never reached its own
# `destroy` step, try once more here before we exit.
# ---------------------------------------------------------------------------

cleanup() {
  if [[ -d "${BASELINE_WORKTREE}" ]]; then
    echo "cleanup: removing baseline worktree at ${BASELINE_WORKTREE}" >&2
    git -C "${REPO_ROOT}" worktree remove --force "${BASELINE_WORKTREE}" >/dev/null 2>&1 \
      || rm -rf "${BASELINE_WORKTREE}"
  fi

  if [[ "${APPLIED}" == "1" && "${DESTROYED}" != "1" ]]; then
    echo "cleanup: run ended before its own destroy step; attempting to destroy" >&2
    echo "cleanup: the real tf-acc-upg-01 / tf-acc-upg-svc-01 objects now..." >&2
    if ! terraform -chdir="${FIXTURE_DIR}" destroy -auto-approve -input=false >&2; then
      echo "cleanup: destroy FAILED -- tf-acc-upg-01 / tf-acc-upg-svc-01 may still" >&2
      echo "cleanup: exist on the tenant and need manual removal." >&2
    fi
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() { echo "==> $*"; }

require_tools() {
  local tool
  for tool in git go terraform; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
      echo "ERROR: required tool '${tool}' not found on PATH." >&2
      exit 1
    fi
  done
}

require_credentials() {
  if [[ -z "${CHECKPOINT_SASE_API_KEY:-}" ]]; then
    echo "ERROR: CHECKPOINT_SASE_API_KEY is not set." >&2
    echo "       UPG-01 applies real objects against a real tenant, so it needs a" >&2
    echo "       real API key. Export it in your shell -- never in a file -- and" >&2
    echo "       re-run. (Use UPG01_DRY_RUN=1 to exercise the harness without one.)" >&2
    exit 1
  fi
  if [[ -z "${BASE_URL:-}" ]]; then
    echo "ERROR: BASE_URL is not set." >&2
    echo "       Export the tenant's Check Point SASE API base URL, e.g." >&2
    echo "       https://api.perimeter81.com/api/rest, and re-run." >&2
    exit 1
  fi
}

# build_provider <git-ref-or-'WORKTREE'> <version> <source-dir>
# Builds the provider binary found in <source-dir> and installs it into the
# filesystem mirror under <version>.
build_provider() {
  local version="$1" src_dir="$2"
  local dest_dir="${MIRROR_DIR}/${MIRROR_INCLUDE}/${version}/${OS_ARCH}"
  mkdir -p "${dest_dir}"
  log "building provider v${version} from ${src_dir}"
  ( cd "${src_dir}" && go build -o "${dest_dir}/${BINARY_NAME}" )
  log "installed ${dest_dir}/${BINARY_NAME}"
}

build_baseline() {
  rm -rf "${BASELINE_WORKTREE}"
  log "creating detached worktree at ${BASELINE_SHA} (v2.3 API baseline)"
  git -C "${REPO_ROOT}" worktree add --detach "${BASELINE_WORKTREE}" "${BASELINE_SHA}"
  build_provider "${BASELINE_VERSION}" "${BASELINE_WORKTREE}"
  log "removing baseline worktree"
  git -C "${REPO_ROOT}" worktree remove --force "${BASELINE_WORKTREE}"
}

build_current() {
  build_provider "${CURRENT_VERSION}" "${REPO_ROOT}"
}

write_cli_config() {
  mkdir -p "${WORK_DIR}"
  cat > "${CLI_CONFIG_FILE}" <<EOF
provider_installation {
  filesystem_mirror {
    path    = "${MIRROR_DIR}"
    include = ["${MIRROR_INCLUDE}"]
  }
  direct {
    exclude = ["${MIRROR_INCLUDE}"]
  }
}
EOF
  log "wrote CLI config ${CLI_CONFIG_FILE}"
}

# write_fixture <version> regenerates the fixture's main.tf pinned to
# <version>. Regenerating the whole file (instead of sed-patching the
# version string in place) sidesteps BSD-vs-GNU `sed -i` differences and
# keeps the "credentials never touch a file" property trivially auditable
# in one place.
write_fixture() {
  local version="$1"
  mkdir -p "${FIXTURE_DIR}"
  cat > "${FIXTURE_DIR}/main.tf" <<EOF
terraform {
  required_providers {
    checkpointsase = {
      source  = "${TF_PROVIDER_SOURCE}"
      version = "${version}"
    }
  }
}

# Credentials come only from the CHECKPOINT_SASE_API_KEY / BASE_URL
# environment variables, read by the provider's own EnvDefaultFunc.
# Do not add api_key or base_url here.
provider "checkpointsase" {}

resource "checkpointsase_object_addresses" "upg" {
  name        = "tf-acc-upg-01"
  description = "UPG-01 upgrade fixture"
  value_type  = "ip"
  value       = ["10.99.0.7"]
}

resource "checkpointsase_object_services" "upg" {
  name        = "tf-acc-upg-svc-01"
  description = "UPG-01 upgrade fixture"
  protocols {
    protocol   = "tcp"
    value      = [443]
    value_type = "single"
  }
}
EOF
  log "wrote fixture ${FIXTURE_DIR}/main.tf (pinned to ${version})"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

require_tools

if [[ "${DRY_RUN}" != "1" ]]; then
  require_credentials
fi

export TF_CLI_CONFIG_FILE="${CLI_CONFIG_FILE}"
export TF_IN_AUTOMATION=1

mkdir -p "${WORK_DIR}" "${MIRROR_DIR}"

build_baseline
build_current
write_cli_config
write_fixture "${BASELINE_VERSION}"

log "terraform init (pinned to v${BASELINE_VERSION}, filesystem mirror only, no direct/registry lookups)"
terraform -chdir="${FIXTURE_DIR}" init -input=false

if [[ "${DRY_RUN}" == "1" ]]; then
  log "UPG01_DRY_RUN=1: stopping after 'terraform init'."
  log "Mirror layout and CLI config are proven; no credentials were used and"
  log "nothing was created on any tenant. Re-run without UPG01_DRY_RUN=1 (and"
  log "with CHECKPOINT_SASE_API_KEY / BASE_URL exported) to complete UPG-01."
  exit 0
fi

echo
echo "################################################################"
echo "# WARNING: about to run 'terraform apply' against a REAL tenant. #"
echo "# This creates checkpointsase_object_addresses \"upg\" (tf-acc-upg-01)"
echo "# and checkpointsase_object_services \"upg\" (tf-acc-upg-svc-01)."
echo "# They are destroyed again at the end of this script.           #"
echo "################################################################"
echo

log "terraform apply -auto-approve (v${BASELINE_VERSION})"
terraform -chdir="${FIXTURE_DIR}" apply -auto-approve -input=false
APPLIED=1

write_fixture "${CURRENT_VERSION}"

log "terraform init -upgrade (re-pinned to v${CURRENT_VERSION})"
terraform -chdir="${FIXTURE_DIR}" init -upgrade -input=false

log "terraform plan -detailed-exitcode (0 = empty plan = UPG-01 PASS, 2 = drift = FAIL)"
set +e
terraform -chdir="${FIXTURE_DIR}" plan -detailed-exitcode -no-color -input=false | tee "${PLAN_LOG}"
plan_exit="${PIPESTATUS[0]}"
set -e

result="HARNESS_ERROR"
case "${plan_exit}" in
  0)
    result="PASS"
    log "UPG-01 PASS: empty plan after upgrading the pin from ${BASELINE_VERSION} to ${CURRENT_VERSION}."
    ;;
  2)
    result="FAIL"
    echo "UPG-01 FAIL: plan reported drift after the upgrade (exit code 2)." >&2
    echo "Full plan output (also saved at ${PLAN_LOG}):" >&2
    cat "${PLAN_LOG}" >&2
    ;;
  *)
    echo "UPG-01 HARNESS ERROR: 'terraform plan -detailed-exitcode' exited ${plan_exit}," >&2
    echo "which is neither 0 (empty plan) nor 2 (drift). 1 means plan itself" >&2
    echo "errored -- treat this as a harness/setup problem, not a plan result." >&2
    ;;
esac

log "terraform destroy -auto-approve (cleaning up the real objects this run created)"
terraform -chdir="${FIXTURE_DIR}" destroy -auto-approve -input=false
DESTROYED=1

log "Result: UPG-01 ${result}"
if [[ "${result}" == "PASS" ]]; then
  exit 0
fi
exit 1
