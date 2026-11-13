#!/usr/bin/env bash

# Copyright 2026 Deep BI, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#--------------------------------------------------------------------

# Writes the first draft of the release notes for a Deep.BI release from the release notes template.
# It fills in <VERSION>, <UPSTREAM> and <RELEASE_SERIES>, and lists the commits since the previous
# release of the same series in a hidden comment. If the release already exists it writes nothing,
# so running the release workflow again keeps notes that someone has edited.
#
# Usage: prepare-release-notes.sh <version>
#   VERSION   release version, e.g. 38.0.0-deepbi3 or 31.0.2-patch10 (or pass it as arg1)
#   TEMPLATE  template file (default: .github/release-notes-template.md in the checkout)
#   OUTPUT    file to write (default: release-notes.md)
#   REF       last commit of the release (default: HEAD)
#   DRY_RUN   1 prints the notes instead of checking GitHub for an existing release
#
# In GitHub Actions it sets the step output "path" to the notes file, or to an empty string when the
# release body must be left alone.

set -euo pipefail

VERSION="${1:-${VERSION:-}}"
if [[ -z "${VERSION}" ]]; then
  echo "::error::VERSION is not set (pass as arg1 or env VERSION)"
  exit 1
fi

TEMPLATE="${TEMPLATE:-.github/release-notes-template.md}"
OUTPUT="${OUTPUT:-release-notes.md}"
REF="${REF:-HEAD}"
DRY_RUN="${DRY_RUN:-0}"
TAG="v${VERSION}"
MAX_COMMITS=500

log() { echo "$*" >&2; }

set_output() {
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "path=$1" >> "${GITHUB_OUTPUT}"
  fi
}

if [[ ! "${VERSION}" =~ ^([0-9]+\.[0-9]+\.[0-9]+)-(deepbi|patch)([0-9]+)$ ]]; then
  echo "::warning::${VERSION} is not a release version (x.y.z-deepbiN or x.y.z-patchN), not preparing release notes"
  set_output ""
  exit 0
fi
UPSTREAM="${BASH_REMATCH[1]}"
KIND="${BASH_REMATCH[2]}"
RELEASE_SERIES="${UPSTREAM}-${KIND}x"

if [[ "${DRY_RUN}" != "1" ]]; then
  if [[ -z "${GITHUB_REPOSITORY:-}" ]]; then
    echo "::error::GITHUB_REPOSITORY is not set"
    exit 1
  fi
  # only "release not found" means there is nothing to keep; any other failure must not overwrite notes
  if view_error="$(gh release view "${TAG}" --repo "${GITHUB_REPOSITORY}" --json tagName 2>&1 > /dev/null)"; then
    log "Release ${TAG} already exists, keeping its notes"
    set_output ""
    exit 0
  elif [[ "${view_error}" != *"release not found"* ]]; then
    echo "::error::Cannot check whether release ${TAG} exists: ${view_error}"
    exit 1
  fi
fi

if [[ ! -f "${TEMPLATE}" ]]; then
  echo "::error::Release notes template ${TEMPLATE} not found"
  exit 1
fi
notes="$(cat "${TEMPLATE}")"
notes="${notes//<VERSION>/${VERSION}}"
notes="${notes//<UPSTREAM>/${UPSTREAM}}"
notes="${notes//<RELEASE_SERIES>/${RELEASE_SERIES}}"

# the highest tag of the same series below this version, e.g. v31.0.2-patch10 before v31.0.2-patch11
PREVIOUS_TAG="$(
  { git tag --list "v${UPSTREAM}-${KIND}[0-9]*"; echo "${TAG}"; } \
    | sort -u -V \
    | awk -v tag="${TAG}" '$0 == tag { print previous; exit } { previous = $0 }'
)"

# a tag created on another branch would list unrelated commits
PREVIOUS_TAG_ON_BRANCH=0
if [[ -n "${PREVIOUS_TAG}" ]]; then
  if git merge-base --is-ancestor "${PREVIOUS_TAG}" "${REF}"; then
    PREVIOUS_TAG_ON_BRANCH=1
  else
    echo "::warning::${PREVIOUS_TAG} is not an ancestor of ${REF}, not listing commits"
  fi
fi

{
  printf '%s\n' "${notes}"
  echo
  if [[ -z "${PREVIOUS_TAG}" ]]; then
    echo "<!-- First release of the ${RELEASE_SERIES} series: describe the Deep.BI changes on top of Apache Druid ${UPSTREAM}. Delete this comment before publishing. -->"
  elif [[ "${PREVIOUS_TAG_ON_BRANCH}" != "1" ]]; then
    echo "<!-- ${PREVIOUS_TAG} does not point to an earlier commit of this branch, so there is no commit list. Delete this comment before publishing. -->"
  else
    echo "<!-- Commits since ${PREVIOUS_TAG}, to describe above. Delete this comment before publishing."
    git log --no-merges --max-count="${MAX_COMMITS}" --format='- %s' "${PREVIOUS_TAG}..${REF}" | sed 's/-->/- ->/g'
    echo "-->"
  fi
} > "${OUTPUT}"

log "Wrote release notes for ${TAG} to ${OUTPUT} (previous release: ${PREVIOUS_TAG:-none})"
if [[ "${DRY_RUN}" == "1" ]]; then
  cat "${OUTPUT}"
fi
set_output "${OUTPUT}"
