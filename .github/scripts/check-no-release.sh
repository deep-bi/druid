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

# Stops the release workflow when the version in pom.xml already has a tag or a release, published or
# draft. The release step (softprops/action-gh-release, checked against v2.6.2) would reuse that release:
#   - A published release stays published, but gets the notes of this run, is marked as a pre-release
#     again, and has its bin tarball replaced by this build of the branch head, not of the tagged commit.
#   - Drafts can't be found by tag, so this build goes into the old draft, which keeps its old target
#     commit and notes. Publishing it would tag a commit other than the one built.
# The workflow runs this check before the build and again right before it creates the release, to catch
# a draft published or a second run started during the build.
#
# Usage: check-no-release.sh [<version>]
#   Run it from the repository root. It reads the version from pom.xml. A <version> argument, the version
#   Maven reports, must be the same.
#   GITHUB_REPOSITORY  owner/repository
#   GH_TOKEN           a token with push access (contents: write), because the API lists drafts only to those

set -euo pipefail

fail() {
  echo "::error::$*" >&2
  exit 1
}

REPOSITORY="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"

version="$(python3 -I - pom.xml <<'PY'
import sys
import xml.etree.ElementTree as ET

version = (ET.parse(sys.argv[1]).getroot().findtext('{*}version') or '').strip()
if not version:
    sys.exit('pom.xml declares no project version')
print(version)
PY
)" || fail "Cannot read the project version from pom.xml"
if [[ -n "${1:-}" && "$1" != "${version}" ]]; then
  fail "Maven reports version $1, but pom.xml says ${version}"
fi
tag="v${version}"
bump="Bump the version in pom.xml before building another release."

# A tag of that name, from a published release or made by hand. matching-refs matches by prefix and
# answers with an empty list when nothing matches, so a failure here is a real error.
tagged="$(gh api "repos/${REPOSITORY}/git/matching-refs/tags/${tag}" \
  | jq --arg ref "refs/tags/${tag}" '[.[] | select(.ref == $ref)] | length')" \
  || fail "Cannot list the tags of ${REPOSITORY}"
if (( tagged > 0 )); then
  fail "${tag} is already tagged, so ${version} is released. ${bump}"
fi

# Releases with that tag name, drafts included. gh prints one JSON array per page.
releases="$(gh api --paginate "repos/${REPOSITORY}/releases?per_page=100" \
  | jq -s -c --arg tag "${tag}" '[.[][] | select(.tag_name == $tag) | {draft, html_url}]')" \
  || fail "Cannot list the releases of ${REPOSITORY}"
published="$(jq -r '[.[] | select(.draft | not) | .html_url] | join(" ")' <<< "${releases}")"
drafts="$(jq -r '[.[] | select(.draft) | .html_url] | join(" ")' <<< "${releases}")"
if [[ -n "${published}" ]]; then
  fail "${version} is already released: ${published}. ${bump}"
fi
if [[ -n "${drafts}" ]]; then
  fail "A draft release of ${tag} exists: ${drafts}. Delete it and run the workflow again, so this build gets a new draft at the right commit."
fi
echo "${tag} has no tag and no release yet."
