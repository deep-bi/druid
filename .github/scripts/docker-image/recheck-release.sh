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

# Reads the release again right before the publish job writes to Docker Hub. resolve-release.sh recorded
# it when the run started, and the build, the smoke test, the approval of the dockerhub environment and
# the publish queue can take hours. Fails unless the release still exists, is published, carries the same
# tag, and that tag still points at the commit the image was built from. A release that is a pre-release
# now passes: it gets its version tag, and floating-tags.sh leaves the floating tags alone.
#
# Environment:
#   WORK_DIR           working directory with release.json
#   GITHUB_REPOSITORY  owner/repo, set by GitHub Actions
#   GH_TOKEN           GitHub token; contents: read is enough
#
# Writes release-check.json to WORK_DIR. publish.sh and floating-tags.sh don't write to Docker Hub
# without it.

set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

WORK_DIR="${WORK_DIR:-${RUNNER_TEMP:?RUNNER_TEMP is not set}/docker-image}"
REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"

release_id="$(jq -r '.release_id' "${WORK_DIR}/release.json")"
tag="$(jq -r '.tag' "${WORK_DIR}/release.json")"
commit="$(jq -r '.commit' "${WORK_DIR}/release.json")"
if [[ ! "${release_id}" =~ ^[0-9]+$ ]]; then
  fail "release.json has no release ID"
fi

# A 404 means the release was deleted, or it is a draft that this token can't see.
errors="${WORK_DIR}/gh-error.txt"
if ! release="$(gh api "repos/${REPO}/releases/${release_id}" 2> "${errors}")"; then
  if grep -q 'HTTP 404' "${errors}"; then
    fail "Release ${tag} was deleted or turned back into a draft after this run started. Nothing was pushed."
  fi
  fail "Cannot read release ${tag} (ID ${release_id}): $(cat "${errors}")"
fi

current_tag="$(jq -r '.tag_name' <<< "${release}")"
draft="$(jq -r '.draft' <<< "${release}")"
prerelease="$(jq -r '.prerelease' <<< "${release}")"
if [[ "${draft}" != false ]]; then
  fail "Release ${tag} was turned back into a draft after this run started. Nothing was pushed."
fi
if [[ "${current_tag}" != "${tag}" ]]; then
  fail "Release ${release_id} carries ${current_tag} now, not ${tag}. Nothing was pushed."
fi
if [[ "${prerelease}" != true && "${prerelease}" != false ]]; then
  fail "Release ${tag} reports prerelease=${prerelease}"
fi
tag_target="$(tag_commit "${REPO}" "${tag}")"
if [[ "${tag_target}" != "${commit}" ]]; then
  fail "${tag} points at ${tag_target} now, but the image was built from ${commit}. Nothing was pushed."
fi

jq -n --argjson release_id "${release_id}" --arg tag "${tag}" --arg commit "${commit}" \
  --argjson prerelease "${prerelease}" --arg checked_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{
    release_id: $release_id,
    tag: $tag,
    commit: $commit,
    draft: false,
    prerelease: $prerelease,
    checked_at: $checked_at
  }' > "${WORK_DIR}/release-check.json"
if [[ "${prerelease}" == true ]]; then
  log "${tag} is published as a pre-release and points at ${commit}. It gets its version tag only."
else
  log "${tag} is still published and points at ${commit}"
fi
