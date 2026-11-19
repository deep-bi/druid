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

# Finds the release behind RELEASE_TAG, the commit its assets were built from, and whether Docker Hub
# already has its image. Writes release.json and assets.json to WORK_DIR and sets the step outputs
# version, line, commit, draft, prerelease, image_exists and image_digest.
#
# Environment:
#   RELEASE_TAG        release tag, for example v38.0.0-deepbi4
#   DRY_RUN            "true" also accepts a draft release (default "false")
#   UPDATE_LATEST      "false" leaves the latest tag where it is, for a backfill (default "true")
#   GITHUB_REPOSITORY  owner/repo, set by GitHub Actions
#   GH_TOKEN           GitHub token. The API lists drafts only to tokens with push access.
#   IMAGE_REPOSITORY   Docker Hub repository (default deepbi/druid)
#   WORK_DIR           output directory (default $RUNNER_TEMP/docker-image)

set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

RELEASE_TAG="${RELEASE_TAG:?RELEASE_TAG is not set}"
DRY_RUN="${DRY_RUN:-false}"
UPDATE_LATEST="${UPDATE_LATEST:-true}"
REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"
IMAGE_REPOSITORY="${IMAGE_REPOSITORY:-deepbi/druid}"
WORK_DIR="${WORK_DIR:-${RUNNER_TEMP:?RUNNER_TEMP is not set}/docker-image}"
mkdir -p "${WORK_DIR}"

if [[ "${UPDATE_LATEST}" != true && "${UPDATE_LATEST}" != false ]]; then
  fail "UPDATE_LATEST must be true or false, not '${UPDATE_LATEST}'"
fi

version="$(version_from_tag "${RELEASE_TAG}")"
line="$(version_line "${version}")"

# A published release is found by its tag. A draft has no tag yet, so look for it in the release list.
errors="${WORK_DIR}/gh-error.txt"
if release="$(gh api "repos/${REPO}/releases/tags/${RELEASE_TAG}" 2> "${errors}")"; then
  :
elif grep -q 'HTTP 404' "${errors}"; then
  drafts="$(gh api --paginate "repos/${REPO}/releases?per_page=100" \
    --jq ".[] | select(.draft and .tag_name == \"${RELEASE_TAG}\")" | jq -s '.')"
  case "$(jq 'length' <<< "${drafts}")" in
    0) fail "No published release or draft for ${RELEASE_TAG} in ${REPO}. Drafts are visible only to a token with contents: write." ;;
    1) release="$(jq '.[0]' <<< "${drafts}")" ;;
    *) fail "Several drafts carry ${RELEASE_TAG}. Delete the stale ones and run again." ;;
  esac
else
  fail "Cannot read release ${RELEASE_TAG}: $(cat "${errors}")"
fi

draft="$(jq -r '.draft' <<< "${release}")"
prerelease="$(jq -r '.prerelease' <<< "${release}")"
if [[ "${draft}" == true && "${DRY_RUN}" != true ]]; then
  fail "${RELEASE_TAG} is still a draft. Publish it first, or run with dry_run to test the draft."
fi

if [[ "${draft}" == true ]]; then
  # Publishing creates the tag at target_commitish, which the release workflow sets to the commit it built.
  commit="$(jq -r '.target_commitish' <<< "${release}")"
  if [[ ! "${commit}" =~ ^[0-9a-f]{40}$ ]]; then
    fail "The draft targets '${commit}', not a commit. The release workflow must set target_commitish to the commit it built."
  fi
else
  commit="$(tag_commit "${REPO}" "${RELEASE_TAG}")"
fi

image_digest="$(registry_digest docker.io "${IMAGE_REPOSITORY}" "${version}")"
image_exists=false
if [[ -n "${image_digest}" ]]; then
  image_exists=true
  log "Docker Hub already has ${IMAGE_REPOSITORY}:${version} (${image_digest}). Version tags are never rebuilt."
fi

jq --arg version "${version}" --arg line "${line}" --arg commit "${commit}" \
  --arg image_repository "${IMAGE_REPOSITORY}" --arg image_exists "${image_exists}" \
  --arg image_digest "${image_digest}" --arg dry_run "${DRY_RUN}" \
  --arg update_latest "${UPDATE_LATEST}" '{
    tag: .tag_name,
    version: $version,
    line: $line,
    commit: $commit,
    release_id: .id,
    draft: .draft,
    prerelease: .prerelease,
    html_url: .html_url,
    published_at: .published_at,
    dry_run: ($dry_run == "true"),
    update_latest: ($update_latest == "true"),
    image_repository: $image_repository,
    image_exists: ($image_exists == "true"),
    existing_digest: $image_digest
  }' <<< "${release}" > "${WORK_DIR}/release.json"
jq '[.assets[] | {id, name, size, created_at}]' <<< "${release}" > "${WORK_DIR}/assets.json"

set_output version "${version}"
set_output line "${line}"
set_output commit "${commit}"
set_output draft "${draft}"
set_output prerelease "${prerelease}"
set_output image_exists "${image_exists}"
set_output image_digest "${image_digest}"
log "Release ${RELEASE_TAG}: draft=${draft} prerelease=${prerelease} commit=${commit} image_exists=${image_exists} update_latest=${UPDATE_LATEST}"
