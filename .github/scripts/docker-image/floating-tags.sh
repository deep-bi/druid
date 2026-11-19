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

# Points <major>.<minor>-latest of the release's line and latest at the newest published, non-pre-release
# release that has an image on Docker Hub, comparing versions in version order. The targets come from the
# releases as GitHub lists them now, never from the state recorded when the run started, so the next run
# corrects a run that was missed or failed and a release that was withdrawn. A floating tag becomes an
# exact copy of the target's manifest, so both report the same digest.
#
# A real run moves no tag unless its own release is in that list, so a pre-release, or a release withdrawn
# after recheck-release.sh, leaves the floating tags alone. A dry run rehearses the run that follows
# publication: it adds its own version to the list, a draft included, and counts it as having an image,
# because that image is only in the local registry.
#
# With update_latest false in release.json, as for a backfill, only <major>.<minor>-latest moves and latest
# stays where it is.
#
# Environment:
#   WORK_DIR           working directory with release.json and publish.json, and in a real run
#                      release-check.json from recheck-release.sh
#   GITHUB_REPOSITORY  owner/repo, set by GitHub Actions
#   GH_TOKEN           GitHub token for listing releases
#   REGISTRY           where the tags are written: docker.io in a real run, host:port of the local registry
#                      in a dry run (default docker.io)
#   IMAGE_REPOSITORY   repository (default deepbi/druid)
#   AUTHFILE           skopeo credentials file from registry-login.sh (optional)
#
# Writes floating.json to WORK_DIR.

set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

WORK_DIR="${WORK_DIR:-${RUNNER_TEMP:?RUNNER_TEMP is not set}/docker-image}"
REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"
REGISTRY="${REGISTRY:-docker.io}"
IMAGE_REPOSITORY="${IMAGE_REPOSITORY:-deepbi/druid}"

version="$(jq -r '.version' "${WORK_DIR}/release.json")"
line="$(jq -r '.line' "${WORK_DIR}/release.json")"
dry_run="$(jq -r '.dry_run' "${WORK_DIR}/release.json")"
# Read without a default, since jq's // would replace false with it.
update_latest="$(jq -r '.update_latest' "${WORK_DIR}/release.json")"
digest="$(jq -r '.digest // empty' "${WORK_DIR}/publish.json")"
if [[ -z "${digest}" ]]; then
  fail "publish.json has no digest"
fi
if [[ "${update_latest}" != true && "${update_latest}" != false ]]; then
  fail "release.json says update_latest is ${update_latest}, expected true or false"
fi

# What a dry run assumes about its own version must never reach Docker Hub.
if [[ "${dry_run}" == true && "${REGISTRY}" == docker.io ]]; then
  fail "A dry run writes only to the local registry, never to docker.io"
fi
if [[ "${dry_run}" != true && "${REGISTRY}" != docker.io ]]; then
  fail "Only a dry run writes floating tags to ${REGISTRY}"
fi

# skip <reason>: records that no tag moves, and stops.
skip() {
  jq -n --arg reason "$1" '{skipped: $reason, tags: []}' > "${WORK_DIR}/floating.json"
  exit 0
}

if [[ "${dry_run}" == true ]]; then
  prerelease="$(jq -r '.prerelease' "${WORK_DIR}/release.json")"
else
  require_release_check "${WORK_DIR}"
  prerelease="$(jq -r '.prerelease' "${WORK_DIR}/release-check.json")"
fi
if [[ "${prerelease}" != false ]]; then
  log "${version} is a pre-release, so no floating tag moves"
  skip "${version} is a pre-release"
fi

# Published, non-pre-release releases as GitHub lists them now. Drafts are listed only to tokens with push
# access, and are dropped anyway.
published="$(gh api --paginate "repos/${REPO}/releases?per_page=100" \
  --jq '.[] | select((.draft | not) and (.prerelease | not)) | .tag_name' | sed -n 's/^v//p')"

if [[ "${dry_run}" == true ]]; then
  candidates="$(printf '%s\n%s\n' "${published}" "${version}")"
elif grep -qxF "${version}" <<< "${published}"; then
  candidates="${published}"
else
  warn "${version} was withdrawn or turned into a pre-release after the re-check, so no floating tag moves"
  skip "${version} was withdrawn or turned into a pre-release after the re-check"
fi

skopeo_args=(--retry-times 3 --multi-arch all --preserve-digests)
if [[ -n "${AUTHFILE:-}" ]]; then
  skopeo_args+=(--authfile "${AUTHFILE}")
fi
if [[ "${REGISTRY}" != docker.io ]]; then
  skopeo_args+=(--src-tls-verify=false --dest-tls-verify=false)
fi

# This run's version has the image publish.sh just pushed or found: on Docker Hub in a real run, in the
# local registry in a dry run. Whether another version has an image is always read from Docker Hub.
# Called inside a condition, where set -e does not apply, so a failed lookup has to stop the run here.
has_image() {
  local found
  if [[ "$1" == "${version}" ]]; then
    return 0
  fi
  if ! found="$(registry_digest docker.io "${IMAGE_REPOSITORY}" "$1")"; then
    fail "Cannot check Docker Hub for ${IMAGE_REPOSITORY}:$1"
  fi
  [[ -n "${found}" ]]
}

copy_tag() {
  local target_digest=$1 floating=$2 after
  skopeo copy "${skopeo_args[@]}" "docker://${REGISTRY}/${IMAGE_REPOSITORY}@${target_digest}" \
    "docker://${REGISTRY}/${IMAGE_REPOSITORY}:${floating}"
  after="$(registry_digest "${REGISTRY}" "${IMAGE_REPOSITORY}" "${floating}")"
  if [[ "${after}" != "${target_digest}" ]]; then
    fail "${REGISTRY}/${IMAGE_REPOSITORY}:${floating} reports ${after:-nothing} after the copy, expected ${target_digest}"
  fi
}

line_target="$(choose_floating_target "${line}" has_image <<< "${candidates}")"
pairs=("${line}-latest=${line_target}")
if [[ "${update_latest}" == true ]]; then
  latest_target="$(choose_floating_target all has_image <<< "${candidates}")"
  pairs+=("latest=${latest_target}")
fi

tags='[]'
for pair in "${pairs[@]}"; do
  floating="${pair%%=*}"
  target="${pair#*=}"
  # This run's version is a candidate with an image in both scopes, so there is always a target.
  if [[ -z "${target}" ]]; then
    fail "No target for ${floating}, although ${version} is a candidate"
  fi
  if [[ "${target}" == "${version}" ]]; then
    target_digest="${digest}"
  else
    target_digest="$(registry_digest docker.io "${IMAGE_REPOSITORY}" "${target}")"
  fi
  # The decision is always against Docker Hub. A dry run rehearses the copy in its local registry when
  # the target is the version it just pushed there.
  before="$(registry_digest docker.io "${IMAGE_REPOSITORY}" "${floating}")"
  if [[ "${before}" == "${target_digest}" ]]; then
    action=unchanged
  elif [[ "${REGISTRY}" != docker.io ]]; then
    action="would move"
    if [[ "${target}" == "${version}" && -n "$(registry_digest "${REGISTRY}" "${IMAGE_REPOSITORY}" "${version}")" ]]; then
      copy_tag "${target_digest}" "${floating}"
      action="would move (copy rehearsed)"
    fi
  else
    copy_tag "${target_digest}" "${floating}"
    action=moved
  fi
  log "${floating}: ${target} (${target_digest}), ${action}"
  tags="$(jq --arg tag "${floating}" --arg target "${target}" --arg digest "${target_digest}" \
    --arg before "${before}" --arg action "${action}" \
    '. + [{tag: $tag, target: $target, digest: $digest, before: $before, action: $action}]' <<< "${tags}")"
done

# A backfill leaves latest where it is, even when this run's version is the newest.
if [[ "${update_latest}" == false ]]; then
  before="$(registry_digest docker.io "${IMAGE_REPOSITORY}" latest)"
  log "latest: stays at ${before:-nothing}, update_latest is false"
  tags="$(jq --arg before "${before}" '. + [{tag: "latest", target: null, digest: null, before: $before,
    action: "skipped (update_latest is false)"}]' <<< "${tags}")"
fi

jq -n --argjson tags "${tags}" '{tags: $tags}' > "${WORK_DIR}/floating.json"
