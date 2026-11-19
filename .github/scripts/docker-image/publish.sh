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

# Pushes the tested image archive as <repository>:<version> without changing its digest, then checks the
# registry digest and pulls the image back. A version tag that already exists is never pushed again:
# the run keeps the existing image and says so.
#
# Environment:
#   WORK_DIR          working directory with release.json, and build.json plus image.oci.tar when this run
#                     built the image. Pushing to Docker Hub also needs release-check.json from
#                     recheck-release.sh.
#   REGISTRY          docker.io, or host:port of a plain HTTP registry for a dry run (default docker.io)
#   IMAGE_REPOSITORY  repository (default deepbi/druid)
#   AUTHFILE          skopeo credentials file from registry-login.sh (optional)
#
# Writes publish.json to WORK_DIR and sets the step output digest.

set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

WORK_DIR="${WORK_DIR:-${RUNNER_TEMP:?RUNNER_TEMP is not set}/docker-image}"
REGISTRY="${REGISTRY:-docker.io}"
IMAGE_REPOSITORY="${IMAGE_REPOSITORY:-deepbi/druid}"

if [[ "${REGISTRY}" == docker.io ]]; then
  require_release_check "${WORK_DIR}"
fi

version="$(jq -r '.version' "${WORK_DIR}/release.json")"
reference="${REGISTRY}/${IMAGE_REPOSITORY}:${version}"
skopeo_args=(--retry-times 3)
if [[ -n "${AUTHFILE:-}" ]]; then
  skopeo_args+=(--authfile "${AUTHFILE}")
fi
if [[ "${REGISTRY}" != docker.io ]]; then
  skopeo_args+=(--dest-tls-verify=false)
fi

built_digest=""
config_digest=""
if [[ -f "${WORK_DIR}/build.json" ]]; then
  built_digest="$(jq -r '.manifest_digest' "${WORK_DIR}/build.json")"
  config_digest="$(jq -r '.config_digest' "${WORK_DIR}/build.json")"
fi

existing="$(registry_digest "${REGISTRY}" "${IMAGE_REPOSITORY}" "${version}")"
if [[ -z "${existing}" && -z "${built_digest}" && "${REGISTRY}" != docker.io ]]; then
  # A dry run for a version Docker Hub already has: report the existing image, there is nothing to push.
  existing="$(jq -r '.existing_digest // empty' "${WORK_DIR}/release.json")"
fi
if [[ -n "${existing}" ]]; then
  digest="${existing}"
  if [[ -z "${built_digest}" ]]; then
    status=existing
    log "${reference} already exists (${existing}). It was not rebuilt or retested by this run."
  elif [[ "${existing}" == "${built_digest}" ]]; then
    status="already-pushed"
    log "${reference} already has the tested image (${existing})"
  else
    status="existing-different"
    warn "${reference} already exists with ${existing}. The image tested by this run (${built_digest}) was not published, and version tags are never replaced."
  fi
else
  if [[ -z "${built_digest}" ]]; then
    fail "${reference} does not exist and this run has no image to push"
  fi
  log "Pushing ${reference}"
  skopeo copy --preserve-digests "${skopeo_args[@]}" "oci-archive:${WORK_DIR}/image.oci.tar" "docker://${reference}"
  digest="$(registry_digest "${REGISTRY}" "${IMAGE_REPOSITORY}" "${version}")"
  if [[ "${digest}" != "${built_digest}" ]]; then
    fail "The registry reports ${digest:-nothing} for ${reference}, but the tested image is ${built_digest}"
  fi
  status=pushed
fi

# Pull the published image back by digest and compare its configuration with the tested one.
pulled_config=""
if [[ -n "${built_digest}" && ( "${status}" == pushed || "${status}" == already-pushed ) ]]; then
  docker pull --quiet "${REGISTRY}/${IMAGE_REPOSITORY}@${digest}" > /dev/null
  pulled_id="$(docker image inspect --format '{{.Id}}' "${REGISTRY}/${IMAGE_REPOSITORY}@${digest}")"
  if [[ "${pulled_id}" != "${config_digest}" && "${pulled_id}" != "${digest}" ]]; then
    fail "The pulled image ${pulled_id} is not the tested image (config ${config_digest})"
  fi
  pulled_config="${config_digest}"
  log "Pulled ${REGISTRY}/${IMAGE_REPOSITORY}@${digest} back; it is the tested image"
fi

jq -n --arg registry "${REGISTRY}" --arg reference "${reference}" --arg status "${status}" \
  --arg digest "${digest}" --arg built_digest "${built_digest}" --arg pulled_config "${pulled_config}" '{
    registry: $registry,
    reference: $reference,
    status: $status,
    digest: $digest,
    built_digest: $built_digest,
    pulled_back_config: $pulled_config
  }' > "${WORK_DIR}/publish.json"
set_output digest "${digest}"
