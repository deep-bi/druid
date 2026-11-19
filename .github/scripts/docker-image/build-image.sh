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

# Builds distribution/docker/Dockerfile of the release commit with BUILD_FROM_SOURCE=false, so nothing is
# compiled and the image carries the jars of the release assets. The build writes a single OCI archive,
# which is what gets published. For the smoke test, the archive goes to the run's throwaway local registry
# and the engine pulls it back by digest, so the tested image is the published image, byte for byte.
#
# Environment:
#   SRC_DIR            checkout of the release commit, prepared by prepare-context.sh
#   WORK_DIR           working directory with release.json
#   GITHUB_REPOSITORY  owner/repo, for the image labels
#   IMAGE_REPOSITORY   Docker Hub repository (default deepbi/druid)
#
# Writes build.json and image.oci.tar to WORK_DIR and sets the step outputs manifest_digest and
# candidate_image.

set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

SRC_DIR="${SRC_DIR:?SRC_DIR is not set}"
REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"
IMAGE_REPOSITORY="${IMAGE_REPOSITORY:-deepbi/druid}"
WORK_DIR="${WORK_DIR:-${RUNNER_TEMP:?RUNNER_TEMP is not set}/docker-image}"

version="$(jq -r '.version' "${WORK_DIR}/release.json")"
commit="$(jq -r '.commit' "${WORK_DIR}/release.json")"
tag="$(jq -r '.tag' "${WORK_DIR}/release.json")"
dockerfile="${SRC_DIR}/distribution/docker/Dockerfile"
archive="${WORK_DIR}/image.oci.tar"
builder=deepbi-docker-image
# A dry run rehearses the publish to deepbi/druid in the same local registry, so the candidate gets a
# repository of its own there.
candidate_repository="candidate/${IMAGE_REPOSITORY##*/}"

# Every FROM in the Dockerfile is a floating tag, so record what each one resolves to right before the
# build. The runtime base is checked against the built image afterwards.
base_list="$(dockerfile_base_images "${dockerfile}")"
bases='[]'
while IFS= read -r image; do
  digest="$(image_digest "${image}")"
  if [[ ! "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    fail "Cannot resolve base image ${image}"
  fi
  bases="$(jq --arg image "${image}" --arg digest "${digest}" '. + [{image: $image, digest: $digest}]' <<< "${bases}")"
  log "Base image ${image}: ${digest}"
done <<< "${base_list}"

if ! docker buildx inspect "${builder}" > /dev/null 2>&1; then
  docker buildx create --name "${builder}" --driver docker-container > /dev/null
fi

docker buildx build \
  --builder "${builder}" \
  --file "${dockerfile}" \
  --platform linux/amd64 \
  --build-arg BUILD_FROM_SOURCE=false \
  --label "org.opencontainers.image.source=https://github.com/${REPO}" \
  --label "org.opencontainers.image.revision=${commit}" \
  --label "org.opencontainers.image.version=${version}" \
  --label "org.opencontainers.image.url=https://github.com/${REPO}/releases/tag/${tag}" \
  --provenance=false \
  --sbom=false \
  --output "type=oci,dest=${archive},name=docker.io/${IMAGE_REPOSITORY}:${version}" \
  "${SRC_DIR}"

# The builder and its cache are not needed any more, and the smoke test needs the disk space.
docker buildx rm "${builder}" > /dev/null

# The digests come from the archive itself, since that is exactly what gets pushed.
oci_file() {
  tar -xOf "${archive}" "$1" 2> /dev/null || tar -xOf "${archive}" "./$1"
}
index="$(oci_file index.json)"
if [[ "$(jq '.manifests | length' <<< "${index}")" != 1 ]]; then
  fail "Expected exactly one image in ${archive}"
fi
manifest_digest="$(jq -r '.manifests[0].digest' <<< "${index}")"
manifest="$(oci_file "blobs/sha256/${manifest_digest#sha256:}")"
media_type="$(jq -r '.mediaType' <<< "${manifest}")"
if [[ "${media_type}" != application/vnd.oci.image.manifest.v1+json ]]; then
  fail "Expected a single-platform OCI manifest in ${archive}, found ${media_type}"
fi
config_digest="$(jq -r '.config.digest' <<< "${manifest}")"
compressed_size="$(jq '[.layers[].size] | add' <<< "${manifest}")"

# Push the archive to the local registry the same way the publish job pushes it to Docker Hub, then pull
# it back by digest for the smoke test.
start_local_registry
skopeo copy --retry-times 3 --preserve-digests --dest-tls-verify=false \
  "oci-archive:${archive}" "docker://${LOCAL_REGISTRY}/${candidate_repository}:${version}"
pushed="$(registry_digest "${LOCAL_REGISTRY}" "${candidate_repository}" "${version}")"
if [[ "${pushed}" != "${manifest_digest}" ]]; then
  fail "The local registry reports ${pushed:-nothing} for the candidate, but the archive holds ${manifest_digest}"
fi
candidate="${LOCAL_REGISTRY}/${candidate_repository}@${manifest_digest}"
docker pull --quiet "${candidate}" > /dev/null
# The classic image store reports the config digest as the image ID, the containerd store the manifest
# digest.
pulled_id="$(docker image inspect --format '{{.Id}}' "${candidate}")"
if [[ "${pulled_id}" != "${config_digest}" && "${pulled_id}" != "${manifest_digest}" ]]; then
  fail "The pulled candidate ${pulled_id} is not the archived image (config ${config_digest})"
fi

runtime_image="$(jq -r '.[-1].image' <<< "${bases}")"
runtime_digest="$(jq -r '.[-1].digest' <<< "${bases}")"
base_layers="$(docker buildx imagetools inspect "${runtime_image}@${runtime_digest}" --format '{{json .Image}}' \
  | jq -c 'if has("rootfs") then .rootfs.diff_ids else .["linux/amd64"].rootfs.diff_ids end')"
image_layers="$(docker image inspect --format '{{json .RootFS.Layers}}' "${candidate}")"
if ! jq -e --argjson base "${base_layers}" '.[0:($base | length)] == $base' <<< "${image_layers}" > /dev/null; then
  fail "The image is not built on ${runtime_image}@${runtime_digest}. The base image moved during the build; run again."
fi

# bash comes from a GitHub download in the Dockerfile, not from a base image, so record its checksum.
bash_sha256="$(docker run --rm --entrypoint sha256sum "${candidate}" /bin/bash | cut -d' ' -f1)"

jq -n --arg candidate "${candidate}" --arg manifest_digest "${manifest_digest}" \
  --arg config_digest "${config_digest}" --argjson compressed_size "${compressed_size}" \
  --argjson base_images "${bases}" --arg bash_sha256 "${bash_sha256}" '{
    candidate: $candidate,
    platform: "linux/amd64",
    manifest_digest: $manifest_digest,
    config_digest: $config_digest,
    compressed_size: $compressed_size,
    base_images: $base_images,
    runtime_base_verified: true,
    bash_static_sha256: $bash_sha256
  }' > "${WORK_DIR}/build.json"

set_output manifest_digest "${manifest_digest}"
set_output candidate_image "${candidate}"
log "Built ${IMAGE_REPOSITORY}:${version}: manifest ${manifest_digest}, config ${config_digest}, ${compressed_size} bytes compressed"
