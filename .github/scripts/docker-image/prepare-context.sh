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

# Downloads and verifies the release assets, then builds the Docker build context: the bin tarball with
# the contrib extensions merged in, at distribution/target/ of the release checkout, keeping the
# apache-druid-<version>/ top-level directory that distribution/docker/Dockerfile expects.
#
# Environment:
#   SRC_DIR            checkout of the release commit
#   GITHUB_REPOSITORY  owner/repo, set by GitHub Actions
#   GH_TOKEN           GitHub token. Draft assets need a token with push access. Without one, the assets of
#                      a published release of a public repository are downloaded anonymously.
#   WORK_DIR           working directory with release.json and assets.json from resolve-release.sh
#
# Writes assets-evidence.json, expected-extensions.txt, expected-files.sha256, dedupe.json and
# wikipedia-index.json to WORK_DIR.

set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

SRC_DIR="${SRC_DIR:?SRC_DIR is not set}"
REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"
GH_TOKEN="${GH_TOKEN:-}"
WORK_DIR="${WORK_DIR:-${RUNNER_TEMP:?RUNNER_TEMP is not set}/docker-image}"

version="$(jq -r '.version' "${WORK_DIR}/release.json")"
commit="$(jq -r '.commit' "${WORK_DIR}/release.json")"
published_at="$(jq -r '.published_at // empty' "${WORK_DIR}/release.json")"

pom_version="$(pom_project_version "${SRC_DIR}/pom.xml")"
if [[ "${pom_version}" != "${version}" ]]; then
  fail "The tag says ${version}, but pom.xml at ${commit} says ${pom_version}"
fi

bin="apache-druid-${version}-bin.tar.gz"
contrib="apache-druid-${version}-contrib-extensions.tar.gz"
required=("${bin}" "${bin}.sha512" "${contrib}" "${contrib}.sha512")
missing=()
for name in "${required[@]}"; do
  if ! jq -e --arg name "${name}" 'any(.[]; .name == $name)' "${WORK_DIR}/assets.json" > /dev/null; then
    missing+=("${name}")
  fi
done
if (( ${#missing[@]} > 0 )); then
  fail "The release is missing these assets: ${missing[*]}"
fi

assets_dir="${WORK_DIR}/assets"
mkdir -p "${assets_dir}"
auth_config=""
if [[ -n "${GH_TOKEN}" ]]; then
  auth_config="header = \"Authorization: Bearer ${GH_TOKEN}\""
fi
for name in "${required[@]}"; do
  id="$(jq -r --arg name "${name}" 'first(.[] | select(.name == $name)) | .id' "${WORK_DIR}/assets.json")"
  log "Downloading ${name}"
  # The token goes in through stdin so it stays out of the process list. curl drops it on the redirect
  # to the storage host.
  curl -fsSL --retry 3 --retry-all-errors -K - -H 'Accept: application/octet-stream' \
    -o "${assets_dir}/${name}" "https://api.github.com/repos/${REPO}/releases/assets/${id}" \
    <<< "${auth_config}"
done

bin_sha512="$(verify_sha512 "${assets_dir}/${bin}" "${assets_dir}/${bin}.sha512")"
contrib_sha512="$(verify_sha512 "${assets_dir}/${contrib}" "${assets_dir}/${contrib}.sha512")"
check_contrib_archive "${assets_dir}/${contrib}" "${version}"
log "Checksums match and the contrib archive only holds extension directories"

# An asset uploaded after the release was published, such as a contrib archive built for a backfill,
# is flagged in the evidence.
jq --arg published "${published_at}" --arg bin "${bin}" --arg bin_sha512 "${bin_sha512}" \
  --arg contrib "${contrib}" --arg contrib_sha512 "${contrib_sha512}" '
  map(select(.name == $bin or .name == $contrib)
      | . + {
          sha512: (if .name == $bin then $bin_sha512 else $contrib_sha512 end),
          attached_after_publication: ($published != "" and .created_at > $published)
        })' "${WORK_DIR}/assets.json" > "${WORK_DIR}/assets-evidence.json"

merge_dir="${WORK_DIR}/merge"
dist="${merge_dir}/apache-druid-${version}"
rm -rf "${merge_dir}"
mkdir -p "${merge_dir}"
tar -xzf "${assets_dir}/${bin}" -C "${merge_dir}"
if [[ ! -d "${dist}/extensions" ]]; then
  fail "${bin} has no apache-druid-${version}/extensions directory"
fi

# The contrib archive may only add extension directories, never replace a file of the main tarball.
contrib_extensions="$(tar -tzf "${assets_dir}/${contrib}" \
  | sed -n "s|^apache-druid-${version}/extensions/\([^/]*\)/.*|\1|p" | LC_ALL=C sort -u)"
while IFS= read -r extension; do
  if [[ -e "${dist}/extensions/${extension}" ]]; then
    fail "${contrib} contains ${extension}, which ${bin} already has"
  fi
done <<< "${contrib_extensions}"
tar -xzf "${assets_dir}/${contrib}" -C "${merge_dir}" --keep-old-files

# The extensions of the two profiles the assets come from: dist for the bin tarball, bundle-contrib-exts
# for the contrib archive.
pom_extensions "${SRC_DIR}/distribution/pom.xml" dist:pull-deps bundle-contrib-exts:pull-deps-contrib-exts \
  > "${WORK_DIR}/expected-extensions.txt"
find "${dist}/extensions" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | LC_ALL=C sort \
  > "${WORK_DIR}/tarball-extensions.txt"
missing_extensions="$(LC_ALL=C comm -23 "${WORK_DIR}/expected-extensions.txt" "${WORK_DIR}/tarball-extensions.txt")"
extra_extensions="$(LC_ALL=C comm -13 "${WORK_DIR}/expected-extensions.txt" "${WORK_DIR}/tarball-extensions.txt")"
if [[ -n "${missing_extensions}" ]]; then
  fail "Extensions listed in distribution/pom.xml are missing from the assets: $(tr '\n' ' ' <<< "${missing_extensions}")"
fi
if [[ -n "${extra_extensions}" ]]; then
  warn "Extensions not listed in distribution/pom.xml: $(tr '\n' ' ' <<< "${extra_extensions}")"
fi

cp "${dist}/quickstart/tutorial/wikipedia-index.json" "${WORK_DIR}/wikipedia-index.json"
file_checksums "${dist}" > "${WORK_DIR}/asset-files.sha256"

mkdir -p "${SRC_DIR}/distribution/target"
tar -C "${merge_dir}" -cf - "apache-druid-${version}" | gzip -1 > "${SRC_DIR}/distribution/target/${bin}"

# The checksums the image must have, for the content check of the smoke test. The Dockerfile turns every
# jar whose file name it has seen before into a symlink to the first one, so the merged tree gets the
# same treatment here, now that the build context is packed. A jar built separately, such as a Druid jar
# in a contrib archive made for a backfill, can differ from the same-named jar it ends up linked to.
linked="$(apply_jar_dedupe "${dist}" "${SRC_DIR}/distribution/docker")"
file_checksums "${dist}" > "${WORK_DIR}/expected-files.sha256"
relinked="$(compare_checksums "${WORK_DIR}/asset-files.sha256" "${WORK_DIR}/expected-files.sha256" \
  | sed 's|^content differs: \./||')"
jq -n --argjson linked "${linked}" --arg changed "${relinked}" \
  '{linked: $linked, changed: ($changed | split("\n") | map(select(. != "")))}' > "${WORK_DIR}/dedupe.json"
if [[ -n "${relinked}" ]]; then
  warn "The image links $(wc -l <<< "${relinked}") jars of the assets to a same-named jar with other content: $(head -5 <<< "${relinked}" | tr '\n' ' ')"
fi

rm -rf "${merge_dir}" "${assets_dir:?}/${bin}" "${assets_dir:?}/${contrib}" "${WORK_DIR}/asset-files.sha256"
log "Build context ready: distribution/target/${bin}, $(wc -l < "${WORK_DIR}/tarball-extensions.txt") extensions, $(wc -l < "${WORK_DIR}/expected-files.sha256") files, ${linked} jars linked as in the Dockerfile"
