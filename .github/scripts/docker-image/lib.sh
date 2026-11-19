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

# Shared helpers for the Deep.BI Docker image workflow (.github/workflows/deepbi-docker-image.yml).
# Source this file. It only defines variables and functions.

# A release tag is v<upstream version>-deepbiN, or v<upstream version>-patchN on lines up to 32.0.x.
RELEASE_TAG_REGEX='^v([0-9]+)\.([0-9]+)\.([0-9]+)-(deepbi|patch)([0-9]+)$'
RELEASE_VERSION_REGEX='^([0-9]+)\.([0-9]+)\.([0-9]+)-(deepbi|patch)([0-9]+)$'

# Manifest lookups accept image indexes, manifest lists and single manifests.
MANIFEST_ACCEPT='application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json'

# The throwaway registry of a run. The smoke test pulls the candidate from it, and a dry run rehearses the
# publish against it.
LOCAL_REGISTRY=localhost:5000
LOCAL_REGISTRY_CONTAINER=deepbi-docker-registry

log() {
  echo "$*" >&2
}

warn() {
  echo "::warning::$*" >&2
}

fail() {
  echo "::error::$*" >&2
  exit 1
}

# set_output <name> <value>: sets a step output when running in GitHub Actions.
set_output() {
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "$1=$2" >> "${GITHUB_OUTPUT}"
  fi
}

# version_from_tag <tag>: prints the version of a release tag, or fails.
version_from_tag() {
  if [[ ! "$1" =~ ${RELEASE_TAG_REGEX} ]]; then
    fail "$1 is not a release tag (expected v<x.y.z>-deepbiN or v<x.y.z>-patchN)"
  fi
  echo "${1#v}"
}

# is_release_version <version>: true for x.y.z-deepbiN and x.y.z-patchN.
is_release_version() {
  [[ "$1" =~ ${RELEASE_VERSION_REGEX} ]]
}

# version_line <version>: prints the release line <major>.<minor>, for example 38.0 for 38.0.0-deepbi3.
version_line() {
  if [[ ! "$1" =~ ${RELEASE_VERSION_REGEX} ]]; then
    fail "$1 is not a release version"
  fi
  echo "$((10#${BASH_REMATCH[1]})).$((10#${BASH_REMATCH[2]}))"
}

# version_key <version>: prints a key that puts release versions in version order with a plain sort,
# so 38.0.0-deepbi10 comes after 38.0.0-deepbi9.
version_key() {
  if [[ ! "$1" =~ ${RELEASE_VERSION_REGEX} ]]; then
    fail "$1 is not a release version"
  fi
  printf '%06d.%06d.%06d.%06d.%s\n' "$((10#${BASH_REMATCH[1]}))" "$((10#${BASH_REMATCH[2]}))" \
    "$((10#${BASH_REMATCH[3]}))" "$((10#${BASH_REMATCH[5]}))" "${BASH_REMATCH[4]}"
}

# sort_versions_desc: reads versions, one per line, and prints the release versions newest first,
# without duplicates. Anything that is not a release version is dropped.
sort_versions_desc() {
  local version
  while IFS= read -r version; do
    if is_release_version "${version}"; then
      printf '%s %s\n' "$(version_key "${version}")" "${version}"
    fi
  done | LC_ALL=C sort -r -u | cut -d' ' -f2
}

# choose_floating_target <scope> <has_image function>
# Reads release versions on stdin and prints the newest one in <scope> that has an image: the version a
# floating tag should point at. <scope> is a line such as 38.0, or "all" for latest. Only the versions read
# count, so the caller decides which releases are eligible. A newer version without an image is skipped.
# Prints nothing when no version in scope has an image.
choose_floating_target() {
  local scope=$1 has_image=$2 candidates version
  candidates="$(sort_versions_desc)"
  while IFS= read -r version; do
    if [[ -z "${version}" ]]; then
      continue
    fi
    if [[ "${scope}" != all && "$(version_line "${version}")" != "${scope}" ]]; then
      continue
    fi
    if "${has_image}" "${version}"; then
      echo "${version}"
      return 0
    fi
  done <<< "${candidates}"
}

# tag_commit <owner/repo> <tag>: prints the commit a tag of the GitHub repository points at, following
# annotated tags, or fails. Needs GH_TOKEN.
tag_commit() {
  local repo=$1 tag=$2 ref type sha
  # Called in a command substitution, where set -e does not apply, so every lookup is checked.
  ref="$(gh api "repos/${repo}/git/ref/tags/${tag}")" || fail "Cannot read tag ${tag} of ${repo}"
  type="$(jq -r '.object.type' <<< "${ref}")"
  sha="$(jq -r '.object.sha' <<< "${ref}")"
  while [[ "${type}" == tag ]]; do
    ref="$(gh api "repos/${repo}/git/tags/${sha}")" || fail "Cannot read the annotated tag ${sha} of ${tag}"
    type="$(jq -r '.object.type' <<< "${ref}")"
    sha="$(jq -r '.object.sha' <<< "${ref}")"
  done
  if [[ "${type}" != commit ]]; then
    fail "${tag} points to a ${type:-nothing}, not a commit"
  fi
  echo "${sha}"
}

# require_release_check <work dir>: fails unless recheck-release.sh checked the release of release.json in
# this job. Everything that writes to Docker Hub calls it first, so nothing is published on the release
# state recorded when the run started.
require_release_check() {
  local checked
  checked="$(jq -r '.release_id // empty' "$1/release-check.json" 2> /dev/null || true)"
  if [[ -z "${checked}" || "${checked}" != "$(jq -r '.release_id' "$1/release.json")" ]]; then
    fail "The release was not re-checked in this job. Run recheck-release.sh before writing to Docker Hub."
  fi
}

# read_sha512 <file>: prints the SHA-512 in a .sha512 file holding either the bare hash or
# "<hash>  <file name>".
read_sha512() {
  local hash
  hash="$(awk 'NF { print tolower($1); exit }' "$1")"
  if [[ ! "${hash}" =~ ^[0-9a-f]{128}$ ]]; then
    fail "$(basename "$1") does not contain a SHA-512 checksum"
  fi
  echo "${hash}"
}

# verify_sha512 <file> <checksum file>: fails unless the file matches, and prints its SHA-512.
verify_sha512() {
  local expected actual
  expected="$(read_sha512 "$2")"
  actual="$(sha512sum "$1" | cut -d' ' -f1)"
  if [[ "${actual}" != "${expected}" ]]; then
    fail "Checksum mismatch for $(basename "$1"): $(basename "$2") says ${expected}, the file is ${actual}"
  fi
  echo "${actual}"
}

# pom_project_version <pom.xml>: prints the project version the pom declares.
pom_project_version() {
  python3 -I - "$1" <<'PY'
import sys
import xml.etree.ElementTree as ET

version = ET.parse(sys.argv[1]).getroot().findtext('{*}version')
if not version:
    sys.exit('no project version in ' + sys.argv[1])
print(version.strip())
PY
}

# pom_extensions <distribution/pom.xml> <profile>:<execution id>...: prints the artifact IDs that the
# given pull-deps executions install as extensions (their -c coordinates), sorted and without duplicates.
# Each execution is looked up in its profile, because execution IDs repeat across profiles: up to 36.x,
# the integration-test profile has a pull-deps execution of its own. Each pair must match exactly one
# profile, exactly one execution in it, and list at least one coordinate.
pom_extensions() {
  python3 -I - "$@" <<'PY'
import sys
import xml.etree.ElementTree as ET

pom, pairs = sys.argv[1], sys.argv[2:]
if not pairs:
    sys.exit('no <profile>:<execution> given for ' + pom)
profiles = ET.parse(pom).getroot().findall('./{*}profiles/{*}profile')
artifacts = set()
for pair in pairs:
    profile_id, separator, execution_id = pair.partition(':')
    if not separator or not profile_id or not execution_id:
        sys.exit('expected <profile>:<execution>, got %r' % pair)
    matches = [p for p in profiles if (p.findtext('{*}id') or '').strip() == profile_id]
    if len(matches) != 1:
        sys.exit('%d profiles named %s in %s, expected 1' % (len(matches), profile_id, pom))
    executions = [e for e in matches[0].iterfind('.//{*}execution')
                  if (e.findtext('{*}id') or '').strip() == execution_id]
    if len(executions) != 1:
        sys.exit('%d executions named %s in profile %s of %s, expected 1'
                 % (len(executions), execution_id, profile_id, pom))
    args = [(arg.text or '').strip() for arg in executions[0].iterfind('.//{*}argument')]
    listed = 0
    for flag, value in zip(args, args[1:]):
        if flag == '-c':
            parts = value.split(':')
            if len(parts) < 2 or not parts[1]:
                sys.exit('unexpected coordinate %r in %s' % (value, pom))
            artifacts.add(parts[1])
            listed += 1
    if not listed:
        sys.exit('%s lists no -c coordinates in %s' % (pair, pom))
print('\n'.join(sorted(artifacts)))
PY
}

# dockerfile_base_images <Dockerfile>: prints the external images the FROM lines use, with ARG defaults
# filled in, skipping references to earlier stages. The last line is the runtime base image.
dockerfile_base_images() {
  python3 -I - "$1" <<'PY'
import re
import sys

args, stages, images = {}, set(), []
with open(sys.argv[1], encoding='utf-8') as dockerfile:
    for raw in dockerfile:
        line = raw.strip()
        arg = re.match(r'(?i)ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)', line)
        if arg:
            args.setdefault(arg.group(1), arg.group(2).strip('"'))
            continue
        base = re.match(r'(?i)FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?', line)
        if not base:
            continue
        image = re.sub(r'\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?',
                       lambda var: args.get(var.group(1), var.group(0)), base.group(1))
        if '$' in image:
            sys.exit('cannot resolve %s in %s' % (base.group(1), sys.argv[1]))
        if image.lower() not in stages:
            if image in images:
                images.remove(image)
            images.append(image)
        if base.group(2):
            stages.add(base.group(2).lower())
print('\n'.join(images))
PY
}

# image_digest <image reference>: prints the digest the reference resolves to right now.
image_digest() {
  docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' | jq -r '.digest'
}

# docker_hub_token <repository>: prints an anonymous pull token for a Docker Hub repository.
docker_hub_token() {
  curl -fsS --retry 3 --retry-all-errors \
    "https://auth.docker.io/token?service=registry.docker.io&scope=repository:$1:pull" | jq -r '.token'
}

# registry_digest <registry> <repository> <tag or digest>
# Prints the digest the reference resolves to, or nothing when it does not exist. Any other answer
# fails, so an error never reads as "missing". <registry> is docker.io, or host:port of a plain HTTP
# registry such as the local registry of a dry run. HEAD requests don't count against Docker Hub's
# pull limit.
registry_digest() {
  local registry=$1 repository=$2 reference=$3 url code headers token
  local -a auth=()
  if [[ "${registry}" == docker.io ]]; then
    url="https://registry-1.docker.io/v2/${repository}/manifests/${reference}"
    token="$(docker_hub_token "${repository}")"
    auth=(-H "Authorization: Bearer ${token}")
  else
    url="http://${registry}/v2/${repository}/manifests/${reference}"
  fi
  headers="$(mktemp)"
  code="$(curl -sS --head --retry 3 --retry-delay 2 -H "Accept: ${MANIFEST_ACCEPT}" "${auth[@]}" \
    -D "${headers}" -o /dev/null -w '%{http_code}' "${url}")" || code=000
  case "${code}" in
    200)
      tr -d '\r' < "${headers}" | awk 'tolower($0) ~ /^docker-content-digest:/ { sub(/^[^:]*: */, ""); print }'
      ;;
    404)
      ;;
    *)
      rm -f "${headers}"
      fail "Unexpected HTTP ${code} for ${registry}/${repository}:${reference}"
      ;;
  esac
  rm -f "${headers}"
}

# start_local_registry: starts registry:2 at LOCAL_REGISTRY unless it is already running, and waits until
# it answers.
start_local_registry() {
  if [[ "$(docker container inspect --format '{{.State.Running}}' "${LOCAL_REGISTRY_CONTAINER}" 2> /dev/null)" != true ]]; then
    docker rm --force --volumes "${LOCAL_REGISTRY_CONTAINER}" > /dev/null 2>&1 || true
    docker run --detach --name "${LOCAL_REGISTRY_CONTAINER}" --publish "127.0.0.1:${LOCAL_REGISTRY##*:}:5000" \
      registry:2 > /dev/null
  fi
  if ! curl -fsS --retry 30 --retry-delay 1 --retry-all-errors "http://${LOCAL_REGISTRY}/v2/" > /dev/null; then
    fail "The local registry at ${LOCAL_REGISTRY} does not answer"
  fi
}

# check_contrib_archive <archive> <version>: fails unless the archive holds only regular files and
# directories under apache-druid-<version>/extensions/<name>/.
check_contrib_archive() {
  local archive=$1 version=$2 name prefix listing entries outside
  name="$(basename "${archive}")"
  prefix="apache-druid-${version//./\\.}"
  listing="$(tar -tvzf "${archive}")" || fail "Cannot read ${name}"
  if awk '{ print substr($1, 1, 1) }' <<< "${listing}" | grep -qv '^[-d]$'; then
    fail "${name} contains links or special files"
  fi
  entries="$(tar -tzf "${archive}")"
  if grep -Eq '(^|/)\.\.(/|$)' <<< "${entries}"; then
    fail "${name} contains '..' in a path"
  fi
  outside="$(grep -Ev "^${prefix}/(extensions/([^/]+(/.*)?)?)?$" <<< "${entries}" || true)"
  if [[ -n "${outside}" ]]; then
    fail "${name} has entries outside apache-druid-${version}/extensions/: $(head -3 <<< "${outside}" | tr '\n' ' ')"
  fi
  if ! grep -Eq "^${prefix}/extensions/[^/]+/." <<< "${entries}"; then
    fail "${name} contains no extension files"
  fi
}
