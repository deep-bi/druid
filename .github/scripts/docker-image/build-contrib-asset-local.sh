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

# Builds the contrib extensions asset of a release that was published before the release workflow made
# it, so the release can get its Docker image. It runs the release's Maven build in a container with the
# JDK of that line's release workflow, then the same packing script as the release workflow. Attaching
# the asset to the release is left to you: the script prints the command. The image workflow flags the
# asset as attached after publication.
#
# Usage: build-contrib-asset-local.sh <tag> [<output directory>]
#   Run it from a clone of deep-bi/druid that has the tag. Needs Docker and git. Takes 30 minutes or more.
#   The Maven repository is kept in the Docker volume deepbi-contrib-m2 between runs.
#   TMPDIR      where to clone the tag (default ~/.cache). Docker must be able to mount it: Docker Desktop on
#               Linux shares only /home by default.
#   MAVEN_OPTS  for the build (default -Xmx3g; the JVM default in an 8 GB Docker Desktop VM is 2 GB)

set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

TAG="${1:?usage: build-contrib-asset-local.sh <tag> [<output directory>]}"
version="$(version_from_tag "${TAG}")"
OUT_DIR="$(realpath -m "${2:-contrib-assets/${TAG}}")"
packer="$(realpath "$(dirname "${BASH_SOURCE[0]}")/../package-contrib-extensions.sh")"
# The Maven command of deepbi-release.yml, the same on every maintained line.
build_command='mvn clean install -Papache-release,dist -DskipTests -Dgpg.skip=true -Dcheckstyle.skip -Ddependency-check.skip=true -B'

git rev-parse --verify --quiet "${TAG}^{commit}" > /dev/null || fail "Tag ${TAG} is not in this clone. Run git fetch --tags first."
workflow="$(git show "${TAG}:.github/workflows/deepbi-release.yml")" || fail "${TAG} has no .github/workflows/deepbi-release.yml"
if [[ "${workflow}" != *"${build_command}"* ]]; then
  fail "The release workflow at ${TAG} builds differently than this script; update build_command first"
fi
jdk="$(sed -n 's/^ *java-version: *"\{0,1\}\([0-9][0-9]*\)"\{0,1\} *$/\1/p' <<< "${workflow}" | head -1)"
[[ -n "${jdk}" ]] || fail "Cannot find java-version in the release workflow at ${TAG}"

work_root="${TMPDIR:-${HOME}/.cache}"
mkdir -p "${work_root}"
work="$(mktemp -d "${work_root}/deepbi-contrib-build.XXXXXX")"
trap 'rm -rf "${work}"' EXIT
log "Cloning ${TAG} into ${work}/src"
git clone --quiet --no-hardlinks --depth 1 --branch "${TAG}" "file://$(git rev-parse --show-toplevel)" "${work}/src"
pom_version="$(pom_project_version "${work}/src/pom.xml")"
[[ "${pom_version}" == "${version}" ]] || fail "pom.xml at ${TAG} says ${pom_version}"
cp "${packer}" "${work}/package-contrib-extensions.sh"
mkdir -p "${OUT_DIR}" "${work}/out"

log "Building ${TAG} with JDK ${jdk}"
# The build runs on the container's own filesystem: a bind-mounted source tree is slow on Docker Desktop
# and would leave root-owned files behind on Linux hosts. Only the archive comes back, through /work/out.
# shellcheck disable=SC2016 # the variables are expanded inside the container
docker run --rm \
  --volume "${work}:/work" \
  --volume deepbi-contrib-m2:/root/.m2 \
  --env VERSION="${version}" \
  --env BUILD_COMMAND="${build_command}" \
  --env MAVEN_OPTS="${MAVEN_OPTS:--Xmx3g}" \
  --env OWNER="$(id -u):$(id -g)" \
  "maven:3.9-eclipse-temurin-${jdk}" \
  bash -euo pipefail -c '
    restore_owner() { chown -R "${OWNER}" /work/out 2> /dev/null || true; }
    trap restore_owner EXIT
    apt-get -qq update > /dev/null
    DEBIAN_FRONTEND=noninteractive apt-get -qq -y install --no-install-recommends python3 python3-yaml git > /dev/null
    cp -a /work/src /build
    git config --global --add safe.directory /build
    cd /build
    ${BUILD_COMMAND}
    OUTPUT_DIR=/work/out bash /work/package-contrib-extensions.sh "${VERSION}"
  '

archive="apache-druid-${version}-contrib-extensions.tar.gz"
cp "${work}/out/${archive}" "${work}/out/${archive}.sha512" "${OUT_DIR}/"
log ""
log "Built ${OUT_DIR}/${archive}"
log "SHA-512: $(cat "${OUT_DIR}/${archive}.sha512")"
log ""
log "To attach it to the release:"
log "  gh release upload ${TAG} --repo deep-bi/druid ${OUT_DIR}/${archive} ${OUT_DIR}/${archive}.sha512"
