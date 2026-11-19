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

# Packs the contrib extensions of a release as apache-druid-<version>-contrib-extensions.tar.gz, with a
# .sha512 file that holds only the hash, like the one of the bin tarball. It runs the pull-deps execution
# of the bundle-contrib-exts profile in distribution/pom.xml, the same execution the official Docker
# images use, and packs the extension directories it adds under apache-druid-<version>/extensions/, so
# the archive can be extracted over the bin tarball.
#
# Run it from the repository root after `mvn install -Pdist`, with the same JDK, so the contrib modules
# and the distribution dependencies are in the local Maven repository.
#
# Usage: package-contrib-extensions.sh <version>
#   OUTPUT_DIR  where to write the archive and its .sha512 (default distribution/target)

set -euo pipefail

VERSION="${1:-${VERSION:-}}"
if [[ -z "${VERSION}" ]]; then
  echo "::error::VERSION is not set (pass it as the first argument or env VERSION)"
  exit 1
fi
OUTPUT_DIR="${OUTPUT_DIR:-distribution/target}"
EXTENSIONS_DIR=distribution/target/extensions
ARCHIVE="apache-druid-${VERSION}-contrib-extensions.tar.gz"

fail() {
  echo "::error::$*" >&2
  exit 1
}

list_extensions() {
  find "${EXTENSIONS_DIR}" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | LC_ALL=C sort
}

if [[ ! -d "${EXTENSIONS_DIR}" ]]; then
  fail "${EXTENSIONS_DIR} does not exist. Build with -Pdist first."
fi

before="$(list_extensions)"
mvn -B -pl distribution -Pbundle-contrib-exts exec:exec@pull-deps-contrib-exts
added="$(LC_ALL=C comm -13 <(echo "${before}") <(list_extensions))"

# The extensions the profile lists, so a pull-deps run that silently skipped one fails here.
expected="$(python3 -I - distribution/pom.xml <<'PY'
import sys
import xml.etree.ElementTree as ET

artifacts = set()
for execution in ET.parse(sys.argv[1]).getroot().iterfind('.//{*}execution'):
    if (execution.findtext('{*}id') or '').strip() != 'pull-deps-contrib-exts':
        continue
    args = [(arg.text or '').strip() for arg in execution.iterfind('.//{*}argument')]
    artifacts.update(value.split(':')[1] for flag, value in zip(args, args[1:]) if flag == '-c')
if not artifacts:
    sys.exit('no pull-deps-contrib-exts execution in ' + sys.argv[1])
print('\n'.join(sorted(artifacts)))
PY
)"
if [[ "${added}" != "${expected}" ]]; then
  echo "Expected:" >&2
  echo "${expected}" >&2
  echo "Added by pull-deps:" >&2
  echo "${added}" >&2
  fail "pull-deps-contrib-exts did not add exactly the extensions listed in distribution/pom.xml"
fi

staging="$(mktemp -d)"
trap 'rm -rf "${staging}"' EXIT
mkdir -p "${staging}/apache-druid-${VERSION}/extensions" "${OUTPUT_DIR}"
while IFS= read -r extension; do
  cp -a "${EXTENSIONS_DIR}/${extension}" "${staging}/apache-druid-${VERSION}/extensions/"
done <<< "${added}"

# Sorted entries, fixed owners and the commit time keep the archive stable for the same jars.
mtime="$(git log -1 --format=%ct 2> /dev/null || date +%s)"
tar -C "${staging}" --sort=name --owner=0 --group=0 --numeric-owner --mtime="@${mtime}" \
  -cf - "apache-druid-${VERSION}" | gzip -n > "${OUTPUT_DIR}/${ARCHIVE}"
sha512sum "${OUTPUT_DIR}/${ARCHIVE}" | cut -d' ' -f1 > "${OUTPUT_DIR}/${ARCHIVE}.sha512"

echo "Packed $(wc -l <<< "${added}") contrib extensions into ${OUTPUT_DIR}/${ARCHIVE} ($(du -h "${OUTPUT_DIR}/${ARCHIVE}" | cut -f1))"
