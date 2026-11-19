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

# Unit tests for the helpers and the publish job scripts of the Docker image workflow. No network and no
# Docker needed: gh, curl and skopeo are replaced by the fakes in fake-bin where a script needs them.
# Usage: .github/scripts/docker-image/tests/run-tests.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "${HERE}/../lib.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
tests=0
failures=0

# expect <name> <expected> <actual>
expect() {
  tests=$((tests + 1))
  if [[ "$2" == "$3" ]]; then
    echo "ok   $1"
  else
    failures=$((failures + 1))
    printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
  fi
}

# expect_failure <name> <command>...: the command must exit with an error.
expect_failure() {
  tests=$((tests + 1))
  if ( "${@:2}" ) > /dev/null 2>&1; then
    failures=$((failures + 1))
    echo "FAIL $1 (no error)"
  else
    echo "ok   $1"
  fi
}

lines() {
  tr '\n' ' ' | sed 's/ $//'
}

# Tags and versions

expect "tag v38.0.0-deepbi3" "38.0.0-deepbi3" "$(version_from_tag v38.0.0-deepbi3)"
expect "tag v31.0.2-patch10" "31.0.2-patch10" "$(version_from_tag v31.0.2-patch10)"
expect_failure "rejects a snapshot tag" version_from_tag v40.0.0-SNAPSHOT
expect_failure "rejects a tag without v" version_from_tag 38.0.0-deepbi3
expect_failure "rejects an rc suffix" version_from_tag v38.0.0-deepbi4-rc1
expect "line of 38.0.0-deepbi3" "38.0" "$(version_line 38.0.0-deepbi3)"
expect "line of 31.0.2-patch10" "31.0" "$(version_line 31.0.2-patch10)"

expect "version order" \
  "39.0.0-deepbi1 38.0.0-deepbi10 38.0.0-deepbi9 38.0.0-deepbi2 37.0.0-deepbi6 31.0.2-patch10 31.0.2-patch9 31.0.1-patch12" \
  "$(printf '%s\n' 38.0.0-deepbi9 31.0.2-patch9 38.0.0-deepbi10 37.0.0-deepbi6 39.0.0-deepbi1 38.0.0-deepbi2 \
    31.0.1-patch12 31.0.2-patch10 40.0.0-SNAPSHOT 38.0.0-deepbi9 | sort_versions_desc | lines)"

# Floating tag targets. Only the versions passed in count: floating-tags.sh passes the releases GitHub
# lists as published and stable, plus its own version in a dry run.

IMAGES=""
has_image_fixture() {
  grep -qxF "$1" <<< "${IMAGES}"
}
images() {
  IMAGES="$(printf '%s\n' "$@")"
}
PUBLISHED=(38.0.0-deepbi3 38.0.0-deepbi2 37.0.0-deepbi6 36.0.0-deepbi5 34.0.0-deepbi9 31.0.2-patch10 40.0.0-SNAPSHOT)
# target <scope> [version]...: the target among PUBLISHED and the given versions.
target() {
  printf '%s\n' "${PUBLISHED[@]}" "${@:2}" | choose_floating_target "$1" has_image_fixture
}

images 38.0.0-deepbi3 37.0.0-deepbi6 38.0.0-deepbi4
expect "new 38.x release moves 38.0-latest" "38.0.0-deepbi4" "$(target 38.0 38.0.0-deepbi4)"
expect "new 38.x release moves latest" "38.0.0-deepbi4" "$(target all 38.0.0-deepbi4)"
images 38.0.0-deepbi3 37.0.0-deepbi6 37.0.0-deepbi7
expect "37.x after 38.x moves 37.0-latest" "37.0.0-deepbi7" "$(target 37.0 37.0.0-deepbi7)"
expect "37.x after 38.x leaves latest on 38.x" "38.0.0-deepbi3" "$(target all 37.0.0-deepbi7)"
images 38.0.0-deepbi3 37.0.0-deepbi6 39.0.0-deepbi1
expect "39.0.0-deepbi1 moves latest" "39.0.0-deepbi1" "$(target all 39.0.0-deepbi1)"
expect "39.0.0-deepbi1 starts 39.0-latest" "39.0.0-deepbi1" "$(target 39.0 39.0.0-deepbi1)"

images 38.0.0-deepbi3 37.0.0-deepbi6 38.0.0-deepbi4
expect "an unlisted release with an image is not its line's target" "38.0.0-deepbi3" "$(target 38.0)"
expect "an unlisted release with an image does not become latest" "38.0.0-deepbi3" "$(target all)"
expect "nothing listed, no target" "" "$(choose_floating_target all has_image_fixture < /dev/null)"
expect "nothing listed in the line, no target" "" "$(target 35.0)"

images 38.0.0-deepbi3 38.0.0-deepbi9 38.0.0-deepbi10
expect "an older release never moves a tag back" "38.0.0-deepbi10" "$(target 38.0 38.0.0-deepbi9 38.0.0-deepbi10)"
images 38.0.0-deepbi3 38.0.0-deepbi9
expect "a newer release without an image is skipped" "38.0.0-deepbi9" \
  "$(target 38.0 38.0.0-deepbi9 38.0.0-deepbi10)"

images 38.0.0-deepbi3 37.0.0-deepbi6 31.0.2-patch10
expect "backfill on 31.x moves 31.0-latest" "31.0.2-patch10" "$(target 31.0)"
expect "backfill on 31.x keeps latest on the newest image" "38.0.0-deepbi3" "$(target all)"

# Publish job scripts. recheck-release.sh, publish.sh and floating-tags.sh run against the gh, curl and
# skopeo of fake-bin, which answer from files: the GitHub API under FAKE_GH, the registries under
# FAKE_REGISTRY.

FAKE_BIN="${HERE}/fake-bin"
SCRIPTS="${HERE}/.."
WORK="${TMP}/work"
export FAKE_GH="${TMP}/gh" FAKE_REGISTRY="${TMP}/registry"
BUILT=1111111111111111111111111111111111111111
OTHER=2222222222222222222222222222222222222222
ANNOTATED=3333333333333333333333333333333333333333

# expect_refusal <name> <part of the error> <command>...: the command must fail with that error, so a test
# can't pass on an unrelated failure.
expect_refusal() {
  local output
  tests=$((tests + 1))
  if output="$("${@:3}" 2>&1)"; then
    failures=$((failures + 1))
    echo "FAIL $1 (no error)"
  elif [[ "${output}" != *"$2"* ]]; then
    failures=$((failures + 1))
    printf 'FAIL %s\n  expected an error with: %s\n  output: %s\n' "$1" "$2" "${output}"
  else
    echo "ok   $1"
  fi
}

# api <path> <json>: what the fake gh answers for an API path.
api() {
  mkdir -p "$(dirname "${FAKE_GH}/$1")"
  printf '%s\n' "$2" > "${FAKE_GH}/$1.json"
}

# releases <tag>:<prerelease>...: the release list as a token without push access sees it, so no drafts.
releases() {
  local pair json='[]'
  for pair in "$@"; do
    json="$(jq --arg tag "${pair%%:*}" --argjson prerelease "${pair#*:}" \
      '. + [{tag_name: $tag, draft: false, prerelease: $prerelease}]' <<< "${json}")"
  done
  api repos/deep-bi/druid/releases "${json}"
}

# release_now <jq object>: release 104 as GitHub reports it now, with the given fields changed.
release_now() {
  api repos/deep-bi/druid/releases/104 \
    "$(jq -n "{id: 104, tag_name: \"v38.0.0-deepbi4\", draft: false, prerelease: false} + $1")"
}

# set_tag <registry> <tag> <digest>: deepbi/druid:<tag> resolves to <digest> in the fake registry.
set_tag() {
  mkdir -p "${FAKE_REGISTRY}/$1/deepbi/druid"
  echo "$3" > "${FAKE_REGISTRY}/$1/deepbi/druid/$2"
}

# tag_digests <registry> <tag>...: what the tags resolve to in the fake registry.
tag_digests() {
  local registry=$1 tag
  shift
  for tag in "$@"; do
    cat "${FAKE_REGISTRY}/${registry}/deepbi/druid/${tag}" 2> /dev/null || echo none
  done | lines
}

# run_script <script> [VAR=value]...: runs a workflow script with the fakes.
run_script() {
  local script=$1
  shift
  env PATH="${FAKE_BIN}:${PATH}" GITHUB_REPOSITORY=deep-bi/druid GH_TOKEN=fake WORK_DIR="${WORK}" \
    REGISTRY=docker.io IMAGE_REPOSITORY=deepbi/druid "$@" bash "${SCRIPTS}/${script}"
}

# run_login [VAR=value]...: runs registry-login.sh with docker and skopeo stubs that fail if they are called.
run_login() {
  local stubs="${TMP}/no-login" tool
  mkdir -p "${stubs}"
  for tool in docker skopeo; do
    printf '#!/usr/bin/env bash\necho "%s must not run" >&2\nexit 99\n' "${tool}" > "${stubs}/${tool}"
    chmod +x "${stubs}/${tool}"
  done
  env PATH="${stubs}:${PATH}" RUNNER_TEMP="${TMP}" "$@" bash "${SCRIPTS}/registry-login.sh"
}

with_fakes() {
  (PATH="${FAKE_BIN}:${PATH}" && "$@")
}

floating_actions() {
  jq -r '[.tags[] | "\(.tag):\(.target // "-"):\(.action)"] | join(" ")' "${WORK}/floating.json"
}

# edit_release <jq filter>: changes release.json as resolve-release.sh wrote it.
edit_release() {
  jq "$1" "${WORK}/release.json" > "${WORK}/release.next" && mv "${WORK}/release.next" "${WORK}/release.json"
}

# scenario: the publish job of v38.0.0-deepbi4 (release 104, an annotated tag on BUILT) after publish.sh
# pushed its image. Docker Hub also has 37.0.0-deepbi6, 38.0.0-deepbi3 and the pre-release 39.0.0-deepbi1,
# and the floating tags are where the previous runs left them.
scenario() {
  rm -rf "${FAKE_GH}" "${FAKE_REGISTRY}" "${WORK}"
  mkdir -p "${WORK}"
  jq -n --arg commit "${BUILT}" '{tag: "v38.0.0-deepbi4", version: "38.0.0-deepbi4", line: "38.0",
    commit: $commit, release_id: 104, draft: false, prerelease: false, dry_run: false, update_latest: true}' \
    > "${WORK}/release.json"
  echo '{"digest": "sha256:d384"}' > "${WORK}/publish.json"
  release_now '{}'
  api repos/deep-bi/druid/git/ref/tags/v38.0.0-deepbi4 "{\"object\": {\"type\": \"tag\", \"sha\": \"${ANNOTATED}\"}}"
  api "repos/deep-bi/druid/git/tags/${ANNOTATED}" "{\"object\": {\"type\": \"commit\", \"sha\": \"${BUILT}\"}}"
  releases v39.0.0-deepbi1:true v38.0.0-deepbi4:false v38.0.0-deepbi3:false v37.0.0-deepbi6:false
  set_tag docker.io 39.0.0-deepbi1 sha256:d391
  set_tag docker.io 38.0.0-deepbi4 sha256:d384
  set_tag docker.io 38.0.0-deepbi3 sha256:d383
  set_tag docker.io 37.0.0-deepbi6 sha256:d376
  set_tag docker.io 38.0-latest sha256:d383
  set_tag docker.io 37.0-latest sha256:d376
  set_tag docker.io latest sha256:d383
}

scenario
expect "tag_commit follows an annotated tag" "${BUILT}" "$(with_fakes tag_commit deep-bi/druid v38.0.0-deepbi4)"
api repos/deep-bi/druid/git/ref/tags/v38.0.0-deepbi3 "{\"object\": {\"type\": \"commit\", \"sha\": \"${OTHER}\"}}"
expect "tag_commit of a lightweight tag" "${OTHER}" "$(with_fakes tag_commit deep-bi/druid v38.0.0-deepbi3)"
expect_failure "tag_commit fails for a missing tag" with_fakes tag_commit deep-bi/druid v38.0.0-deepbi9

scenario
api repos/deep-bi/druid/releases/tags/v38.0.0-deepbi4 \
  '{"id": 104, "tag_name": "v38.0.0-deepbi4", "draft": false, "prerelease": false, "assets": []}'
rm "${WORK}/release.json"
run_script resolve-release.sh RELEASE_TAG=v38.0.0-deepbi4 2> /dev/null
expect "resolve-release.sh records the release, its commit and the existing image" "104 ${BUILT} true" \
  "$(jq -r '"\(.release_id) \(.commit) \(.image_exists)"' "${WORK}/release.json")"
expect "resolve-release.sh updates latest by default" true "$(jq -r '.update_latest' "${WORK}/release.json")"
run_script resolve-release.sh RELEASE_TAG=v38.0.0-deepbi4 UPDATE_LATEST=false 2> /dev/null
expect "resolve-release.sh records update_latest false" false "$(jq -r '.update_latest' "${WORK}/release.json")"
expect_refusal "resolve-release.sh rejects an update_latest other than true or false" \
  "UPDATE_LATEST must be true or false" run_script resolve-release.sh RELEASE_TAG=v38.0.0-deepbi4 UPDATE_LATEST=no

# The release re-check

scenario
expect "re-check passes an unchanged release" ok "$(run_script recheck-release.sh 2> /dev/null && echo ok)"
expect "re-check records the release" "104 v38.0.0-deepbi4 ${BUILT} false" \
  "$(jq -r '"\(.release_id) \(.tag) \(.commit) \(.prerelease)"' "${WORK}/release-check.json")"

scenario
rm "${FAKE_GH}/repos/deep-bi/druid/releases/104.json"
expect_refusal "re-check stops a release deleted while the publish waited for approval" \
  "was deleted or turned back into a draft" run_script recheck-release.sh
expect "a failed re-check leaves no release-check.json" no "$([[ -e "${WORK}/release-check.json" ]] && echo yes || echo no)"

scenario
release_now '{draft: true}'
expect_refusal "re-check stops a release turned back into a draft" "turned back into a draft" \
  run_script recheck-release.sh

scenario
api "repos/deep-bi/druid/git/tags/${ANNOTATED}" "{\"object\": {\"type\": \"commit\", \"sha\": \"${OTHER}\"}}"
expect_refusal "re-check stops a release whose tag moved" "but the image was built from ${BUILT}" \
  run_script recheck-release.sh

scenario
rm "${FAKE_GH}/repos/deep-bi/druid/git/ref/tags/v38.0.0-deepbi4.json"
expect_refusal "re-check stops a release whose tag was deleted" "Cannot read tag v38.0.0-deepbi4" \
  run_script recheck-release.sh

scenario
release_now '{tag_name: "v38.0.0-deepbi5"}'
expect_refusal "re-check stops a release that carries another tag" "carries v38.0.0-deepbi5 now" \
  run_script recheck-release.sh

scenario
release_now '{prerelease: true}'
expect "re-check passes a release changed to a pre-release" ok "$(run_script recheck-release.sh 2> /dev/null && echo ok)"
expect "re-check records the pre-release" true "$(jq -r '.prerelease' "${WORK}/release-check.json")"

# Nothing writes to Docker Hub without a re-check in the same job

scenario
expect_refusal "publish.sh doesn't push to Docker Hub without a re-check" "was not re-checked" run_script publish.sh
expect_refusal "floating-tags.sh doesn't write to Docker Hub without a re-check" "was not re-checked" \
  run_script floating-tags.sh
echo '{"release_id": 99}' > "${WORK}/release-check.json"
expect_refusal "a re-check of another release doesn't count" "was not re-checked" run_script publish.sh
expect "and Docker Hub is unchanged" "sha256:d383 sha256:d383" "$(tag_digests docker.io 38.0-latest latest)"

# Docker Hub login. When a calling workflow doesn't pass the secrets, they are empty and registry-login.sh
# stops before docker or skopeo runs.

expect_refusal "registry-login.sh stops without a username" "DOCKERHUB_USERNAME is empty" \
  run_login DOCKERHUB_USERNAME= DOCKERHUB_TOKEN=token
expect_refusal "registry-login.sh stops without a token" "DOCKERHUB_TOKEN is empty" \
  run_login DOCKERHUB_USERNAME=someone DOCKERHUB_TOKEN=

# Floating tags in the publish job

scenario
run_script recheck-release.sh 2> /dev/null
run_script floating-tags.sh 2> /dev/null
expect "a published release moves 38.0-latest and latest" "sha256:d384 sha256:d384" \
  "$(tag_digests docker.io 38.0-latest latest)"
expect "and records the moves" "38.0-latest:38.0.0-deepbi4:moved latest:38.0.0-deepbi4:moved" "$(floating_actions)"
expect "and leaves 37.0-latest alone" "sha256:d376" "$(tag_digests docker.io 37.0-latest)"

scenario
run_script recheck-release.sh 2> /dev/null
releases v39.0.0-deepbi1:true v38.0.0-deepbi3:false v37.0.0-deepbi6:false
run_script floating-tags.sh 2> /dev/null
expect "a release withdrawn after the re-check moves no tag" "sha256:d383 sha256:d383" \
  "$(tag_digests docker.io 38.0-latest latest)"
expect "and says why" "38.0.0-deepbi4 was withdrawn or turned into a pre-release after the re-check" \
  "$(jq -r '.skipped' "${WORK}/floating.json")"

scenario
run_script recheck-release.sh 2> /dev/null
releases
run_script floating-tags.sh 2> /dev/null
expect "an empty release list moves no tag" "sha256:d383 sha256:d383" "$(tag_digests docker.io 38.0-latest latest)"

scenario
run_script recheck-release.sh 2> /dev/null
releases v39.0.0-deepbi1:true v38.0.0-deepbi4:true v38.0.0-deepbi3:false v37.0.0-deepbi6:false
run_script floating-tags.sh 2> /dev/null
expect "a release turned into a pre-release after the re-check moves no tag" "sha256:d383 sha256:d383" \
  "$(tag_digests docker.io 38.0-latest latest)"

scenario
release_now '{prerelease: true}'
releases v39.0.0-deepbi1:true v38.0.0-deepbi4:true v38.0.0-deepbi3:false v37.0.0-deepbi6:false
run_script recheck-release.sh 2> /dev/null
run_script floating-tags.sh 2> /dev/null
expect "a stable release changed to a pre-release before the publish moves no tag" "sha256:d383 sha256:d383" \
  "$(tag_digests docker.io 38.0-latest latest)"
expect "and says why, although release.json still says stable" "38.0.0-deepbi4 is a pre-release" \
  "$(jq -r '.skipped' "${WORK}/floating.json")"

scenario
releases v39.0.0-deepbi1:true v38.0.0-deepbi5:false v38.0.0-deepbi4:false v38.0.0-deepbi3:false \
  v37.0.0-deepbi6:false
set_tag docker.io 38.0.0-deepbi5 sha256:d385
set_tag docker.io 38.0-latest sha256:d385
set_tag docker.io latest sha256:d385
run_script recheck-release.sh 2> /dev/null
run_script floating-tags.sh 2> /dev/null
expect "a run that finishes after a newer release's run moves no tag back" "sha256:d385 sha256:d385" \
  "$(tag_digests docker.io 38.0-latest latest)"
expect "and records both tags as unchanged" "38.0-latest:38.0.0-deepbi5:unchanged latest:38.0.0-deepbi5:unchanged" \
  "$(floating_actions)"

scenario
set_tag docker.io 38.0.0-deepbi5 sha256:d385
set_tag docker.io 38.0-latest sha256:d385
set_tag docker.io latest sha256:d385
run_script recheck-release.sh 2> /dev/null
run_script floating-tags.sh 2> /dev/null
expect "the next run moves the tags off a withdrawn release" "sha256:d384 sha256:d384" \
  "$(tag_digests docker.io 38.0-latest latest)"

scenario
expect_refusal "a real run writes floating tags only to Docker Hub" "Only a dry run" \
  run_script floating-tags.sh REGISTRY=localhost:5000

# update_latest false, as for a backfill

scenario
edit_release '.update_latest = false'
run_script recheck-release.sh 2> /dev/null
run_script floating-tags.sh 2> /dev/null
expect "update_latest false moves 38.0-latest and leaves latest alone" "sha256:d384 sha256:d383" \
  "$(tag_digests docker.io 38.0-latest latest)"
expect "and records latest as skipped where it stands" \
  "38.0-latest:38.0.0-deepbi4:moved latest:-:skipped (update_latest is false) sha256:d383" \
  "$(floating_actions) $(jq -r '.tags[1].before' "${WORK}/floating.json")"
summary="$(run_script summary.sh GITHUB_STEP_SUMMARY= 2> /dev/null)"
expect "the summary says latest is not updated" "| Update latest | no |" \
  "$(grep -F '| Update latest |' <<< "${summary}")"
expect "and shows where latest stays" "| latest | - | - | \`sha256:d383\` | skipped (update_latest is false) |" \
  "$(grep -F '| latest |' <<< "${summary}")"

scenario
edit_release 'del(.update_latest)'
run_script recheck-release.sh 2> /dev/null
expect_refusal "floating-tags.sh refuses a release.json without update_latest" "update_latest is null" \
  run_script floating-tags.sh
expect "and moves no tag" "sha256:d383 sha256:d383" "$(tag_digests docker.io 38.0-latest latest)"

# Floating tags in a dry run

scenario
edit_release '.tag = "v38.0.0-deepbi5" | .version = "38.0.0-deepbi5" | .draft = true | .dry_run = true'
echo '{"digest": "sha256:d385"}' > "${WORK}/publish.json"
set_tag localhost:5000 38.0.0-deepbi5 sha256:d385
run_script floating-tags.sh REGISTRY=localhost:5000 2> /dev/null
expect "a dry run of a draft rehearses moving both tags to it" \
  "38.0-latest:38.0.0-deepbi5:would move (copy rehearsed) latest:38.0.0-deepbi5:would move (copy rehearsed)" \
  "$(floating_actions)"
expect "the rehearsal copies stay in the local registry" "sha256:d385 sha256:d385" \
  "$(tag_digests localhost:5000 38.0-latest latest)"
expect "a dry run leaves Docker Hub alone" "sha256:d383 sha256:d383" "$(tag_digests docker.io 38.0-latest latest)"
expect_refusal "a dry run never writes floating tags to Docker Hub" "never to docker.io" run_script floating-tags.sh

scenario
edit_release '.tag = "v38.0.0-deepbi5" | .version = "38.0.0-deepbi5" | .draft = true | .dry_run = true
  | .update_latest = false'
echo '{"digest": "sha256:d385"}' > "${WORK}/publish.json"
set_tag localhost:5000 38.0.0-deepbi5 sha256:d385
run_script floating-tags.sh REGISTRY=localhost:5000 2> /dev/null
expect "a dry run with update_latest false rehearses 38.0-latest only" \
  "38.0-latest:38.0.0-deepbi5:would move (copy rehearsed) latest:-:skipped (update_latest is false)" \
  "$(floating_actions)"
expect "and copies nothing to latest" "sha256:d385 none" "$(tag_digests localhost:5000 38.0-latest latest)"

scenario
edit_release '.prerelease = true | .dry_run = true'
run_script floating-tags.sh REGISTRY=localhost:5000 2> /dev/null
expect "a dry run of a pre-release moves no tag" "38.0.0-deepbi4 is a pre-release" \
  "$(jq -r '.skipped' "${WORK}/floating.json")"

# Checksums

hash="$(printf 'druid' | sha512sum | cut -d' ' -f1)"
printf 'druid' > "${TMP}/asset.tar.gz"
echo "${hash}" > "${TMP}/bare.sha512"
echo "${hash}  asset.tar.gz" > "${TMP}/named.sha512"
echo "${hash^^}" > "${TMP}/upper.sha512"
echo "not a checksum" > "${TMP}/bad.sha512"
expect "bare .sha512" "${hash}" "$(read_sha512 "${TMP}/bare.sha512")"
expect "sha512sum-style .sha512" "${hash}" "$(read_sha512 "${TMP}/named.sha512")"
expect "upper-case .sha512" "${hash}" "$(read_sha512 "${TMP}/upper.sha512")"
expect_failure "rejects a .sha512 without a hash" read_sha512 "${TMP}/bad.sha512"
expect "matching checksum" "${hash}" "$(verify_sha512 "${TMP}/asset.tar.gz" "${TMP}/bare.sha512")"
printf 'other' > "${TMP}/other.tar.gz"
expect_failure "checksum mismatch" verify_sha512 "${TMP}/other.tar.gz" "${TMP}/bare.sha512"

# pom.xml parsing

cat > "${TMP}/pom.xml" <<'XML'
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent><groupId>org.apache.druid</groupId><artifactId>druid</artifactId><version>1</version></parent>
  <artifactId>distribution</artifactId>
  <version>38.0.0-deepbi3</version>
  <profiles>
    <profile><id>integration-test</id><build><plugins><plugin><executions>
      <execution><id>pull-deps</id><configuration><arguments>
        <argument>-c</argument><argument>org.apache.druid:druid-integration-tests</argument>
        <argument>-c</argument><argument>org.apache.druid.extensions:druid-testing-tools</argument>
        <argument>-c</argument><argument>org.apache.druid.extensions:druid-histogram</argument>
      </arguments></configuration></execution>
    </executions></plugin></plugins></build></profile>
    <profile><id>dist</id><build><plugins><plugin><executions>
      <execution><id>pull-deps</id><configuration><arguments>
        <argument>-classpath</argument><classpath />
        <argument>-c</argument><argument>org.apache.druid.extensions:druid-histogram</argument>
        <argument>-c</argument>
        <argument>org.apache.druid.extensions:druid-avro-extensions</argument>
        <argument>--clean</argument>
      </arguments></configuration></execution>
      <execution><id>distro-assembly</id></execution>
    </executions></plugin></plugins></build></profile>
    <profile><id>bundle-contrib-exts</id><build><plugins><plugin><executions>
      <execution><id>pull-deps-contrib-exts</id><configuration><arguments>
        <argument>-c</argument><argument>org.apache.druid.extensions.contrib:grpc-query</argument>
        <argument>-c</argument><argument>org.apache.druid.extensions.contrib:kafka-emitter</argument>
        <argument>-c</argument><argument>org.apache.druid.extensions.contrib:grpc-query</argument>
      </arguments></configuration></execution>
    </executions></plugin></plugins></build></profile>
  </profiles>
</project>
XML
expect "project version" "38.0.0-deepbi3" "$(pom_project_version "${TMP}/pom.xml")"
expect "dist extensions" "druid-avro-extensions druid-histogram" \
  "$(pom_extensions "${TMP}/pom.xml" dist:pull-deps | lines)"
expect "dist and contrib extensions, without duplicates or the integration-test profile" \
  "druid-avro-extensions druid-histogram grpc-query kafka-emitter" \
  "$(pom_extensions "${TMP}/pom.xml" dist:pull-deps bundle-contrib-exts:pull-deps-contrib-exts | lines)"
expect "the integration-test pull-deps counts only when asked for" \
  "druid-histogram druid-integration-tests druid-testing-tools" \
  "$(pom_extensions "${TMP}/pom.xml" integration-test:pull-deps | lines)"
expect_failure "rejects an execution without its profile" pom_extensions "${TMP}/pom.xml" pull-deps
expect_failure "missing profile" pom_extensions "${TMP}/pom.xml" no-such-profile:pull-deps
expect_failure "missing execution" pom_extensions "${TMP}/pom.xml" dist:no-such-execution
expect_failure "an execution without coordinates" pom_extensions "${TMP}/pom.xml" dist:distro-assembly
sed 's|<id>bundle-contrib-exts</id>|<id>dist</id>|' "${TMP}/pom.xml" > "${TMP}/two-profiles.xml"
expect_failure "two profiles with the same ID" pom_extensions "${TMP}/two-profiles.xml" dist:pull-deps
sed 's|<id>distro-assembly</id>|<id>pull-deps</id>|' "${TMP}/pom.xml" > "${TMP}/two-executions.xml"
expect_failure "two executions with the same ID in one profile" \
  pom_extensions "${TMP}/two-executions.xml" dist:pull-deps

REPO_ROOT="$(git -C "${HERE}" rev-parse --show-toplevel 2> /dev/null || true)"
if [[ -f "${REPO_ROOT}/distribution/pom.xml" ]]; then
  count="$(pom_extensions "${REPO_ROOT}/distribution/pom.xml" dist:pull-deps bundle-contrib-exts:pull-deps-contrib-exts \
    | wc -l)"
  listed=false
  if (( count > 40 )); then
    listed=true
  fi
  expect "this checkout's distribution/pom.xml lists over 40 extensions (${count})" true "${listed}"
fi

# Dockerfile base images

cat > "${TMP}/Dockerfile" <<'DOCKERFILE'
ARG JDK_VERSION=21
FROM --platform=linux/amd64 maven:3.9 as builder
ARG BUILD_FROM_SOURCE="true"
FROM alpine:3 AS bash-static
ARG TARGETARCH
FROM busybox:1.35.0-glibc as busybox
FROM gcr.io/distroless/java$JDK_VERSION-debian12
COPY --from=busybox /bin/busybox /busybox/busybox
DOCKERFILE
expect "base images" "maven:3.9 alpine:3 busybox:1.35.0-glibc gcr.io/distroless/java21-debian12" \
  "$(dockerfile_base_images "${TMP}/Dockerfile" | lines)"
printf 'FROM builder AS second\nFROM %s/image\n' "\${UNKNOWN}" > "${TMP}/Dockerfile.bad"
expect_failure "unresolvable base image" dockerfile_base_images "${TMP}/Dockerfile.bad"

# Contrib archive layout

make_archive() {
  local name=$1
  shift
  rm -rf "${TMP}/stage"
  mkdir -p "${TMP}/stage"
  (cd "${TMP}/stage" && "$@")
  tar -C "${TMP}/stage" -czf "${TMP}/${name}" .
}
v=38.0.0-deepbi3
good() {
  mkdir -p "apache-druid-${v}/extensions/kafka-emitter"
  echo jar > "apache-druid-${v}/extensions/kafka-emitter/kafka-emitter.jar"
}
make_archive dotted.tar.gz good
rm -rf "${TMP}/stage" && mkdir -p "${TMP}/stage" && (cd "${TMP}/stage" && good)
tar -C "${TMP}/stage" -czf "${TMP}/good.tar.gz" "apache-druid-${v}"
expect "a well-formed contrib archive passes" ok "$(check_contrib_archive "${TMP}/good.tar.gz" "${v}" && echo ok)"
expect_failure "rejects entries starting with ./" check_contrib_archive "${TMP}/dotted.tar.gz" "${v}"

rm -rf "${TMP}/stage" && mkdir -p "${TMP}/stage" && (cd "${TMP}/stage" && good && mkdir -p "apache-druid-${v}/lib" && echo x > "apache-druid-${v}/lib/core.jar")
tar -C "${TMP}/stage" -czf "${TMP}/outside.tar.gz" "apache-druid-${v}"
expect_failure "rejects files outside extensions/" check_contrib_archive "${TMP}/outside.tar.gz" "${v}"

rm -rf "${TMP}/stage" && mkdir -p "${TMP}/stage" && (cd "${TMP}/stage" && good && ln -s /etc/passwd "apache-druid-${v}/extensions/kafka-emitter/link.jar")
tar -C "${TMP}/stage" -czf "${TMP}/link.tar.gz" "apache-druid-${v}"
expect_failure "rejects symlinks" check_contrib_archive "${TMP}/link.tar.gz" "${v}"

rm -rf "${TMP}/stage" && mkdir -p "${TMP}/stage" && (cd "${TMP}/stage" && good)
tar -C "${TMP}/stage" -czf "${TMP}/dotdot.tar.gz" "apache-druid-${v}" \
  --transform "s|kafka-emitter/kafka-emitter.jar|kafka-emitter/../../../evil.jar|"
expect_failure "rejects .. in paths" check_contrib_archive "${TMP}/dotdot.tar.gz" "${v}"

rm -rf "${TMP}/stage" && mkdir -p "${TMP}/stage/apache-druid-${v}/extensions"
tar -C "${TMP}/stage" -czf "${TMP}/empty.tar.gz" "apache-druid-${v}"
expect_failure "rejects an archive without extensions" check_contrib_archive "${TMP}/empty.tar.gz" "${v}"

rm -rf "${TMP}/stage" && mkdir -p "${TMP}/stage" && (cd "${TMP}/stage" && good)
tar -C "${TMP}/stage" -czf "${TMP}/other-version.tar.gz" "apache-druid-${v}"
expect_failure "rejects another version's directory" check_contrib_archive "${TMP}/other-version.tar.gz" 38.0.0-deepbi4

echo
echo "${tests} tests, ${failures} failed"
(( failures == 0 ))
