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

# Writes the release evidence of a run (policy section 7.1) to evidence.json and to the job summary: tag,
# source commit, the release re-check before the push, asset checksums, the jars the Dockerfile links,
# image digest, base image digests, test results, floating tags and the run URL. Every part is optional,
# so a failed run still reports what it got to.
#
# Environment:
#   WORK_DIR  working directory with the JSON files of the other steps
#   STAGE     what this job did, for the heading (for example "Build and test" or "Publish")

set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

WORK_DIR="${WORK_DIR:-${RUNNER_TEMP:?RUNNER_TEMP is not set}/docker-image}"
STAGE="${STAGE:-Docker image}"
run_url="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}"

part() {
  if [[ -s "${WORK_DIR}/$1" ]]; then
    cat "${WORK_DIR}/$1"
  else
    echo null
  fi
}

jq -n --arg run_url "${run_url}" --arg stage "${STAGE}" \
  --argjson release "$(part release.json)" --argjson release_check "$(part release-check.json)" \
  --argjson assets "$(part assets-evidence.json)" --argjson dedupe "$(part dedupe.json)" \
  --argjson build "$(part build.json)" --argjson smoke "$(part smoke.json)" \
  --argjson publish "$(part publish.json)" --argjson floating "$(part floating.json)" '{
    stage: $stage,
    run_url: $run_url,
    release: $release,
    release_check: $release_check,
    assets: $assets,
    jar_dedupe: $dedupe,
    image: $build,
    tests: $smoke,
    publish: $publish,
    floating_tags: $floating
  }' > "${WORK_DIR}/evidence.json"

markdown="$(jq -r '
  def code: if . == null or . == "" then "-" else "`\(.)`" end;
  def yesno: if . then "yes" else "no" end;
  [
    "## \(.stage): \(.release.version // "unknown version")",
    "",
    "| Item | Value |",
    "| --- | --- |",
    (if .release then
      "| Release | [\(.release.tag)](\(.release.html_url)) (\(if .release.draft then "draft" elif .release.prerelease then "pre-release" else "published" end)) |",
      "| Source commit | \(.release.commit | code) |",
      "| Dry run | \(.release.dry_run | yesno) |",
      "| Update latest | \(.release.update_latest | yesno) |"
    else empty end),
    (if .release_check then
      "| Re-checked before the push | \(if .release_check.prerelease then "pre-release" else "published" end), tag on the source commit (\(.release_check.checked_at)) |"
    else empty end),
    "| Run | \(.run_url) |",
    (if .image then
      "| Image digest | \(.image.manifest_digest | code) (\(.image.platform)) |",
      "| Image config | \(.image.config_digest | code) |",
      "| Compressed size | \(.image.compressed_size) bytes |",
      "| Runtime base verified | \(.image.runtime_base_verified | yesno) |",
      "| /bin/bash SHA-256 | \(.image.bash_static_sha256 | code) |"
    else empty end),
    (if .jar_dedupe then
      "| Jar links | \(.jar_dedupe.linked) jars link to the first jar of the same name, as in the Dockerfile\(
        if (.jar_dedupe.changed | length) > 0 then
          "; \(.jar_dedupe.changed | length) of them hold other content than in the assets: \(
            .jar_dedupe.changed[0:10] | map("`\(.)`") | join(", "))\(
            if (.jar_dedupe.changed | length) > 10 then " and more" else "" end)"
        else "" end) |"
    else empty end),
    (if .publish then
      "| Pushed to | \(.publish.reference | code) |",
      "| Push result | \(.publish.status) |",
      "| Published digest | \(.publish.digest | code) |"
    else empty end),
    "",
    (if .assets then
      "### Release assets",
      "",
      "| Asset | Size | SHA-512 | Uploaded |",
      "| --- | --- | --- | --- |",
      (.assets[] | "| \(.name) | \(.size) | \(.sha512 | code) | \(.created_at)\(if .attached_after_publication then ", after publication" else "" end) |"),
      ""
    else empty end),
    (if .image then
      "### Base images",
      "",
      "| Image | Digest |",
      "| --- | --- |",
      (.image.base_images[] | "| \(.image) | \(.digest | code) |"),
      ""
    else empty end),
    (if .tests then
      "### Tests",
      "",
      "| Check | Result | Detail |",
      "| --- | --- | --- |",
      (.tests[] | "| \(.check) | \(.result) | \(.detail) |"),
      ""
    else empty end),
    (if .floating_tags then
      "### Floating tags",
      "",
      (if .floating_tags.skipped then "Not moved: \(.floating_tags.skipped)." else
        "| Tag | Target | Digest | Before | Action |",
        "| --- | --- | --- | --- | --- |",
        (.floating_tags.tags[] | "| \(.tag) | \(.target // "-") | \(.digest | code) | \(.before | code) | \(.action) |")
      end),
      ""
    else empty end)
  ] | join("\n")' "${WORK_DIR}/evidence.json")"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  echo "${markdown}" >> "${GITHUB_STEP_SUMMARY}"
else
  echo "${markdown}"
fi
