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

# Smoke-tests the candidate image. It first compares the image content with the release assets, then
# starts the release's own distribution/docker/docker-compose.yml with the candidate in place of
# apache/druid, ingests the wikipedia sample and runs the native, SQL and MSQ checks of test_dist.sh with
# the query files of the release commit. Two contrib extensions are loaded on top of the line's load list
# to show that the contrib extensions load, not only that they are present.
#
# Environment:
#   SRC_DIR         checkout of the release commit
#   WORK_DIR        working directory with release.json, build.json and the prepare-context.sh output
#   POSTGRES_IMAGE  metadata store image for the test (default postgres:17.6). The 31.x and 34.x compose
#                   files use postgres:latest, and PostgreSQL 18 images refuse their volume layout.
#
# Writes smoke.json and file-differences.txt to WORK_DIR, and compose-logs.txt when the compose test fails.

set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

SRC_DIR="${SRC_DIR:?SRC_DIR is not set}"
WORK_DIR="${WORK_DIR:-${RUNNER_TEMP:?RUNNER_TEMP is not set}/docker-image}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:17.6}"

version="$(jq -r '.version' "${WORK_DIR}/release.json")"
image="$(jq -r '.candidate' "${WORK_DIR}/build.json")"
compose_dir="${SRC_DIR}/distribution/docker"
project=deepbi-docker-smoke
results="${WORK_DIR}/smoke-results.jsonl"
: > "${results}"

# Contrib extensions added to the load list, with the Guice module each one registers.
declare -A EXTRA_MODULES=(
  [druid-distinctcount]=org.apache.druid.query.aggregation.distinctcount.DistinctCountDruidModule
  [druid-time-min-max]=org.apache.druid.query.aggregation.TimestampMinMaxModule
)
SERVICES=(coordinator broker historical middlemanager router)
declare -A PORTS=([coordinator]=8081 [broker]=8082 [historical]=8083 [middlemanager]=8091 [router]=8888)
ROUTER=http://localhost:8888

passed() {
  jq -cn --arg check "$1" --arg detail "$2" '{check: $check, result: "pass", detail: $detail}' >> "${results}"
  log "PASS ${1}: ${2}"
}

failed() {
  jq -cn --arg check "$1" --arg detail "$2" '{check: $check, result: "fail", detail: $detail}' >> "${results}"
  fail "${1}: ${2}"
}

dc() {
  docker compose --project-name "${project}" --project-directory "${compose_dir}" \
    --file "${compose_dir}/docker-compose.yml" --file "${WORK_DIR}/compose.override.json" "$@"
}

compose_started=false
finish() {
  local status=$?
  if [[ "${compose_started}" == true ]]; then
    if (( status != 0 )); then
      dc logs --no-color --timestamps > "${WORK_DIR}/compose-logs.txt" 2>&1 || true
    fi
    dc down --volumes --remove-orphans > /dev/null 2>&1 || true
  fi
  jq -s '.' "${results}" > "${WORK_DIR}/smoke.json" || true
  exit "${status}"
}
trap finish EXIT

# poll_task <task id> <jq path to the state> <check name>: waits up to 10 minutes for a task to succeed.
poll_task() {
  local task=$1 path=$2 check=$3 state=""
  for _ in $(seq 1 200); do
    state="$(curl -fsS "${ROUTER}/druid/indexer/v1/task/${task}/status" | jq -r "${path}")" || state=unknown
    case "${state}" in
      SUCCESS) return 0 ;;
      FAILED) failed "${check}" "task ${task} failed" ;;
    esac
    sleep 3
  done
  failed "${check}" "task ${task} still ${state} after 10 minutes"
}

# sql <query>: runs a SQL query through the router and prints the JSON result.
sql() {
  curl -fsS -X POST -H 'Content-Type: application/json' "${ROUTER}/druid/v2/sql" \
    -d "$(jq -cn --arg query "$1" '{query: $query}')"
}

# 1. Image content

image_extensions="$(docker run --rm --entrypoint sh "${image}" -c 'ls -1 /opt/druid/extensions' | LC_ALL=C sort)"
missing="$(LC_ALL=C comm -23 "${WORK_DIR}/expected-extensions.txt" <(echo "${image_extensions}"))"
if [[ -n "${missing}" ]]; then
  failed "Extensions" "missing from the image: $(tr '\n' ' ' <<< "${missing}")"
fi
passed "Extensions" "all $(wc -l < "${WORK_DIR}/expected-extensions.txt") extensions of the dist and bundle-contrib-exts lists are in the image"

# shellcheck disable=SC2016 # $f is expanded by the shell inside the container
docker run --rm --entrypoint sh "${image}" -c \
  'cd /opt/druid && find . ! -path "./var/*" \( -type f -o -type l \) | while IFS= read -r f; do sha256sum "$f"; done' \
  | LC_ALL=C sort -k2 > "${WORK_DIR}/image-files.sha256"
compare_checksums "${WORK_DIR}/expected-files.sha256" "${WORK_DIR}/image-files.sha256" \
  > "${WORK_DIR}/file-differences.txt"
if [[ -s "${WORK_DIR}/file-differences.txt" ]]; then
  failed "Files" "$(wc -l < "${WORK_DIR}/file-differences.txt") paths in /opt/druid don't match the release assets: $(head -5 "${WORK_DIR}/file-differences.txt" | paste -sd ';' - | sed 's/;/; /g')"
fi
passed "Files" "$(wc -l < "${WORK_DIR}/image-files.sha256") files in /opt/druid match the release assets and the Dockerfile's jar links"

# 2. Compose stack

load_list="$(sed -n 's/^druid_extensions_loadList=//p' "${compose_dir}/environment")"
if ! jq -e 'type == "array"' <<< "${load_list}" > /dev/null 2>&1; then
  fail "Cannot read druid_extensions_loadList from distribution/docker/environment"
fi
load_list="$(jq -c --args '. + ($ARGS.positional - .)' "${!EXTRA_MODULES[@]}" <<< "${load_list}")"

docker compose --project-directory "${compose_dir}" --file "${compose_dir}/docker-compose.yml" \
  config --format json > "${WORK_DIR}/compose.config.json"
jq --arg image "${image}" --arg postgres "${POSTGRES_IMAGE}" --arg load_list "${load_list}" '
  {services: (.services | with_entries(
    if ((.value.image // "") | startswith("apache/druid")) then
      .value = {image: $image, environment: {druid_extensions_loadList: $load_list}}
    elif .key == "postgres" then
      .value = {image: $postgres}
    else
      empty
    end))}' "${WORK_DIR}/compose.config.json" > "${WORK_DIR}/compose.override.json"
for service in "${SERVICES[@]}"; do
  if ! jq -e --arg service "${service}" --arg image "${image}" '.services[$service].image == $image' \
    "${WORK_DIR}/compose.override.json" > /dev/null; then
    fail "distribution/docker/docker-compose.yml has no apache/druid service named ${service}"
  fi
done

compose_started=true
dc up --detach --quiet-pull

deadline=$((SECONDS + 900))
for service in "${SERVICES[@]}"; do
  until [[ "$(curl -fsS "http://localhost:${PORTS[${service}]}/status/health" 2> /dev/null)" == true ]]; do
    if [[ "$(docker inspect --format '{{.State.Status}}' "${service}" 2> /dev/null)" == exited ]]; then
      failed "Services" "${service} exited"
    fi
    if (( SECONDS > deadline )); then
      failed "Services" "${service} is not healthy after 15 minutes"
    fi
    sleep 5
  done
done
passed "Services" "coordinator, broker, historical, middlemanager and router are healthy"

for service in "${SERVICES[@]}"; do
  status="$(curl -fsS "http://localhost:${PORTS[${service}]}/status")"
  reported="$(jq -r '.version' <<< "${status}")"
  if [[ "${reported}" != "${version}" ]]; then
    failed "Version" "${service} reports ${reported}, expected ${version}"
  fi
  for extension in "${!EXTRA_MODULES[@]}"; do
    if ! jq -e --arg module "${EXTRA_MODULES[${extension}]}" 'any(.modules[]; .name == $module)' \
      <<< "${status}" > /dev/null; then
      failed "Contrib extensions" "${service} did not load ${extension}"
    fi
  done
done
passed "Version" "every service reports ${version}"
passed "Contrib extensions" "every service loaded $(tr ' ' '\n' <<< "${!EXTRA_MODULES[*]}" | LC_ALL=C sort | tr '\n' ' ')"

task="$(curl -fsS -X POST -H 'Content-Type: application/json' -d @"${WORK_DIR}/wikipedia-index.json" \
  http://localhost:8081/druid/indexer/v1/task | jq -r '.task')"
if [[ -z "${task}" || "${task}" == null ]]; then
  failed "Ingestion" "the overlord returned no task ID"
fi
poll_task "${task}" '.status.status' "Ingestion"

segments=0
for _ in $(seq 1 60); do
  segments="$(sql "SELECT COUNT(*) AS c FROM sys.segments WHERE datasource = 'wikipedia' AND is_available = 1" \
    | jq -r '.[0].c // 0')" || segments=0
  if (( segments > 0 )); then
    break
  fi
  sleep 5
done
if (( segments == 0 )); then
  failed "Ingestion" "no wikipedia segment became available within 5 minutes"
fi
passed "Ingestion" "task ${task} succeeded, ${segments} segment(s) available"

rows="$(curl -fsS -X POST -H 'Content-Type: application/json' "${ROUTER}/druid/v2" \
  -d @"${SRC_DIR}/.github/resources/native_query.json" | jq 'if type == "array" then length else -1 end')"
if (( rows < 1 )); then
  failed "Native query" "no rows"
fi
passed "Native query" "${rows} rows"

rows="$(curl -fsS -X POST -H 'Content-Type: application/json' "${ROUTER}/druid/v2/sql" \
  -d @"${SRC_DIR}/.github/resources/sql_query.json" | jq 'if type == "array" then length else -1 end')"
if (( rows < 1 )); then
  failed "SQL query" "no rows"
fi
passed "SQL query" "${rows} rows"

msq_task="$(curl -fsS -X POST -H 'Content-Type: application/json' "${ROUTER}/druid/v2/sql/task" \
  -d @"${SRC_DIR}/.github/resources/sql_query.json" | jq -r '.taskId')"
if [[ -z "${msq_task}" || "${msq_task}" == null ]]; then
  failed "MSQ query" "no task ID"
fi
poll_task "${msq_task}" '.status.statusCode' "MSQ query"
rows="$(curl -fsS "${ROUTER}/druid/indexer/v1/task/${msq_task}/reports" \
  | jq '.multiStageQuery.payload.results.results | if type == "array" then length else -1 end')"
if (( rows < 1 )); then
  failed "MSQ query" "no rows"
fi
passed "MSQ query" "task ${msq_task}, ${rows} rows"
