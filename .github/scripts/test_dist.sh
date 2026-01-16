#!/usr/bin/env bash
set -euo pipefail

echo "Running integration tests"

VERSION="${1:-${VERSION:-}}"
if [[ -z "${VERSION}" ]]; then
  echo "::error::VERSION is not set (pass as arg1 or env VERSION)"
  exit 1
fi

ARTIFACT_DIR="${ARTIFACT_DIR:-distribution/target}"

TARBALL="${ARTIFACT_DIR}/apache-druid-${VERSION}-bin.tar.gz"
SHAFILE="${ARTIFACT_DIR}/apache-druid-${VERSION}-bin.tar.gz.sha512"

if [[ ! -f "${TARBALL}" ]]; then
  echo "::error::Missing tarball: ${TARBALL}"
  exit 1
fi
if [[ ! -f "${SHAFILE}" ]]; then
  echo "::error::Missing sha512: ${SHAFILE}"
  exit 1
fi

echo "-------- Verify the sha512 signature and decompress the archive --------"

mkdir -p druid
cp -a "${TARBALL}" "${SHAFILE}" ./druid/

ls -lh ./druid

expected="$(tr -d ' \t\r\n' < "druid/$(basename "${SHAFILE}")")"
actual="$(sha512sum "druid/$(basename "${TARBALL}")" | awk '{print $1}')"
if [[ "$actual" != "$expected" ]]; then
  echo "::error::sha512 mismatch"
  exit 1
fi
echo "sha512 OK"

tar -xzf "druid/$(basename "${TARBALL}")" -C druid

cd "druid/apache-druid-${VERSION}"

echo "-------- Start Druid (micro-quickstart) and run health checks --------"

nohup bash -lc "./bin/start-micro-quickstart" >/tmp/druid.out 2>&1 &

check_health() {
  local name=$1
  local port=$2
  local retries=120

  echo "Waiting for $name on port $port..."
  for _ in $(seq 1 $retries); do
    if curl -fsS "http://localhost:${port}/status/health" >/dev/null 2>&1; then
      echo "$name is healthy"
      return 0
    fi
    sleep 3
  done

  echo "::error::$name failed after $((retries*3)) seconds"
  exit 1
}

check_health "Router" 8888
check_health "Coordinator" 8081
check_health "Broker" 8082
check_health "Historical" 8083

echo "-------- Load sample data using batch ingestion --------"

TASK_ID=$(curl -fsS -X 'POST' -H 'Content-Type:application/json' \
  -d @quickstart/tutorial/wikipedia-index.json \
  http://localhost:8081/druid/indexer/v1/task | jq -r .task)

echo "TASK_ID=$TASK_ID"

for _ in {1..120}; do
  STATUS=$(curl -fsS "http://localhost:8888/druid/indexer/v1/task/${TASK_ID}/status" | jq -r .status.status)
  echo "Status: $STATUS"
  if [[ "$STATUS" == "SUCCESS" ]]; then echo "Ingestion is successful!"; break; fi
  if [[ "$STATUS" == "FAILED" ]]; then echo "::error::Ingestion failed"; exit 1; fi
  sleep 3
done

echo "---- ingestion row stats for ${TASK_ID} ----"
curl -s "http://localhost:8081/druid/indexer/v1/task/${TASK_ID}/reports" \
  | jq '.ingestionStatsAndErrors.payload.rowStats' \
  || echo "No rowStats in reports"
echo

echo "-------- WAIT FOR SEGMENTS TO LOAD --------"

MAX_WAIT=120
WAITED=0
SEG_COUNT=0

echo "Waiting for segments for datasource wikipedia ..."

while [ $WAITED -lt $MAX_WAIT ]; do
  RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
    http://localhost:8888/druid/v2/sql \
    -d '{"query":"SELECT COUNT(*) AS c FROM sys.segments WHERE datasource='\''wikipedia'\'' AND is_available = 1"}')

  SEG_COUNT=$(echo "$RESPONSE" | jq -r '.[0].c // 0')

  if [ "$SEG_COUNT" -gt 0 ]; then
    echo "Segments are available: ${SEG_COUNT} segment(s) loaded."
    break
  fi

  echo "No segments yet... waited ${WAITED}s"
  sleep 5
  WAITED=$((WAITED+5))
done

if [ "$SEG_COUNT" -eq 0 ]; then
  echo "::error::Timed out waiting for segments to load."
  exit 1
fi

echo
echo "-------- segments by datasource --------"
curl -s -X POST -H "Content-Type: application/json" \
  http://localhost:8888/druid/v2/sql \
  -d '{"query":"SELECT datasource, COUNT(*) AS segments FROM sys.segments GROUP BY datasource"}'
echo

echo "-------- Run and verify native group-by query --------"

NATIVE=$(curl -fsS -X POST -H "Content-Type:application/json" \
  http://localhost:8888/druid/v2 \
  -d @../../.github/resources/native_query.json)

COUNT=$(jq 'length' <<<"$NATIVE")

if [[ "$COUNT" -ge 1 ]]; then
  echo "Native query is successful. Response contains $COUNT rows"
else
  echo "::error::No rows from native query"
  exit 1
fi

echo "-------- Run and verify SQL query --------"

SQL=$(curl -fsS -X POST -H "Content-Type: application/json" \
  http://localhost:8888/druid/v2/sql \
  -d @../../.github/resources/sql_query.json)

COUNT=$(jq 'length' <<<"$SQL")

if [[ "$COUNT" -ge 1 ]]; then
  echo "SQL is successful. Response contains $COUNT rows"
else
  echo "::error::No rows from SQL"
  exit 1
fi

echo "-------- Run and verify MSQ query --------"

MSQ=$(curl -fsS -X POST -H "Content-Type:application/json" \
  http://localhost:8888/druid/v2/sql/task \
  -d @../../.github/resources/sql_query.json)

MSQ_ID=$(echo "$MSQ" | jq -r '.taskId')

if [[ -z "$MSQ_ID" || "$MSQ_ID" == "null" ]]; then
  echo "::error::Failed to extract MSQ task ID"
  exit 1
fi
echo "Task ID is $MSQ_ID"

for _ in {1..120}; do
  STATE=$(curl -fsS "http://localhost:8888/druid/indexer/v1/task/${MSQ_ID}/status" | jq -r .status.statusCode)
  echo "MSQ status: $STATE"
  if [[ "$STATE" == "SUCCESS" ]]; then echo "Running MSQ query is successful!"; break; fi
  if [[ "$STATE" == "FAILED" ]]; then echo "::error::MSQ query failed"; exit 1; fi
  sleep 3
done

COUNT=$(curl -fsS "http://localhost:8888/druid/indexer/v1/task/${MSQ_ID}/reports" | jq '.multiStageQuery.payload.results.results | length')
if [[ "$COUNT" -ge 1 ]]; then
  echo "MSQ query is successful. Response contains $COUNT rows"
else
  echo "::error::No rows from MSQ query"
  exit 1
fi
