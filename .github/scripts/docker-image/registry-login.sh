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

# Logs Docker and skopeo in to Docker Hub with the push token of the dockerhub environment. A workflow
# that calls deepbi-docker-image.yml must pass both secrets, or they are empty here.
#
# Environment:
#   DOCKERHUB_USERNAME  secret of the dockerhub environment: the account that owns a personal access token,
#                       or the organization name for an organization access token. GitHub masks it in this
#                       job's log, so a name that is part of the image name, such as deepbi, also hides the
#                       image names and versions there.
#   DOCKERHUB_TOKEN     secret of the dockerhub environment
#   AUTHFILE            skopeo credentials file (default $RUNNER_TEMP/dockerhub-auth.json). Keep it out
#                       of WORK_DIR, whose files are uploaded as evidence.

set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [[ -z "${DOCKERHUB_USERNAME:-}" ]]; then
  fail "DOCKERHUB_USERNAME is empty. Set it as a secret of the dockerhub environment, and pass it from the calling workflow if there is one."
fi
if [[ -z "${DOCKERHUB_TOKEN:-}" ]]; then
  fail "DOCKERHUB_TOKEN is empty. Set it as a secret of the dockerhub environment, and pass it from the calling workflow if there is one."
fi
AUTHFILE="${AUTHFILE:-${RUNNER_TEMP:?RUNNER_TEMP is not set}/dockerhub-auth.json}"

printf '%s' "${DOCKERHUB_TOKEN}" | docker login docker.io --username "${DOCKERHUB_USERNAME}" --password-stdin
printf '%s' "${DOCKERHUB_TOKEN}" | skopeo login docker.io --authfile "${AUTHFILE}" \
  --username "${DOCKERHUB_USERNAME}" --password-stdin
