#!/usr/bin/env bash
set -euo pipefail

CONTAINER="${CONTAINER:-eapol-middleware-eapol-middleware-1}"

docker cp tests "${CONTAINER}:/app/"
docker cp app.py "${CONTAINER}:/app/app.py"
docker cp config.example.json "${CONTAINER}:/app/config.example.json"
docker cp docker-compose.yml "${CONTAINER}:/app/docker-compose.yml"
docker cp Dockerfile "${CONTAINER}:/app/Dockerfile"
# TestDockerfileContract / TestComposeContract 會讀這兩個檔
docker cp .dockerignore "${CONTAINER}:/app/.dockerignore"
docker cp run.sh "${CONTAINER}:/app/run.sh"
# Frontend contract tests read static/*.js directly — keep them in sync
docker cp static "${CONTAINER}:/app/"
docker cp templates "${CONTAINER}:/app/"
docker exec "${CONTAINER}" python3 -m unittest discover -s tests -v "$@"
