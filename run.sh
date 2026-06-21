#!/usr/bin/env bash
# 重啟 middleware：停容器 → 重建 → 重開 → 等 localhost:5000 健康檢查
set -euo pipefail

cd "$(dirname "$0")"

if [[ ! -f config.json ]]; then
    echo "ERROR: config.json 不存在" >&2
    echo "       cp config.example.json config.json && vim config.json" >&2
    exit 1
fi

echo "==> Stopping"
docker compose down

echo "==> Building and starting"
docker compose up -d --build

echo
echo "==> Waiting for http://localhost:5000/api/health..."
ok=0
for i in {1..30}; do
    if curl -sf http://localhost:5000/api/health >/dev/null 2>&1; then
        ok=1
        echo "==> OK"
        break
    fi
    sleep 2
done

echo
echo "==> Status:"
docker compose ps

echo
if [[ "$ok" != "1" ]]; then
    echo "WARN: health check 還沒過，請追 log 確認。" >&2
fi
echo "追 log：$ docker compose logs -f"
echo "驗證　：$ curl http://localhost:5000/api/health"
