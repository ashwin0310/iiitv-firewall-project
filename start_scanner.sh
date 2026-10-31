#!/bin/bash

cd /home/kali/iiitv-firewall-project/iiitv-firewall-project/backend || exit 1

# Start server only if it isn't already running
if ! curl -fsS --max-time 2 http://127.0.0.1:8000/ >/dev/null; then
    python3 -m uvicorn app:app --host 127.0.0.1 --port 8000 \
        > /tmp/iiitv-scanner.log 2>&1 &
fi

# Wait for dashboard to become ready
for i in $(seq 1 30); do
    if curl -fsS --max-time 2 http://127.0.0.1:8000/ >/dev/null; then
        xdg-open http://127.0.0.1:8000/
        exit 0
    fi
    sleep 1
done

echo "Scanner failed to start. Check /tmp/iiitv-scanner.log"
exit 1
