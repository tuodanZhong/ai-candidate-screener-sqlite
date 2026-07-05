# AI Candidate Screener SQLite Version

Run the local app:

```bash
cd /Users/zhongzhiyuan/Documents/Codex/2026-07-04/pin/outputs/ai-candidate-screener-sqlite
python3 server.py
```

Open:

```text
http://127.0.0.1:8765/
```

Stored data:

- Candidate list and candidate profile JSON
- All stage inputs and evaluation results
- Engine settings
- Uploaded resume files, including PDF text layers, scanned PDFs, and images

SQLite database path:

```text
data/candidates.sqlite3
```

Back up the app data by copying `data/candidates.sqlite3`.

## Deploy With GitHub Actions

Production server:

```text
http://43.143.122.43:8765/
```

This repository deploys from GitHub Actions on every push to `main`.

Required GitHub repository secrets:

- `DEPLOY_HOST`: server IP or domain, for example `43.143.122.43`
- `DEPLOY_USER`: SSH user, for example `ubuntu`
- `DEPLOY_SSH_KEY`: private key for SSH login
- `DEEPSEEK_API_KEY`: DeepSeek API key used by the server-side proxy

Optional secrets:

- `DEPLOY_PATH`: defaults to `/home/ubuntu/ai-candidate-screener-sqlite`
- `SERVICE_NAME`: defaults to `ai-candidate-screener`
- `APP_PORT`: defaults to `8765`

The remote user needs passwordless sudo permission for restarting only this
service:

```text
ubuntu ALL=(root) NOPASSWD: /bin/systemctl restart ai-candidate-screener
```

The workflow packages the app, uploads it to the server, keeps the existing
server-side SQLite database, restarts the systemd service, and checks
`/api/health`.

Manual deploy from this directory is still available:

```bash
./deploy.sh
```

The script packages the app, uploads it to `ubuntu@43.143.122.43`, keeps the
existing server-side SQLite database, installs/updates the systemd service, and
checks `/api/health`.

Server paths:

- App: `/home/ubuntu/ai-candidate-screener-sqlite`
- Database: `/home/ubuntu/ai-candidate-screener-sqlite/data/candidates.sqlite3`
- Service: `ai-candidate-screener`

The deploy script does not store SSH passwords. Use SSH key auth or enter the
password when prompted.
