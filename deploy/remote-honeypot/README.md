# Remote Cowrie Honeypot Deployment

This bundle runs a single Cowrie SSH honeypot on a remote Linux host and keeps
its JSON audit log in a host-mounted directory for collection by the local
analysis pipeline.

The official Cowrie Docker quick start exposes SSH on container port `2222`,
and Cowrie writes JSON audit events to `var/log/cowrie/cowrie.json`. This
deployment keeps those defaults and maps the host port through `.env`.

## Remote Host Checklist

Use an isolated VPS or VM with no route into trusted networks.

1. Install Docker and the Docker Compose plugin.
2. Install `rsync` on both the remote host and local analysis workstation for
   pull-based collection.
3. Move real administrative SSH away from the public honeypot port before using
   port `22` for Cowrie.
4. Allow inbound TCP only for the administrative SSH port and Cowrie ports.
5. Keep outbound traffic restricted. Start with only DNS, HTTP/HTTPS for image
   pulls and package updates, and SSH/SFTP from the collector if needed.
6. Treat downloaded files and TTY captures as malicious artifacts.

## Deploy

From this repository, copy `deploy/remote-honeypot` to the remote host:

```bash
rsync -a deploy/remote-honeypot/ user@REMOTE:/opt/honeypot/cowrie/
```

On the remote host:

```bash
cd /opt/honeypot/cowrie
cp .env.example .env
mkdir -p var/log/cowrie var/lib/cowrie/downloads var/lib/cowrie/tty
sudo chown -R 1000:1000 var
docker compose pull
docker compose up -d
docker compose logs -f cowrie
```

Keep `COWRIE_HOST_SSH_PORT=2222` for the first boot. After confirming that
administrative SSH is reachable on another port, change it to `22` in `.env`
and restart:

```bash
docker compose up -d
```

## Verify Logging

From another machine, connect to the honeypot port and attempt a test login:

```bash
ssh -p 2222 root@REMOTE
```

Then confirm the JSON audit stream exists on the remote host:

```bash
tail -n 5 /opt/honeypot/cowrie/var/log/cowrie/cowrie.json
```

## Collect Logs Locally

From the repository root on the analysis workstation:

```bash
HONEYPOT_HOST=REMOTE \
HONEYPOT_USER=user \
HONEYPOT_REMOTE_DIR=/opt/honeypot/cowrie/var/log/cowrie \
scripts/collect-remote-cowrie.sh
```

The collector stores raw Cowrie JSON under `logs/raw/cowrie/<host>/` and writes
a Markdown report under `logs/reports/`. Both directories are ignored by git.

For scheduled collection, run the script from cron or a systemd timer on the
analysis workstation. A five-minute cron interval is enough for early
observation:

```cron
*/5 * * * * cd /home/d/projects/nsf_research && HONEYPOT_HOST=REMOTE HONEYPOT_USER=user scripts/collect-remote-cowrie.sh >/tmp/honeypot-collect.log 2>&1
```

## Operational Notes

- Do not expose the Docker socket or any management UI on the honeypot host.
- Keep the collector pull-based over SSH so the honeypot does not need SIEM
  credentials.
- Rotate or snapshot `logs/raw` before long experiments; Cowrie brute-force
  traffic can grow quickly once port `22` is exposed.
- Preserve raw logs unchanged. Generate derived reports separately so the
  research data remains reproducible.
