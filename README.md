# RestoreRunner

Upload an Unraid AppData Backup archive, boot the captured container in a
sandbox, watch its logs live, click one button to stop it.

Designed for the homelabber who wonders "did my backup actually work?"
without having to commit to a full restore.

## What it does

One web page:

1. Drop a `.zip`, `.rar`, `.tar`, `.tar.gz`, or `.tar.zst` backup archive
   onto the drop-zone.
2. RestoreRunner streams it to disk (multi-GB uploads don't OOM), extracts
   it, and scans for the Unraid container XML template the AppData Backup
   plugin writes alongside your appdata.
3. It pulls the image, starts the container with a random host port,
   resource caps (`--memory=1g --cpus=1.0`), and `cap-drop=ALL
   --security-opt no-new-privileges`.
4. Live logs stream to your browser over Server-Sent Events.
5. Click **Stop** and it's gone. Or wait the 10-minute auto-stop.

## Running it

```bash
docker compose up -d
```

Then open `http://<host>:8922` and create your admin via the first-run
wizard.

See `docker-compose.yml` for the mount + env var shape. If you're on
Unraid, import `Restore-Runner.xml` as a Docker template.

## Configuration

Everything's an env var or default:

| Env var              | Default | Notes                                   |
|----------------------|---------|-----------------------------------------|
| `RR_MAX_UPLOAD_MB`   | `2048`  | Hard cap on archive size                |
| `RR_RUN_TIMEOUT_MIN` | `10`    | Auto-stop after this many minutes       |
| `ADMIN_USERNAME`     | —       | Optional, seeds the admin               |
| `ADMIN_PASSWORD`     | —       | Optional, seeds the admin (web wizard otherwise) |

## What it doesn't do (by design)

- No schedules, cron jobs, or rehearsals. It's a point-and-click tool.
- No notifications. Look at the page to see the status.
- No multi-user. Single admin, single sandbox at a time.
- No docker-socket passthrough to the sandboxed container. If the image
  needed it, you'll see that in the logs and can decide what to do.

## Licence

MIT.
