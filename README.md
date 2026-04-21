# RestoreRunner

Upload an Unraid AppData Backup archive, boot the captured container in a
fully isolated sandbox, preview its WebUI inline, watch logs live, one click
to stop.

Designed for the homelabber who wonders "did my backup actually work?"
without risking their live stack.

## What it does

One web page:

1. Drop a `.zip`, `.rar`, `.tar`, `.tar.gz`, or `.tar.zst` backup archive
   onto the drop-zone.
2. RestoreRunner streams it to disk (multi-GB uploads don't OOM), extracts
   it, and scans for the Unraid container XML the AppData Backup plugin
   writes alongside your appdata.
3. It pulls the image and starts the container on an **internal docker
   network with no route to your LAN or the internet**. Resource caps
   (`--memory=1g --cpus=1.0`), `cap-drop=ALL`, `no-new-privileges`, and
   **zero host-port publishing**.
4. The sandbox's WebUI is reverse-proxied back to your browser via
   `/run/<id>/preview/` — iframe on the run detail page, "Open in new
   tab" fallback for apps that reject framing.
5. Live logs stream over Server-Sent Events.
6. Click **Stop** and it's gone. Or wait the 10-minute auto-stop.

## Why v0.4 matters

v0.3 published sandbox ports to the host (collisions + exposure) and
bind-mounted the XML's original `/mnt/user/appdata/<app>` path (risk of
corrupting the live running stack on first write). **v0.4 fixes both**:

- **Ephemeral appdata.** Every bind mount is rewritten to live inside
  the extracted upload tree. A safety assertion refuses to start if any
  mount source still points at a protected host path (`/mnt/user/...`,
  `/boot`, `/etc`, `/var/lib/docker`, etc).
- **Internal bridge network.** Sandboxes join `rr-sandbox-net`, a
  docker bridge created with `Internal: true`. No host ports, no LAN
  egress, no internet.
- **Reverse-proxied WebUI.** RestoreRunner joins the same network on
  startup and proxies `/run/<id>/preview/*` to the sandbox's IP on its
  declared WebUI port. WebSocket upgrades are supported.

## Running it

```bash
docker compose up -d
```

Then open `http://<host>:8922` and create your admin via the first-run
wizard.

On Unraid, import `Restore-Runner.xml` as a Docker template.

## Configuration

| Env var                 | Default | Notes                                                           |
|-------------------------|---------|-----------------------------------------------------------------|
| `RR_MAX_UPLOAD_MB`      | `2048`  | Hard cap on archive size                                        |
| `RR_RUN_TIMEOUT_MIN`    | `10`    | Auto-stop after this many minutes                               |
| `RR_HOST_DENY_PREFIXES` | —       | Comma-separated extra host paths the sandbox must never touch   |
| `ADMIN_USERNAME`        | —       | Optional non-interactive admin seed                             |
| `ADMIN_PASSWORD`        | —       | Optional non-interactive admin seed (web wizard otherwise)      |

## What it doesn't do (by design)

- No schedules. It's a point-and-click tool.
- No notifications. Look at the page.
- No multi-user. Single admin.
- No docker-socket passthrough to the sandbox — granting docker-in-docker
  to a restored-from-backup container would be trivial host compromise.
- No host ports. Previews go through the in-app proxy.
- No internet for the sandbox — some apps complain on first boot; that's
  the point.

## Licence

MIT.
