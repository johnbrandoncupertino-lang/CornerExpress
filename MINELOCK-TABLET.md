# MineLock Pocket Tablet

## Current capabilities

The MineLock Pocket Tablet runs on a standard CC:Tweaked Pocket Computer with a wireless modem. It uses the shared controller source with `ROLE = "tablet"` and does not require a monitor.

- Discover doors authorized for this tablet.
- Select a door from the returned list.
- Confirm a five-second remote unlock or a remote lock.
- Display the current lockdown flag received from the server.
- Authenticate requests and responses with the tablet's own secret.
- Reject stale/replayed requests server-side and enforce the tablet's per-door permissions.

## Register and install

1. Boot the server and unlock the admin console.
2. Open **9) Remote control / lockdown**.
3. Select **5) Manage pocket tablets**, then **1) Register tablet**.
4. Choose the door numbers the tablet is permitted to operate. At least one valid door must be selected.
5. Copy the displayed tablet ID and secret into the updated installer when prompted.
6. On the pocket computer, run the updated `doorlock-installer.lua` and choose **3) MineLock pocket tablet**.
7. Confirm the installer writes `startup.lua`; reboot or run it to start the tablet UI.

The tablet secret is a credential. Do not share it or put it on an unsecured floppy. If exposed, revoke the tablet from the server. A revoked tablet is rejected even if it still has the old secret configured.

## Controls

- **R** — refresh authorized door discovery.
- **Up / Down** — select a door.
- **U** — request remote unlock; requires explicit confirmation.
- **L** — request remote lock; requires explicit confirmation.
- **A** — show auto-open readiness information.
- **Q** — quit the tablet app.

Unlock duration is fixed at five seconds for this initial version. Global lockdown blocks unlock requests. A lock request remains available.

## Proximity and auto-open

Auto-open is intentionally disabled in this MVP. Wireless discovery means a door is reachable over the modem network; it does not prove the player is physically near that door. The follow-up implementation should add one of:

- GPS-based distance checks, after configuring a working GPS constellation and door coordinates; or
- a compatible physical player/entity sensor at the door.

Auto-open must remain opt-in, use a short duration and cooldown, and fail closed if the server is unavailable or lockdown is active. Manual operation remains available as a fallback.

## Status semantics and limitations

The current success response confirms that the server accepted the tablet request and broadcast the signed door command. It does **not** confirm that the target client received the packet, executed it, or physically moved the door. The next protocol stage should add signed door acknowledgements and an online/stale/offline status indicator.

The tablet requires the server and door clients to use the same channel. It must not be used as a replacement for physical emergency access or a server-side security console.
