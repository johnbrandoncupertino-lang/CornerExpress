# Door Lock Features — Remote Control and Lockdown

These controls are part of the main-branch single-file controller. Reinstall/update the controller on the server and each client so every computer has the matching protocol.

## Server monitor

The optional server monitor refreshes continuously and displays recent access events, grants/denials, card and door counts, and a prominent red lockdown banner. Access events are also appended to the configured `access.log` file; the on-screen list is the current server session's in-memory tail.

## Remote door control

From the server admin console:

1. Unlock the admin console.
2. Select **9) Remote control / lockdown**.
3. Choose **Remote unlock** or **Remote lock**, select a configured door, and confirm.

Remote unlock accepts a duration from 1 to 30 seconds. Control packets are signed with that door's existing secret, include a timestamp and one-time nonce, and are verified by the client before execution. Commands are broadcast over the configured modem channel, so the server does not have a guaranteed acknowledgement that the target is online or physically moved; treat the message as a command attempt, not proof of door state.

## Global security lockdown

In **Remote control / lockdown**, choose **Enable global lockdown** and confirm. The server:

- Persists the lockdown flag in the card database, so it remains active after a server restart.
- Denies card-access requests without consuming a card use.
- Broadcasts signed lock commands to configured door clients to close currently open doors.
- Displays a lockdown banner on the server monitor and records the change in the access log.

Choose **Clear global lockdown** to persistently restore normal card authorization and broadcast the clear command. Clearing lockdown does not itself unlock doors.

The server remains authoritative for card access. Clients that miss a broadcast can still send requests, but the server will deny them while lockdown is active. A remote command cannot operate a disconnected client, a detached modem, or a physically jammed door.

## Security and deployment notes

- Update the server and all door clients from the same current `main` controller before using remote controls.
- Keep each door secret private. Anyone with that secret can forge control packets for that door.
- Lockdown is persisted in `cards.db`; back up the database securely.
- Test on a non-critical door first, including the redstone polarity and what happens if the modem network is interrupted.


## MineLock pocket tablet

The standard CC:Tweaked Pocket Computer can run the controller with `ROLE = "tablet"`. Register a tablet from the server's **Remote control / lockdown → Manage pocket tablets** menu and grant only the doors it should control. Each tablet receives a separate 32-character secret. The server authenticates requests, rejects replayed or stale requests, enforces per-door permissions, and denies tablet unlock requests during global lockdown.

The tablet supports wireless discovery of its authorized doors, manual selection, and confirmation before remote unlock/lock. Unlock requests use a fixed five-second duration in this MVP. The tablet does not hold door secrets and cannot directly issue door-authenticated commands.

**Status limitation:** the tablet currently reports that the server broadcast a command, not that a door acknowledged or physically changed state. A disconnected door may not execute the request. Auto-open is not enabled yet; wireless range alone is not a reliable physical-proximity measurement. The next stage is door acknowledgements/status plus a tested GPS or compatible sensor integration.

To install, run the updated installer and choose **MineLock pocket tablet**. Register the device first on the server, then enter its tablet ID and secret. Revoke the tablet on the server immediately if the secret is exposed.
