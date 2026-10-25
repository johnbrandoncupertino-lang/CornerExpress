# Door Lock Overhaul — Installation

The maintained controller and installer are on `main`.

## Install the guided installer

On a ComputerCraft computer with HTTP enabled, run:

```text
wget https://raw.githubusercontent.com/johnbrandoncupertino-lang/CornerExpress/main/doorlock-installer.lua doorlock-installer.lua
doorlock-installer
```

Choose **Server / admin console** on the server computer, **Door client** on each door computer, or **MineLock pocket tablet** on a standard CC:Tweaked Pocket Computer. For a tablet, register it first from the server admin console under **Remote control / lockdown → Manage pocket tablets → Register tablet**, choose the allowed doors, and enter the generated tablet ID and secret in the installer. The installer writes the configured controller to `startup.lua`; it asks before replacing an existing startup file.

## Pair a client without copying a long key by hand

1. On the server, open **Doors → Add door** and create the door.
2. Insert a writable floppy into a server-attached disk drive.
3. Open **Doors → Export pairing file**, select the door, and confirm.
4. Move the floppy to the client computer and run the installer.
5. The installer detects `doorpair.txt`, imports the door ID and secret, and offers to delete the pairing file.

**Security:** `doorpair.txt` contains the door secret in plain text. Treat the floppy as a credential, keep it under your control, and delete the file after import. The installer also supports manual credential entry.

## MineLock pocket tablet

The tablet uses the same controller file with `ROLE = "tablet"`. Register each tablet on the server and grant access only to the doors it needs. The tablet secret is unique to that device; keep it private and revoke the tablet from the server if the credential is exposed. The current MVP supports authenticated discovery and manually confirmed remote lock/unlock requests. A successful tablet response means the server accepted and broadcast the command; it does **not** yet prove that the door received or executed it. Auto-open is not enabled until GPS coordinates or a compatible physical proximity sensor are configured and tested.

The tablet requires a wireless modem and the same server channel as the door clients. It works on the standard pocket computer terminal without a monitor.

## Classic Peripherals NFC

The controller now targets the Classic Peripherals peripheral type `nfc_reader`. Card presentations use the `nfc_data` event; write completion is checked through `nfc_write`. The NFC payload remains `CCL2:<32 hex characters>`, shared with the existing floppy-card format. NFC public-key authentication is not required.

Attach the NFC reader to the server for enrollment/wiping and/or to a door client for access. Use a writable NFC card when enrolling; write-protected cards cannot be enrolled or erased.

## Maintenance and recovery

- On an idle client, press **M** to open the maintenance menu.
- Press **R** there to reboot safely, or **Q** to return to the access screen.
- Accidental termination is ignored by the controller. A fatal error forces the client door output to its configured locked state and leaves the computer stopped for an explicit reboot instead of creating an automatic reboot loop.
- The server monitor remains optional; the terminal admin console continues to work without one.

## Before deployment

Test first in a safe world or with a non-critical door. Verify the configured redstone side and polarity, card expiry/use limits, server/client channel match, database persistence, and NFC write/erase behavior with your installed Classic Peripherals version. The source is committed directly to `main`; the environment here cannot run a live CC:Tweaked world test.
