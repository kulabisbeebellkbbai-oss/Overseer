# Remote GUI Control Plan

## Purpose

Provide a trusted remote GUI/control channel for local GUI-only administration tasks, starting with Obsidian Documents MCP verification.

## Use Policy

This channel is a last-resort capability. Use direct CLI, API, MCP, service, or file-based automation first. Use the remote GUI channel only when a workflow requires direct human GUI intervention or when a GUI-only application cannot be completed safely through non-GUI controls.

Every activation or use of this channel requires explicit human approval for the specific workflow. Sisko or another automated Overseer role may stage, review, and recommend the work, but must not approve GUI control on behalf of the human.

## Current State

- An active KDE/Wayland desktop session exists for user `god`.
- The Codex shell is a TTY and does not inherit `DISPLAY` or `WAYLAND_DISPLAY`.
- Obsidian can be started against the desktop session from SSH, but the Local REST API plugin is not yet listening.
- A localhost-only TigerVNC virtual desktop is installed for last-resort GUI intervention.
- Existing SSH is listening; no new inbound network exposure is required for the proposed setup.

## Proposed Setup

Install and run a localhost-only TigerVNC virtual desktop for user `god`.

Packages:

- `tigervnc-standalone-server`
- `tigervnc-common`
- `openbox`
- `xdotool`
- `dbus-x11`

Installed state:

- TigerVNC, Openbox, xdotool, and dbus-x11 are installed.
- The active VNC display is `:90`.
- The VNC listener is bound to loopback only.
- The VNC credential is stored locally at `/home/god/.local/share/overseer/secrets/remote-gui-vnc-password.txt`.
- The TigerVNC password file is stored locally at `/home/god/.local/share/overseer/secrets/remote-gui-vnc.passwd`.

Runtime:

- Start a user-owned virtual desktop with `vncserver -localhost yes`.
- Store VNC credentials under `/home/god/.local/share/overseer/secrets/`.
- Start Obsidian inside the virtual desktop when GUI interaction is needed.
- Access the desktop remotely only through an SSH tunnel.

## Intended Traffic

- Source: authenticated SSH client.
- Destination: localhost-bound VNC listener on this host.
- Direction: SSH tunnel to loopback service.
- Network exposure: none beyond existing SSH.

## Security Controls

- Bind VNC to localhost only.
- Require SSH authentication before any remote VNC access.
- Store generated VNC secret files with user-only permissions.
- Do not open firewall rules or bind VNC to `0.0.0.0`.
- Do not expose Obsidian Local REST API beyond `127.0.0.1`.

## Risks

- Anyone with SSH access to user `god` and access to the VNC secret can control the virtual desktop.
- GUI applications started in the virtual desktop run as user `god`.
- Clipboard, screenshots, and visible documents in the virtual desktop should be treated as sensitive.

## Rollback

- Stop the VNC session with `vncserver -kill :90` or the active display number.
- Remove generated VNC secret files from `/home/god/.local/share/overseer/secrets/`.
- Remove user VNC config under `/home/god/.vnc/` if it is no longer needed.
- Optionally remove packages with `sudo apt remove tigervnc-standalone-server tigervnc-common openbox xdotool dbus-x11`.

## Validation

- Confirm the VNC listener is bound only to loopback.
- Confirm Obsidian can run inside the virtual desktop.
- Confirm Obsidian Local REST API listens only on localhost.
- Confirm the Documents MCP wrapper can connect without exposing the API key.

## Operator Access

Use an SSH tunnel from the operator workstation:

```bash
ssh -L 5990:127.0.0.1:5990 god@<host>
```

Then connect a VNC viewer on the operator workstation to:

```text
127.0.0.1:5990
```

Retrieve the VNC password over SSH only when needed. Do not paste it into chat, commits, issues, or logs.

```bash
ssh god@<host> 'cat /home/god/.local/share/overseer/secrets/remote-gui-vnc-password.txt'
```

Stop the last-resort GUI session when the approved GUI-only workflow is complete:

```bash
vncserver -kill :90
```
