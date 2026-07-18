# Physical Asset Checkout Model

Kira owns physical assets: USB devices, serial and COM ports, connected hardware, power-sensitive resources, and storage arrays. The goal is to prevent two threads from touching the same physical asset or unsafe dependent assets at the same time.

## Physical Resource Types

- `usb_device`
- `serial_port`
- `com_port`
- `connected_device`
- `power_resource`
- `storage_array`
- `composite_physical_asset`

## Identity Fields

Physical resources require explicit identity fields because path names can drift between boots.

Required fields:

- `resource_id`
- `kind`
- `display_name`
- `owner_domain`: `kira`
- `risk_level`
- `stable_id`
- `observed_paths`
- `vendor_id`
- `product_id`
- `serial_number`
- `capabilities`
- `power_profile`
- `storage_profile`
- `exclusive_groups`
- `depends_on`

Identity examples:

- USB serial adapter: `/dev/serial/by-id/...`, VID/PID, serial number, current `/dev/ttyUSB*`.
- Native USB MCU: USB VID/PID, product string, serial, expected firmware role.
- Power resource: outlet, hub, bus, maximum current, dependent devices.
- Storage array: mount UUID, mount path, capacity class, attached services.

## Checkout Rules

- Physical asset checkout is exclusive by default.
- A device path alone is not enough identity when VID/PID or serial is available.
- Flashing, firmware changes, destructive tests, and power changes require explicit approval.
- Power resources are dependencies of attached devices.
- Storage arrays are dependencies of services that read or write them.
- Expired physical leases require operator review before another thread can take over.

## Conflict Rules

A physical checkout conflicts when any of these overlap:

- same stable identity,
- same observed path,
- same USB serial number,
- same serial or COM port,
- same power resource,
- same storage array,
- same exclusive group,
- dependency held by another exclusive claim.

Default behavior:

- Read-only observation can share only when no exclusive claim is active.
- Any write, flash, reset, mount, unmount, or power action is exclusive.
- If identity is incomplete, the claim escalates for Kira or human review.
- If a device is power-sensitive, power dependencies must be checked out or approved.
- If a storage array is shared, write claims require rollback or backup notes.

## Release Evidence

A physical asset can be released when:

- the operation is complete,
- the device still matches expected identity when identity matters,
- serial or USB paths are no longer held,
- storage writes are flushed or verified,
- power state is stable,
- post-check evidence is recorded.

## First Slice

The first executable slice should:

1. Normalize physical identity fields.
2. Detect conflicts by stable ID, observed path, serial number, exclusive group, and dependency.
3. Escalate incomplete physical identity.
4. Represent power and storage risk flags.
