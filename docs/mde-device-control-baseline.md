# Microsoft Defender for Endpoint Device Control Baseline (Windows)

This baseline is designed for a **DLP-first rollout** where the default posture is to prevent data exfiltration to USB removable storage while preserving justified business exceptions.

## 1) Scope and objectives

- Platform: Windows endpoints only (phase 1).
- Objective: Prevent unauthorized writes to removable storage devices.
- Requirement: Centralized visibility for all allow/block/audit decisions.
- Operational design: Start in audit mode, then move to controlled enforcement.

## 2) Security group model (with exclusions)

Use Entra ID groups to keep policy assignment simple, auditable, and reversible.

### Core groups

- `DG-DC-Prod-Devices`  
  All managed Windows devices in scope.
- `DG-DC-Excluded-ITAdmins`  
  Operational admin exceptions (time-bound).
- `DG-DC-Excluded-SecOps`  
  Incident response and forensics exceptions (time-bound).
- `DG-DC-Allowed-USB-Users`  
  Users approved for removable media write access.
- `DG-DC-Allowed-USB-Devices`  
  Optional allowlist of approved removable device serials/hardware IDs.
- `DG-DC-BreakGlass-Temporary`  
  Emergency-only temporary exceptions with automatic expiry.

### Governance for exclusions

- Exception membership requires ticket + approval.
- Membership should be time-bound (PIM or scheduled removal).
- Weekly review of all excluded members.
- Monthly access recertification.

## 3) Policy rollout plan

### Phase 0: Discovery (Audit only, 1-2 weeks)

- Enable auditing for removable storage events.
- Observe which teams and apps rely on USB writes.
- Build justified allowlist candidates.

### Phase 1: Controlled enforcement

- Default posture: block removable write and execute.
- Keep approved exception groups functional.
- Monitor helpdesk impact and false positives.

### Phase 2: Hardening

- Restrict write access to approved users + approved devices.
- Prefer encrypted approved media where supported.
- Reduce or remove broad exclusions.

## 4) Intune assignment matrix

| Policy name | Included groups | Excluded groups | Mode | Purpose |
|---|---|---|---|---|
| `DC-01-Global-Restrictive` | `DG-DC-Prod-Devices` | `DG-DC-Excluded-ITAdmins`, `DG-DC-Excluded-SecOps`, `DG-DC-Allowed-USB-Users`, `DG-DC-BreakGlass-Temporary` | Enforce | Deny removable write/execute by default |
| `DC-02-Allowed-USB-Users` | `DG-DC-Allowed-USB-Users` | None | Enforce | Allow removable write for approved users (optionally restricted to approved devices) |
| `DC-03-BreakGlass-Temporary` | `DG-DC-BreakGlass-Temporary` | None | Enforce | Short-term emergency exception with elevated monitoring |
| `DC-00-Audit-Baseline` | Pilot device group | None | Audit | Validate behavior prior to broad enforcement |

## 5) Recommended policy behavior

### Global restrictive policy (`DC-01-Global-Restrictive`)

- Removable storage read: allow (or move to restricted if policy requires).
- Removable storage write: block.
- Execute from removable storage: block.
- Audit events: enabled for all block and allow decisions.

### Allowed USB users policy (`DC-02-Allowed-USB-Users`)

- Write: allow for approved users.
- Optional: require device match against approved hardware IDs/serials.
- Audit: enabled.

### Break-glass policy (`DC-03-BreakGlass-Temporary`)

- Write: allow only during approved window.
- Membership: temporary by design.
- All activity: high-priority monitoring.

## 6) Event collection and telemetry

Forward Defender for Endpoint events to SIEM (Microsoft Sentinel or equivalent) and retain with your incident response standards.

Minimum fields to retain:

- `Timestamp`
- `DeviceName`
- `DeviceId`
- `AccountName`
- `InitiatingProcessFileName`
- `ActionType`
- Removable media identifiers (serial/model/vendor where available)

## 7) KQL starter pack (Sentinel / Defender advanced hunting)

> Note: Event table/field names may vary by connector version. Validate in your tenant.

### Query A: USB/removable storage actions by user and device

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType has_any ("RemovableStorage", "Usb")
| summarize Events=count() by AccountName, DeviceName, ActionType
| order by Events desc
```

### Query B: Blocked removable write attempts

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType has_any ("RemovableStorage", "Usb")
| where ActionType has_any ("Blocked", "Deny")
| project Timestamp, DeviceName, AccountName, ActionType, InitiatingProcessFileName
| order by Timestamp desc
```

### Query C: New/unseen removable devices in the last 24h

```kql
let historical =
    DeviceEvents
    | where Timestamp between (ago(30d) .. ago(1d))
    | where ActionType has_any ("RemovableStorage", "Usb")
    | summarize by DeviceName, AdditionalFields;
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType has_any ("RemovableStorage", "Usb")
| join kind=leftanti historical on DeviceName, AdditionalFields
| project Timestamp, DeviceName, AccountName, ActionType, AdditionalFields
| order by Timestamp desc
```

### Query D: Potential high-volume exfil indicator (proxy)

```kql
DeviceFileEvents
| where Timestamp > ago(24h)
| where FolderPath startswith "E:\\" or FolderPath startswith "F:\\" or FolderPath startswith "G:\\"
| summarize FilesWritten=count(), DistinctFileTypes=dcount(FileType)
    by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1h)
| where FilesWritten > 500
| order by FilesWritten desc
```

## 8) Operational runbook checkpoints

- Confirm pilot endpoints are healthy after policy assignment.
- Validate expected block events in SIEM.
- Validate approved users can perform business-required writes.
- Confirm excluded groups are minimal and documented.
- Define escalation path for repeated blocked attempts.

## 9) Recommended implementation order

1. Build and populate groups.
2. Deploy `DC-00-Audit-Baseline` to pilot devices.
3. Tune allowlists and exclusions based on evidence.
4. Deploy `DC-01-Global-Restrictive` broadly.
5. Deploy `DC-02-Allowed-USB-Users` for approved exceptions.
6. Keep `DC-03-BreakGlass-Temporary` disabled until needed.

## 10) Change control statement template

> All Windows endpoints are subject to removable media control. Removable write access is denied by default and granted only through approved, time-bound exceptions. All media-control decisions are centrally logged and reviewed for DLP monitoring.
