# Investigation Timeline

## 07:10 — Investigation Workspace Created

### Investigation Action

Created:

```text
C:\PSRemotingLab
C:\PSRemotingLab\Evidence
```

Both paths returned:

```text
True
True
```

---

## 07:12:23 — Investigation Timestamp Recorded

### Investigation Action

```powershell
Get-Date
```

Recorded:

```text
22 September 2026 07:12:23
```

This timestamp provides a reference point for subsequent investigation activity.

---

## 07:xx — Host Baseline Collected

### Observation

```text
Hostname: DESKTOP-9MMM37V
Domain: WORKGROUP
DomainRole: 0
```

### Observation

```text
Microsoft Windows 11 Pro
Version: 10.0.26200
Build: 26200
```

### Interpretation

The endpoint is a standalone/workgroup Windows workstation.

---

## 07:xx — WinRM Service Checked

### Observation

```text
Name  Status  StartType
----  ------  ---------
WinRM Stopped Manual
```

### Interpretation

WinRM was stopped at the time of the explicit service-state check.

This does not establish historical non-use of WinRM.

---

## 07:xx — WinRM Configuration Examined

### Observation

Relevant configuration included:

```text
URLPrefix: wsman
HTTP: 5985
HTTPS: 5986
AllowUnencrypted: false
```

### Interpretation

The endpoint contained WinRM configuration supporting HTTP and HTTPS transports.

Configuration does not prove remote activity.

---

## 07:xx — PowerShell Remoting Configuration Checked

### Investigation Action

```powershell
Get-PSSessionConfiguration |
Select-Object Name, Permission, Enabled
```

### Observation

No session configuration output was captured.

### Interpretation

The captured result does not establish the presence or absence of a specific remoting endpoint.

---

## 07:xx — WinRM Listener Identified

### Observation

```text
Address: *
Transport: HTTP
Port: 5985
Enabled: true
URLPrefix: wsman
```

### Interpretation

An enabled WinRM HTTP listener was configured.

This establishes listening capability but not remote client activity.

---

## 07:xx — TCP Port 5985 Checked

### Observation

```text
LocalAddress LocalPort State  OwningProcess
------------ --------- ------ -------------
::           5985      Listen 4
```

### Interpretation

Port `5985` was listening at the time of the check.

No remote source is established by this observation.

---

## 07:20:31 — WSMan Operational Activity

### Observation

WinRM Operational events included:

```text
Event ID 145
WSMan operation Enumeration started

Event ID 132
WSMan operation Enumeration completed successfully

Event ID 254
Activity Transfer
```

The operations referenced:

```text
http://microsoft.com
```

### Interpretation

WSMan activity was observed.

Because the analyst was also executing WinRM/WSMan commands during the investigation, these events must be correlated with the investigation activity before being treated as independent historical remote activity.

---

## 07:23:12 — WSMan Enumeration

### Observation

```text
Event ID 145
WSMan operation Enumeration started

Event ID 132
WSMan operation Enumeration completed successfully
```

### Interpretation

A WSMan enumeration operation completed successfully.

The evidence does not establish that the operation originated from an external host.

---

## 07:23:21 — WSMan Enumeration

### Observation

```text
Event ID 145
WSMan operation Enumeration started

Event ID 132
WSMan operation Enumeration completed successfully
```

### Interpretation

Another WSMan enumeration operation was recorded.

Its proximity to the investigation activity requires caution when attributing it to an external source.

---

## 07:24 — PowerShell Startup Events

### Observation

Multiple Event ID `40961` events were observed:

```text
PowerShell console is starting up
```

### Interpretation

PowerShell console activity occurred.

This does not establish PowerShell Remoting.

---

## 07:27:26 — Sysmon PowerShell Process Activity

### Observation

Sysmon Event ID `1` showed PowerShell process creation.

The captured output was abbreviated as:

```text
Process Create:...
```

### Interpretation

PowerShell process creation was observed.

The available screenshot does not expose sufficient process context to determine whether the process was locally or remotely initiated.

---

## 07:27–07:29 — Repeated PowerShell Process Creation

### Observation

Multiple PowerShell process creation events were observed between approximately:

```text
07:27:26
and
07:29:54
```

### Interpretation

Repeated PowerShell process creation was present in the telemetry.

The available event output did not expose complete command-line or parent-process information.

---

## 07:29:54 — Latest Captured PowerShell Process Event

### Observation

A Sysmon Event ID `1` PowerShell process creation event was present.

### Interpretation

The endpoint generated PowerShell process telemetry.

Remote execution attribution cannot be established from the abbreviated output.

---

## Security Authentication Investigation

### Observation

The search for Event ID `4624` returned:

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

### Interpretation

No matching successful-logon events were returned in the captured search.

---

## Privileged Authentication Investigation

### Observation

The search for Event ID `4672` returned:

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

### Interpretation

No matching privileged-authentication events were returned in the captured search.

---

## Sysmon Network Investigation

### Observation

The search for Sysmon Event ID `3` involving:

```text
5985
5986
```

returned no matching output.

### Interpretation

No Sysmon network connection evidence involving the standard WinRM ports was captured.

---

## Wazuh Investigation

### Observation

The captured Wazuh event used:

```text
decoder.name:
syscheck_registry_value_modified
```

The affected registry value was:

```text
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\VSS\Diag\WMI Writer\BACKUPSHUTDOWN
```

### Interpretation

The event represents registry integrity monitoring.

It does not establish WinRM or PowerShell Remoting activity.

---

# Correlated Timeline

```text
07:10
  |
  +-- Investigation workspace created
  |
07:12:23
  |
  +-- Investigation timestamp recorded
  |
07:xx
  |
  +-- Host identified as WORKGROUP Windows 11
  |
07:xx
  |
  +-- WinRM service observed stopped
  |
07:xx
  |
  +-- WinRM configuration examined
  |
07:xx
  |
  +-- HTTP listener on 5985 identified
  |
07:xx
  |
  +-- TCP 5985 observed listening
  |
07:20:31
  |
  +-- WSMan Enumeration activity
  |
07:23:12
  |
  +-- WSMan Enumeration
  |
07:23:21
  |
  +-- WSMan Enumeration
  |
07:24
  |
  +-- PowerShell startup events
  |
07:27:26 - 07:29:54
  |
  +-- Multiple PowerShell process creation events
  |
  +-- No captured 4624 authentication evidence
  |
  +-- No captured 4672 privileged authentication evidence
  |
  +-- No captured Sysmon 5985/5986 network evidence
  |
  +-- Wazuh registry integrity event unrelated to remoting
```

---

