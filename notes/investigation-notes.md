# Investigation Notes — PowerShell Remoting Investigation

## Investigation Focus

This investigation examined whether the Windows endpoint showed evidence of **PowerShell Remoting or WinRM-based remote execution**.

The investigation deliberately separated:

- Configuration
- Runtime service state
- WSMan activity
- Authentication
- Network connections
- PowerShell process creation
- Remote-session evidence
- SIEM telemetry

The objective was to determine what the available telemetry could actually establish without assuming that every WinRM or PowerShell artifact represented remote activity.

---

## Host Baseline

### Host Information

```text
Hostname: DESKTOP-9MMM37V
Domain: WORKGROUP
DomainRole: 0
```

### Operating System

```text
Microsoft Windows 11 Pro
Version: 10.0.26200
Build: 26200
```

The endpoint is a WORKGROUP system rather than an Active Directory domain member.

This is relevant because some authentication and Kerberos-related telemetry expected in domain environments may not be available.

---

## Investigation Workspace

The investigation workspace was created at:

```text
C:\PSRemotingLab
```

The evidence directory was:

```text
C:\PSRemotingLab\Evidence
```

Both paths were verified successfully.

---

## Investigation Timestamp

The investigation timestamp recorded at the beginning of the activity was:

```text
22 September 2026 07:12:23
```

This timestamp provides a reference point for distinguishing investigation activity from earlier endpoint telemetry.

---

## WinRM Service

The initial service-state query was:

```powershell
Get-Service WinRM |
Select-Object Name, Status, StartType
```

The result was:

```text
Name  Status  StartType
----  ------  ---------
WinRM Stopped Manual
```

### Interpretation

WinRM was stopped at the time of the explicit service-state check.

This does not prove that WinRM had never been configured or used previously.

---

## WinRM Configuration

The WinRM configuration was queried successfully.

Relevant values included:

```text
MaxEnvelopeSizekb: 500
MaxTimeoutms: 60000
MaxBatchItems: 32000
URLPrefix: wsman
AllowUnencrypted: false
Default HTTP Port: 5985
Default HTTPS Port: 5986
```

Configured authentication mechanisms included:

```text
Basic
Digest
Kerberos
Negotiate
Certificate
```

CredSSP was disabled.

### Interpretation

The endpoint has WinRM configuration supporting HTTP and HTTPS transports.

This is configuration evidence only.

It does not establish that a remote client connected to the host.

---

## PowerShell Remoting Configuration

The following command was used:

```powershell
Get-PSSessionConfiguration |
Select-Object Name, Permission, Enabled
```

No session configuration output was captured in the screenshots.

### Interpretation

The captured output does not establish the presence or absence of a specific PowerShell Remoting endpoint.

The result should therefore be recorded as a telemetry observation rather than converted into a stronger conclusion.

---

## WinRM Listener

The listener was queried using:

```powershell
Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate
```

The listener returned:

```text
Address: *
Transport: HTTP
Port: 5985
Enabled: true
URLPrefix: wsman
```

### Interpretation

The host had an enabled HTTP WinRM listener on port `5985`.

This establishes that the host was configured to accept WinRM HTTP traffic.

It does not establish that a remote client connected.

---

## TCP Listening State

The following command was used:

```powershell
Get-NetTCPConnection -State Listen |
Where-Object {
    $_.LocalPort -in 5985,5986
} |
Select-Object LocalAddress, LocalPort, State, OwningProcess
```

The result was:

```text
LocalAddress LocalPort State  OwningProcess
------------ --------- ------ -------------
::           5985      Listen 4
```

### Interpretation

Port `5985` was listening at the time of the check.

This confirms runtime listening state.

It does not provide historical evidence of a remote connection.

---

## PowerShell Operational Telemetry

The PowerShell logs were enumerated using:

```powershell
Get-WinEvent -ListLog *PowerShell* |
Select-Object LogName, IsEnabled, RecordCount
```

The PowerShell Operational channel was enabled and contained a large number of events.

Recent events included:

```text
Event ID: 40961
Message: PowerShell console is starting up
```

A remoting-related keyword search was performed using:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 500 |
Where-Object {
    $_.Message -match "PSSession|Enter-PSSession|Invoke-Command|WinRM|WSMan|Remote"
} |
Select-Object TimeCreated, Id, Message
```

No matching events were returned in the captured output.

### Interpretation

PowerShell activity was present, but the captured PowerShell Operational telemetry did not directly confirm a PowerShell Remoting session.

---

## WinRM Operational Telemetry

The WinRM Operational channel was enumerated using:

```powershell
Get-WinEvent -ListLog *WinRM* |
Select-Object LogName, IsEnabled, RecordCount
```

The channel was enabled and contained:

```text
1672
```

events.

Observed events included:

```text
Event ID 145
WSMan operation Enumeration started

Event ID 132
WSMan operation Enumeration completed successfully

Event ID 254
Activity Transfer
```

The observed WSMan operations referenced:

```text
http://microsoft.com
```

### Interpretation

The endpoint generated WSMan activity.

However, the captured events do not provide sufficient evidence to establish:

- Remote source IP
- Remote destination
- Remote user
- Remote authentication
- Remote PowerShell session
- Remote command execution

The correct finding is:

> WSMan activity observed.

The evidence does not support:

> PowerShell Remoting confirmed.

---

## Windows Security Authentication

The investigation searched for Event ID `4624`:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id = 4624
} -MaxEvents 100 |
Select-Object TimeCreated, Id, Message
```

The result was:

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

Event ID `4672` was also searched:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id = 4672
} -MaxEvents 100 |
Select-Object TimeCreated, Id, Message
```

The result again indicated that no matching events were found.

### Interpretation

No successful authentication or privileged-authentication evidence was captured from these searches.

This is a telemetry limitation.

It should not be interpreted as proof that no authentication ever occurred.

---

## Sysmon Process Creation

Sysmon Event ID `1` was searched for PowerShell:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 1
} -MaxEvents 500 |
Where-Object {
    $_.Message -match "powershell.exe|pwsh.exe"
} |
Select-Object TimeCreated, Message
```

Multiple process creation events were observed.

The captured timestamps ranged approximately from:

```text
07:27:26
to
07:29:54
```

The screenshot output was abbreviated:

```text
Process Create:...
```

### Interpretation

PowerShell process creation is established.

However, the captured output does not expose complete:

- Command line
- Parent process
- User
- Process ID
- Parent Process ID
- Hash

Therefore, the evidence does not establish that these processes were created as a result of remote PowerShell execution.

---

## Sysmon Network Connections

Sysmon Event ID `3` was searched for:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 3
} -MaxEvents 500 |
Where-Object {
    $_.Message -match "5985|5986"
} |
Select-Object TimeCreated, Message
```

No matching output was captured.

### Interpretation

The investigation did not obtain Sysmon network evidence showing a connection involving the standard WinRM ports.

This does not prove that no network connection ever occurred.

---

## Wazuh Telemetry

The captured Wazuh event contained:

```text
decoder.name: syscheck_registry_value_modified
```

The monitored registry value was:

```text
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\VSS\Diag\WMI Writer\BACKUPSHUTDOWN
```

### Interpretation

This was a registry integrity monitoring event.

It was not evidence of PowerShell Remoting or WinRM remote execution.

The event was therefore excluded from the remoting evidence chain.

---

## Investigation-Induced Telemetry

An important consideration in this lab is that the analyst executed commands that interact with WinRM and WSMan.

Examples include:

```powershell
winrm get winrm/config
```

and:

```powershell
Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate
```

These actions can generate local WSMan Operational events.

Therefore, WSMan events occurring close to the investigation commands must not automatically be attributed to an external host.

The analyst's own activity must be considered when building the timeline.

---

## Evidence Correlation

The expected remote execution chain is:

```text
Remote Source
      |
      v
Authentication
      |
      v
Connection to 5985/5986
      |
      v
WinRM / WSMan Activity
      |
      v
Remote PowerShell Session
      |
      v
PowerShell Process
      |
      v
Command Execution
```

The investigation established:

```text
WinRM configuration
      +
Enabled listener
      +
TCP 5985 listening
      +
WSMan activity
      +
PowerShell process creation
```

The following elements were not established:

```text
Remote source
Authentication correlation
WinRM network connection
Remote PowerShell session
Remote command execution
```

---

## Evidence Assessment

### Confirmed

- Windows host identity and role
- WORKGROUP configuration
- WinRM configuration
- Enabled HTTP WinRM listener
- TCP port `5985` listening at the time of the check
- WSMan Operational events
- PowerShell process creation events

### Not Confirmed

- Remote PowerShell session
- Remote authentication
- Remote source IP
- Remote command execution
- Lateral movement
- Malicious use of WinRM

---

## Assessment

The evidence supports **WinRM configuration and local WSMan activity**, but does not establish confirmed PowerShell Remoting.

The available telemetry is insufficient to reconstruct a complete remote execution chain.

The investigation therefore follows the principle:

> **Follow the evidence, not the assumption.**
