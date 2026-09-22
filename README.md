# PowerShell Remoting Investigation Lab

## Overview

This lab investigates **PowerShell Remoting and Windows Remote Management (WinRM)** activity on a Windows endpoint from a SOC/DFIR perspective.

PowerShell Remoting is commonly used for legitimate administration, automation, and remote management. The same mechanisms can also be abused for lateral movement and remote command execution. Because legitimate and malicious activity can generate similar telemetry, this investigation focuses on establishing an evidence chain rather than treating individual artifacts as proof of remote execution.

The investigation covers:

- Windows host and domain configuration
- WinRM service state
- WinRM configuration
- PowerShell Remoting configuration
- WinRM listeners and ports
- PowerShell Operational events
- WinRM Operational events
- Windows Security authentication events
- Sysmon process creation
- Sysmon network connections
- Wazuh telemetry
- Source-to-destination correlation
- Evidence limitations

The central investigation principle is:

> **Configuration is not activity, and activity is not automatically malicious.**

---

## Lab Environment

| Component | Value |
|---|---|
| Hostname | `DESKTOP-9MMM37V` |
| Operating System | Windows 11 Pro |
| Version | `10.0.26200` |
| Build | `26200` |
| Domain | `WORKGROUP` |
| Domain Role | `0` |
| WinRM Service | Stopped during initial service check |
| WinRM HTTP Listener | Enabled |
| WinRM Port | `5985` |
| PowerShell Operational Log | Enabled |
| WinRM Operational Log | Enabled |
| Sysmon | Present |
| Wazuh Agent | `001` |

---

## Investigation Scenario

A Windows workstation is being investigated for possible PowerShell Remoting activity.

The analyst needs to determine whether WinRM or PowerShell Remoting was actually used, identify the available authentication and process telemetry, and establish whether the observed activity can be attributed to a remote source.

The endpoint is not joined to an Active Directory domain, and no second Windows host was used to generate a genuine remote PowerShell session during this investigation.

Therefore, the investigation does not fabricate remote activity. Instead, it validates the local remoting configuration and available telemetry while documenting where the evidence is insufficient to establish an actual remote session.

---

## Investigation Objectives

1. Establish the identity and role of the investigated Windows host.
2. Determine the current WinRM service state.
3. Examine WinRM configuration.
4. Identify configured PowerShell Remoting endpoints.
5. Identify active WinRM listeners and ports.
6. Review PowerShell Operational telemetry.
7. Review WinRM Operational telemetry.
8. Investigate Windows authentication events.
9. Examine Sysmon PowerShell process creation.
10. Examine Sysmon network telemetry involving WinRM ports.
11. Review Wazuh telemetry.
12. Correlate authentication, network, WinRM, PowerShell, and process evidence.
13. Separate investigation-generated activity from historical endpoint activity.
14. Determine whether the available evidence supports confirmed remoting, remoting-related activity, configuration-only findings, or an inconclusive assessment.

---

## Investigation Chain

```text
Remote Source
      |
      v
Authentication
      |
      v
WinRM / WSMan Connection
      |
      v
PowerShell Remoting Session
      |
      v
PowerShell Process
      |
      v
Command / Parent-Process Context
      |
      v
Source -> Destination Correlation
      |
      v
Evidence Assessment
```

---

## Key Evidence Distinctions

```text
WinRM is enabled
        !=
A remote connection occurred

WinRM listener exists
        !=
A remote client connected

PowerShell process exists
        !=
PowerShell Remoting was used

WSMan activity exists
        !=
Malicious activity occurred

Authentication event exists
        !=
PowerShell Remoting occurred
```

---

## Investigation Findings

### Host Baseline

The investigated endpoint was identified as:

```text
Hostname: DESKTOP-9MMM37V
Domain: WORKGROUP
DomainRole: 0
Operating System: Windows 11 Pro
Version: 10.0.26200
Build: 26200
```

The system is a standalone/workgroup Windows workstation.

### WinRM Service

The initial service check returned:

```text
Name  Status  StartType
----  ------  ---------
WinRM Stopped Manual
```

This establishes that WinRM was stopped at the time of the explicit service-state check.

It does not prove that WinRM had never been configured or used previously.

### WinRM Configuration

The WinRM configuration was successfully queried.

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

Configured authentication mechanisms included Basic, Digest, Kerberos, Negotiate, and Certificate authentication.

These values describe the configured WinRM environment. They do not establish that a remote session occurred.

### PowerShell Remoting Configuration

The following command was used:

```powershell
Get-PSSessionConfiguration |
Select-Object Name, Permission, Enabled
```

No session configuration output was captured in the investigation screenshots.

This should be documented as an observation of the captured command output rather than proof that no remoting endpoint exists.

### WinRM Listener

An enabled WinRM HTTP listener was identified:

```text
Address: *
Transport: HTTP
Port: 5985
Enabled: true
URLPrefix: wsman
```

This establishes that the host was configured to accept WinRM HTTP connections.

It does not establish that a remote client connected.

### TCP Listener

Port `5985` was observed in a listening state:

```text
LocalAddress LocalPort State  OwningProcess
------------ --------- ------ -------------
::           5985      Listen 4
```

This confirms runtime listening state at the time of the check.

It does not establish a historical remote connection.

### PowerShell Operational Telemetry

The PowerShell Operational channel was enabled and contained a large number of events.

Recent events included Event ID `40961`:

```text
PowerShell console is starting up
```

A search for the following remoting-related terms returned no matching output in the captured result:

```text
PSSession
Enter-PSSession
Invoke-Command
WinRM
WSMan
Remote
```

Therefore, the captured PowerShell Operational telemetry does not directly confirm a PowerShell Remoting session.

### WinRM Operational Telemetry

The WinRM Operational channel was enabled and contained `1672` events.

Observed events included:

```text
Event ID 145
WSMan operation Enumeration started

Event ID 132
WSMan operation Enumeration completed successfully

Event ID 254
Activity Transfer
```

The events referenced WSMan operations against:

```text
http://microsoft.com
```

These events establish WSMan activity on the endpoint.

However, the captured events do not establish an external source, remote authentication, or confirmed remote PowerShell execution.

### Windows Security Authentication

The investigation searched for Event ID `4624`.

The captured result was:

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

Event ID `4672` was also searched, with the same result.

Therefore, the captured investigation output does not provide successful authentication evidence that can be correlated with remote PowerShell activity.

### Sysmon Process Creation

Sysmon Event ID `1` was searched for:

```text
powershell.exe
pwsh.exe
```

Multiple PowerShell process creation events were observed between approximately:

```text
07:27:26
and
07:29:54
```

The captured event output was abbreviated as:

```text
Process Create:...
```

The screenshots therefore do not expose complete command-line, parent-process, user, process-ID, or hash information.

The evidence supports PowerShell process creation, but not remote PowerShell execution.

### Sysmon Network Connections

Sysmon Event ID `3` was searched for connections involving:

```text
5985
5986
```

No matching output was captured.

Therefore, no Sysmon network evidence for a connection involving the standard WinRM ports was captured.

### Wazuh

The captured Wazuh event was generated by:

```text
decoder: syscheck_registry_value_modified
```

The monitored registry value was:

```text
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\VSS\Diag\WMI Writer\BACKUPSHUTDOWN
```

The event represented registry integrity monitoring.

It was not evidence of PowerShell Remoting or WinRM remote execution.

---

## Evidence Correlation

The desired evidence chain is:

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

The investigation established only portions of this chain:

```text
WinRM configuration
      +
Enabled WinRM listener
      +
TCP 5985 listening
      +
WSMan activity
      +
PowerShell process creation
```

The following links were not established:

```text
Remote source
Authentication correlation
WinRM network connection
Remote PowerShell session
Remote command execution
```

---

## Evidence Summary

| Evidence Source | Observation | Interpretation |
|---|---|---|
| Host configuration | WORKGROUP, DomainRole 0 | Standalone/workgroup host |
| WinRM service | Stopped during service check | Service was not running at that point |
| WinRM configuration | Configuration available | WinRM configuration exists |
| WinRM listener | HTTP/5985 enabled | Host configured for WinRM |
| TCP listener | 5985 listening | WinRM endpoint listening |
| PowerShell Operational | Startup events | PowerShell activity observed |
| Remoting keyword search | No matching output | No direct remoting evidence captured |
| Security 4624 | No matching output | No authentication correlation captured |
| Security 4672 | No matching output | No privileged-authentication correlation captured |
| Sysmon Event 1 | PowerShell process events | PowerShell process creation observed |
| Sysmon Event 3 | No 5985/5986 matches | No WinRM network evidence captured |
| Wazuh | Registry integrity event | Unrelated to confirmed remoting |

---

## Assessment

### Configuration and Local WSMan Activity Observed

The investigation establishes that the endpoint had WinRM configuration, an enabled HTTP listener on port `5985`, WSMan Operational activity, and PowerShell process creation telemetry.

However, the captured evidence does not establish the complete chain required to confirm a remote PowerShell session.

Specifically, the investigation did not obtain correlated evidence showing:

```text
Remote source
+
Remote authentication
+
WinRM network connection
+
PowerShell Remoting session
+
Remote command execution
```

Therefore, the evidence should not be described as confirmed PowerShell Remoting or confirmed lateral movement.

---

## Evidence Limitations

- The endpoint is a WORKGROUP system rather than an Active Directory domain member.
- No second Windows endpoint was used to generate a controlled remote PowerShell session.
- Security Event IDs `4624` and `4672` returned no matching events in the captured searches.
- Sysmon Event ID `3` returned no captured matches for ports `5985` or `5986`.
- PowerShell remoting keyword searches returned no matching events in the captured output.
- Sysmon process output was abbreviated and did not expose full command-line or parent-process context.
- The captured Wazuh event was a registry integrity event unrelated to confirmed remoting.
- Some WSMan events occurred while investigation commands were being executed and therefore require caution when attributing them to independent historical activity.

---

## Evidence Files

```text
C:\PSRemotingLab\Evidence\
|
+-- 00-investigation-time.txt
+-- 01-host-role.txt
+-- 02-operating-system.txt
+-- 03-winrm-service.txt
+-- 04-winrm-configuration.txt
+-- 05-pssession-configurations.txt
+-- 06-winrm-listener.txt
+-- 07-winrm-listening-ports.txt
+-- 08-powershell-operational-events.txt
+-- 09-remoting-related-events.txt
+-- 10-winrm-operational-events.txt
+-- 11-sysmon-powershell-processes.txt
+-- 12-sysmon-winrm-network.txt
```

---

## SOC Lessons

### Configuration Is Not Execution

An enabled WinRM listener shows that remote management is possible. It does not prove that remote management occurred.

### PowerShell Is Not Automatically Suspicious

PowerShell is a legitimate administrative tool. Investigation should focus on execution context, command line, parent process, account, source, destination, and surrounding activity.

### Authentication Requires Correlation

A successful logon event can provide useful remote-access context, but it should be correlated with network and process telemetry before attributing activity to PowerShell Remoting.

### SIEM Events Require Context

The Wazuh registry integrity event observed during this investigation was not evidence of WinRM activity.

### Missing Telemetry Is a Limitation

When relevant events are unavailable, the correct response is to document the limitation rather than reconstruct an unsupported attack chain.

---

## Conclusion

This investigation validated the Windows endpoint's WinRM and PowerShell telemetry and identified an enabled WinRM HTTP listener on port `5985`, WSMan Operational activity, and repeated PowerShell process creation. However, the available evidence did not establish a remote source, correlated authentication, a WinRM network connection, or confirmed remote PowerShell command execution. The appropriate evidence-based assessment is therefore limited to **WinRM configuration and local WSMan activity**, with remote PowerShell execution remaining unconfirmed.

---

## Investigation Principle

> **Follow the evidence, not the assumption.**
