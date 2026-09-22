# Troubleshooting Notes — PowerShell Remoting Investigation

## Purpose

This document records the technical issues encountered while validating WinRM, PowerShell Remoting, Windows Event Logs, Sysmon, and Wazuh telemetry.

Troubleshooting actions are kept separate from historical endpoint evidence so that analyst-generated activity is not incorrectly attributed to an attacker.

---

## 1. WinRM Configuration Query Error

### Command

```powershell
winrm get winrm/config
```

### Initial Error

The command initially returned:

```text
WSManFault

Message = The client cannot connect to the destination specified in the request.

Error number:
-2144108526
0x80338012
```

The message recommended checking the WinRM service and referenced:

```text
winrm quickconfig
```

---

## 2. WinRM Service State

The service was checked with:

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

The WinRM service was stopped at the time of the check.

This provides a plausible explanation for the initial WS-Man connection error.

---

## 3. Preserve the Original State

Because this is an investigation lab, the original service state should be captured before changing the system.

The following command was used:

```powershell
Get-Service WinRM |
Select-Object Name, Status, StartType |
Out-File "$EvidencePath\03-winrm-service.txt"
```

This preserves the initial observation.

---

## 4. Avoid Unnecessary Configuration Changes

The error message suggested:

```powershell
winrm quickconfig
```

However, this should not automatically be executed during a forensic investigation.

`winrm quickconfig` can modify the system's WinRM configuration.

Because the purpose of this lab is evidence validation, configuration changes should not be made solely to produce a successful command response.

The existing state was therefore documented first.

---

## 5. WinRM Configuration Became Available

The WinRM configuration was subsequently available and returned values including:

```text
URLPrefix = wsman
HTTP = 5985
HTTPS = 5986
AllowUnencrypted = false
```

This allowed the investigation to continue with configuration and telemetry validation.

---

## 6. Checking the WinRM Listener

The listener was checked using:

```powershell
Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate
```

The listener showed:

```text
Address: *
Transport: HTTP
Port: 5985
Enabled: true
URLPrefix: wsman
```

A second command was also used:

```powershell
winrm enumerate winrm/config/listener
```

### Interpretation

The endpoint had an enabled WinRM HTTP listener.

This establishes configuration and listening capability, not historical client activity.

---

## 7. Checking Listening Ports

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

This is runtime state rather than evidence of a historical remote connection.

---

## 8. PowerShell Operational Log

The PowerShell logs were enumerated with:

```powershell
Get-WinEvent -ListLog *PowerShell* |
Select-Object LogName, IsEnabled, RecordCount
```

The Operational log was enabled and contained a large number of events.

Recent events included:

```text
Event ID 40961
PowerShell console is starting up
```

A remoting keyword search was then performed:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 500 |
Where-Object {
    $_.Message -match "PSSession|Enter-PSSession|Invoke-Command|WinRM|WSMan|Remote"
} |
Select-Object TimeCreated, Id, Message
```

No matching events were returned in the captured output.

---

## 9. WinRM Operational Log

The WinRM Operational channel was checked using:

```powershell
Get-WinEvent -ListLog *WinRM* |
Select-Object LogName, IsEnabled, RecordCount
```

The channel was enabled and contained:

```text
1672
```

events.

The captured events included:

```text
Event ID 145
WSMan operation Enumeration started

Event ID 132
WSMan operation Enumeration completed successfully

Event ID 254
Activity Transfer
```

### Interpretation

WSMan activity was present.

However, the events did not establish an external remote source or a confirmed remote PowerShell session.

---

## 10. Security Event Searches

The investigation searched for Event ID `4624`:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id = 4624
} -MaxEvents 100 |
Select-Object TimeCreated, Id, Message
```

No matching events were returned.

Event ID `4672` was also searched:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id = 4672
} -MaxEvents 100 |
Select-Object TimeCreated, Id, Message
```

No matching events were returned.

### Interpretation

The captured searches did not provide authentication evidence that could be correlated with remote PowerShell activity.

This is a telemetry limitation and not proof that authentication never occurred.

---

## 11. Sysmon Process Creation

Sysmon Event ID `1` was searched for:

```text
powershell.exe
pwsh.exe
```

Multiple events were returned.

The observed timestamps ranged approximately from:

```text
07:27:26
to
07:29:54
```

The captured event content was abbreviated as:

```text
Process Create:...
```

### Limitation

The screenshots did not expose complete:

- Command line
- Parent process
- User
- Process ID
- Parent Process ID
- Hash

Therefore, the events establish PowerShell process creation but not remote PowerShell execution.

---

## 12. Sysmon Network Connection Search

Sysmon Event ID `3` was searched for:

```text
5985
5986
```

No matching output was captured.

### Interpretation

No Sysmon network connection evidence involving the standard WinRM ports was obtained.

This does not prove that no network connection occurred at any other time.

---

## 13. Wazuh Event Interpretation

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

The event was therefore excluded from the remoting evidence chain.

---

## 14. Investigation-Generated WSMan Activity

Some WSMan Operational events occurred around the same period as commands executed during the investigation.

For example:

```powershell
winrm get winrm/config
```

and:

```powershell
Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate
```

can themselves generate WSMan telemetry.

Therefore, events such as:

```text
WSMan operation Enumeration started
WSMan operation Enumeration completed successfully
Activity Transfer
```

must be correlated with the analyst's activity before being treated as independent historical evidence.

---

## 15. No Fabricated Remote Session

No second Windows endpoint was used to generate a controlled remote PowerShell session.

The investigation therefore does not claim:

```text
Remote PowerShell session established
```

without supporting telemetry.

This preserves the evidence-driven nature of the lab.

---

## 16. Troubleshooting Outcome

The initial WinRM error was investigated by checking the service state and validating the WinRM configuration.

The endpoint was shown to have:

```text
WinRM configuration
+
Enabled HTTP listener
+
TCP 5985 listening
+
WSMan Operational telemetry
```

However, the available evidence did not establish:

```text
Remote source
+
Authentication
+
WinRM network connection
+
Remote PowerShell session
+
Remote command execution
```

The troubleshooting therefore resolved the configuration and telemetry investigation path without converting configuration artifacts into unsupported claims of remote execution.

---

## Key Troubleshooting Principle

> **Fix the technical issue without changing the evidence into something it does not prove.**
