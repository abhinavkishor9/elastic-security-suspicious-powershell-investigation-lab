# Investigation Notes 

## Initial Telemetry Validation

The investigation started with:

```text
FROM logs-*
```

The selected `logs-*` data contained endpoint telemetry and returned approximately 1,000 processed documents during the investigation.

The endpoint agent information observed in the telemetry included:

```text
Agent type: endpoint
Agent version: 9.5.4+build202609161310
Data stream dataset: endpoint.events.library
Data stream namespace: default
```

This confirmed that endpoint events were reaching Elastic.

## Host Baseline

Normal PowerShell activity was generated from the Windows endpoint.

Commands included:

```powershell
whoami
hostname
Get-Service
```

The observed identity and hostname were:

```text
User: desktop-9mmm37v\dell
Hostname: DESKTOP-9MMM37V
```

The installed PowerShell version used during the activity was:

```text
PowerShell 7.6.6
```

These commands were used to establish baseline PowerShell activity before investigating the encoded command.

## PowerShell Hunting

The initial ES|QL query was:

```text
FROM logs-*
| WHERE process.name == "powershell.exe"
```

The query returned PowerShell process events.

The available endpoint fields included process and agent-related telemetry such as:

```text
process.pid
process.parent.pid
process.parent.name
process.parent.command_line
process.parent.executable
process.command_line
process.executable
agent.id
agent.type
agent.version
data_stream.dataset
```

## Encoded PowerShell Hunt

The investigation then searched specifically for encoded PowerShell execution:

```text
FROM logs-*
| WHERE process.name == "powershell.exe"
| AND process.command_line LIKE "*EncodedCommand*"
```

The query returned one matching document.

Observed event:

```text
Timestamp: Sep 20, 2026 @ 06:51:50.905
Process PID: 9264
Parent process: pwsh.exe
```

The parent command line referenced the PowerShell 7.6.6 executable installed under:

```text
C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\
```

## Parent Process Analysis

The parent-process information was reviewed to determine what launched the PowerShell process.

For the encoded PowerShell event, the observed parent process was:

```text
pwsh.exe
```

The evidence therefore supports:

```text
pwsh.exe
    |
    +-- powershell.exe
```

The investigation did not establish:

```text
WINWORD.EXE
    |
    +-- powershell.exe
```

Therefore, a Word-to-PowerShell relationship is not claimed as a finding.

This distinction is important because the investigation is based on actual endpoint telemetry rather than the intended scenario alone.

## Field Availability

Some PowerShell events contained parent-process information while other results showed null values for fields such as:

```text
process.parent.pid
process.parent.name
process.parent.command_line
```

This demonstrated that parent-process telemetry was not consistently available across every event.

The absence of a parent-process value was therefore treated as a telemetry limitation rather than evidence that the process had no parent.

## Encoded Command Analysis

The presence of:

```text
-EncodedCommand
```

was used as the primary hunting indicator.

Encoded PowerShell commands can make the underlying command less immediately readable in process telemetry.

However, the presence of `-EncodedCommand` alone does not prove malicious behavior.

In this lab, the encoded command was generated intentionally for a benign simulation.

The controlled command was:

```powershell
Write-Output "Elastic SOC Lab 01"
```

No malicious payload was used.

## Process Investigation

The following process fields were considered during the investigation:

```text
process.name
process.pid
process.parent.name
process.parent.pid
process.parent.command_line
process.parent.executable
process.command_line
process.executable
```

The purpose was to establish:

1. Which process executed.
2. Which process launched it.
3. Which command line was used.
4. Whether additional process context was available.
5. Whether the observed activity differed from the normal PowerShell baseline.

## Related Activity

Additional PowerShell events were reviewed using:

```text
FROM logs-*
| WHERE process.name == "powershell.exe"
```

The results showed multiple PowerShell-related events during the investigation period.

Some events contained parent-process information while others contained null parent fields.

This prevented a single uniform process tree from being established across all PowerShell events.

## Evidence Assessment

### Observed

- PowerShell process activity.
- Encoded PowerShell activity.
- `-EncodedCommand` in the command line.
- Process PID `9264` for the encoded event.
- Parent process `pwsh.exe`.
- PowerShell 7.6.6 installation path in the parent command line.
- Endpoint telemetry from Elastic Defend.

### Confirmed

The encoded PowerShell activity was generated as part of a controlled lab exercise.

### Not Confirmed

The following were not demonstrated:

- Malware execution.
- Credential access.
- Persistence.
- Privilege escalation.
- Command-and-control.
- Malicious Office execution.
- `WINWORD.EXE` as the parent of the observed encoded PowerShell process.

## MITRE ATT&CK Mapping

### T1059.001 — PowerShell

The primary technique is PowerShell because the investigated process executed PowerShell commands.

### T1027 — Obfuscated/Compressed Files and Information

The use of an encoded command can be investigated in the context of obfuscation.

For this lab, however, the encoding was intentionally generated and did not contain a malicious payload.

