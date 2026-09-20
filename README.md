# Elastic Security Lab 01 — Suspicious PowerShell Execution

This lab investigates PowerShell process activity using **Elastic Security, Elastic Defend, Elastic Agent, Discover, and ES|QL**.

The investigation focuses on identifying PowerShell execution, detecting the use of `-EncodedCommand`, examining process and parent-process telemetry, and validating what can actually be concluded from the available endpoint evidence.

The activity was performed in a controlled Windows environment using benign PowerShell commands. No malicious payload, persistence mechanism, credential theft, or command-and-control activity was intentionally executed.

## Lab Environment

- Windows 10 Pro 22H2
- Elastic Security Serverless
- Elastic Defend
- Elastic Agent `9.5.4+build202609161310`
- Fleet policy: `Windows-SOC-Lab`
- Discover
- ES|QL
- PowerShell `7.6.6`

## Lab Objectives

- Validate Elastic Defend endpoint telemetry.
- Confirm PowerShell process events are being collected.
- Establish a baseline for normal PowerShell activity.
- Generate controlled encoded PowerShell activity.
- Detect PowerShell executions containing `-EncodedCommand`.
- Examine process IDs and parent-process information.
- Investigate available command-line telemetry.
- Use Discover and ES|QL for endpoint hunting.
- Examine surrounding endpoint activity.
- Identify telemetry limitations and inconsistent field availability.
- Map the observed behavior to MITRE ATT&CK.
- Produce an evidence-based assessment without treating an indicator as proof of malicious activity.

## Investigation Scenario

PowerShell is a legitimate Windows administration and automation tool, so the presence of `powershell.exe` alone is not sufficient to classify activity as suspicious.

The investigation uses encoded PowerShell execution as the primary hunting signal. The purpose is to determine what Elastic records about the process, command line, parent process, and surrounding activity.

A benign PowerShell command was encoded and executed with the `-EncodedCommand` parameter. Elastic Defend subsequently recorded the PowerShell process activity, allowing the behavior to be investigated through Discover.

The investigation therefore focuses on the evidence available in endpoint telemetry rather than assuming that encoded PowerShell represents malware.

## Telemetry Validation

Initial endpoint telemetry was validated in Discover using:

```text
FROM logs-*
```

The `logs-*` data view contained endpoint events, with approximately 1,000 documents processed during several searches.

PowerShell telemetry was then searched using:

```text
FROM logs-*
| WHERE process.name == "powershell.exe"
```

The results demonstrated that Elastic was receiving PowerShell process telemetry from the Windows endpoint.

## Normal PowerShell Baseline

Basic PowerShell activity was generated using commands such as:

```powershell
whoami
hostname
Get-Service
```

The commands were used only to establish normal endpoint activity and confirm that PowerShell execution was visible in Elastic.

The observed host information included:

```text
User: desktop-9mmm37v\dell
Hostname: DESKTOP-9MMM37V
PowerShell: 7.6.6
```

## Encoded PowerShell Detection

The investigation searched for PowerShell commands containing `EncodedCommand` using:

```text
FROM logs-*
| WHERE process.name == "powershell.exe"
| AND process.command_line LIKE "*EncodedCommand*"
```

The query returned one matching document.

The observed event included:

```text
Timestamp: Sep 20, 2026 @ 06:51:50.905
Process PID: 9264
Parent process name: pwsh.exe
```

The parent process command line referenced the installed PowerShell 7.6.6 executable under the WindowsApps directory.

## Process Investigation

The investigation examined:

- `process.pid`
- `process.parent.pid`
- `process.parent.name`
- `process.parent.command_line`
- `process.command_line`
- `process.executable`
- `host.name`
- `user.name`

The encoded PowerShell event showed a parent process of:

```text
pwsh.exe
```

This is important because the observed evidence does not demonstrate a `WINWORD.EXE -> powershell.exe` relationship.

Other PowerShell events showed null parent-process fields. This demonstrated that parent-process information was not consistently populated across every observed event.

## ES|QL Hunting

The primary PowerShell hunting query was:

```text
FROM logs-*
| WHERE process.name == "powershell.exe"
```

The encoded-command hunting query was:

```text
FROM logs-*
| WHERE process.name == "powershell.exe"
| AND process.command_line LIKE "*EncodedCommand*"
```

These queries provided a simple starting point for endpoint investigation and detection development.

## MITRE ATT&CK

### T1059.001 — PowerShell

The observed activity involved execution of PowerShell and is therefore relevant to:

- **T1059.001 — PowerShell**

The use of `-EncodedCommand` can also be discussed in the context of:

- **T1027 — Obfuscated/Compressed Files and Information**

However, the lab did not demonstrate malicious obfuscation. The encoded command was intentionally generated for a controlled test.

## Findings

### Confirmed

- Elastic Agent was successfully enrolled and collecting endpoint telemetry.
- Elastic Defend telemetry was available through `logs-*`.
- PowerShell process events were observed.
- An event containing `-EncodedCommand` was successfully detected.
- The encoded PowerShell event had process PID `9264`.
- The parent process recorded for that event was `pwsh.exe`.
- Parent-process information was not consistently available for every PowerShell event.

### Not Demonstrated

- Malicious payload execution.
- Credential theft.
- Persistence.
- Privilege escalation.
- Command-and-control communication.
- Malicious Word document execution.
- A confirmed `WINWORD.EXE -> powershell.exe` process chain.

## Investigation Conclusion

The lab successfully demonstrated endpoint telemetry collection and investigation of PowerShell activity using Elastic Security.

An encoded PowerShell execution was identified through ES|QL using the `-EncodedCommand` parameter. Process and parent-process fields were then examined to provide additional context.

The observed encoded command was part of a controlled and benign simulation. Therefore, the event should be treated as an investigation signal rather than confirmed malicious activity.

The lab also demonstrated that endpoint telemetry is not always uniform. Some PowerShell events contained parent-process information while others had null parent fields. This reinforces the need to validate the available telemetry before drawing conclusions.

## Key Takeaways

- PowerShell activity must be investigated in context.
- `powershell.exe` alone is not evidence of malicious activity.
- `-EncodedCommand` is a useful hunting indicator but is not proof of compromise.
- Parent-process information can provide valuable execution context.
- Telemetry fields may not be populated consistently across all events.
- ES|QL provides a practical way to search endpoint process telemetry in Elastic Discover.
- Investigation conclusions should be based on observed evidence and documented limitations.
