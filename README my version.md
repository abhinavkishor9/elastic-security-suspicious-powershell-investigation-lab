# elastic-security-suspicious-powershell-investigation-lab
PowerShell is a legitimate Windows administration and automation tool, but attackers frequently abuse it to execute commands, download payloads, perform reconnaissance, modify the system, or establish persistence.

For a SOC analyst, the important question is not simply "Was PowerShell executed?"

PowerShell execution by itself is common and usually benign.

The investigation becomes more meaningful when we examine the context surrounding the process.

For example:

Normal:

explorer.exe
    └── powershell.exe

This could simply represent a user opening PowerShell.

A more suspicious chain might look like:

WINWORD.EXE
    └── powershell.exe
          └── encoded command

Here, the analyst has additional context:

Which process launched PowerShell?
Which user executed it?
What command line was used?
Was the command encoded?
When did execution occur?
What happened immediately before and after it?
Did PowerShell create another process?
Did it make network connections?
Is the activity consistent with the user's expected behavior?

The goal of this lab is therefore to practice process-based investigation, rather than treating a single PowerShell event as proof of compromise.

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

# Lab Objectives

- Validate endpoint telemetry collection through Elastic Defend.
- Confirm that PowerShell process activity is visible in Elastic Discover.
- Establish a baseline for normal PowerShell execution.
- Generate controlled encoded PowerShell activity using a benign command.
- Detect PowerShell executions containing `-EncodedCommand`.
- Examine process IDs and available parent-process information.
- Investigate PowerShell command-line telemetry using ES|QL.
- Review related PowerShell activity within the available time range.
- Identify limitations in parent-process and endpoint telemetry fields.
- Practice evidence-based investigation without treating a suspicious indicator as proof of malicious activity.
- Map the observed PowerShell behavior to relevant MITRE ATT&CK techniques.
- Document confirmed observations, non-observations, and telemetry limitations.
  
## Investigation Scenario

A Windows endpoint is monitored using Elastic Defend, and the SOC analyst is tasked with investigating PowerShell activity in Elastic Security.

The investigation involves:

- Reviewing available PowerShell endpoint telemetry.
- Establishing normal PowerShell activity before hunting.
- Searching for `-EncodedCommand` execution using ES|QL.
- Examining process, command-line, PID, and parent-process details.
- Checking whether the available telemetry supports the observed process relationship.

A controlled and benign encoded PowerShell command is used for the investigation. The analyst focuses on validating what Elastic recorded and documenting any telemetry gaps rather than treating the activity as confirmed malicious behavior.## Telemetry Validation

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

