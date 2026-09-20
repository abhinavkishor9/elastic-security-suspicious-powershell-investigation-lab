# Investigation Timeline 

## 06:18–06:33 — Initial Endpoint Telemetry

Elastic Discover displayed endpoint telemetry across the selected `logs-*` data.

The time range covered approximately:

```text
Sep 20, 2026 @ 06:18:29.127
-
Sep 20, 2026 @ 06:33:29.127
```

The telemetry included endpoint agent information such as:

```text
agent.type: endpoint
agent.version: 9.5.4+build202609161310
data_stream.dataset: endpoint.events.library
data_stream.namespace: default
```

This established that Elastic was receiving endpoint telemetry from the Windows system.

## 06:19–06:33 — Baseline Telemetry Review

Discover was reviewed to understand the available fields and event volume.

The available field count changed as different event sets were examined, with endpoint-related fields including:

```text
@timestamp
agent.id
agent.type
agent.version
data_stream.dataset
data_stream.namespace
data_stream.type
process.*
```

The activity provided the initial telemetry baseline for the investigation.

## 06:40 — PowerShell Hunting

An ES|QL query was executed to search for PowerShell processes:

```text
FROM logs-*
| WHERE process.name == "powershell.exe"
```

The query returned PowerShell process telemetry.

The endpoint agent version visible in the results was:

```text
9.5.4+build202609161310
```

## 06:45:58 — PowerShell Process Observation

A PowerShell-related process event was observed with:

```text
Process PID: 26904
```

The event was reviewed as part of the PowerShell process investigation.

No malicious conclusion was drawn from the PID alone.

## 06:51:50 — Encoded PowerShell Event

The encoded PowerShell hunting query was executed:

```text
FROM logs-*
| WHERE process.name == "powershell.exe"
| AND process.command_line LIKE "*EncodedCommand*"
```

The query returned:

```text
1 document
```

Observed event:

```text
Timestamp: Sep 20, 2026 @ 06:51:50.905
Process PID: 9264
```

This was the primary event investigated in the lab.

## 06:51:50 — Parent Process Investigation

The matching PowerShell event contained parent-process information.

Observed parent:

```text
pwsh.exe
```

The parent command line referenced the PowerShell 7.6.6 installation under:

```text
C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\
```

The available evidence therefore supported a PowerShell parent relationship involving `pwsh.exe`.

A `WINWORD.EXE -> powershell.exe` relationship was not established.

## 06:51:50 — Encoded Command Investigation

The command line was investigated for:

```text
-EncodedCommand
```

The encoded PowerShell activity was part of the controlled lab simulation.

The encoded command represented a benign PowerShell command:

```powershell
Write-Output "Elastic SOC Lab 01"
```

No malicious payload was used.

## 06:51–06:57 — Related PowerShell Review

Additional PowerShell activity was searched using:

```text
FROM logs-*
| WHERE process.name == "powershell.exe"
```

The results demonstrated that multiple PowerShell-related events existed within the investigation period.

Some events contained parent-process information while other events showed null parent-process fields.

This established a telemetry limitation that was documented rather than interpreted as evidence of a missing or abnormal parent process.

## 06:57:19 — Additional PowerShell Events

Additional PowerShell events were observed around:

```text
Sep 20, 2026 @ 06:57:19.866
Sep 20, 2026 @ 06:57:19.870
Sep 20, 2026 @ 06:57:19.885
```

The observed process PID was:

```text
10092
```

The available parent-process fields for these events were null.

These events were retained as part of the telemetry investigation but were not linked to the encoded PowerShell event without supporting evidence.

