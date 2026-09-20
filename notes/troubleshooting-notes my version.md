# Troubleshooting Notes 

## 1. Discover Interface Was Different From the Expected KQL Interface

### Issue

The initial investigation instructions assumed that Discover would provide a traditional KQL search bar.

The actual Elastic interface displayed an ES|QL editor with:

```text
FROM logs-*
```

### Resolution

The investigation was adapted to use ES|QL directly.

Example:

```text
FROM logs-*
| WHERE process.name == "powershell.exe"
```

This became the primary method for searching endpoint process telemetry.

### Lesson

Elastic Discover can present different query interfaces depending on the current configuration and workflow.

Before entering a query, identify whether the interface is using KQL or ES|QL.

---

## 2. "Search Field Names" Was Initially Confused With the Query Editor

### Issue

The Discover page displayed:

```text
Search field names
```

This was initially mistaken for the location where the investigation query should be entered.

### Resolution

The actual query was entered in the ES|QL editor at the top of Discover.

The field search box was used only for locating available fields.

### Lesson

`Search field names` is for discovering fields such as:

```text
process.name
process.pid
process.parent.name
```

It is not the main telemetry query input.

---

## 3. Confirming the Correct Data Source

### Issue

Before investigating PowerShell, it was necessary to determine whether the selected data source contained endpoint telemetry.

### Resolution

The following query was used:

```text
FROM logs-*
```

The query processed approximately 1,000 documents and exposed endpoint-related fields.

Observed fields included:

```text
agent.id
agent.type
agent.version
data_stream.dataset
data_stream.namespace
data_stream.type
```

The data stream information showed endpoint telemetry, including:

```text
data_stream.dataset: endpoint.events.library
```

### Lesson

Validate the data source before assuming that a detection query is failing.

A zero-result detection query can be caused by incorrect data selection, missing fields, an incorrect time range, or genuinely absent activity.

---

## 4. PowerShell Telemetry Validation

### Issue

The investigation required confirmation that PowerShell process activity was actually being collected.

### Resolution

The following ES|QL query was used:

```text
FROM logs-*
| WHERE process.name == "powershell.exe"
```

PowerShell events were returned.

### Lesson

Always validate telemetry before building a detection around it.

The detection should be based on fields that are actually populated in the environment.

---

## 5. Encoded PowerShell Detection

### Query

The following query was used:

```text
FROM logs-*
| WHERE process.name == "powershell.exe"
| AND process.command_line LIKE "*EncodedCommand*"
```

### Result

The query returned:

```text
1 document
```

The matching event had:

```text
Timestamp: Sep 20, 2026 @ 06:51:50.905
Process PID: 9264
```

### Lesson

The query successfully demonstrated that command-line content can be used as a hunting condition in Elastic.

---

## 6. Parent-Process Information Was Not Consistent

### Observation

The encoded PowerShell event contained parent-process information.

The observed parent was:

```text
pwsh.exe
```

The parent command line referenced the PowerShell 7.6.6 executable.

However, other PowerShell events showed null values for fields such as:

```text
process.parent.pid
process.parent.name
process.parent.command_line
```

### Resolution

The investigation treated the missing fields as a telemetry limitation.

It did not assume that a null parent field meant the process had no parent.

### Lesson

Do not infer execution relationships from missing telemetry.

Only document relationships that are actually supported by the event data.

---

## 7. Avoiding an Unsupported WINWORD.EXE Finding

### Issue

The original investigation concept considered a:

```text
WINWORD.EXE -> powershell.exe
```

process chain.

### Observation

The collected telemetry did not establish this relationship.

The identified encoded PowerShell event instead showed:

```text
pwsh.exe -> powershell.exe
```

### Resolution

The final investigation documentation does not claim a Word-to-PowerShell relationship.

### Lesson

A planned scenario and an observed event are not the same thing.

The portfolio should document what the telemetry actually demonstrated.

---

## 8. Interpreting -EncodedCommand

### Observation

The query:

```text
FROM logs-*
| WHERE process.name == "powershell.exe"
| AND process.command_line LIKE "*EncodedCommand*"
```

successfully identified an encoded PowerShell event.

### Important Limitation

The use of `-EncodedCommand` does not automatically mean the process is malicious.

Encoded PowerShell can be used by legitimate administrative scripts and automation.

### Lab Context

The encoded command in this exercise was intentionally generated and contained a benign command.

### Lesson

The correct investigation approach is:

```text
Indicator
    ↓
Investigate context
    ↓
Validate command
    ↓
Review parent process
    ↓
Review related activity
    ↓
Assess evidence
```

rather than:

```text
EncodedCommand
    ↓
Malware
```

---

## 9. Time Range Considerations

The investigation used:

```text
Last 15 minutes
```

This was useful for quickly locating newly generated lab activity.

The observed telemetry covered several timestamps during the session, including events around:

```text
06:18–06:33
06:40
06:45
06:51
06:57
```

### Lesson

A short time range is useful during active testing, but it should be expanded when investigating historical activity.

If an expected event is missing, verify the time range before changing the query.

---

