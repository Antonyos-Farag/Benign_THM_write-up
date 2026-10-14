# Screenshots

This folder is where screenshots for the write-up live.

The write-up in [`../README.md`](../README.md) is written so it stands on its
own **without** images — every step is described as a Splunk query plus the
expected result — so it works in plain text, in a terminal, and on GitHub's
rendered view.

If you fork this repo and want to add your own evidence, capture:

| Filename suggestion | What to capture |
| --- | --- |
| `01-event-count.png` | Splunk event count for `index=win_eventlogs` with the March 2022 date range (`13959` events) |
| `02-imposter-user.png` | `\| stats count BY UserName` output showing `Amel1a` next to `Amelia` |
| `03-schtasks-hr.png` | The `schtasks.exe` event from `Chris.fort` with the `\Temp\update.exe` command line |
| `04-certutil-event.png` | The `certutil.exe -urlcache` event from `haroon`, with timestamp `2022-03-04` |
| `05-flag-source.png` | The staging page holding the `THM{...}` flag |

Guidelines that keep a portfolio write-up professional:

* **Redact** any personal or employer-specific data before publishing.
* **Crop** to the fields that matter (`_time`, `UserName`, `HostName`,
  `ProcessName`, `CommandLine`) rather than dumping a whole screen.
* Keep the original Splunk styling — authenticity is a feature in a write-up.
* Stay within TryHackMe's rules: no copying room content wholesale, no giant
  screenshots of the question text.

> Avoid committing hundreds of megabytes of screenshots. Compress to PNG/JPEG,
> keep individual files well under ~500 KB, and prefer a handful of high-signal
> images over dozens of low-signal ones.
