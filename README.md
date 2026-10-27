## Welcome to Mac Monitor
![Feature overview](./Resources/v1.9.0/overview-graphic-v1.9.png)

Mac Monitor is an **advanced, stand-alone system monitoring tool tailor-made for macOS security research, malware triage, and system troubleshooting**. Leveraging Apple's Endpoint Security (ES) and System Extension APIs, it collects and enriches system events, displaying them graphically, with an expansive feature set designed to surface only the events that are relevant to you. The telemetry collected includes process, interprocess, memory, XPC, file events, and more in addition to rich metadata, allowing users to contextualize events and tell a story with ease. With an intuitive interface and a rich set of analysis features, Mac Monitor was designed for a wide range of skill levels and backgrounds to detect macOS threats that would otherwise go unnoticed. 

### OBTS v8.0 Presentation
**Introducing the Next Generation of Mac Monitor**:
* [📊 Slides](https://swiftlydetecting-conferences.s3.us-west-2.amazonaws.com/public/2025/OBTSv8/Introducing+the+Next+Generation+of+Mac+Monitor.pdf)
* [📺 YouTube](https://www.youtube.com/watch?v=h_i_H6RzzHA)


## Requirements
- Processor: We recommend an `Apple Silicon` machine, but `Intel` works too!
  - (`3.0.0+`) Every binary is `x86_64`, `arm64` and `arm64e`.
- System memory: `4GB+` is recommended
- macOS version: `13.1+` (Ventura)


## How can I install this thing?

**☕️ (Recommended) Homebrew**
* `brew install --cask mac-monitor`

**📦 Installer package**
* Go to the releases section and download the latest installer: https://github.com/Brandon7CC/mac-monitor/releases

**Install**
* Open the app: `Mac Monitor.app`
* You'll be prompted to "Open System Settings" to "Allow" the System Extension.
* Next, System Settings will automatically open to `Full Disk Access`. Flip the switch for the `Mac Monitor Security Extension`. Full Disk Access is a [*requirement* of Endpoint Security](https://developer.apple.com/documentation/endpointsecurity/3259700-es_new_client#:~:text=The%20user%20does%20this%20in%20the%20Security%20and%20Privacy%20pane%20of%20System%20Preferences%2C%20by%20adding%20the%20app%20to%20Full%20Disk%20Access.).
* 🏎️ Click the "Start" button in the app and you'll be prompted to reopen the app. Done!

**Updates**
* (`3.0.0+`) Settings ▸ General ▸ **Check Now** looks for a new release, and **Release Notes…** shows what changed in yours.

![Install process](./Resources/v1.9.0/Install+Graphic.png)

### Install footprint
- App: `/Applications/Mac Monitor.app` (`com.swiftlydetecting.agent`).
- Security Extension: `/Library/SystemExtensions/../com.swiftlydetecting.agent.securityextension.systemextension`.
- (`3.0.0+`) Command line tool: `Mac Monitor.app/Contents/MacOS/macmonitor` (`com.swiftlydetecting.agent.cli`), linked to `/usr/local/bin/macmonitor` only if you install it from Settings.
- (`3.0.0+`) Saved mute set: `/Library/Application Support/com.swiftlydetecting.agent.securityextension/mutes.json`, readable only by `root`.


## Uninstall
* **From the Finder** delete the app and authenticate to remove the System Extension. You can't do this from the Dock. It's that easy!
* You can also *just* remove the Security Extension from the app's menu bar or its settings.
* (`1.0.3+`) Or run `../Contents/SharedSupport/uninstall.sh`. (`3.0.0+`) It also deletes the saved mute set and the `/usr/local/bin/macmonitor` link.


## Path mutes
(`3.0.0+`) Mac Monitor keeps one **saved mute set**. The Security Extension applies it to every Endpoint Security client it creates, keeps it across restarts, and shares it with `sudo macmonitor`. A change applies right away, even to a running trace.

- **Settings ▸ Path Muting** shows the set. Right-click an event, or use **Add a path mute** (the + button), to add to it.
- **Import Mutes…** reads a mute file or a 2.1 export, then replaces the set or adds to it. Mutes that only name `AUTH` events are left out, since Mac Monitor subscribes to `NOTIFY` events.
- **Export Saved Mute Set…** writes the set as a mute file. **Export Apple Mute Set…** writes Endpoint Security's own defaults.
- **Reset to Default…** restores Mac Monitor's set. Its `~/Library/Caches/` and `~/Library/Biome/streams/` mutes use the home folder of whoever is logged in at the console.
- **Only an administrator can change it.** Everyone else sees it read-only.

Coming from 2.1? Its mutes only lived in memory. Use Export ▸ Current mute set… in 2.1 before updating, then import the file.

Every change is logged with who made it:

```
log show --predicate 'subsystem == "com.swiftlydetecting.agent.securityextension" && category == "SavedMuteSet"' --info
```

A mute file is JSON:

```json
{
  "mutes" : [
    { "events" : [], "path" : "/usr/libexec/logd", "type" : "ES_MUTE_PATH_TYPE_LITERAL" },
    { "events" : [ "ES_EVENT_TYPE_NOTIFY_MMAP" ], "path" : "/Library/Caches/", "type" : "ES_MUTE_PATH_TYPE_TARGET_PREFIX" }
  ],
  "version" : 1
}
```

- `PREFIX` and `LITERAL` match the process's executable. `TARGET_PREFIX` and `TARGET_LITERAL` match the event's target.
- An empty `events` mutes every event.
- Endpoint Security matches resolved paths: use `/private/tmp/…`, not `/tmp/…`.


## Command line
(`3.0.0+`) `macmonitor` streams events from Mac Monitor's Security Extension to a terminal or a pipe, and checks traces against the [telemetry schema](#telemetry-schema). It's inside the app. Settings ▸ Command Line ▸ Install… links it to `/usr/local/bin/macmonitor`.

```
sudo macmonitor stream                     # Mac Monitor's default events
sudo macmonitor stream exec fork exit      # only these events
sudo macmonitor stream all | jq -c .       # every event, as JSONL
sudo macmonitor stream exec --for 30s      # 30 seconds of execs
sudo macmonitor stream open --count 100    # the next 100 opens
sudo macmonitor stream exec --process curl --grep '(?i)token'

# an osascript script asking for a password, as macOS stealers do
sudo macmonitor stream exec --target '/osascript$' \
    --predicate 'event.exec.script_content CONTAINS[c] "display dialog" AND event.exec.script_content CONTAINS[c] "password"'

sudo macmonitor mute list                  # the saved mute set
macmonitor validate trace.jsonl            # check an export against the schema
macmonitor completion zsh                  # shell completion (or bash)
```

- **Output**: text on a terminal, JSONL when piped. The JSONL is the same as Export telemetry, an eslogger superset.
- **Root**: `stream` and `mute` need `sudo`. Each stream has its own Endpoint Security clients, so it never changes what Mac Monitor records. Up to 3 run at once.
- **Filters**: `--pid`, `--process`, `--signing-id`, `--target` and `--grep` take a regular expression. `--predicate` takes an NSPredicate on the record. For an exec, `--target` is the program it runs.
- **Stopping**: Ctrl-C, `--for` or `--count`. Every event captured before the stop is written. Lost events are reported on standard error.
- **Installing**: `sudo` runs the tool as root, so Settings only links a copy owned by `root`, as the installer package installs it. Without the link, run it by its full path.
- `macmonitor help <command>` covers every option and exit status.


## What are some standout features?
- **High fidelity ES events modeled and enriched** with some events containing further enrichment. For example, a process being File Quarantine-aware, a file being quarantined, code signing certificates, etc.
- **Dynamic runtime ES event subscriptions**. You have the ability to on-the-fly modify your event subscriptions, enabling you to cut down on noise while you're working through traces.
- **Path muting at the API level**. Apple's Endpoint Security team has put a lot of work recently into enabling advanced path muting / inversion capabilities. Here, we cover the majority of the API features: `es_mute_path` and `es_mute_path_events` along with the types of `ES_MUTE_PATH_TYPE_PREFIX`, `ES_MUTE_PATH_TYPE_LITERAL`, `ES_MUTE_PATH_TYPE_TARGET_PREFIX`, and `ES_MUTE_PATH_TYPE_TARGET_LITERAL`. Right now we do not support inversion. **I'd love it if the ES team added inversion on a per-event basis instead of per-client**.
![Path muting and event subscriptions](./Resources/v1.9.0/muting-and-subscriptions-v1.9.png)

- **Detailed event facts**. **Right click on any event** in a table row to access event metadata, filtering, muting, and unsubscribe options. Core to the user experience is the ability to drill down into any given event or set of events. To enable this functionality we’ve developed “Event facts” windows which contain metadata / additional enrichment about any given event. Each event has a curated set metadata that is displayed. For example, process execution events will generally contain code signing information, environment variables, correlated events, etc. Below you see examples of file creation and BTM launch item added event facts.
![Event facts overview](./Resources/v1.9.0/event-metadata-overview-v1.9.png)

- **Event correlation** is an *exceptionally* important component in any analyst's tool belt. The ability to see which events are "related" to one-another enables you to manipulate the telemetry in a way that makes sense (other than simply dumping to JSON or representing an individual event). We perform event correlation at the process level. This means that for any given event (which have an initiating and/or target process) we can deeply link events that any given process instigated. 
  - (`3.0.0+`) Event Facts' **Correlation** tab is a dashboard. A summary and a bar of the event kinds sit above cards for the findings worth a look. Below them are a search, a chip for each event type, and the events, with the selected one's details beside them.
- (`3.0.0+`) **Findings** point out events worth a look. Each is a predicate on an event's record, shown as a card in Event Facts. Settings ▸ Findings lists Mac Monitor's own. You can change them, turn them off, or add your own. Filters ▸ Findings shows only the events a finding matches.
- **Process grouping** is another helpful way to represent process telemetry around a given `ES_EVENT_TYPE_NOTIFY_EXEC` or `ES_EVENT_TYPE_NOTIFY_FORK` event. By grouping processes in this way you can easily identify the chain of activity.
- **Artifact filtering** enabled users to remove (but not destroy) events from view based on: event type, initiating process path, or target process path. This standout feature enables analysts to cut through the noise quickly while still retaining all data.
  - Lossy filtering (i.e. events that are dropped from the trace) is also available in the form of "dropping platform binaries", another useful technique to cut through the noise.
  - (`3.0.0+`) The Filters sheet can also show only the events whose record matches a predicate, as `macmonitor stream --predicate` does. Write it in the predicate editor (View ▸ Predicate Editor, ⌥⌘F).

![Artifact filtering overview](./Resources/v1.9.0/lossless-filtering-v1.9.png)

- **Telemetry export**. Right now we support pretty JSON and JSONL (one JSON object per-line) for the full or partial system trace (keyboard shortcuts too). You can access these options in the menu bar under "Export Telemetry". (`3.0.0+`) Every record follows the [telemetry schema](#telemetry-schema).
- (`3.0.0+`) **Open a trace**. File ▸ Open Trace… replaces the events on screen with a saved trace: a Mac Monitor export, or eslogger's JSON. Open Recent and dropping a file on a window work too.
- **Process subtree generation**. When viewing the event facts window for any given event we’ll attempt to generate a process lineage subtree in the left hand sidebar. This tree is intractable: click on any process and you’ll be taken to its event facts. **Similarly, you can right click on any process in the tree to pop out the facts for that event**.
- **Dynamic event distribution chart**. This is a fun one enabled by the SwiftUI team. The graph shows the distribution of events you're subscribed to, currently in-scope (i.e. not filtered), and have a count of more than nothing. This enables you to *very* quickly identify noisy events. The chart auto-shows/hides itself, but you can bring it back with the: "Mini-chart" button in the toolbar.

![Event distribution chart](./Resources/v1.9.0/DistributionChart-v1.9.png)


## Some other features
- Another very important feature of any dynamic analysis tool is to not let an event limiter or memory inefficient implementation get in the way of the user experience. To address this (the best we currently can) we’ve implemented an asynchronous parent / child-like **Core Data stack** which stores our events as “entities” in-memory. This enables us to store virtually unlimited events with Mac Monitor. Although, the time of insertions does become more taxing as the event limit gets very large.  
- Since Mac Monitor is based on a Security Extension which is always running in the background (like an EDR sensor) we baked in functionality such that it **does not process events when a system trace is not occurring**. This means that the Security Extension (`com.swiftlydetecting.agent.securityextension`) will not needlessly utilize resources / battery power when a trace is not occurring. 
- Distribution package: **The install process is often overlooked**. However, if users do not have a good understanding of what’s being installed or if it’s too complex to install the barrier to entry might be just high enough to dissuade people from using it. This is why we ship Mac Monitor as a notarized distribution package.


## Telemetry schema
(`3.0.0+`) Every record Mac Monitor exports, and `macmonitor` writes, follows a [JSON Schema](https://json-schema.org/draft/2020-12): eslogger's JSON plus Mac Monitor's enrichments, each key marked `x-mac-monitor-origin`. Each record carries its `telemetry_version`.

- **Where**: each release attaches it as [`Mac-Monitor.telemetry.schema.json`](https://github.com/Brandon7CC/mac-monitor/releases/latest/download/Mac-Monitor.telemetry.schema.json). The repository keeps it in [`Schema/`](./Schema).
- **Checking a trace**: Help ▸ Telemetry Schema… or `macmonitor validate <trace>`.
- **Versions**: MAJOR when a key is removed, renamed or retyped, MINOR when one is added, PATCH when only the text changes.

[`Schema/README.md`](./Schema/README.md) has more, including how to use it with other validators.
