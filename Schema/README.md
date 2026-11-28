# Mac Monitor telemetry schema

`mac-monitor-telemetry.schema.json` describes every record Mac Monitor writes: the JSONL and pretty exports, the
Event Facts JSON tab, and the `macmonitor` command line's output. We wrote it so a pipeline consuming Mac Monitor's
telemetry can check what it receives instead of trusting that the shape didn't move between releases.

Each GitHub release attaches it as `Mac-Monitor.telemetry.schema.json`, and the latest is at
`https://github.com/Brandon7CC/mac-monitor/releases/latest/download/Mac-Monitor.telemetry.schema.json`.

## eslogger's keys and Mac Monitor's

A record is eslogger's JSON for an ES message (`es_message_t`) plus Mac Monitor's enrichments. Every
eslogger key keeps eslogger's key path and value; Mac Monitor's keys sit beside them. The schema marks every property
with `x-mac-monitor-origin`:

- `eslogger`: eslogger writes the key, at the same path, with the same value.
- `mac-monitor`: one of Mac Monitor's enrichments, with a `description` saying what it holds and how it's derived.

The mark describes the key itself. Everything under a Mac Monitor key is Mac Monitor's, even where it reuses one of
eslogger's shapes: `launched_by_parent.audit_token` is written the way eslogger writes an audit token, but it's an
enrichment.

Two of eslogger's integers that Mac Monitor can't reproduce keep eslogger's keys: `seq_num` and `global_seq_num` count
the messages of the ES client that received them, so Mac Monitor's numbers never match eslogger's.

A close of an unmodified file is left out by default (Settings > Subscriptions, or `macmonitor stream --every close`,
brings it back). Its message still advances `seq_num` and `global_seq_num`, so gaps there are expected, not losses.

## Versions

Every record carries `telemetry_version`, the version of this schema it follows. eslogger's own `schema_version` (an
integer) is untouched. The telemetry version is independent of the app's and follows the record's shape:

- **MAJOR** when a key is removed, renamed or retyped, or a value's format changes.
- **MINOR** when a key, an event type, or a value of an enum is added.
- **PATCH** when only the schema's text changes.

| Telemetry | Mac Monitor | Change |
|---|---|---|
| 1.0.0 | 3.0.0 | The first schema. |
| 1.1.0 | 3.1.0 | Adds the keys below, and removes none. |
| 1.2.0 | 3.2.0 | Adds ATT&CK v19's tactics to `tactic` and `tactic_id`, and removes nothing. |
| 1.3.0 | 3.3.0 | Adds `yara_scan` to modified closes, renames and execs, `where_froms` to execs, and the network events `new_flow` and `flow_closed`, and removes nothing. |

### Added in 1.1.0

| Where | Keys | What they hold |
|---|---|---|
| Every process | `process_age_ms` | How old the process was at the event. |
| `mmap` | `protection_names`, `max_protection_names`, `flag_names` | The `PROT_*` and `MAP_*` names of the bits set. |
| `setmode` | `mode_symbolic`, `previous_mode`, `mode_added` | The new mode as `ls -l` shows it, the mode before, and what the change added. |
| Launch items | `bundle`, `app_bundle` | The bundle an item names and its app's: Info.plist essentials, signing, quarantine, where-froms and age. |
| `iokit_open` | `parent_class`, `driver_bundle_id` | The service being opened and its driver. |
| `mmap`, modified `close`, `rename` | `file_type`, `mach_o_type` | What the file is by its content: a Launch Services type and a Mach-O's `MH_*` type. |
| Every record | `indicators`, `indicators_undetermined` | The indicators the event matched, and those the Security Extension couldn't rule out. |

### Added in 1.2.0

ATT&CK v19 split Defense Evasion into Stealth, which kept its identity, TA0005, and Defense Impairment, TA0112. An
indicator's `tactic` can be `Stealth` or `Defense Impairment`, and its `tactic_id` `TA0112`. A record Mac Monitor 3.2
or later writes never names Defense Evasion, and `TA0005` is Stealth in it. `Defense Evasion` stays a valid `tactic`,
for records written before.

### Added in 1.3.0

| Where | Keys | What they hold |
|---|---|---|
| Modified `close`, `rename` | `yara_scan`: `status`, `xprotect_version`, `rules`, `names`, `report_only` | What scanning the written file with Apple's XProtect rules found: whether it was scanned, the XProtect version, the rules that matched with XProtect's names for them, and those XProtect only reports. |
| `exec` | `yara_scan`, as for a close | What scanning the script the exec runs found: `script`, the script an interpreter's arguments name, or an AppleScript or JXA applet's `main.scpt`. |
| `exec` | `where_froms` | Where the program the exec runs was downloaded from: the `com.apple.metadata:kMDItemWhereFroms` attribute of the first found of the script it runs and its executable, each before the bundle it's the main executable of, as a launch item bundle's `where_froms`. |
| `new_flow`, `flow_closed` | `identifier`, `remote_endpoint`, `remote_address_scope`, `local_endpoint`, `remote_hostname`, `url`, `first_party_site`, `direction`, `socket_family`, `socket_type`, `socket_protocol` and their `_string`s, `source_app`, `start_time`, and for `flow_closed` `bytes_inbound_count`, `bytes_outbound_count` | A network flow that opened or closed, as the kernel's network statistics socket reported it, and the process it's from as a `flow_process`. |

`yara_scan` is read from the recording Mac when the event is recorded, while scanning is on. A rename carries the
scan of the close that wrote the file it moves. An exec's describes the script it runs, not its target. It's absent
when the file isn't one that's scanned, the exec runs no script Mac Monitor found, scanning was off, or Mac Monitor
3.3.0 or later didn't record the event. An indicator's `matched` also lists the first string an
`ANY ... !=` comparison found.

A network flow's record is Mac Monitor's own and follows `#/$defs/network_record`, not the root: it has no `version`,
`schema_version`, sequence numbers, `thread`, `action`, `event_type` or `es_event_type`. Its process has only the
keys the socket and Mac Monitor's lineage gave, under a process's names. The URL and first-party site are what the
process asked for, and so is a Network.framework connection's hostname. A BSD socket's hostname is the name
mDNSResponder last resolved its remote address to for the same program, unless the process set one. Mac Monitor reads
no DNS traffic. `remote_address_scope` says where the remote address is, from IANA's special-purpose registries:
`public`, `private`, `shared`, `link_local`, `loopback`, `multicast` or `reserved`.

Each key's `description` in the schema says how it's derived and when it's `null`. Three things hold across them:

- **Derived from the record** (`process_age_ms`, the `mmap` and `setmode` names): filled in when an older trace is
  opened and exported again.
- **Read from the recording Mac** (bundles, the IOKit registry, file types): read when the event is recorded, never when
  a trace is opened, so a trace without them exports `null`.
- **`indicators`** is `[]` when none matched and absent when nothing was evaluated. `evaluated_by` says who matched:
  `security_extension` at capture, or `export` when Mac Monitor matched as it wrote the record.
  `indicators_undetermined` lists at most 32 that the Security Extension couldn't decide: each may or may not match.

`released-versions.txt` lists each released version with the SHA-256 of its file, and a test fails if a released
version's file changes. To validate an older trace, use the schema attached to the release that wrote it. A trace
exported before Mac Monitor 3.0.0 names no telemetry version: open it with File > Open Trace... and export it again to
check it.

## Checking a trace

In Mac Monitor, **Help > Telemetry Schema...** shows the schema it ships with (⌘F searches it), copies or saves it,
and checks a trace with **Validate Trace...**. The report gives the number of valid, invalid and malformed records, how
many issues of each kind there are, and the first 100 issues with the line their record starts on and the path of the
value: `line 812: event.exec.target.cdhash: "0df5..." doesn't match ^[0-9A-F]{40}$`. For eslogger's own JSON, **Check
eslogger's Fields** checks only the keys eslogger writes. The `macmonitor` command line tool does the same with
`macmonitor schema` and `macmonitor validate [--eslogger] <trace>`, which prints the same report and exits 0 when
every record is valid, 65 when one isn't or the trace has no records, and 66 when the trace can't be read.

## How it's made

The schema is generated and its source is a declarative description of the export in
`ProjectSutro/SutroESFrameworkTests/Telemetry Schema/Source`, and
`ProjectSutro/Scripts/Generate/generate-telemetry-schema.sh` writes it. The framework bundles this file, so the app and
the command line validate against exactly the bytes in the repository.

The tests keep the schema and the exports in sync. Every object has `additionalProperties: false` and every key
that's always written is `required`, so an added or dropped key fails. Synthetic events of every type, with every
field filled and with every optional field left out, are exported and validated, and every part of the schema has to
be exercised by them, so a stale part fails too. The keys marked `eslogger` are checked against eslogger's own keys
(`Fixtures/eslogger-keys.json`), both ways.

## Keywords

The schema uses `type`, `properties`, `required`, `additionalProperties: false`, `items`, `enum`, `const`,
`pattern`, `minProperties` and `maxProperties` (only on `event`, which holds exactly one event), `anyOf` (for unions
and nullable objects), `$ref` to `#/$defs`, and the annotations `title`, `description` and `x-mac-monitor-origin`.
A nullable scalar is `"type": ["string", "null"]`.

Mac Monitor validates with its own validator (`TelemetryValidator` in SutroESFramework), which supports that subset
and rejects a schema that uses anything else, naming the keyword and where it is, so a constraint is never silently
ignored.

The schema is strict on purpose. eslogger's required keys follow eslogger's own contract, so a re-export of a partial
or hand-edited trace opened with File > Open Trace... (one whose processes have no `executable`, say) is reported
invalid.

## Other validators

Any draft 2020-12 validator reads the schema.

- `$id` is `urn:mac-monitor:telemetry:<version>`: a versioned name that doesn't resolve. Download the file from the
  release instead.
- Patterns use only `[0-9]`-style classes, anchors, alternatives and counted repeats. ECMA-262, which JSON Schema
  specifies, matches `$` only at the end of the string, as Mac Monitor's validator does; ICU and Python's `re` also
  match it before a final newline, so a validator built on them accepts a value with a trailing newline that ajv
  rejects.
- There's no `format` keyword, so nothing needs `ajv-formats`.
- ajv's strict mode rejects unknown keywords. Register the origin mark, or turn strict mode off:

  ```js
  const ajv = new Ajv2020();
  ajv.addKeyword("x-mac-monitor-origin");
  const validate = ajv.compile(schema);
  ```

- With Python's `jsonschema`: `jsonschema.Draft202012Validator(schema).iter_errors(record)`.
