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

Since Mac Monitor 3.1.0, a close of an unmodified file is left out by default (Settings > Subscriptions turns that off
for Mac Monitor's recording, and `macmonitor stream --every close` for one stream). Its message still advances
`seq_num` and `global_seq_num`, so close gaps and file-client `global_seq_num` gaps are expected, not losses.

## Versions

Every record carries `telemetry_version`, the version of this schema it follows. eslogger's own `schema_version` (an
integer) is untouched. The telemetry version is independent of the app's and follows the record's shape:

- **MAJOR** when a key is removed, renamed or retyped, or a value's format changes.
- **MINOR** when a key, an event type, or a value of an enum is added.
- **PATCH** when only the schema's text changes.

Telemetry 1.0.0 is the version Mac Monitor 3.0.0 ships. Telemetry 1.1.0, from Mac Monitor 3.1.0, adds `process_age_ms`
to every process object: how old the process was at the event, in milliseconds from its `start_time` to the message's
time, `null` when the start time is unknown and negative when the clock stepped back. A trace without it (eslogger's, or
one exported from 3.0.0) gets it derived from its own `start_time` and `time` when it's opened. One exported before
3.0.0 gets none: its `time` is the recording Mac's local time, which can't be read back exactly. It also adds
`protection_names`, `max_protection_names` and `flag_names` to `mmap` events: the `PROT_*` and `MAP_*` names of the bits
`protection`, `max_protection` and `flags` have, in bit order, written beside the integers whenever a record is
exported, so a trace exported before 3.1.0 gets them too. It adds `mode_symbolic`, `previous_mode` and `mode_added` to
`setmode` events the same way: the new mode as `ls -l` shows it (`rwxr-xr-x`), the permission bits the target's stat had
before the change (`null` without a stat), and what the change added: `executable`, `setuid`, `setgid` or
`world_writable`. And it adds `bundle` and `app_bundle` to every launch item: the app or helper bundle the item names,
and the bundle of the app it belongs to, with their Info.plist's path and essentials, signing, quarantine, where-froms,
birth time and `age_ms`. They're read from the Mac that recorded the event when it recorded it, never when a trace is
opened, so a trace without them (an eslogger trace, or one exported before 3.1.0) keeps none and exports them as `null`,
and they're `null` on a remove whose bundle is already gone. `plist_contents` now also holds a bundle item's Info.plist,
a property list stored in binary is converted to XML, and none is read through a symbolic link below its bundle, app or
folder. It adds `parent_class` and `driver_bundle_id` to `iokit_open` events: the class of the service being opened and
its driver's bundle ID (the service's `CFBundleIdentifier`, else its nearest provider's, unless a third-party kext
defines the service's class), read from the IOKit registry when the event is recorded. The service is found by
`parent_path` when the entry it finds has the event's `parent_registry_id`, else by that ID. Both keys are always
written, `null` before message version 10, when the service is gone, and in a trace without them, as opening a trace
never reads the registry. It adds `file_type` and `mach_o_type` to `mmap` events and to `close` events whose `modified`
is true: what the file is by its content, never its name, the Launch Services type identifier of its first 4 KB
(`com.apple.mach-o-dylib`, `public.zsh-script`, `public.zip-archive`), and a Mach-O's `MH_*` file type. A universal
binary is named by the slice the recording Mac runs, else its first. `file_type` is `empty` for a file of 0 bytes,
`dyld_shared_cache` for a dyld shared cache, and `replaced` when the path no longer names the event's file: its device
or inode differ, or a symbolic link is on the path now. They're read when the event is recorded, only from a regular,
local file the event's process could read, and both keys are always written: `null` when the file wasn't read, for an
unmodified close, and in a trace without them, as opening a trace never reads the disk. And it adds `indicators` to
every record Export telemetry and `macmonitor stream` write, and to Event Facts' JSON tab and copied events: the
indicators in this Mac's saved set that this one event matched, each with its `id`, `name`, MITRE ATT&CK `tactic`,
`tactic_id` and `technique` (`null` for none), its `severity` (`low`, `medium` or `high`), whether it's one of Mac
Monitor's default indicators (`default`), whether this Mac `edited` a default, and who matched it, `evaluated_by`:
`security_extension` when the Security Extension evaluated the event as it captured it, and `export` when it didn't (an opened trace, an eslogger trace, or an event from an older Security
Extension) and Mac Monitor matched the set as it wrote the record. It's `[]` when none matched, and absent when nothing
was evaluated. Beside it, `indicators_undetermined` lists, in the same shape plus a `reason`, at most 32 indicators the
Security Extension could not rule out for the event: `scan_budget` when evaluating the event's values exceeded its
per-event scan budget, and `value_limit` when a value that isn't ASCII was longer than the 64 KiB it compares. Each may
or may not match. While `indicators` has fewer than 32 entries and `indicators_undetermined` fewer than 32, an
indicator in neither list did not match; a list of 32 may have been cut short, and then an indicator in neither may
match. It's absent when every indicator was decided, and in a record whose `indicators` Mac Monitor matched as it
wrote it. Opening a trace keeps its records' `indicators` and
`indicators_undetermined`, and `--indicator NAME` writes only the events an indicator matches.
`released-versions.txt` lists each released version with the SHA-256 of the file released with it, and a test fails
if a released version's file changes. To validate an older trace, use the schema attached to the release that wrote
it. A trace exported before Mac Monitor 3.0.0 names no telemetry version, and no schema describes it: open it with
File > Open Trace... and export it again to check it.

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
`ProjectSutro/Scripts/generate-telemetry-schema.sh` writes it. The framework bundles this file, so the app and
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
