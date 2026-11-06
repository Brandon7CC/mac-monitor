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

Since Mac Monitor 3.0.1, a close of an unmodified file is left out by default (Settings ▸ Subscriptions turns that off
for Mac Monitor's recording, and `macmonitor stream --every close` for one stream). Its message still advances
`seq_num` and `global_seq_num`, so close gaps and file-client `global_seq_num` gaps are expected, not losses.

## Versions

Every record carries `telemetry_version`, the version of this schema it follows. eslogger's own `schema_version` (an
integer) is untouched. The telemetry version is independent of the app's and follows the record's shape:

- **MAJOR** when a key is removed, renamed or retyped, or a value's format changes.
- **MINOR** when a key, an event type, or a value of an enum is added.
- **PATCH** when only the schema's text changes.

Telemetry 1.0.0 is the version Mac Monitor 3.0.0 ships. Telemetry 1.1.0, from Mac Monitor 3.0.1, adds
`process_age_ms` to every process object: how old the process was at the event, in milliseconds from its
`start_time` to the message's time, `null` when the start time is unknown and negative when the clock stepped back.
A trace without it (eslogger's, or one exported from 3.0.0) gets it derived from its own `start_time` and `time`
when it's opened. One exported before 3.0.0 gets none: its `time` is the recording Mac's local time, which can't be
read back exactly. It also adds `protection_names`, `max_protection_names` and `flag_names` to `mmap` events: the
`PROT_*` and `MAP_*` names of the bits `protection`, `max_protection` and `flags` have, in bit order, written beside
the integers whenever a record is exported, so a trace exported before 3.0.1 gets them too. `released-versions.txt`
lists each released version with the SHA-256 of the file released with it, and a test fails if a released version's
file changes. To validate an older trace, use the schema attached to the release that wrote it. A trace exported
before Mac Monitor 3.0.0 names no telemetry version, and no schema describes it: open it with File > Open Trace... and
export it again to check it.

## Checking a trace

In Mac Monitor, **Help ▸ Telemetry Schema...** shows the schema it ships with (⌘F searches it), copies or saves it,
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
