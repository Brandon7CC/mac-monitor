# Mac Monitor telemetry schema

`mac-monitor-telemetry.schema.json` describes every record Mac Monitor writes: the JSONL and pretty exports, the
Event Facts JSON tab, and the `macmonitor` command line's output. We wrote it so a pipeline consuming Mac Monitor's
telemetry can check what it receives instead of trusting that the shape didn't move between releases.

It's a [JSON Schema](https://json-schema.org/draft/2020-12) (draft 2020-12). Each GitHub release attaches it beside
`Mac-Monitor.pkg` as `Mac-Monitor.telemetry.schema.json`, a name that sorts after the installer's (GitHub lists a
release's assets by name), and the latest is at
`https://github.com/Brandon7CC/mac-monitor/releases/latest/download/Mac-Monitor.telemetry.schema.json`.

## eslogger's keys and Mac Monitor's

A record is eslogger's JSON for an Endpoint Security message (`es_message_t`) plus Mac Monitor's additions. Every
eslogger key keeps eslogger's key path and value; Mac Monitor's keys sit beside them. The schema marks every property
with `x-mac-monitor-origin`:

- `eslogger`: eslogger writes the key, at the same path, with the same value.
- `mac-monitor`: Mac Monitor adds it. Every addition has a `description` saying what it holds and how it's derived.

The mark describes the key itself. Everything under a Mac Monitor key is Mac Monitor's, even where it reuses one of
eslogger's shapes: `launched_by_parent.audit_token` is written the way eslogger writes an audit token, but it's an
addition.

Two of eslogger's integers that Mac Monitor can't reproduce keep eslogger's keys: `seq_num` and `global_seq_num` count
the messages of the Endpoint Security client that received them, so Mac Monitor's numbers never match eslogger's.

## Versions

Every record carries `telemetry_version`, the version of this schema it follows. eslogger's own `schema_version` (an
integer) is untouched. The telemetry version is independent of the app's and follows the record's shape:

- **MAJOR** when a key is removed, renamed or retyped, or a value's format changes.
- **MINOR** when a key, an event type, or a value of an enum is added.
- **PATCH** when only the schema's text changes.

Telemetry 1.0.0 is the version Mac Monitor 2.2.0 ships. `released-versions.txt` lists each released version with the
SHA-256 of the file released with it, and a test fails if a released version's file changes. To validate an older
trace, use the schema attached to the release that wrote it. A trace exported before Mac Monitor 2.2.0 names no
telemetry version, and no schema describes it: open it with File > Open Trace… and export it again to check it.
[`RELEASING.md`](../RELEASING.md) says how a release lists its version and attaches the schema after the installer,
with `ProjectSutro/Scripts/attach-telemetry-schema.sh`.

## Checking a trace

In Mac Monitor, **Help ▸ Telemetry Schema…** shows the schema it ships with (⌘F searches it), copies or saves it,
and checks a trace with **Validate Trace…**. The report gives the number of valid, invalid and malformed records, how
many issues of each kind there are, and the first 100 issues with the line their record starts on and the path of the
value: `line 812: event.exec.target.cdhash: "0df5…" doesn't match ^[0-9A-F]{40}$`. For eslogger's own JSON, **Check
eslogger's Fields** checks only the keys eslogger writes. The `macmonitor` command line tool does the same with
`macmonitor schema` and `macmonitor validate [--eslogger] <trace>`, which prints the same report and exits 0 when
every record is valid, 65 when one isn't or the trace has no records, and 66 when the trace can't be read.

## How it's made

The schema is generated, never edited by hand. Its source is a declarative description of the export in
`ProjectSutro/SutroESFrameworkTests/Telemetry Schema/Source`, and
`ProjectSutro/Scripts/generate-telemetry-schema.sh` writes it here. The framework bundles this file, so the app and
the command line validate against exactly the bytes in the repository.

The tests keep the schema and the exports in step. Every object has `additionalProperties: false` and every key
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
or hand-edited trace opened with File > Open Trace… (one whose processes have no `executable`, say) is reported
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
