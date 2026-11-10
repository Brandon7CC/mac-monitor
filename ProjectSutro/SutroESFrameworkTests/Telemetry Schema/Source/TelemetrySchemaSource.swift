//
//  TelemetrySchemaSource.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Mac Monitor's telemetry, described
/// The source of Mac Monitor's telemetry schema: a description of the records Mac Monitor exports, which
/// ``SchemaGenerator`` writes as `Schema/mac-monitor-telemetry.schema.json`.
///
/// Every key is eslogger's or one of Mac Monitor's enrichments. Every object is closed and every key always written is
/// required, so a key added to or dropped from the export fails the drift tests. Values come only from Swift sources
/// (`CaseIterable` types and the SDK's event list), and nothing here depends on the Mac it runs on, so the schema is
/// the same wherever it's generated.
enum TelemetrySchemaSource {
    /// Where the schema can be downloaded, for its description.
    static let latestURL = "https://github.com/Brandon7CC/mac-monitor/releases/latest/download/"
        + TelemetrySchema.releaseAssetName
    
    /// What the schema describes.
    static var description: String {
        "The records Mac Monitor writes: its JSONL and pretty exports, and the macmonitor command line's output. Each "
            + "record is eslogger's JSON for an Endpoint Security event plus Mac Monitor's enrichments; every key is "
            + "marked x-mac-monitor-origin: eslogger or mac-monitor, and everything under a Mac Monitor key is Mac "
            + "Monitor's. Each GitHub release attaches the schema as \(TelemetrySchema.releaseAssetName), and the "
            + "latest is at \(latestURL)."
    }
    
    /// Every event type Mac Monitor records.
    static var events: [SchemaEvent] { processEvents + fileEvents + systemEvents + directoryEvents }
    
    /// A record: one Endpoint Security message, `es_message_t`.
    static var root: SchemaObject {
        SchemaObject(nil, [
            eslogger("version", .integer, "The Endpoint Security message's version."),
            eslogger("schema_version", .integer, "eslogger's own schema version."),
            enrichment(TelemetrySchema.versionKey, .constant(TelemetrySchema.version),
                     "The version of Mac Monitor's telemetry schema the record follows."),
            enrichment("indicators", .array(.ref("indicator")),
                       "The indicators in this Mac's saved set (Settings > Indicators, `macmonitor indicators`) that "
                        + "this event matched, evaluated by the Security Extension as it captured the event "
                        + "(`evaluated_by: security_extension`). When the Security Extension did not evaluate the "
                        + "event, these are the indicators Mac Monitor matched as it wrote the record (`evaluated_by: "
                        + "export`). Empty when none matched. The indicators the Security Extension could not rule "
                        + "out are in `indicators_undetermined`.",
                       absent: Absence("nothing was evaluated: the writer had no indicators to match, or the record "
                                       + "is from Mac Monitor before 3.1.0")),
            enrichment("indicators_undetermined", .array(.ref("indicator_undetermined")),
                       "The indicators in this Mac's saved set that the Security Extension could not rule out for "
                        + "this event, in the set's order, at most \(CompiledIndicators.undeterminedLimit). `reason` "
                        + "says why: `scan_budget` when evaluating the event's values exceeded the Security "
                        + "Extension's per-event scan budget, and `value_limit` when a value that isn't ASCII was "
                        + "longer than the 64 KiB the Security Extension compares. Each may or may not match. While "
                        + "`indicators` has fewer than \(CompiledIndicators.hitLimit) entries and "
                        + "`indicators_undetermined` fewer than \(CompiledIndicators.undeterminedLimit), an "
                        + "indicator in neither did not match. A list at its limit may have been cut short, and then "
                        + "an indicator in neither may match. A consumer that must not miss a match should treat both "
                        + "lists as possible matches; one that wants only certain matches reads `indicators`.",
                       absent: Absence("every indicator was decided, or the record wasn't evaluated by the Security "
                                       + "Extension (`evaluated_by: export` never writes it)")),
            eslogger("seq_num", .integer, "The message's sequence number among its type's, for the client that "
                        + "received it: Mac Monitor's numbers never match eslogger's."),
            eslogger("global_seq_num", .integer, "The message's sequence number among all, for the client that "
                        + "received it: Mac Monitor's numbers never match eslogger's."),
            eslogger("time", .pattern(.timespec)),
            eslogger("mach_time", .integer),
            enrichment("macOS", .string, "The macOS version of the Mac that recorded the event: 27.0 (Build 26A1)."),
            enrichment("sip_status", .nullable(.values(["custom", "disabled", "enabled"])),
                       "System Integrity Protection on the Mac that recorded the event, as csrutil status names it: "
                        + "enabled, disabled, or custom when only some protections are off. null in a trace that "
                        + "didn't record it, such as eslogger's."),
            enrichment("sensor_id", .string, "The Sensor ID of the Mac Monitor that recorded the event."),
            eslogger("process", .ref("process")),
            eslogger("thread", .nullable(.ref("thread"))),
            eslogger("event", .ref("event")),
            eslogger("event_type", .integers(events.map(\.number).sorted())),
            enrichment("es_event_type", .values(events.map(\.constant).sorted()), "The SDK's name for `event_type`."),
            eslogger("action", .ref("action")),
            eslogger("action_type", .integer),
            enrichment("action_type_string", .string, "The name of `action_type`: ES_ACTION_TYPE_NOTIFY."),
            enrichment("context", .string, "A summary of the event, as Mac Monitor's event list shows it."),
            enrichment("target_path", .string, "The path the event is about, or \"Not supported\"."),
        ])
    }
    
    /// The event dispatcher: one key, the event's.
    static var dispatcher: SchemaObject {
        SchemaObject("The event: one key, named for its type, as eslogger names it.", events.map {
            eslogger($0.name, .ref($0.definition), absent: Absence("the record is another type's"))
        }, keyCount: 1...1)
    }
    
    /// Every definition: the shared objects, the dispatcher, and each event's object.
    static var definitions: [String: SchemaObject] {
        var all = artifacts
        all["event"] = dispatcher
        for event in events { all[event.definition] = event.object }
        return all
    }
    
    /// The schema, and each property's key.
    ///
    /// - Returns: The schema document, and the generator that made it, which knows each property's key.
    static func generate() -> (document: OrderedJSON, generator: SchemaGenerator) {
        let generator = SchemaGenerator()
        let document = generator.document(root: root, definitions: definitions, identity: [
            ("$schema", JSONSchemaCompiler.draft), ("$id", TelemetrySchema.identifier),
            ("title", "Mac Monitor telemetry \(TelemetrySchema.version)"), ("description", description),
        ])
        return (document, generator)
    }
    
    /// The schema's text, as committed.
    static var text: String { SchemaJSONWriter.text(generate().document) }
}
