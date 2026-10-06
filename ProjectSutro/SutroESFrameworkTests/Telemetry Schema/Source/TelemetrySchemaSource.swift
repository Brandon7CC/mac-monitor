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
/// Every key is eslogger's or one of Mac Monitor's additions. Every object is closed and every key always written is
/// required, so a key added to or dropped from the export fails the drift tests; values come only from Swift sources
/// (`CaseIterable` types and the SDK's event list), and nothing here depends on the Mac it runs on, so the schema is
/// the same wherever it's generated.
enum TelemetrySchemaSource {
    /// Where the schema can be downloaded, for its description.
    static let latestURL = "https://github.com/Brandon7CC/mac-monitor/releases/latest/download/"
        + TelemetrySchema.releaseAssetName
    
    /// What the schema describes.
    static var description: String {
        "The records Mac Monitor writes: its JSONL and pretty exports, and the macmonitor command line's output. Each "
            + "record is eslogger's JSON for an Endpoint Security event plus Mac Monitor's additions; every key is "
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
            addition(TelemetrySchema.versionKey, .constant(TelemetrySchema.version),
                     "The version of Mac Monitor's telemetry schema the record follows."),
            eslogger("seq_num", .integer, "The message's sequence number among its type's, for the client that "
                        + "received it: Mac Monitor's numbers never match eslogger's."),
            eslogger("global_seq_num", .integer, "The message's sequence number among all, for the client that "
                        + "received it: Mac Monitor's numbers never match eslogger's."),
            eslogger("time", .pattern(.timespec)),
            eslogger("mach_time", .integer),
            addition("macOS", .string, "The macOS version of the Mac that recorded the event: 27.0 (Build 26A1)."),
            addition("sensor_id", .string, "The Sensor ID of the Mac Monitor that recorded the event."),
            eslogger("process", .ref("process")),
            eslogger("thread", .nullable(.ref("thread"))),
            eslogger("event", .ref("event")),
            eslogger("event_type", .integers(events.map(\.number).sorted())),
            addition("es_event_type", .values(events.map(\.constant).sorted()), "The SDK's name for `event_type`."),
            eslogger("action", .ref("action")),
            eslogger("action_type", .integer),
            addition("action_type_string", .string, "The name of `action_type`: ES_ACTION_TYPE_NOTIFY."),
            addition("context", .string, "A summary of the event, as Mac Monitor's event list shows it."),
            addition("target_path", .string, "The path the event is about, or \"Not supported\"."),
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
