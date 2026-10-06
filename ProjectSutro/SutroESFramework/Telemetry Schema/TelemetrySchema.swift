//
//  TelemetrySchema.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Telemetry schema
/// Mac Monitor's telemetry schema: a JSON Schema (draft 2020-12) of the records Mac Monitor writes, in its JSONL and
/// pretty exports and on the command line.
///
/// Every record is eslogger's JSON plus Mac Monitor's own fields, and the schema marks each key with
/// `x-mac-monitor-origin`: `eslogger` or `mac-monitor`. It's generated from the test target's description of the export
/// and committed as `Schema/mac-monitor-telemetry.schema.json`; the framework bundles that file, and each release on
/// GitHub attaches it beside the installer, as ``releaseAssetName``. ``TelemetryValidator`` checks records against it.
///
/// Every record carries ``version`` under ``versionKey``, beside eslogger's own `schema_version`.
public enum TelemetrySchema {
    /// The version of the records' shape, independent of the app's: MAJOR when a key is removed, renamed or retyped,
    /// or a value's format changes; MINOR when a key, event type or value is added; PATCH when only the schema's text
    /// changes.
    public static let version = "1.0.0"
    /// The key every record carries ``version`` under.
    public static let versionKey = "telemetry_version"
    /// The schema's file name: in the repository's `Schema` folder and the framework's resources.
    public static let fileName = "mac-monitor-telemetry.schema.json"
    /// The schema's name as a GitHub release's asset. GitHub lists a release's assets by name, ignoring case, and
    /// Mac Monitor's update check installs the first, so the name sorts after `Mac-Monitor.pkg`: ``fileName`` doesn't.
    public static let releaseAssetName = "Mac-Monitor.telemetry.schema.json"
    /// The schema's `$id`: a versioned name that doesn't pretend to be a URL.
    public static var identifier: String { "urn:mac-monitor:telemetry:\(version)" }
    
    /// The committed schema, from the framework's resources.
    ///
    /// - Returns: The schema's JSON text.
    /// - Throws: ``TelemetrySchemaError/missingResource`` if the framework doesn't bundle it, or the error reading it.
    public static func data() throws -> Data {
        guard let url = Bundle(for: BundleToken.self).url(forResource: fileName, withExtension: nil) else {
            throw TelemetrySchemaError.missingResource
        }
        return try Data(contentsOf: url)
    }
    
    /// A class of the framework's, so `Bundle(for:)` finds its resources.
    private final class BundleToken {}
}


// MARK: - Errors
/// Why a schema can't be used to validate telemetry.
public enum TelemetrySchemaError: Error, LocalizedError, Equatable {
    /// The framework doesn't bundle the telemetry schema.
    case missingResource
    /// The schema isn't JSON, or isn't a JSON object: why.
    case notJSON(String)
    /// A keyword the validator doesn't check, and where: rejected so no constraint is ever silently ignored.
    case unsupportedKeyword(String, at: String)
    /// A supported keyword whose value isn't valid, and where.
    case invalidKeyword(String, at: String)
    /// A `$ref` that names no definition, and where.
    case unresolvedReference(String, at: String)
    /// A `$ref` that comes back to the same value without reading into it, where: checking would never end.
    case referenceCycle(at: String)
    
    /// What's wrong, as a sentence.
    public var errorDescription: String? {
        switch self {
        case .missingResource: "Mac Monitor's telemetry schema is missing from its framework."
        case .notJSON(let reason): "The schema isn't a JSON object: \(reason)"
        case .unsupportedKeyword(let keyword, let location):
            "The schema uses \(keyword) at \(location), which Mac Monitor's validator doesn't support."
        case .invalidKeyword(let keyword, let location): "The schema's \(keyword) at \(location) isn't valid."
        case .unresolvedReference(let reference, let location):
            "The schema's $ref \(reference) at \(location) names no definition in its $defs."
        case .referenceCycle(let location): "The schema's $ref at \(location) refers back to itself."
        }
    }
}
