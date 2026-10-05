//
//  FilePathUnion.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 8/18/25.
//

///
///
/// ```swift
/// union {
///   es_string_token_t file_path;
///   es_file_t *_Nonnull file;
/// } file;```
///
///
///

/// Models the union
public enum FilePathUnion: Hashable, Codable {
    case file_path(String)
    case file(File)
    /// A `file_type` this version of Mac Monitor doesn't know, or a path arm whose path is `NULL` (which eslogger
    /// writes as `"file": null`): there's nothing to read.
    case unknown
    
    /// The union as `file_type` says to read it.
    ///
    /// - Parameter override: The event.
    /// - Returns: The path or the file, or ``unknown`` for a `file_type` that names neither or a `NULL` path.
    static func from(override: es_event_gatekeeper_user_override_t) -> FilePathUnion {
        switch override.file_type {
        case ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_PATH:
            return override.file.file_path.string.map(FilePathUnion.file_path) ?? .unknown
            
        case ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_FILE:
            return .file(
                File(from: override.file.file.pointee)
            )
            
        default:
            /// A newer macOS's file type: recording it beats stopping the Security Extension.
            return .unknown
        }
    }
}

/// Accessors
extension FilePathUnion {
    // MARK: Process events
    var file_path: String? {
        if case .file_path(let e) = self { return e }
        return nil
    }
    
    var file: File? {
        if case .file(let e) = self { return e }
        return nil
    }
}
