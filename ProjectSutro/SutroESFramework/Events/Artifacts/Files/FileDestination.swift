//
//  FileDestination.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 5/7/25.
//

import Foundation

/// Models the union
public enum FileDestination: Hashable, Codable {
    case existing_file(File)
    case new_path(NewPath)
    
    static func from(create: es_event_create_t) -> FileDestination {
        switch create.destination_type {
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            return .existing_file(
                File(from: create.destination.existing_file.pointee)
            )
            
        case ES_DESTINATION_TYPE_NEW_PATH:
            return .new_path(
                NewPath(from: create)
            )
            
        default:
            fatalError("Unhandled destination type \(create.destination_type)")
        }
    }
    
    static func from(rename: es_event_rename_t) -> FileDestination {
        switch rename.destination_type {
        case ES_DESTINATION_TYPE_EXISTING_FILE:
            return .existing_file(
                File(from: rename.destination.existing_file.pointee)
            )
            
        case ES_DESTINATION_TYPE_NEW_PATH:
            return .new_path(
                NewPath(from: rename)
            )
            
        default:
            fatalError("Unhandled destination type \(rename.destination_type)")
        }
    }
}


/// Accessors
extension FileDestination {
    /// The name of an `es_destination_type_t`.
    ///
    /// - Parameter type: The destination type's raw value.
    /// - Returns: Its name, or `NOT_MAPPED`.
    static func typeName(_ type: Int) -> String {
        switch es_destination_type_t(rawValue: UInt32(truncatingIfNeeded: type)) {
        case ES_DESTINATION_TYPE_EXISTING_FILE: "ES_DESTINATION_TYPE_EXISTING_FILE"
        case ES_DESTINATION_TYPE_NEW_PATH: "ES_DESTINATION_TYPE_NEW_PATH"
        default: "NOT_MAPPED"
        }
    }
    
    // MARK: Process events
    var existing_file: File? {
        if case .existing_file(let e) = self { return e }
        return nil
    }
    
    var new_path: NewPath? {
        if case .new_path(let e) = self { return e }
        return nil
    }
}
