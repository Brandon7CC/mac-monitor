//
//  FileRenameEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 2/17/23.
//

import Foundation


// https://developer.apple.com/documentation/endpointsecurity/es_event_rename_t
public struct FileRenameEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
    public var source: File
    
    public var destination_type: Int
    public var destination_type_string = ""
    public var destination: FileDestination
    
    /// @note Mac Monitor enrichment
    public var destination_path: String = ""
    public var is_quarantined: Int16 = 0
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: FileRenameEvent, rhs: FileRenameEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    // @note files_not_quarantined should be a list of sub paths
    init(from rawMessage: UnsafePointer<es_message_t>, files_not_quarantined: [String] = []) {
        let fileRenameEvent: es_event_rename_t = rawMessage.pointee.event.rename
        
        self.source = File(from: fileRenameEvent.source.pointee)
        self.destination_type = Int(fileRenameEvent.destination_type.rawValue)
        self.destination = FileDestination.from(rename: fileRenameEvent)
        
        enrich()
        if !destination_path.isEmpty {
            self.is_quarantined = Int16(ProcessHelpers.isFileQuarantined(filePath: destination_path))
        }
    }
}


// MARK: - Mac Monitor enrichment
extension FileRenameEvent: ESEnrichable {
    /// Derive the destination type's name and the destination's full path.
    ///
    /// Not derived: `is_quarantined`, which is read from the file.
    public mutating func enrich() {
        destination_type_string = FileDestination.typeName(destination_type)
        switch destination {
        case .existing_file(let file):
            destination_path = file.path
        case .new_path(let path):
            destination_path = path.fullPath
        case .unknown:
            destination_path = ""
        }
    }
}
