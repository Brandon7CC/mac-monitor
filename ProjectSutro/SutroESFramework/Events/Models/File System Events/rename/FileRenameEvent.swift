//
//  FileRenameEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 2/17/23.
//

import Foundation


// https://developer.apple.com/documentation/endpointsecurity/es_event_rename_t
public struct FileRenameEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    public var source: File
    
    public var destination_type: Int
    public var destination_type_string = ""
    public var destination: FileDestination
    
    /// @note Mac Monitor enrichment
    public var destination_path: String = ""
    public var is_quarantined: Int16 = 0

    /* Mac Monitor enrichment, read from the renamed file at capture: FileTypeReader */
    /// What the renamed file's first bytes are: a Launch Services type identifier (`public.zip-archive`),
    /// ``FileType/empty``, ``FileType/dyldSharedCache`` or ``FileType/replaced``, taken from the close that wrote it
    /// when there was one. `nil` for a folder, or when the file wasn't read (dataless, on a volume that isn't local,
    /// gone, or one the process couldn't read), or in a record from Mac Monitor before 3.1.0 or eslogger.
    public var file_type: String?
    /// The `MH_*` file type of a renamed Mach-O, such as `MH_EXECUTE`. `nil` for any other file, or as
    /// ``file_type`` is.
    public var mach_o_type: String?
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
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
        destination_path = destination.fullPath ?? ""
    }
}
