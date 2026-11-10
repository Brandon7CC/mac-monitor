//
//  FileCloseEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/23.
//

import Foundation


// https://developer.apple.com/documentation/endpointsecurity/es_event_close_t
public struct FileCloseEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    public var target: File
    public var modified: Bool
    public var was_mapped_writable: Bool?
    
    /* Mac Monitor enrichment, read from a modified file at capture: FileTypeReader */
    /// What the closed file's first bytes are, only when it was modified: a Launch Services type identifier
    /// (`public.zip-archive`), ``FileType/empty``, ``FileType/dyldSharedCache`` or ``FileType/replaced``. `nil` for an
    /// unmodified close, when the file wasn't read (not a regular file, dataless, on a volume that isn't local, gone,
    /// or one the process couldn't read), or in a record from Mac Monitor before 3.1.0 or eslogger.
    public var file_type: String?
    /// The `MH_*` file type of a modified Mach-O, such as `MH_EXECUTE`. `nil` for any other file, or as
    /// ``file_type`` is.
    public var mach_o_type: String?
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the file write event
        let event: es_event_close_t = rawMessage.pointee.event.close
        let version: Int = Int(rawMessage.pointee.version)
        
        target = File(from: event.target.pointee)
        modified = event.modified
        was_mapped_writable = version >= 6 ? event.was_mapped_writable : nil
    }
}
