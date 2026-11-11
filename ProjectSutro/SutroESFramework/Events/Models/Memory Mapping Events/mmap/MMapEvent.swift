//
//  MMapEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/13/23.
//

import Foundation


// https://developer.apple.com/documentation/endpointsecurity/es_event_mmap_t
public struct MMapEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    public var protection, max_protection, flags: Int32
    /// Endpoint Security's `uint64_t`, kept by bit pattern as `Stat`'s `st_ino` is.
    public var file_pos: Int64
    public var source: File
    
    /* Mac Monitor enrichment, read from the mapped file at capture: FileTypeReader */
    /// What the mapped file's first bytes are: a Launch Services type identifier (`com.apple.mach-o-dylib`),
    /// ``FileType/empty``, ``FileType/dyldSharedCache`` or ``FileType/replaced``. `nil` when the file wasn't read (not
    /// a regular file, dataless, on a volume that isn't local, gone, or one the process couldn't read), or in a record
    /// from Mac Monitor before 3.1.0 or eslogger.
    public var file_type: String?
    /// The `MH_*` file type of a mapped Mach-O, such as `MH_DYLIB`. `nil` for any other file, or as ``file_type`` is.
    public var mach_o_type: String?
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let mmapEvent: es_event_mmap_t = rawMessage.pointee.event.mmap
        
        self.protection = mmapEvent.protection
        self.max_protection = mmapEvent.max_protection
        self.flags = mmapEvent.flags
        self.file_pos = Int64(bitPattern: mmapEvent.file_pos)
        self.source = File(from: mmapEvent.source.pointee)
    }
}
