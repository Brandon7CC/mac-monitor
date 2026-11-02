//
//  FileOpenEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/1/23.
//

import Foundation


// https://developer.apple.com/documentation/endpointsecurity/es_event_open_t
public struct FileOpenEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    public var file: File
    public var fflag: Int32
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the file open event
        let fileOpenEvent: es_event_open_t = rawMessage.pointee.event.open
        self.file = File(from: fileOpenEvent.file.pointee)
        self.fflag = fileOpenEvent.fflag
    }
}
