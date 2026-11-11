//
//  RawMessageFixture+FileEvents.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
import EndpointSecurity


// MARK: - File events
/// Fills a message's event as one of the file events a recording is mostly made of. Only for a message made with the
/// matching type (`rawMessage(type: ES_EVENT_TYPE_NOTIFY_OPEN)` for ``open(_:flags:)``, and so on). Every path is used
/// as given, so the capture code's enrichment (`getxattr`, `stat`) runs against the real file system.
extension RawMessageFixture {
    /// An open of a file.
    ///
    /// - Parameters:
    ///   - path: The file.
    ///   - flags: The `fflag` it was opened with, `FREAD` by default.
    func open(_ path: String, flags: Int32 = FREAD) {
        message.pointee.event.open.file = file(path)
        message.pointee.event.open.fflag = flags
    }

    /// A close of a file.
    ///
    /// - Parameters:
    ///   - path: The file.
    ///   - modified: Was it written to while open?
    func close(_ path: String, modified: Bool) {
        message.pointee.event.close.target = file(path)
        message.pointee.event.close.modified = modified
    }

    /// A create of a new file, named by its directory and name, as Endpoint Security names one.
    ///
    /// - Parameters:
    ///   - name: The new file's name.
    ///   - directory: Its directory.
    func create(_ name: String, in directory: String) {
        message.pointee.event.create.destination_type = ES_DESTINATION_TYPE_NEW_PATH
        message.pointee.event.create.destination.new_path.dir = file(directory)
        message.pointee.event.create.destination.new_path.filename = token(name)
        message.pointee.event.create.destination.new_path.mode = 0o644
    }

    /// A map of a file's pages, as dyld maps a library's code.
    ///
    /// - Parameters:
    ///   - path: The mapped file.
    ///   - protection: The pages' protection, read and execute by default.
    func mmap(_ path: String, protection: Int32 = PROT_READ | PROT_EXEC) {
        message.pointee.event.mmap.source = file(path)
        message.pointee.event.mmap.protection = protection
        message.pointee.event.mmap.max_protection = PROT_READ | PROT_EXEC
        message.pointee.event.mmap.flags = MAP_PRIVATE | MAP_FIXED
        message.pointee.event.mmap.file_pos = 16_384
    }
}
