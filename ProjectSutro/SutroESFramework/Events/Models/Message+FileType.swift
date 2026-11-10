//
//  Message+FileType.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation
import EndpointSecurity


// MARK: - File types at capture
extension Message {
    /// Name the type of the file an mmap maps, a modified close closed, or a rename moved, from its first bytes
    /// (``FileTypeReader``). A capture lane does this as it builds the event, so a trace opened later never reads the
    /// disk: its events keep what their records have. An unmodified close's file isn't read, nor a create's (a new file
    /// is empty then). A rename of a file a close just read takes that close's type (``FileTypeMemory``).
    ///
    /// - Parameters:
    ///   - message: The Endpoint Security message the event was built from, for its file's stat and its process's
    ///     audit token. Only valid during the call.
    ///   - memory: The capture lane's file types, which mmaps look up.
    mutating func identifyFileType(of message: UnsafePointer<es_message_t>, in memory: FileTypeMemory) {
        let token = message.pointee.process.pointee.audit_token
        let reader = FileReader(uid: audit_token_to_euid(token), gid: audit_token_to_egid(token))
        switch event {
        case .mmap(var mmap):
            guard let file = Self.readable(message.pointee.event.mmap.source) else { return }
            mmap.setFileType(memory.mappedFileType(at: file.path, stat: file.info, for: reader))
            event = .mmap(mmap)
        case .close(var close) where close.modified:
            guard let file = Self.readable(message.pointee.event.close.target) else { return }
            close.setFileType(memory.closedFileType(at: file.path, stat: file.info, for: reader))
            event = .close(close)
        case .rename(var rename):
            let source = message.pointee.event.rename.source
            guard !rename.destination_path.isEmpty, !source.pointee.path_truncated else { return }
            rename.setFileType(memory.renamedFileType(at: rename.destination_path, stat: source.pointee.stat,
                                                      for: reader))
            event = .rename(rename)
        default:
            return
        }
    }

    /// An event's file, when its path can be opened: one Endpoint Security cut short names some other file.
    ///
    /// - Parameter file: The event's file.
    /// - Returns: Its path and stat, or `nil` for a path cut short or none.
    private static func readable(_ file: UnsafeMutablePointer<es_file_t>) -> (path: String, info: stat)? {
        guard !file.pointee.path_truncated, let path = file.pointee.path.string, !path.isEmpty else { return nil }
        return (path, file.pointee.stat)
    }
}


// MARK: - Setting a file type
/// An event with a file whose type is read at capture.
protocol FileTypeEnriched {
    /// What the file's first bytes are.
    var file_type: String? { get set }
    /// A Mach-O's `MH_*` file type.
    var mach_o_type: String? { get set }
}

extension FileTypeEnriched {
    /// Keep a type read from the file.
    ///
    /// - Parameter type: The type, or `nil` when the file wasn't read.
    mutating func setFileType(_ type: FileType?) {
        (file_type, mach_o_type) = (type?.identifier, type?.machOType)
    }
}

extension MMapEvent: FileTypeEnriched {}
extension FileCloseEvent: FileTypeEnriched {}
extension FileRenameEvent: FileTypeEnriched {}
