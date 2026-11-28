//
//  FileScanReader.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/24/26.
//

import Foundation


// MARK: - Reading a file to scan
/// Reads all of a written file for a scan, held to the event's version of it and to what its writer could read, as a
/// file type's read is (``FileTypeReader``).
///
/// The file is opened as ``FileTypeReader`` opens one: no symbolic link anywhere on its path, and the open file's
/// device and inode must be the event's. It must still have the event's size and modification time, so a file written
/// again since is left to the close of that write. Its change time isn't compared: renaming a file into place, as an
/// installer does with a temporary file right after its close, changes it and nothing in the file. A rewrite that puts
/// the old modification time back is still a version of its own, by its change time (``FileScanVersion``). Its bytes
/// are read with `pread` under the no access time, no download policy (``ReadingThreadPolicy``), never mapped: a
/// mapping updates the access time whatever the policy says.
enum FileScanReader {
    /// What a read gave.
    enum Reading {
        /// The file's bytes.
        case bytes(FileScanBuffer)
        /// Why it wasn't read: a ``YaraScan`` status.
        case notRead(String)
    }

    /// Reads a file an event named.
    ///
    /// - Parameters:
    ///   - path: The file's path, as the event names it.
    ///   - info: The event's stat of the file.
    ///   - reader: Who wrote it: the event's process's effective user and group.
    ///   - maxBytes: The largest file read.
    /// - Returns: The bytes, or why they weren't read.
    static func read(_ path: String, stat info: stat, for reader: FileReader, maxBytes: Int) -> Reading {
        guard case .read = FileTypeReader.precheck(info) else { return .notRead(YaraScan.unreadable) }
        guard info.st_size <= off_t(maxBytes) else { return .notRead(YaraScan.tooLarge) }
        return ReadingThreadPolicy.whileReading {
            let descriptor = FileTypeReader.openForReading(path, expecting: info)
            guard descriptor >= 0 else { return .notRead(YaraScan.unreadable) }
            defer { close(descriptor) }
            var opened = stat()
            guard fstat(descriptor, &opened) == 0, opened.st_dev == info.st_dev, opened.st_ino == info.st_ino,
                  opened.st_mode & S_IFMT == S_IFREG else { return .notRead(YaraScan.unreadable) }
            guard isContent(opened, of: info) else { return .notRead(YaraScan.changed) }
            guard reader.canRead(opened, of: descriptor) else { return .notRead(YaraScan.unreadable) }
            guard let buffer = FileScanBuffer(count: Int(opened.st_size)) else { return .notRead(YaraScan.unreadable) }
            switch buffer.fill(from: descriptor) {
            case .some(true): return .bytes(buffer)
            case .some(false): return .notRead(YaraScan.changed)
            case nil: return .notRead(YaraScan.unreadable)
            }
        }
    }
}


// MARK: - The same content
extension FileScanReader {
    /// Does an open file still hold the version an event's stat describes: the same size and modification time?
    ///
    /// - Parameters:
    ///   - info: The open file's `fstat`.
    ///   - expected: The event's stat.
    /// - Returns: Whether both match.
    static func isContent(_ info: stat, of expected: stat) -> Bool {
        info.st_size == expected.st_size
            && info.st_mtimespec.tv_sec == expected.st_mtimespec.tv_sec
            && info.st_mtimespec.tv_nsec == expected.st_mtimespec.tv_nsec
    }
}


// MARK: - A file's bytes
/// Memory for a file's bytes, from `vm_allocate`, so it goes back to the system as soon as the scan is done instead
/// of staying in the extension's heap.
final class FileScanBuffer {
    /// The bytes.
    let pointer: UnsafeMutableRawPointer
    /// How many.
    let count: Int
    /// The pages allocated, at least one.
    private let allocated: vm_size_t

    /// - Parameter count: How many bytes.
    init?(count: Int) {
        let size = vm_size_t(max(count, 1))
        var address: vm_address_t = 0
        guard vm_allocate(mach_task_self_, &address, size, VM_FLAGS_ANYWHERE) == KERN_SUCCESS,
              let pointer = UnsafeMutableRawPointer(bitPattern: UInt(address)) else { return nil }
        self.pointer = pointer
        self.count = count
        allocated = size
    }

    deinit {
        vm_deallocate(mach_task_self_, vm_address_t(UInt(bitPattern: pointer)), allocated)
    }

    /// The bytes, for a scan.
    var bytes: UnsafeRawBufferPointer { UnsafeRawBufferPointer(start: pointer, count: count) }

    /// Fill the buffer from a file's start.
    ///
    /// - Parameter descriptor: The open file.
    /// - Returns: `true` when every byte was read, `false` when the file ended early (it was cut short since), or
    ///   `nil` when a read failed.
    func fill(from descriptor: Int32) -> Bool? {
        var done = 0
        while done < count {
            let read = pread(descriptor, pointer + done, count - done, off_t(done))
            if read < 0, errno == EINTR { continue }
            guard read >= 0 else { return nil }
            guard read > 0 else { return false }
            done += read
        }
        return true
    }
}
