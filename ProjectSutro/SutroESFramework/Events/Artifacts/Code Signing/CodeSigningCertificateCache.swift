//
//  CodeSigningCertificateCache.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import os


// MARK: - Code signing certificate cache
/// Remembers the code signing certificates read from each executable, so they're read once per file rather than once
/// per event.
///
/// Reading them (`SecCodeCopySigningInformation` with `kSecCSSigningInformation`) verifies the CMS signature and its
/// timestamp, and evaluates trust with a synchronous call to `trustd`: about 1.5 ms of wall time (0.8 ms of CPU) for
/// Google Chrome. A validly signed third-party process's code signing type comes from its certificates, so every event
/// of every such process paid it, and every exec read the new image's chain.
///
/// **Freshness:** the key is the path plus a `stat(2)` of it taken on every lookup (device, inode, size, and change and
/// modification times), so a file that was rewritten or replaced is read again, as it was before. An entry is used for
/// ``lifetime`` after it was read, which bounds how long a change of trust (a revoked or expired certificate) goes
/// unseen. A path that can't be `stat`ed, or a signature that can't be read, isn't remembered.
///
/// **Threading:** safe on any thread. Every capture lane of every session shares ``shared``. Certificates are read
/// outside the lock, so a lane never waits for another's read; two lanes missing the same file at once both read it.
final class CodeSigningCertificateCache {
    /// A file at a path, as `stat(2)` describes it: any change to the file's contents changes its identity.
    struct FileIdentity: Hashable {
        let path: String
        let device: Int32
        let inode: UInt64
        let size: Int64
        let changedSeconds: Int, changedNanoseconds: Int
        let modifiedSeconds: Int, modifiedNanoseconds: Int
        
        /// The identity of the file at a path now, following symbolic links as reading its signature does.
        ///
        /// - Parameter path: The file's path.
        /// - Returns: The identity, or `nil` if the path can't be `stat`ed.
        init?(path: String) {
            var info = stat()
            guard stat(path, &info) == 0 else { return nil }
            self.path = path
            device = info.st_dev
            inode = info.st_ino
            size = info.st_size
            changedSeconds = info.st_ctimespec.tv_sec
            changedNanoseconds = info.st_ctimespec.tv_nsec
            modifiedSeconds = info.st_mtimespec.tv_sec
            modifiedNanoseconds = info.st_mtimespec.tv_nsec
        }
    }
    
    /// A file's certificates, and when they were read.
    private struct Entry {
        let certificates: [X509Cert]
        /// Uptime in nanoseconds.
        let readAt: UInt64
    }
    
    /// The cache the Security Extension's capture lanes share, reading with
    /// ``ProcessHelpers/readCodeSigningCerts(forBinaryAt:)``.
    static let shared = CodeSigningCertificateCache()
    
    /// How long an entry is used after its file was read, in nanoseconds.
    let lifetime: UInt64
    /// How many files' certificates are kept: at this many, the table is emptied before the next one is added.
    let capacity: Int
    /// Reads a file's certificates: `nil` if its signature can't be read.
    private let read: (String) -> [X509Cert]?
    /// The time now, in nanoseconds.
    private let clock: () -> UInt64
    /// The certificates, by file.
    private let entries = OSAllocatedUnfairLock(uncheckedState: [FileIdentity: Entry]())
    
    /// An empty cache.
    ///
    /// - Parameters:
    ///   - lifetime: How long an entry is used after its file was read, in seconds.
    ///   - capacity: How many files' certificates to keep before emptying the table.
    ///   - read: Reads a file's certificates, returning `nil` if its signature can't be read.
    ///   - clock: The time now in nanoseconds; uptime by default.
    init(lifetime: TimeInterval = 600, capacity: Int = 1_024,
         read: @escaping (String) -> [X509Cert]? = ProcessHelpers.readCodeSigningCerts(forBinaryAt:),
         clock: @escaping () -> UInt64 = { clock_gettime_nsec_np(CLOCK_UPTIME_RAW) }) {
        self.lifetime = UInt64(lifetime * 1e9)
        self.capacity = capacity
        self.read = read
        self.clock = clock
    }
    
    /// The certificates of the executable at a path, leaf first: the ones remembered if this file's were read within
    /// ``lifetime``, otherwise read now.
    ///
    /// - Parameter path: The executable's path.
    /// - Returns: The certificates, or none if they can't be read.
    func certificates(at path: String) -> [X509Cert] {
        guard let file = FileIdentity(path: path) else { return read(path) ?? [] }
        let now = clock()
        if let entry = entries.withLockUnchecked({ $0[file] }), now &- entry.readAt < lifetime {
            return entry.certificates
        }
        guard let certificates = read(path) else { return [] }
        entries.withLockUnchecked { table in
            if table.count >= capacity, table[file] == nil { table.removeAll(keepingCapacity: true) }
            table[file] = Entry(certificates: certificates, readAt: now)
        }
        return certificates
    }
    
    /// How many files' certificates are remembered.
    var count: Int {
        entries.withLockUnchecked { $0.count }
    }
}
