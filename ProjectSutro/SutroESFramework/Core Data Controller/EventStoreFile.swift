//
//  EventStoreFile.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Event store files
/// The event store's files on disk: one store per running Mac Monitor, each claimed with a lock.
///
/// Every process gets its own SQLite store in the caches folder and holds an exclusive `flock` on a `.lock` file beside it
/// for as long as it runs. A second copy of Mac Monitor (`open -n`, or a development build with the same bundle ID) gets a
/// store of its own instead of deleting the first one's trace. A store whose lock can be taken belongs to a process that
/// has quit or crashed, so it's deleted.
struct EventStoreFile {
    /// The store's SQLite file.
    let url: URL
    
    private static let prefix = "Events"
    private static let storeSuffixes = [".sqlite", ".sqlite-wal", ".sqlite-shm"]
    
    /// Claim `Events.sqlite`, or a store of its own if another Mac Monitor has that one, then delete every store left by a
    /// process that's gone (including this store's, from a run that crashed).
    ///
    /// - Parameter directory: Mac Monitor's caches folder.
    /// - Returns: `nil` if no store could be claimed (for example, the folder can't be written).
    init?(in directory: URL) {
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        guard let name = [Self.prefix, "\(Self.prefix)-\(UUID().uuidString)"].first(where: { Self.claim($0, in: directory) != nil }) else { return nil }
        url = directory.appendingPathComponent(name + ".sqlite")
        Self.removeStore(name, in: directory)
        
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        let stores = Set(names.compactMap { file in
            (Self.storeSuffixes + [".lock"]).first { file.hasPrefix(Self.prefix) && file.hasSuffix($0) }.map { String(file.dropLast($0.count)) }
        })
        for store in stores where store != name {
            /// Still claimed: another Mac Monitor is using it.
            guard let lock = Self.claim(store, in: directory) else { continue }
            Self.removeStore(store, in: directory)
            unlink(directory.appendingPathComponent(store + ".lock").path)
            close(lock)
        }
    }
    
    /// Delete this store's files, and its lock, at quit.
    ///
    /// Only the names go: the open connections keep working on the files until the process exits, so a save that lands
    /// meanwhile can't hit a store that's been taken away (which raises an exception Swift can't catch).
    func delete() {
        let directory = url.deletingLastPathComponent(), name = url.deletingPathExtension().lastPathComponent
        Self.removeStore(name, in: directory)
        unlink(directory.appendingPathComponent(name + ".lock").path)
    }
    
    /// Take the lock on store `name`, if no running process holds it.
    ///
    /// The lock is never released: the kernel drops it when the process exits.
    ///
    /// - Parameters:
    ///   - name: The store's name, without extension.
    ///   - directory: The caches folder.
    /// - Returns: The locked file descriptor, or `nil` if another process holds the lock (or it couldn't be taken).
    @discardableResult
    private static func claim(_ name: String, in directory: URL) -> Int32? {
        let path = directory.appendingPathComponent(name + ".lock").path
        let lock = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard lock >= 0 else { return nil }
        /// Another launch may have deleted the lock file between `open` and `flock`; a lock on a deleted file guards nothing.
        var held = stat(), current = stat()
        guard flock(lock, LOCK_EX | LOCK_NB) == 0, fstat(lock, &held) == 0, stat(path, &current) == 0,
              held.st_dev == current.st_dev, held.st_ino == current.st_ino else {
            close(lock)
            return nil
        }
        return lock
    }
    
    /// Delete store `name`'s SQLite files, if they exist.
    ///
    /// - Parameters:
    ///   - name: The store's name, without extension.
    ///   - directory: The caches folder.
    private static func removeStore(_ name: String, in directory: URL) {
        for suffix in storeSuffixes { unlink(directory.appendingPathComponent(name + suffix).path) }
    }
}
