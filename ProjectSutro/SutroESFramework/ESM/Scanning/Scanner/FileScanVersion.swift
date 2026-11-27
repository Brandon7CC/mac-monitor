//
//  FileScanVersion.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/24/26.
//

import Foundation


// MARK: - One version of a file
/// One version of a file, by its stat: device, inode, size, modification time and change time.
///
/// The change time is part of it. A writer can put a file's old modification time back after rewriting it (`touch -r`,
/// `futimes`), which leaves the size and modification time of the old version, but not its change time, which user
/// space can't set. Without it a rewrite would be answered with the old version's result.
struct FileScanVersion: Hashable, Sendable {
    let device: Int32
    let inode: UInt64
    let size: Int64
    let modified: timespec
    let changed: timespec

    /// - Parameter info: An event's stat of the file.
    init(_ info: stat) {
        device = info.st_dev
        inode = info.st_ino
        size = info.st_size
        modified = info.st_mtimespec
        changed = info.st_ctimespec
    }

    /// - Parameter info: The stat an event's model keeps, such as the script an exec's Endpoint Security names.
    init(_ info: Stat) {
        device = Int32(truncatingIfNeeded: info.st_dev)
        inode = UInt64(bitPattern: info.st_ino)
        size = info.st_size
        modified = timespec(tv_sec: info.st_mtimespec.tv_sec, tv_nsec: info.st_mtimespec.tv_nsec)
        changed = timespec(tv_sec: info.st_ctimespec.tv_sec, tv_nsec: info.st_ctimespec.tv_nsec)
    }

    /// The version without its change time.
    var content: FileScanContent {
        FileScanContent(device: device, inode: inode, size: size, seconds: modified.tv_sec,
                        nanoseconds: modified.tv_nsec)
    }

    static func == (left: FileScanVersion, right: FileScanVersion) -> Bool {
        left.content == right.content
            && left.changed.tv_sec == right.changed.tv_sec && left.changed.tv_nsec == right.changed.tv_nsec
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(content)
        hasher.combine(changed.tv_sec)
        hasher.combine(changed.tv_nsec)
    }
}


// MARK: - A version's content
/// A version of a file without its change time: device, inode, size and modification time, as
/// ``FileScanReader/isContent(_:of:)`` compares them.
///
/// An exec looks a script up by it. A `chmod +x`, a quarantine attribute or a rename after the script's close changes
/// its change time and nothing in it, so the close's scan still answers. A rewrite that keeps the size and puts the
/// old modification time back (`touch -r`) closes again, and that close forgets the old answer
/// (``FileScanMemory/forgetContent(changedBy:)``).
struct FileScanContent: Hashable, Sendable {
    let device: Int32
    let inode: UInt64
    let size: Int64
    let seconds: Int
    let nanoseconds: Int
}


// MARK: - Results remembered
/// The results of the latest scans, by version and by the rule files that ran, so another session's lane, a rename
/// after a close, or an exec of a script already scanned gets the answer without a second scan. Bounded: once full,
/// the oldest half is forgotten.
///
/// A result answers a request whose rule files it ran: all of them, or more. A JXA `#!` script's close asks for
/// `XProtect.yara` and also gets `XPScripts.yr` once its first line is read, so it answers the `osascript` exec that
/// asks for both.
///
/// **Threading:** not thread-safe. ``FileScanner`` keeps it under its lock.
struct FileScanMemory {
    /// A result, and the rule files that ran.
    private struct Remembered {
        let files: Set<XProtectRuleFile>
        let result: YaraScan
    }

    /// The most results kept.
    let capacity: Int
    private var results: [FileScanVersion: Remembered] = [:]
    private var order: [FileScanVersion] = []
    /// The latest version whose result describes its content, by content, for lookups that ignore the change time.
    private var latest: [FileScanContent: FileScanVersion] = [:]

    /// - Parameter capacity: The most results kept.
    init(capacity: Int) {
        self.capacity = max(capacity, 2)
    }

    /// The result for a version, if one is remembered that ran the rule files asked for.
    ///
    /// - Parameters:
    ///   - version: The version.
    ///   - files: The rule files asked for. Empty takes a result of any.
    ///   - anyChangeTime: Look the version up by its content alone, as an exec does. Only a result that describes
    ///     the file's content answers then (``YaraScan/describesContent``).
    /// - Returns: The result.
    func result(for version: FileScanVersion, covering files: Set<XProtectRuleFile> = [],
                anyChangeTime: Bool = false) -> YaraScan? {
        guard let key = anyChangeTime ? latest[version.content] : version,
              let remembered = results[key], remembered.files.isSuperset(of: files) else { return nil }
        return remembered.result
    }

    /// Remember a version's result, forgetting the oldest half once full. A result already remembered that ran more
    /// rule files is kept.
    ///
    /// - Parameters:
    ///   - result: The result.
    ///   - files: The rule files that ran.
    ///   - version: The version.
    mutating func remember(_ result: YaraScan, files: Set<XProtectRuleFile>, for version: FileScanVersion) {
        if let known = results[version], known.files.isStrictSuperset(of: files) { return }
        if results.updateValue(Remembered(files: files, result: result), forKey: version) == nil {
            order.append(version)
        }
        if result.describesContent {
            latest[version.content] = version
        } else if latest[version.content] == version {
            latest.removeValue(forKey: version.content)
        }
        guard order.count > capacity else { return }
        let forgotten = order.prefix(order.count - capacity / 2)
        for version in forgotten {
            results.removeValue(forKey: version)
            if latest[version.content] == version { latest.removeValue(forKey: version.content) }
        }
        order.removeFirst(forgotten.count)
    }

    /// Forget what an earlier version with the same content said, for lookups that ignore the change time: a close of
    /// this version wrote it again, maybe with the old size and modification time.
    ///
    /// - Parameter version: The version a close names.
    mutating func forgetContent(changedBy version: FileScanVersion) {
        guard let known = latest[version.content], known != version else { return }
        latest.removeValue(forKey: version.content)
    }

    /// Forget everything.
    mutating func removeAll() {
        results.removeAll()
        order.removeAll()
        latest.removeAll()
    }

    /// How many results are remembered.
    var count: Int { results.count }
}
