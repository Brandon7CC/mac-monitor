//
//  FileScanJob.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/26/26.
//

import Foundation


// MARK: - What's scanned
extension FileScanner {
    /// One file to scan: where its bytes come from, its version, and the rule files to run.
    struct Job {
        /// Where a job's bytes come from.
        enum Source {
            /// The file, read on the scan queue as its writer or runner could read it (``FileScanReader``).
            case file(path: String, info: stat, reader: FileReader)
            /// Bytes read already, as the lane reads all of an exec's script for its `script_content`.
            case bytes(Data)
            /// Nothing to read: a script Endpoint Security names that the lane couldn't read. Only a remembered
            /// result answers it.
            case unread
        }

        /// Where its bytes come from.
        let source: Source
        /// The version scanned.
        let version: FileScanVersion
        /// The rule files to run. A script that `osascript` runs gets `XPScripts.yr` too once it's read
        /// (``FileScanKind/ruleFiles(_:reading:)``).
        let files: Set<XProtectRuleFile>
        /// Look the version up ignoring its change time, as an exec does (``FileScanContent``)?
        let anyChangeTime: Bool

        /// A file to read.
        ///
        /// - Parameters:
        ///   - path: The file's path with no symbolic link, as an event names it.
        ///   - info: The event's stat of the file.
        ///   - reader: Who wrote it, or who runs it.
        ///   - files: The rule files its type gets.
        ///   - anyChangeTime: Look it up ignoring its change time, as an exec does.
        init(path: String, info: stat, reader: FileReader, files: Set<XProtectRuleFile>, anyChangeTime: Bool = false) {
            source = .file(path: path, info: info, reader: reader)
            version = FileScanVersion(info)
            self.files = files
            self.anyChangeTime = anyChangeTime
        }

        /// All of an exec's script, read already. It's looked up ignoring its change time. Its first line is read only
        /// when it's scanned, so a script already scanned costs a lookup.
        ///
        /// - Parameters:
        ///   - bytes: Every byte of the file.
        ///   - info: The open file's `fstat`.
        ///   - files: The rule files its interpreter gets.
        init(bytes: Data, info: stat, files: Set<XProtectRuleFile>) {
            source = .bytes(bytes)
            version = FileScanVersion(info)
            self.files = files
            anyChangeTime = true
        }

        /// A script Endpoint Security names that wasn't read. It's looked up ignoring its change time.
        ///
        /// - Parameters:
        ///   - version: The version Endpoint Security's stat names.
        ///   - files: The rule files its interpreter gets.
        init(unread version: FileScanVersion, files: Set<XProtectRuleFile>) {
            source = .unread
            self.version = version
            self.files = files
            anyChangeTime = true
        }

        /// The bytes the budget admits it by: the file's size, or the bytes read.
        var size: Int {
            switch source {
            case .file(_, let info, _): return Int(info.st_size)
            case .bytes(let bytes): return bytes.count
            case .unread: return 0
            }
        }
    }

    /// What ``submit(_:answer:)`` says at once.
    enum Submission: Equatable {
        /// The answer, now: remembered, or why it won't be scanned.
        case answered(YaraScan)
        /// The scan is queued. `answer` is called once it's done.
        case queued
    }

    /// A scan queued or running, and who waits for it.
    struct Pending {
        /// The rule files it runs: those its job asked for.
        let files: Set<XProtectRuleFile>
        /// Called with its result.
        var answers: [(YaraScan) -> Void]
    }
}
