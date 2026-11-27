//
//  Message+YaraScan.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
import EndpointSecurity


// MARK: - Scanning a written file or a script
extension Message {
    /// Ask the scanner for the scan this event's file needs (Security Extension context): a modified close's, a
    /// rename's that moves a file scanned at its close, or the script an exec runs
    /// (``ProcessExecEvent/scanJob(of:volumes:)``). A close's or a rename's file is scanned only when it's of a kind
    /// ``FileScanKind`` scans, whose type was read (``identifyFileType(of:in:)``, so call that first). A modified
    /// close of any other file still forgets what an exec of its content was answered with
    /// (``FileScanner/forgetContent(changedBy:)``), as `bash notes.txt` runs a script of any name.
    ///
    /// The answer goes on the event when the scanner has it now: remembered, or why the file isn't scanned. When
    /// the scan is queued, the lane holds the event for it (``EventHold``). A rename only follows a close's scan,
    /// and starts none of its own: renaming a file changes nothing in it. An exec's script read is taken off the
    /// event whether it's scanned or not, so the bytes never wait in a hold.
    ///
    /// A ticket is made only for an event the scanner is asked about, so every other event allocates nothing.
    ///
    /// - Parameters:
    ///   - message: The message. Only valid during the call.
    ///   - scanner: The scanner, or `nil` on a lane that doesn't scan.
    ///   - volumes: The lane's local volumes.
    /// - Returns: Where the answer will come, when the scan is queued.
    mutating func requestYaraScan(of message: UnsafePointer<es_message_t>, from scanner: FileScanner?,
                                  volumes: LocalVolumes) -> FileScanTicket? {
        let read = takeScriptRead()
        guard let scanner, let request = scanRequest(of: message, read: read, from: scanner, volumes: volumes) else {
            return nil
        }
        let ticket = FileScanTicket()
        let submission: FileScanner.Submission?
        switch request {
        case .submit(let job): submission = scanner.submit(job, answer: ticket.deliver)
        case .follow(let version): submission = scanner.follow(version, answer: ticket.deliver)
        }
        switch submission {
        case .answered(let scan)?:
            setYaraScan(scan)
            return nil
        case .queued?:
            return ticket
        case nil:
            return nil
        }
    }

    /// What an event asks the scanner for.
    private enum ScanRequest {
        /// A file to scan, or to answer from memory.
        case submit(FileScanner.Job)
        /// The scan a close asked for, which a rename follows.
        case follow(FileScanVersion)
    }

    /// What to ask the scanner for this event's file, if anything. A modified close of a file that isn't scanned
    /// forgets what an exec of its content was answered with instead.
    ///
    /// - Parameters:
    ///   - message: The message. Only valid during the call.
    ///   - read: What the lane read of an exec's script.
    ///   - scanner: The scanner.
    ///   - volumes: The lane's local volumes.
    /// - Returns: The request, or `nil` for an event whose file isn't scanned.
    private func scanRequest(of message: UnsafePointer<es_message_t>, read: ScriptRead?, from scanner: FileScanner,
                             volumes: LocalVolumes) -> ScanRequest? {
        switch event {
        case .close(let close) where close.modified:
            let info = message.pointee.event.close.target.pointee.stat
            guard let files = FileScanKind.ruleFiles(fileType: close.file_type, machOType: close.mach_o_type,
                                                     path: close.target.path) else {
                scanner.forgetContent(changedBy: FileScanVersion(info))
                return nil
            }
            let token = message.pointee.process.pointee.audit_token
            return .submit(FileScanner.Job(path: close.target.path, info: info,
                                           reader: FileReader(uid: audit_token_to_euid(token),
                                                              gid: audit_token_to_egid(token)),
                                           files: files))
        case .rename(let rename):
            guard FileScanKind.ruleFiles(fileType: rename.file_type, machOType: rename.mach_o_type,
                                         path: rename.destination_path) != nil else { return nil }
            return .follow(FileScanVersion(message.pointee.event.rename.source.pointee.stat))
        case .exec(let exec):
            guard let job = exec.scanJob(of: read, volumes: volumes) else { return nil }
            return .submit(job)
        default:
            return nil
        }
    }

    /// Take an exec's script read off it, so the bytes never wait in a hold.
    ///
    /// - Returns: The read, or `nil` for another event or an exec that read none.
    private mutating func takeScriptRead() -> ScriptRead? {
        guard case .exec(var exec) = event, let read = exec.scriptRead else { return nil }
        exec.scriptRead = nil
        event = .exec(exec)
        return read
    }

    /// Put a scan on a close, a rename or an exec.
    ///
    /// - Parameter scan: The scan, or `nil` for none.
    mutating func setYaraScan(_ scan: YaraScan?) {
        switch event {
        case .close(var close):
            close.yara_scan = scan
            event = .close(close)
        case .rename(var rename):
            rename.yara_scan = scan
            event = .rename(rename)
        case .exec(var exec):
            exec.yara_scan = scan
            event = .exec(exec)
        default:
            return
        }
    }
}
