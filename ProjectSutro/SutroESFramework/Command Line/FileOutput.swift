//
//  FileOutput.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - File output
/// Writes to a file descriptor with `write(2)`, such as `macmonitor`'s standard output: no buffering, so each batch is
/// on its way, whole, before the Security Extension sends the next.
///
/// A write is retried after `EINTR` and continued after a partial write, so a reader never sees half an event. `EPIPE`
/// (`| head` has its lines) is ``StreamOutputError/closed``, which needs `SIGPIPE` ignored or `F_SETNOSIGPIPE` set.
public final class FileOutput: StreamOutput {
    /// The descriptor written to. Not closed by this object.
    public let descriptor: Int32
    
    /// - Parameter descriptor: An open descriptor, such as `STDOUT_FILENO`.
    public init(descriptor: Int32) {
        self.descriptor = descriptor
    }
    
    /// Write all of `data`, blocking for as long as the reader takes.
    ///
    /// - Parameter data: The bytes.
    /// - Throws: ``StreamOutputError/closed`` for `EPIPE`, ``StreamOutputError/failed(_:)`` for any other error.
    public func write(_ data: Data) throws {
        switch data.writeAll(to: descriptor) {
        case nil: return
        case EPIPE?: throw StreamOutputError.closed
        case let code?: throw StreamOutputError.failed(code)
        }
    }
    
    /// Write one line to standard error, ignoring failure: diagnostics must never stop a stream.
    ///
    /// - Parameter line: The line, without its newline.
    public static func writeError(_ line: String) {
        try? FileOutput(descriptor: STDERR_FILENO).write(Data((line + "\n").utf8))
    }
}
