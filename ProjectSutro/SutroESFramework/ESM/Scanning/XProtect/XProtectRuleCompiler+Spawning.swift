//
//  XProtectRuleCompiler+Spawning.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/24/26.
//

import Foundation


// MARK: - The parent
extension XProtectRuleCompiler {
    /// Why the child didn't compile the rules.
    enum Failure: Error, Equatable {
        /// It couldn't be started, with `posix_spawn`'s error.
        case notStarted(Int32)
        /// It ran past its time and was killed.
        case timedOut
        /// It ended without compiling: the status it ended with, or 128 plus the signal, and what it reported.
        case ended(status: Int32, diagnostics: [YaraDiagnostic])
    }

    /// The most diagnostics output read from the child.
    static let maxDiagnosticBytes = 1 << 20

    /// The child's environment: nothing of the extension's.
    static let environment = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin"]

    /// Compiles rule text in a child process, which writes the compiled rules to `output`.
    ///
    /// Blocks until the child ends, so call it off any queue that mustn't wait. Spawned with `posix_spawn` and
    /// waited for with `waitpid`, as ``ToolRunner`` is, and the child inherits no descriptor but its three.
    ///
    /// - Parameters:
    ///   - text: The rule text.
    ///   - output: The open file the compiled rules are written to, at its current offset.
    ///   - executable: The child's executable: the Security Extension's own.
    ///   - timeout: How long the child may take before it's killed.
    /// - Returns: The compiler's warnings.
    /// - Throws: ``Failure`` when the rules weren't compiled.
    static func compile(_ text: Data, into output: Int32, executable: String,
                        timeout: TimeInterval = 30) throws -> [YaraDiagnostic] {
        let input = Pipe(), errors = Pipe()
        /// A child that ends before reading its input makes the write fail instead of raising `SIGPIPE`.
        _ = fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1)

        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        posix_spawn_file_actions_adddup2(&actions, input.fileHandleForReading.fileDescriptor, STDIN_FILENO)
        posix_spawn_file_actions_adddup2(&actions, output, STDOUT_FILENO)
        posix_spawn_file_actions_adddup2(&actions, errors.fileHandleForWriting.fileDescriptor, STDERR_FILENO)
        var attributes: posix_spawnattr_t?
        posix_spawnattr_init(&attributes)
        defer { posix_spawnattr_destroy(&attributes) }
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT))

        let argv = [executable, argument].map { strdup($0) } + [nil]
        let envp = environment.map { strdup($0) } + [nil]
        defer { (argv + envp).forEach { free($0) } }
        var pid: pid_t = 0
        let spawned = posix_spawn(&pid, executable, &actions, &attributes, argv, envp)
        try? input.fileHandleForReading.close()
        try? errors.fileHandleForWriting.close()
        guard spawned == 0 else {
            try? input.fileHandleForWriting.close()
            throw Failure.notStarted(spawned)
        }

        let killed = Killed()
        let deadline = DispatchWorkItem { killed.kill(pid) }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout, execute: deadline)
        /// The input is written while the diagnostics are read, so neither pipe can fill and stall the other.
        let written = DispatchGroup()
        DispatchQueue.global(qos: .utility).async(group: written) {
            _ = text.writeAll(to: input.fileHandleForWriting.fileDescriptor)
            try? input.fileHandleForWriting.close()
        }
        let reported = errors.fileHandleForReading.readAll(upTo: maxDiagnosticBytes) ?? Data()
        written.wait()
        var status: Int32 = 0
        while waitpid(pid, &status, 0) == -1 && errno == EINTR {}
        deadline.cancel()

        let signal = status & 0x7f
        let code = signal == 0 ? (status >> 8) & 0xff : 128 + signal
        /// Killed by the deadline, not a child that ended on its own just before it.
        if killed.didKill && signal == SIGKILL { throw Failure.timedOut }
        let diagnostics = parse(reported)
        guard code == Status.compiled.rawValue else { throw Failure.ended(status: code, diagnostics: diagnostics) }
        return diagnostics
    }

    /// The diagnostics the child reported, one JSON object per line. A line that isn't one is left out.
    ///
    /// - Parameter data: The child's standard error.
    /// - Returns: The diagnostics.
    static func parse(_ data: Data) -> [YaraDiagnostic] {
        let decoder = JSONDecoder()
        return data.split(separator: UInt8(ascii: "\n")).compactMap { line in
            try? decoder.decode(YaraDiagnostic.self, from: line)
        }
    }

    /// Whether the deadline killed the child, set once from the timer's queue.
    private final class Killed: @unchecked Sendable {
        private let lock = NSLock()
        private var killed = false

        /// Kills the child and remembers it.
        ///
        /// - Parameter pid: The child.
        func kill(_ pid: pid_t) {
            lock.lock()
            defer { lock.unlock() }
            killed = Darwin.kill(pid, SIGKILL) == 0
        }

        /// Did the deadline kill it?
        var didKill: Bool {
            lock.lock()
            defer { lock.unlock() }
            return killed
        }
    }
}
