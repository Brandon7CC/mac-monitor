//
//  ToolRunner.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/27/26.
//

import Foundation


// MARK: - Tool runner
/// Runs a command line tool to completion and captures one of its output streams.
///
/// Spawned with `posix_spawn` and waited for with `waitpid`, not `Process`. In the Security Extension on macOS 13,
/// `Process.waitUntilExit()` spun forever after `spctl` had exited: the task never saw the exit. Nothing here depends on
/// a run loop or a notification.
public enum ToolRunner {
    /// Which output stream to capture. The other goes to `/dev/null`, as standard input comes from it.
    public enum Stream: Sendable {
        case standardOutput
        case standardError
    }

    /// Run a tool and wait for it. Blocks, so call it off the main thread.
    ///
    /// The captured stream is read to its end before waiting, so a chatty tool can't fill the pipe and stall. The tool
    /// inherits no other file descriptor.
    ///
    /// - Parameters:
    ///   - tool: Absolute path to the executable.
    ///   - arguments: Its arguments.
    ///   - stream: The stream to capture.
    /// - Returns: Its exit status, or 128 plus the signal that ended it, and the captured output.
    /// - Throws: A `POSIXError` when the tool can't be spawned.
    public static func run(_ tool: String, _ arguments: [String],
                           capturing stream: Stream) throws -> (status: Int32, output: Data) {
        let pipe = Pipe()
        let captured = stream == .standardOutput ? STDOUT_FILENO : STDERR_FILENO
        let discarded = stream == .standardOutput ? STDERR_FILENO : STDOUT_FILENO

        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_adddup2(&actions, pipe.fileHandleForWriting.fileDescriptor, captured)
        posix_spawn_file_actions_addopen(&actions, discarded, "/dev/null", O_WRONLY, 0)

        var attributes: posix_spawnattr_t?
        posix_spawnattr_init(&attributes)
        defer { posix_spawnattr_destroy(&attributes) }
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT))

        let argv = ([tool] + arguments).map { strdup($0) } + [nil]
        defer { argv.forEach { free($0) } }
        var pid: pid_t = 0
        let spawned = posix_spawn(&pid, tool, &actions, &attributes, argv, environ)
        try? pipe.fileHandleForWriting.close()
        guard spawned == 0 else { throw POSIXError(POSIXErrorCode(rawValue: spawned) ?? .EINVAL) }

        let output = pipe.fileHandleForReading.readDataToEndOfFile()
        var status: Int32 = 0
        while waitpid(pid, &status, 0) == -1 && errno == EINTR {}
        let signal = status & 0x7f
        return (signal == 0 ? (status >> 8) & 0xff : 128 + signal, output)
    }
}
