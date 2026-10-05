//
//  MuteCommand.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import os


// MARK: - Mute command
/// `macmonitor mute ...` (command line context): one request about the saved mute set, and what to write about the
/// Security Extension's answer.
///
/// The Security Extension never reads a file: `import` reads it here, as root, with ``MuteFileReader`` (Mac Monitor's
/// mute files and the lists exported before 2.2), says what was left out, and sends the mutes. `export` writes the
/// saved set to standard output, so the shell creates the file, as the user.
///
/// `import` and `reset` replace or grow the set Mac Monitor and every stream follow, so they say what they'd change
/// and ask first, unless given `--yes` (see `MuteCommand+Confirmation.swift`).
public final class MuteCommand {
    let client: StreamClient
    private let output: StreamOutput
    /// Writes one line to standard error.
    private let diagnose: (String) -> Void
    /// The last notice said, so asking first and answering don't say it twice.
    private let saidNotice = OSAllocatedUnfairLock<String?>(initialState: nil)
    /// Asks the user a yes-or-no question: `true` for yes, `false` for no, `nil` with no terminal to ask at.
    let confirm: (String) -> Bool?
    /// Reads a file to import, or standard input for `-`.
    private let readFile: (String) throws -> Data
    /// Who's logged in at the console, as the Security Extension will find them when `reset` makes the default set.
    private let consoleUser: () -> ConsoleUser?
    
    /// - Parameters:
    ///   - client: The connection to the Security Extension, activated.
    ///   - output: Standard output.
    ///   - diagnose: Writes one line to standard error.
    ///   - confirm: Asks the user a yes-or-no question, such as ``TerminalPrompt/ask(_:)``. By default there's no
    ///     one to ask, so `import` and `reset` need `--yes`.
    ///   - readFile: Reads a file to import, or standard input for `-`.
    ///   - consoleUser: Who's logged in at the console, whose home folder the default set `reset` asks about mutes:
    ///     the system's answer, unless a test passes its own.
    public init(client: StreamClient, output: StreamOutput, diagnose: @escaping (String) -> Void,
                confirm: @escaping (String) -> Bool? = { _ in nil },
                readFile: @escaping (String) throws -> Data = MuteCommand.readImport,
                consoleUser: @escaping () -> ConsoleUser? = { ConsoleUser.current() }) {
        self.client = client
        self.output = output
        self.diagnose = diagnose
        self.confirm = confirm
        self.readFile = readFile
        self.consoleUser = consoleUser
    }
    
    /// Run one mute command.
    ///
    /// - Parameters:
    ///   - invocation: The command.
    ///   - completion: Called once, on any thread: success, or why not.
    public func run(_ invocation: MuteInvocation, completion: @escaping (Result<Void, CommandLineFailure>) -> Void) {
        let request: MuteRequest
        var change: PendingChange?
        switch invocation {
        case .list, .export:
            request = MuteRequest(.list)
        case .add(let entry):
            request = MuteRequest(.add, [entry])
        case .remove(let entry):
            request = MuteRequest(.remove, [entry])
        case .reset(let confirmed):
            request = MuteRequest(.reset)
            change = confirmed ? nil : .reset(for: consoleUser())
        case .importFile(let path, let merge, let confirmed):
            do {
                let list = try importList(from: path)
                request = MuteRequest(merge ? .add : .replace, MuteFile(list).mutes)
                change = confirmed ? nil : .importing(list, from: path == "-" ? "standard input" : Self.name(path),
                                                      merging: merge)
            } catch {
                return completion(.failure(error as? CommandLineFailure ?? CommandLineFailure(.software, "\(error)")))
            }
        }
        let send = { [self] in
            client.send(request, timeout: .seconds(10)) { [self] result in
                completion(result.flatMap { finish(invocation, with: $0) })
            }
        }
        guard let change else { return send() }
        ask(about: change, then: send, otherwise: completion)
    }
    
    /// A file's usable mutes, for an import. What was left out goes to standard error.
    ///
    /// - Parameter path: The file, or `-` for standard input.
    /// - Returns: The mutes, merged by path and type.
    /// - Throws: ``CommandLineFailure``: 66 for a file that can't be read, 65 for one with no usable mutes.
    private func importList(from path: String) throws -> MuteList {
        let name = path == "-" ? "Standard input" : Self.name(path)
        let data: Data
        do {
            data = try readFile(path)
        } catch {
            throw CommandLineFailure(.noInput, "\(name) couldn't be read: \(Self.reason(error)).")
        }
        let imported: MuteImport
        do {
            imported = try MuteFileReader.read(data)
        } catch {
            throw CommandLineFailure(.dataError, "\(name) couldn't be imported. \(error)")
        }
        imported.warnings.forEach { diagnose("macmonitor: \(TerminalSafeText.text($0))") }
        guard !imported.list.isEmpty else {
            throw CommandLineFailure(.dataError, """
                \(name) has no mutes Mac Monitor can use. The saved set is unchanged.
                """)
        }
        return imported.list
    }
    
    /// A file's name for a message, quoted and escaped for a terminal.
    ///
    /// - Parameter path: The file.
    /// - Returns: Such as “mutes.json”.
    static func name(_ path: String) -> String {
        "“\(TerminalSafeText.text(path))”"
    }
    
    /// Report an answer: the notice and warnings on standard error, the result on standard output.
    ///
    /// - Parameters:
    ///   - invocation: The command.
    ///   - reply: The Security Extension's answer.
    /// - Returns: Success, or why not.
    private func finish(_ invocation: MuteInvocation, with reply: MuteReply) -> Result<Void, CommandLineFailure> {
        say(reply.notice)
        if let failure = CommandLineFailure.reply(reply) { return .failure(failure) }
        reply.problems.forEach { diagnose("macmonitor: \(TerminalSafeText.text($0))") }
        let count = String.counted(reply.mutes.count, "mute")
        let text: String
        switch invocation {
        case .list(.text):
            text = MuteTable.text(reply.mutes)
        case .list(.json), .export:
            return write(MuteFile(mutes: reply.mutes).encoded())
        case .reset:
            text = "The saved mute set is Mac Monitor's default set again: \(count).\n"
        case .add(let entry):
            text = "\(reply.changed ? "Muted" : "Already muted:") \(MuteTable.describe(entry)). \(count) now.\n"
        case .remove(let entry):
            text = "\(reply.changed ? "Unmuted" : "Wasn't muted:") \(MuteTable.describe(entry)). \(count) now.\n"
        case .importFile(_, let merge, _):
            let verb = merge ? "Added the file's mutes to the saved set" : "Replaced the saved set with the file's"
            text = "\(reply.changed ? verb : "The saved set already had them"): \(count) now.\n"
        }
        return write(Data(text.utf8))
    }
    
    /// Say the Security Extension's notice about the saved set on standard error, unless it was just said.
    ///
    /// - Parameter notice: The notice, if the answer had one.
    func say(_ notice: String?) {
        guard let notice, saidNotice.withLock({ said in defer { said = notice }; return said != notice }) else {
            return
        }
        diagnose("macmonitor: \(TerminalSafeText.text(notice))")
    }
    
    /// Write to standard output. A closed pipe is a success.
    ///
    /// - Parameter data: The bytes.
    /// - Returns: Success, or the output failure.
    private func write(_ data: Data) -> Result<Void, CommandLineFailure> {
        do {
            try output.write(data)
        } catch StreamOutputError.failed(let code) {
            return .failure(.output(code))
        } catch {
            /// `.closed`: the reader has what it wanted.
        }
        return .success(())
    }
}


// MARK: - Reading a file to import
extension MuteCommand {
    /// Read a file to import: a regular file, never a device or a pipe that could hang, or standard input for `-`,
    /// at most one byte past ``MuteLimits/maxFileBytes`` so a larger one is reported as too large.
    ///
    /// - Parameter path: The path, or `-`.
    /// - Returns: The bytes.
    /// - Throws: A `POSIXError`, or `CocoaError(.fileReadUnsupportedScheme)` for something that isn't a regular file.
    public static func readImport(_ path: String) throws -> Data {
        guard path != "-" else {
            return try FileHandle.standardInput.read(upToCount: MuteLimits.maxFileBytes + 1) ?? Data()
        }
        let descriptor = open(path, O_RDONLY | O_NONBLOCK)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var status = stat()
        guard fstat(descriptor, &status) == 0, status.st_mode & S_IFMT == S_IFREG else {
            throw CocoaError(.fileReadUnsupportedScheme)
        }
        return try file.read(upToCount: MuteLimits.maxFileBytes + 1) ?? Data()
    }
    
    /// Why a file couldn't be read, in a few words.
    ///
    /// - Parameter error: The error.
    /// - Returns: Such as "No such file or directory".
    static func reason(_ error: Error) -> String {
        if let posix = error as? POSIXError { return String(cString: strerror(posix.code.rawValue)) }
        if (error as? CocoaError)?.code == .fileReadUnsupportedScheme { return "it isn't a regular file" }
        return error.localizedDescription
    }
}
