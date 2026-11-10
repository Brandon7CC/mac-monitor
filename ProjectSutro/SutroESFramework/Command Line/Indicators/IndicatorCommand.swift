//
//  IndicatorCommand.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
import os


// MARK: - Indicator command
/// `macmonitor indicators ...` (command line context): one change to the Mac's indicator set, or a look at it, and
/// what to write about the Security Extension's answer.
///
/// The Security Extension never reads a file: `import` reads it here, as the user running `macmonitor` (root, unless
/// Settings allows changes without `sudo`), at most ``IndicatorLimits/maxFileBytes``, and sends the indicators.
/// `export` writes the set, or the indicators it names, to standard output, so the shell creates the file, as the
/// user. `remove`, `enable`, `disable` and `edit` list the set first to find each indicator by its ID or name, then
/// send identities; `edit` sends only the fields it changes (see `IndicatorCommand+Edit.swift`).
///
/// `import` and `edit --file` change the set Mac Monitor and every stream run from a file, so they say what they
/// would change and ask first, unless given `--yes` (see `IndicatorCommand+Confirmation.swift`). Every name, reason
/// and notice the Security Extension sends is escaped for a terminal.
public final class IndicatorCommand {
    let client: StreamClient
    let output: StreamOutput
    /// Writes one line to standard error.
    let diagnose: (String) -> Void
    /// The last notice said, so asking first and answering don't say it twice.
    private let saidNotice = OSAllocatedUnfairLock<String?>(initialState: nil)
    /// Asks the user a yes-or-no question: `true` for yes, `false` for no, `nil` with no terminal to ask at.
    let confirm: (String) -> Bool?
    /// Reads a file to import or edit from, or standard input for `-`.
    private let readFile: (String) throws -> Data
    /// Writes indicators as an indicator file, for `export` and `list --format json`.
    private let encode: ([Indicator]) throws -> Data
    /// How long to wait for each answer. A Security Extension older than 3.1 cuts the connection off at the request;
    /// the timeout covers one that never answers.
    let timeout: DispatchTimeInterval

    /// - Parameters:
    ///   - client: The connection to the Security Extension, activated.
    ///   - output: Standard output.
    ///   - diagnose: Writes one line to standard error.
    ///   - confirm: Asks the user a yes-or-no question, such as ``TerminalPrompt/ask(_:)``. By default there's no
    ///     one to ask, so `import` needs `--yes`.
    ///   - readFile: Reads a file to import, or standard input for `-`.
    ///   - encode: Writes indicators as an indicator file: ``IndicatorExchange/data(of:)`` unless given.
    ///   - timeout: How long to wait for each answer: 10 seconds unless given.
    public init(client: StreamClient, output: StreamOutput, diagnose: @escaping (String) -> Void,
                confirm: @escaping (String) -> Bool? = { _ in nil },
                readFile: @escaping (String) throws -> Data = IndicatorCommand.readImport,
                encode: @escaping ([Indicator]) throws -> Data = IndicatorExchange.data(of:),
                timeout: DispatchTimeInterval = .seconds(10)) {
        self.client = client
        self.output = output
        self.diagnose = diagnose
        self.confirm = confirm
        self.readFile = readFile
        self.encode = encode
        self.timeout = timeout
    }

    /// Run one indicator command.
    ///
    /// - Parameters:
    ///   - invocation: The command.
    ///   - completion: Called once, on any thread: success, or why not.
    public func run(_ invocation: IndicatorInvocation,
                    completion: @escaping (Result<Void, CommandLineFailure>) -> Void) {
        switch invocation {
        case .list(.text):
            send(IndicatorRequest(.list), completion) { IndicatorTable.text($0.indicators, problems: $0.problems) }
        case .list(.json):
            send(IndicatorRequest(.list), completion) { [self] reply in try file(of: reply.indicators) }
        case .show(let references):
            listing(completion) { [self] reply in
                let targets = try IndicatorLookup(indicators: reply.indicators).unique(references)
                completion(output.writeResult(Data(IndicatorTable.details(targets, problems: reply.problems).utf8)))
            }
        case .export(let references) where references.isEmpty:
            run(.list(format: .json), completion: completion)
        case .export(let references):
            acting(on: references, completion) { [self] targets in
                completion(output.writeResult(Data(try file(of: targets).utf8)))
            }
        case .add(let name, let predicate, let severity):
            add(Indicator(name: name, description: "", symbol: "exclamationmark.magnifyingglass", color: .orange,
                          predicate: predicate, severity: severity), completion)
        case .edit(let edit): self.edit(edit, completion)
        case .importFile(let path, let replace, let confirmed):
            importFile(path, replacing: replace, confirmed: confirmed, completion)
        case .remove(let references):
            acting(on: references, completion) { [self] targets in
                send(IndicatorRequest(.remove, ids: targets.map(\.id)), completion) { reply in
                    "Removed \(IndicatorTable.names(targets)). \(Self.count(reply)) now.\n"
                }
            }
        case .enable(let references): turn(references, on: true, completion)
        case .disable(let references): turn(references, on: false, completion)
        }
    }

    /// `add`: refuse a name the set already has, so a name always finds one indicator, then add it.
    ///
    /// - Parameters:
    ///   - indicator: The indicator.
    ///   - completion: Called once, on any thread.
    private func add(_ indicator: Indicator, _ completion: @escaping (Result<Void, CommandLineFailure>) -> Void) {
        listing(completion) { [self] current in
            if let taken = IndicatorLookup(indicators: current.indicators).matches(indicator.name).first {
                throw CommandLineFailure(.dataError, """
                    An indicator is already named \(IndicatorTable.describe(taken)). Choose another name.
                    """)
            }
            send(IndicatorRequest(.add, indicators: [indicator]), completion) { reply in
                "Added \(IndicatorTable.describe(indicator)). \(Self.count(reply)) now.\n"
            }
        }
    }

    /// `enable` or `disable`: turn indicators on or off, saying which already were.
    ///
    /// - Parameters:
    ///   - references: Each indicator's ID or name.
    ///   - enabled: On or off.
    ///   - completion: Called once, on any thread.
    private func turn(_ references: [String], on enabled: Bool,
                      _ completion: @escaping (Result<Void, CommandLineFailure>) -> Void) {
        acting(on: references, completion) { [self] targets in
            let already = targets.filter { $0.isEnabled == enabled }
            let turned = targets.filter { $0.isEnabled != enabled }
            let state = enabled ? "on" : "off"
            send(IndicatorRequest(.setEnabled, ids: targets.map(\.id), enabled: enabled), completion) { reply in
                let sentences = [turned.isEmpty ? nil : "Turned \(state) \(IndicatorTable.names(turned)).",
                                 already.isEmpty ? nil : "Already \(state): \(IndicatorTable.names(already))."]
                return (sentences.compactMap { $0 } + ["\(Self.count(reply)) now."]).joined(separator: " ") + "\n"
            }
        }
    }

    /// `import`: read the file, then ask first unless `--yes`, then send it.
    ///
    /// - Parameters:
    ///   - path: The file, or `-` for standard input.
    ///   - replace: Make the set exactly the file's indicators, rather than add them to it.
    ///   - confirmed: Go ahead without asking.
    ///   - completion: Called once, on any thread.
    private func importFile(_ path: String, replacing replace: Bool, confirmed: Bool,
                            _ completion: @escaping (Result<Void, CommandLineFailure>) -> Void) {
        let imported: [Indicator]
        do {
            imported = try importList(from: path)
        } catch {
            return completion(.failure(Self.failure(error)))
        }
        let source = path == "-" ? "standard input" : TerminalSafeText.quoted(path)
        let request = IndicatorRequest(replace ? .replace : .add, indicators: imported)
        let send = { [self] in
            self.send(request, completion) { reply in
                let count = Self.count(reply)
                guard reply.changed else { return "This Mac's indicators already had the file's: \(count) now.\n" }
                return replace ? "Replaced this Mac's indicators with the file's: \(count) now.\n"
                    : "Added the file's indicators to this Mac's: \(count) now.\n"
            }
        }
        guard !confirmed else { return send() }
        ask(about: .importing(imported, from: source, replacing: replace), then: send, otherwise: completion)
    }

    /// A file's indicators, for an import.
    ///
    /// - Parameter path: The file, or `-` for standard input.
    /// - Returns: The indicators, in the file's order.
    /// - Throws: ``CommandLineFailure``: 66 for a file that can't be read, 65 for one that's too large or isn't
    ///   indicators.
    func importList(from path: String) throws -> [Indicator] {
        let (name, data) = try input(from: path, for: "imported")
        do {
            return try IndicatorExchange.indicators(from: data)
        } catch {
            let reason = (error as? IndicatorExchange.ImportError)?.message ?? "\(error)"
            throw CommandLineFailure(.dataError, "\(name) couldn't be imported. \(TerminalSafeText.text(reason))")
        }
    }

    /// A file's bytes, at most ``IndicatorLimits/maxFileBytes``.
    ///
    /// - Parameters:
    ///   - path: The file, or `-` for standard input.
    ///   - use: What's done with it, for the message when it's too large, such as "imported".
    /// - Returns: How messages name it, such as “mine.json” or "Standard input", and its bytes.
    /// - Throws: ``CommandLineFailure``: 66 for a file that can't be read, 65 for one that's too large.
    func input(from path: String, for use: String) throws -> (name: String, data: Data) {
        let name = path == "-" ? "Standard input" : TerminalSafeText.quoted(path)
        let data: Data
        do {
            data = try readFile(path)
        } catch {
            throw CommandLineFailure.unreadable(name, because: error)
        }
        guard data.count <= IndicatorLimits.maxFileBytes else {
            throw CommandLineFailure(.dataError, """
                \(name) is larger than \(IndicatorLimits.maxFileBytes >> 20) MiB, so it wasn't \(use).
                """)
        }
        return (name, data)
    }

    /// Indicators as the indicator file `export` and `list --format json` write.
    ///
    /// - Parameter indicators: The indicators, in the set's order.
    /// - Returns: The file, and a newline.
    /// - Throws: ``CommandLineFailure`` (70) when they can't be encoded, so nothing is written and the command fails
    ///   rather than leave an empty file.
    func file(of indicators: [Indicator]) throws -> String {
        do {
            return String(decoding: try encode(indicators), as: UTF8.self) + "\n"
        } catch {
            throw CommandLineFailure(.software, """
                The indicators couldn't be written as JSON: \(TerminalSafeText.text(error.localizedDescription))
                """)
        }
    }
}


// MARK: - Requests
extension IndicatorCommand {
    /// Send a request, and report its answer: the notice and the indicators it can't run on standard error, what
    /// `describe` says on standard output.
    ///
    /// The indicators it can't run are those the request brings, or turns on: one turned on that can't run never
    /// matches, and `stream --indicator` refuses it.
    ///
    /// - Parameters:
    ///   - request: The request.
    ///   - completion: Called once, on any thread: success, or why not.
    ///   - describe: What to write about a successful answer. What it throws ends the command, and nothing is
    ///     written.
    func send(_ request: IndicatorRequest, _ completion: @escaping (Result<Void, CommandLineFailure>) -> Void,
              describe: @escaping (IndicatorReply) throws -> String) {
        client.send(request, timeout: timeout) { [self] result in
            completion(answer(result, to: request.operation).flatMap { reply in
                let turnedOn = request.enabled == true ? request.ids : []
                let brought = Set(request.indicators.map(\.id) + turnedOn)
                for problem in reply.problems where brought.contains(problem.id) {
                    let name = reply.indicators.first { $0.id == problem.id }?.name ?? problem.id.uuidString
                    diagnose("""
                        macmonitor: The Security Extension can't run \(TerminalSafeText.quoted(name)), so it never \
                        matches. \(TerminalSafeText.text(problem.reason))
                        """)
                }
                do {
                    return output.writeResult(Data(try describe(reply).utf8))
                } catch {
                    return .failure(Self.failure(error))
                }
            })
        }
    }

    /// List the set, then act on it.
    ///
    /// - Parameters:
    ///   - completion: Called once, on any thread, if listing or `body` fails.
    ///   - body: Acts on the set's answer. What it throws ends the command.
    func listing(_ completion: @escaping (Result<Void, CommandLineFailure>) -> Void,
                 then body: @escaping (IndicatorReply) throws -> Void) {
        client.send(IndicatorRequest(.list), timeout: timeout) { [self] result in
            do {
                try body(try answer(result, to: .list).get())
            } catch {
                completion(.failure(Self.failure(error)))
            }
        }
    }

    /// List the set, find the indicators named, then act on them.
    ///
    /// - Parameters:
    ///   - references: Each indicator's ID or name.
    ///   - completion: Called once, on any thread, if listing or indicator them fails.
    ///   - body: Acts on the indicators, each once, in the order named.
    func acting(on references: [String], _ completion: @escaping (Result<Void, CommandLineFailure>) -> Void,
                then body: @escaping ([Indicator]) throws -> Void) {
        listing(completion) { reply in
            try body(try IndicatorLookup(indicators: reply.indicators).unique(references))
        }
    }

    /// An answer, or why there's none: the notice said, a refusal as its failure, and no answer at all as a Security
    /// Extension older than 3.1, or as a change that may have been made (``CommandLineFailure/indicators(_:to:)``).
    ///
    /// - Parameters:
    ///   - result: What the client got.
    ///   - operation: What the request asked.
    /// - Returns: The answer, or the failure.
    private func answer(_ result: Result<IndicatorReply, CommandLineFailure>,
                        to operation: IndicatorRequest.Operation) -> Result<IndicatorReply, CommandLineFailure> {
        switch result {
        case .failure(let failure):
            return .failure(.indicators(failure, to: operation))
        case .success(let reply):
            say(reply.notice)
            return CommandLineFailure.reply(reply).map { .failure($0) } ?? .success(reply)
        }
    }

    /// Say the Security Extension's notice about the set on standard error, unless it was just said.
    ///
    /// - Parameter notice: The notice, if the answer had one.
    func say(_ notice: String?) {
        guard let notice, saidNotice.withLock({ said in defer { said = notice }; return said != notice }) else {
            return
        }
        diagnose("macmonitor: \(TerminalSafeText.text(notice))")
    }

    /// The failure an error ends the command with: itself, if it's a ``CommandLineFailure``, else a bug (70).
    ///
    /// - Parameter error: What was thrown.
    /// - Returns: The failure.
    static func failure(_ error: Error) -> CommandLineFailure {
        error as? CommandLineFailure ?? CommandLineFailure(.software, "\(error)")
    }

    /// How many indicators the set has after an answer.
    ///
    /// - Parameter reply: The answer.
    /// - Returns: Such as "28 indicators".
    static func count(_ reply: IndicatorReply) -> String {
        String.counted(reply.indicators.count, "indicator")
    }

    /// Read a file to import (``FileInput/read(_:upTo:)``), at most one byte past ``IndicatorLimits/maxFileBytes``
    /// so a larger one is reported as too large.
    ///
    /// - Parameter path: The path, or `-`.
    /// - Returns: The bytes.
    /// - Throws: A `POSIXError`, or `CocoaError(.fileReadUnsupportedScheme)` for something that isn't a regular file.
    public static func readImport(_ path: String) throws -> Data {
        try FileInput.read(path, upTo: IndicatorLimits.maxFileBytes)
    }
}
