//
//  XCTestCase+IndicatorCommand.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - What an indicators command did
/// What one `macmonitor indicators` command did in a test.
struct IndicatorRun {
    /// Success, or why not, or `nil` if it never finished.
    let result: Result<Void, CommandLineFailure>?
    /// Standard output.
    let output: String
    /// Standard error's lines.
    let errors: [String]

    /// Why it failed, or `nil` if it didn't.
    var failure: CommandLineFailure? {
        if case .failure(let failure)? = result { return failure }
        return nil
    }

    /// The table `list` wrote, without its header.
    var rows: [String] {
        Array(output.split(separator: "\n").map(String.init).dropFirst())
    }
}


// MARK: - Running indicators commands
extension XCTestCase {
    /// Run one `macmonitor indicators` command end to end and wait for it: ``IndicatorCommand`` and ``StreamClient``
    /// over a real NSXPC connection to ``StreamService``.
    ///
    /// - Parameters:
    ///   - invocation: The command.
    ///   - savedMutes: The Security Extension's mute set.
    ///   - savedIndicators: The Security Extension's indicator set.
    ///   - grant: What the caller may do: everything, as root may.
    ///   - input: What standard input holds, for `import -`.
    ///   - readFile: Reads a file to import, unless the real reader is wanted.
    ///   - confirm: Answers the question `import` asks: by default there's no one to ask.
    /// - Returns: What it did.
    func runIndicators(_ invocation: IndicatorInvocation, savedMutes: SavedMuteSet,
                       savedIndicators: SavedIndicatorSet, grant: CommandLineGrant = .everything,
                       input: Data = Data(), readFile: ((String) throws -> Data)? = nil,
                       confirm: @escaping (String) -> Bool? = { _ in nil }) -> IndicatorRun {
        let harness = StreamHarness(savedMutes: savedMutes, grant: grant, savedIndicators: savedIndicators)
        let client = StreamClient(connection: NSXPCConnection(listenerEndpoint: harness.endpoint), requirement: nil)
        client.activate(receiving: TestStreamReader()) { _ in }
        defer { client.invalidate() }
        let (output, errors) = (BufferOutput(), DiagnosticLines())
        let read = readFile ?? { path in path == "-" ? input : try IndicatorCommand.readImport(path) }
        let command = IndicatorCommand(client: client, output: output, diagnose: errors.append, confirm: confirm,
                                       readFile: read)
        let result = try? awaitCallback(timeout: 15) { command.run(invocation, completion: $0) }
        return IndicatorRun(result: result, output: output.text, errors: errors.all)
    }

    /// A file of indicators, as Settings > Indicators exports one.
    ///
    /// - Parameters:
    ///   - indicators: The indicators.
    ///   - name: The file's name.
    /// - Returns: The file.
    /// - Throws: If it can't be written.
    func indicatorFile(of indicators: [Indicator], named name: String) throws -> URL {
        try temporaryFile(containing: String(decoding: try IndicatorExchange.data(of: indicators), as: UTF8.self),
                          named: name)
    }
}
