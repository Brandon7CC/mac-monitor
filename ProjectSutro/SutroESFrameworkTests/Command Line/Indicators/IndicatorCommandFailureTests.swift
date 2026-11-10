//
//  IndicatorCommandFailureTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - macmonitor indicators, when it can't finish
/// What `macmonitor indicators` says when it can't finish: indicators that can't be encoded, a change the Security
/// Extension doesn't answer in time, and which failures say the Security Extension is older than 3.1.
final class IndicatorCommandFailureTests: XCTestCase {
    /// An encoder that always fails.
    private struct EncodingFailed: LocalizedError {
        var errorDescription: String? { "Nothing encodes." }
    }

    /// Run one indicators command against a Security Extension that lists its set but never answers a change.
    ///
    /// - Parameters:
    ///   - invocation: The command.
    ///   - service: The Security Extension.
    ///   - file: What every file read holds, as JSON: the first shipped indicator in an indicator file unless given.
    ///   - encode: Writes indicators as an indicator file: the real encoder unless given.
    /// - Returns: What it did.
    private func run(_ invocation: IndicatorInvocation, against service: ServiceHoldingChanges, file: Any? = nil,
                     encode: @escaping ([Indicator]) throws -> Data = IndicatorExchange.data(of:)) throws
        -> IndicatorRun {
        let client = StreamClient(connection: NSXPCConnection(listenerEndpoint: service.endpoint), requirement: nil)
        client.activate(receiving: TestStreamReader()) { _ in }
        defer { client.invalidate() }
        let (output, errors) = (BufferOutput(), DiagnosticLines())
        let file = try file.map { try JSONSerialization.data(withJSONObject: $0) }
            ?? IndicatorExchange.data(of: [Indicator.defaults[0]])
        let command = IndicatorCommand(client: client, output: output, diagnose: errors.append,
                                       readFile: { _ in file }, encode: encode, timeout: .milliseconds(300))
        let result = try awaitCallback(timeout: 10) { command.run(invocation, completion: $0) }
        return IndicatorRun(result: result, output: output.text, errors: errors.all)
    }

    /// `export` and `list --format json` fail (70) and write nothing when the indicators can't be encoded, so
    /// `export > backup.json` doesn't leave an empty file behind a success.
    func testIndicatorsThatCantBeEncodedFail() throws {
        let service = ServiceHoldingChanges()
        for invocation in [IndicatorInvocation.export(), .list(format: .json)] {
            let failed = try run(invocation, against: service) { _ in throw EncodingFailed() }
            XCTAssertEqual(failed.failure, CommandLineFailure(.software, """
                The indicators couldn't be written as JSON: Nothing encodes.
                """), "\(invocation)")
            XCTAssertEqual(failed.output, "", "\(invocation)")
        }
        let exported = try run(.export(), against: service)
        XCTAssertEqual(try IndicatorExchange.indicators(from: Data(exported.output.utf8)), Indicator.defaults)
        XCTAssertTrue(exported.output.hasSuffix("}\n"))
    }

    /// A change the Security Extension reached but didn't answer in time may have been made, as a large import it's
    /// still compiling and saving may be: it says so and to list the set (69), rather than call the Security
    /// Extension older than `macmonitor`.
    func testAChangeThatTimesOutMayHaveBeenMade() throws {
        let service = ServiceHoldingChanges()
        let plist = try XCTUnwrap(Indicator.defaults.first { $0.name == "Plist modified" })
        let changes: [IndicatorInvocation] = [
            .importFile(path: "big.json", replace: true, confirmed: true), .remove([plist.name]),
            .disable([plist.id.uuidString]), .add(name: "Curl", predicate: IndicatorCommandLineTests.curl),
            .edit(IndicatorEdit(plist.name, .values([.severity: "high"]))),
        ]
        for change in changes {
            let unanswered = try run(change, against: service)
            XCTAssertEqual(unanswered.failure, .indicatorChangeUnanswered, "\(change)")
            XCTAssertEqual(unanswered.output, "", "\(change)")
        }
        XCTAssertEqual(service.heldChanges, [.replace, .remove, .setEnabled, .add, .update])
        XCTAssertTrue(CommandLineFailure.indicatorChangeUnanswered.message.contains("'macmonitor indicators list'"))
        XCTAssertNoThrow(try run(.list(), against: service).result?.get())
    }

    /// A Security Extension that doesn't know `update`, as one would if it slipped to a later 3.1, answers an edit
    /// unsupported: it says the Security Extension is older (69), and nothing else is sent, an add least of all.
    func testAnEditTheExtensionDoesntKnowSaysItsOlder() throws {
        let service = ServiceHoldingChanges(answering: .unsupported)
        let plist = try XCTUnwrap(Indicator.defaults.first { $0.name == "Plist modified" })
        let changes: [IndicatorEdit.Change] = [.values([.predicate: IndicatorCommandLineTests.curl]),
                                               .file("one.json", confirmed: true)]
        for change in changes {
            let edited = try run(.edit(IndicatorEdit(plist.id.uuidString, change)), against: service,
                                 file: ["severity": "high"])
            XCTAssertEqual(edited.failure, .olderSecurityExtension, "\(change)")
            XCTAssertEqual(edited.output, "", "\(change)")
        }
        XCTAssertEqual(service.heldChanges, [.update, .update])
    }

    /// A connection cut off before any answer is a Security Extension older than 3.1, whatever was asked; no answer
    /// in time is one only for a list. Any other failure is said as it is.
    func testWhichFailuresSayTheExtensionIsOlder() {
        let changes: [IndicatorRequest.Operation] = [.add, .remove, .setEnabled, .replace, .update]
        for operation in changes + [.list] {
            XCTAssertEqual(CommandLineFailure.indicators(.refusedBeforeAnswer, to: operation), .indicatorsUnanswered)
            XCTAssertEqual(CommandLineFailure.indicators(.stopped, to: operation), .stopped)
        }
        XCTAssertEqual(CommandLineFailure.indicators(.noAnswer, to: .list), .indicatorsUnanswered)
        for operation in changes {
            XCTAssertEqual(CommandLineFailure.indicators(.noAnswer, to: operation), .indicatorChangeUnanswered)
        }
    }
}
