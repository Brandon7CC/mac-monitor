//
//  XCTestCase+ScanBudget.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Events and programs for the scan budget's tests
extension XCTestCase {
    /// An exec's type number.
    static let execTypeNumber = Int(ES_EVENT_TYPE_NOTIFY_EXEC.rawValue)
    /// The exec type check a rule on execs starts with.
    static let execCheck = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#
    /// The synthetic corpus's first exec, made once.
    private static let firstCorpusExec = Result {
        try XCTUnwrap(SyntheticCorpus.records().map(\.message)
            .first { $0.es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" })
    }

    /// The synthetic corpus's first exec, changed.
    ///
    /// - Parameter change: Changes the exec.
    /// - Returns: The event.
    /// - Throws: The error making the corpus, or a failure when it has no exec.
    func corpusExec(_ change: (inout ProcessExecEvent) -> Void = { _ in }) throws -> Message {
        var message = try Self.firstCorpusExec.get()
        var exec = try XCTUnwrap(message.event.exec)
        change(&exec)
        message.event = .exec(exec)
        return message
    }

    /// Compiles a predicate on execs, after the exec type check.
    ///
    /// - Parameter comparison: A predicate on an exec, after its type check.
    /// - Returns: Its program.
    /// - Throws: A failure when it doesn't compile.
    func execProgram(_ comparison: String) throws -> IndicatorProgram {
        switch IndicatorCompiler.compile(Self.execCheck + " AND " + comparison) {
        case .success(let rule): return rule.program
        case .failure(let problem): throw BenchmarkFailure("\(comparison) doesn't compile: \(problem)")
        }
    }

    /// A program's verdict on an exec, on a fresh cache with a limit.
    ///
    /// - Parameters:
    ///   - program: The program.
    ///   - message: The exec.
    ///   - limit: The event's allowance.
    /// - Returns: The verdict, and the cache after it, which still has the event's budget.
    func verdict(_ program: IndicatorProgram, on message: Message,
                 limit: Int = ScanBudget.eventLimit) -> (IndicatorVerdict, MessageValueCache) {
        var values = MessageValueCache()
        values.scan.limit = limit
        let verdict = program.verdict(message, eventType: Self.execTypeNumber, values: &values)
        return (verdict, values)
    }

    /// An indicator of someone's own on execs.
    ///
    /// - Parameters:
    ///   - name: Its name.
    ///   - comparison: Its predicate on an exec, after its type check.
    /// - Returns: An indicator of someone's own on execs.
    func execIndicator(_ name: String, _ comparison: String) -> Indicator {
        Indicator(name: name, description: "", symbol: "star", color: .blue,
                  predicate: Self.execCheck + " AND " + comparison)
    }
}
