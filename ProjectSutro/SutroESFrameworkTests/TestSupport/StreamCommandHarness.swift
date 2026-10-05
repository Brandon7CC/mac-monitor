//
//  StreamCommandHarness.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import os
@testable import SutroESFramework


// MARK: - Output
/// Standard output in a test: keeps what's written, or fails the way a test says.
final class BufferOutput: StreamOutput {
    /// What's written, and the failure to throw.
    private struct State {
        var data = Data()
        var failure: StreamOutputError?
    }
    
    private let state = OSAllocatedUnfairLock(uncheckedState: State())
    
    /// Everything written so far, as text.
    var text: String {
        String(decoding: state.withLockUnchecked { $0.data }, as: UTF8.self)
    }
    
    /// The lines written so far.
    var lines: [String] {
        text.split(separator: "\n").map(String.init)
    }
    
    /// Fail every write from now on.
    ///
    /// - Parameter failure: The error.
    func fail(with failure: StreamOutputError) {
        state.withLockUnchecked { $0.failure = failure }
    }
    
    /// Keep the bytes, or throw the failure.
    ///
    /// - Parameter data: The bytes.
    /// - Throws: The failure set with ``fail(with:)``.
    func write(_ data: Data) throws {
        try state.withLockUnchecked { state in
            if let failure = state.failure { throw failure }
            state.data.append(data)
        }
    }
}


// MARK: - Diagnostics
/// Standard error in a test: keeps each line.
final class DiagnosticLines {
    private let lines = OSAllocatedUnfairLock<[String]>(initialState: [])
    
    /// Every line, in order.
    var all: [String] {
        lines.withLock { $0 }
    }
    
    /// Keep a line.
    ///
    /// - Parameter line: The line.
    func append(_ line: String) {
        lines.withLock { $0.append(line) }
    }
}


// MARK: - A command against the in-process extension
/// `macmonitor stream` in a test: a ``StreamCommand`` connected to a ``StreamHarness``, writing to a buffer.
final class StreamCommandRun {
    let command: StreamCommand
    let output: BufferOutput
    let diagnostics: DiagnosticLines
    private let outcomes = OSAllocatedUnfairLock<[StreamCommand.Outcome]>(uncheckedState: [])
    
    /// - Parameters:
    ///   - harness: The in-process Security Extension.
    ///   - formatter: How events become output.
    ///   - scope: Which events are the pipeline's own.
    ///   - toolVersion: `macmonitor`'s version.
    ///   - isChatty: Is standard error a terminal?
    init(harness: StreamHarness, formatter: StreamPipeline.Formatter, scope: PipelineScope,
         toolVersion: String = "2.2.0 (1)", isChatty: Bool = true) {
        let client = StreamClient(connection: NSXPCConnection(listenerEndpoint: harness.endpoint), requirement: nil)
        let pipeline = StreamPipeline(formatter: formatter, scope: scope, forTerminal: false)
        let (output, diagnostics) = (BufferOutput(), DiagnosticLines())
        self.output = output
        self.diagnostics = diagnostics
        command = StreamCommand(client: client, pipeline: pipeline, output: output, toolVersion: toolVersion,
                                isChatty: isChatty, diagnose: diagnostics.append)
    }
    
    /// Every outcome reported, which should only ever be one.
    var reported: [StreamCommand.Outcome] {
        outcomes.withLockUnchecked { $0 }
    }
    
    /// Start the stream.
    ///
    /// - Parameter invocation: The stream asked for.
    func start(_ invocation: StreamInvocation = StreamInvocation()) {
        command.run(invocation) { [outcomes] outcome in outcomes.withLockUnchecked { $0.append(outcome) } }
    }
}
