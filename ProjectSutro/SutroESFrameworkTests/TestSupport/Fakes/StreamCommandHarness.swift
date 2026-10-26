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
    
    /// Everything written so far.
    var data: Data {
        state.withLockUnchecked { $0.data }
    }
    
    /// Everything written so far, as text.
    var text: String {
        String(decoding: data, as: UTF8.self)
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
typealias DiagnosticLines = Recorded<String>


// MARK: - A command against the in-process extension
/// `macmonitor stream` in a test: a ``StreamCommand`` connected to a ``StreamHarness``, writing to a buffer.
final class StreamCommandRun {
    let command: StreamCommand
    let output: BufferOutput
    let diagnostics: DiagnosticLines
    private let outcomes = Recorded<StreamCommand.Outcome>()
    
    /// - Parameters:
    ///   - harness: The in-process Security Extension.
    ///   - formatter: How events become output.
    ///   - scope: Which events are the pipeline's own.
    ///   - toolVersion: `macmonitor`'s version.
    ///   - isChatty: Is standard error a terminal?
    ///   - requirement: The code signing requirement `macmonitor` pins on the Security Extension, if any.
    ///   - filter: Which events are written.
    ///   - limit: The most events to write (`--count`), if any.
    init(harness: StreamHarness, formatter: StreamPipeline.Formatter, scope: PipelineScope,
         toolVersion: String = "3.0.0 (1)", isChatty: Bool = true, requirement: String? = nil,
         filter: StreamFilter = StreamFilter(), limit: Int? = nil) {
        let client = StreamClient(connection: NSXPCConnection(listenerEndpoint: harness.endpoint),
                                  requirement: requirement)
        let pipeline = StreamPipeline(formatter: formatter, scope: scope, forTerminal: false, filter: filter,
                                      limit: limit)
        let (output, diagnostics) = (BufferOutput(), DiagnosticLines())
        self.output = output
        self.diagnostics = diagnostics
        command = StreamCommand(client: client, pipeline: pipeline, output: output, toolVersion: toolVersion,
                                isChatty: isChatty, diagnose: diagnostics.append)
    }
    
    /// Every outcome reported, which should only ever be one.
    var reported: [StreamCommand.Outcome] {
        outcomes.all
    }
    
    /// Start the stream.
    ///
    /// - Parameter invocation: The stream asked for.
    func start(_ invocation: StreamInvocation = StreamInvocation()) {
        command.run(invocation, completion: outcomes.append)
    }
}
