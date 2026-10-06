//
//  SchemaCommandTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - macmonitor schema
/// Pins `macmonitor schema`: the bundled schema, byte for byte as committed, a closed pipe as a success, and the exit
/// statuses for output that can't be written and a schema that can't be read.
final class SchemaCommandTests: XCTestCase {
    /// `schema` writes exactly the bytes the framework bundles, which are the committed
    /// `Schema/mac-monitor-telemetry.schema.json`, and needs no root.
    ///
    /// - Throws: The error reading either file, or an `XCTest` failure.
    func testItWritesTheBundledSchemaByteForByte() throws {
        XCTAssertEqual(try CommandLineParser.parse(["schema"]), .schema)
        XCTAssertFalse(try CommandLineParser.parse(["schema"]).requiresRoot)
        let output = BufferOutput()
        XCTAssertNoThrow(try SchemaCommand(output: output).run().get())
        XCTAssertEqual(output.data, try TelemetrySchema.data())
        XCTAssertEqual(output.data, try Data(contentsOf: Self.schemaFileURL))
        XCTAssertEqual(try TelemetryValidator(schema: output.data).schemaVersion, TelemetrySchema.version)
    }
    
    /// A reader that closes the pipe (`macmonitor schema | head`) before the schema is written is a success, through a
    /// real pipe and with more than a pipe holds; any other write error exits 74.
    ///
    /// - Throws: An `XCTest` failure.
    func testOutputThatCantBeWritten() throws {
        var descriptors: [Int32] = [0, 0]
        XCTAssertEqual(pipe(&descriptors), 0)
        /// `EPIPE` rather than `SIGPIPE` in the test process, as `macmonitor` ignores `SIGPIPE`.
        XCTAssertEqual(fcntl(descriptors[1], F_SETNOSIGPIPE, 1), 0)
        close(descriptors[0])
        defer { close(descriptors[1]) }
        XCTAssertGreaterThan(try TelemetrySchema.data().count, 65_536, "More than a pipe holds")
        XCTAssertNoThrow(try SchemaCommand(output: FileOutput(descriptor: descriptors[1])).run().get())
        
        let closed = BufferOutput()
        closed.fail(with: .closed)
        XCTAssertNoThrow(try SchemaCommand(output: closed).run().get())
        
        let failure = { (output: StreamOutput) -> CommandLineFailure? in
            guard case .failure(let failure) = SchemaCommand(output: output).run() else { return nil }
            return failure
        }
        XCTAssertEqual(failure(FileOutput(descriptor: -1)), .output(EBADF))
        let full = BufferOutput()
        full.fail(with: .failed(ENOSPC))
        XCTAssertEqual(failure(full)?.exit, .ioError)
        XCTAssertEqual(failure(full)?.description, "macmonitor: Couldn't write the output: No space left on device.")
    }
    
    /// A schema the framework doesn't bundle is a bug in the build: exit 70, saying so, with nothing written.
    func testAMissingSchemaExits70() {
        let output = BufferOutput()
        let result = SchemaCommand(output: output, schema: { throw TelemetrySchemaError.missingResource }).run()
        guard case .failure(let failure) = result else { return XCTFail("The schema was written.") }
        XCTAssertEqual(failure, CommandLineFailure(.software,
                                                   "Mac Monitor's telemetry schema is missing from its framework."))
        XCTAssertEqual(failure.exit.rawValue, 70)
        XCTAssertEqual(output.data, Data())
    }
}
