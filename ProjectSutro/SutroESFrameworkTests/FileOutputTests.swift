//
//  FileOutputTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - File output
/// Pins how `macmonitor` writes standard output: everything, whatever the pipe's size, a closed pipe as
/// ``StreamOutputError/closed``, and any other error by its `errno`.
final class FileOutputTests: XCTestCase {
    /// A pipe that reports a closed reader as `EPIPE` instead of raising `SIGPIPE` in the test process.
    ///
    /// - Returns: The read and write descriptors.
    /// - Throws: An `XCTest` failure if the pipe can't be made.
    private func makePipe() throws -> (read: Int32, write: Int32) {
        var descriptors: [Int32] = [0, 0]
        XCTAssertEqual(pipe(&descriptors), 0)
        XCTAssertEqual(fcntl(descriptors[1], F_SETNOSIGPIPE, 1), 0)
        return (descriptors[0], descriptors[1])
    }
    
    /// More than a pipe holds at once is written whole, while a reader drains it.
    ///
    /// - Throws: An `XCTest` failure or the write's error.
    func testWritesEverything() throws {
        let (reader, writer) = try makePipe()
        defer { close(reader) }
        let data = Data((0..<1_000_000).map { UInt8($0 % 251) })
        var read = Data()
        let drained = expectation(description: "drained")
        DispatchQueue.global().async {
            var buffer = [UInt8](repeating: 0, count: 65_536)
            while case let count = Darwin.read(reader, &buffer, buffer.count), count > 0 {
                read.append(contentsOf: buffer[0..<count])
            }
            drained.fulfill()
        }
        try FileOutput(descriptor: writer).write(data)
        close(writer)
        wait(for: [drained], timeout: 10)
        XCTAssertEqual(read, data)
    }
    
    /// A reader that went away is a closed pipe, not a failure; a bad descriptor fails with its `errno`.
    ///
    /// - Throws: An `XCTest` failure.
    func testClosedAndFailed() throws {
        let (reader, writer) = try makePipe()
        close(reader)
        defer { close(writer) }
        XCTAssertThrowsError(try FileOutput(descriptor: writer).write(Data("x\n".utf8))) { error in
            XCTAssertEqual(error as? StreamOutputError, .closed)
        }
        XCTAssertThrowsError(try FileOutput(descriptor: -1).write(Data("x\n".utf8))) { error in
            XCTAssertEqual(error as? StreamOutputError, .failed(EBADF))
        }
        XCTAssertNoThrow(try FileOutput(descriptor: -1).write(Data()), "Nothing to write is no write.")
    }
}
