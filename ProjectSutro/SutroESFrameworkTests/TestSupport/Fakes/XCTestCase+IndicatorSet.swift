//
//  XCTestCase+IndicatorSet.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Indicator sets in temporary directories
extension XCTestCase {
    /// A fresh 0700 directory, owned by the user running the test as root owns the real one, and removed when the
    /// test ends.
    ///
    /// - Returns: The directory.
    /// - Throws: If it can't be created.
    func makeIndicatorDirectory() throws -> URL {
        try makeTemporaryDirectory(prefix: "SavedIndicatorSetTests", mode: 0o700)
    }

    /// An indicator set kept in a directory, as the Security Extension keeps it.
    ///
    /// - Parameters:
    ///   - directory: The directory: a fresh one unless given.
    ///   - defaults: The shipped indicators.
    /// - Returns: The set, not loaded yet.
    /// - Throws: If the directory can't be created.
    func makeSavedIndicatorSet(in directory: URL? = nil,
                               defaults: [Indicator] = Indicator.defaults) throws -> SavedIndicatorSet {
        SavedIndicatorSet(directory: try directory ?? makeIndicatorDirectory(), owner: getuid(), defaults: defaults)
    }

    /// Write a file as the saved set, bypassing the set.
    ///
    /// - Parameters:
    ///   - contents: The file's bytes.
    ///   - name: The file's name in the directory.
    ///   - directory: The directory.
    /// - Throws: If it can't be written.
    func writeIndicatorFile(_ contents: Data, named name: String = IndicatorFile.layout.fileName,
                            in directory: URL) throws {
        let url = directory.appendingPathComponent(name)
        try contents.write(to: url)
        chmod(url.path, 0o600)
    }

    /// A file in the set's directory, bypassing the set.
    ///
    /// - Parameters:
    ///   - name: The file's name: the saved set's unless given.
    ///   - directory: The directory.
    /// - Returns: Its bytes, or `nil` if there's no such file.
    func indicatorFile(named name: String = IndicatorFile.layout.fileName, in directory: URL) -> Data? {
        FileManager.default.contents(atPath: directory.appendingPathComponent(name).path)
    }

    /// The indicators a saved file holds.
    ///
    /// - Parameters:
    ///   - directory: The directory.
    ///   - defaults: The shipped indicators.
    /// - Returns: Them, in order.
    /// - Throws: A failure when there's no file, or it doesn't decode.
    func savedIndicators(in directory: URL, defaults: [Indicator] = Indicator.defaults) throws -> [Indicator] {
        let data = try XCTUnwrap(indicatorFile(in: directory), "No saved file")
        return try IndicatorFile.decode(data, defaults: defaults).saved.indicators
    }

    /// The names in a directory.
    ///
    /// - Parameter directory: The directory.
    /// - Returns: The names, sorted.
    func names(in directory: URL) -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []).sorted()
    }
}


// MARK: - Requests to an indicator set
extension SavedIndicatorSet {
    /// Send a request as a caller with `access`, and wait for the reply, failing the test if none comes.
    ///
    /// - Parameters:
    ///   - request: The request.
    ///   - access: What the caller may do.
    ///   - file: The caller's file.
    ///   - line: The caller's line.
    /// - Returns: The reply, as sending its bytes returns it.
    @discardableResult
    func send(_ request: IndicatorRequest, access: MuteAccess = .write, file: StaticString = #filePath,
              line: UInt = #line) -> IndicatorReply {
        send(request.encoded(), access: access, file: file, line: line)
    }

    /// Send raw request bytes as a caller with `access`, and wait for the reply, failing the test if none comes or it
    /// doesn't read.
    ///
    /// - Parameters:
    ///   - data: The bytes.
    ///   - access: What the caller may do.
    ///   - file: The caller's file.
    ///   - line: The caller's line.
    /// - Returns: The reply. When none came the test has already failed, and this is only a placeholder.
    @discardableResult
    func send(_ data: Data, access: MuteAccess = .write, file: StaticString = #filePath,
              line: UInt = #line) -> IndicatorReply {
        var reply: IndicatorReply?
        handle(data, access: access, caller: "Test") { reply = IndicatorReply.decode($0) }
        waitUntilIdle()
        guard let reply else {
            XCTFail("No reply, or one that doesn't read", file: file, line: line)
            return IndicatorReply(status: .unsupported, indicators: [], failure: "No reply.")
        }
        return reply
    }

    /// The compiled set now, read on the set's queue.
    var current: CompiledIndicators {
        queue.sync { compiled }
    }
}
