//
//  XCTestCase+MuteStore.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Mute stores in temporary directories
extension XCTestCase {
    /// A store in a fresh 0700 directory, owned by the user running the test as root owns the real one, and removed
    /// (whatever a test did to its mode) when the test ends.
    ///
    /// - Returns: The store.
    /// - Throws: If its directory can't be created.
    func makeMuteStore() throws -> MuteStore {
        MuteStore(directory: try makeTemporaryDirectory(prefix: "MuteStoreTests", mode: 0o700), owner: getuid())
    }
    
    /// Write a file as the saved set, bypassing the store.
    ///
    /// - Parameters:
    ///   - contents: The file's bytes.
    ///   - store: The store.
    /// - Throws: If it can't be written.
    func writeSavedFile(_ contents: String, in store: MuteStore) throws {
        try Data(contents.utf8).write(to: store.fileURL)
        chmod(store.fileURL.path, 0o600)
    }
    
    /// The saved set's bytes, bypassing the store.
    ///
    /// - Parameter store: The store.
    /// - Returns: The bytes, or `nil` if there's no file.
    func savedFile(in store: MuteStore) -> Data? {
        FileManager.default.contents(atPath: store.fileURL.path)
    }
    
    /// The bytes the Security Extension saves for a set: its mute file, at the current default set revision.
    ///
    /// - Parameter list: The set.
    /// - Returns: The file's bytes.
    func savedBytes(_ list: MuteList) -> Data {
        MuteFile(list, defaultsRevision: MuteSet.currentRevision).encoded()
    }
    
    /// The names in a store's directory.
    ///
    /// - Parameter store: The store.
    /// - Returns: The names, sorted.
    func namesInDirectory(of store: MuteStore) -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: store.directory.path)) ?? []).sorted()
    }
}


// MARK: - A default set that doesn't depend on who's logged in
extension ConsoleUser {
    /// The console user the tests' saved sets make Mac Monitor's default set for, whoever is logged in.
    static let tester = ConsoleUser(name: "tester", uid: 501, home: "/Users/tester")
}


extension MuteList {
    /// Mac Monitor's default set for ``ConsoleUser/tester``: what the tests' saved sets start from and reset to.
    static let testDefault = MuteList.shippedDefault(for: .tester)
}


extension SavedMuteSet {
    /// A saved set whose default set is made for ``ConsoleUser/tester``.
    ///
    /// - Parameter store: Where the set is kept.
    convenience init(testing store: MuteStore) {
        self.init(store: store, consoleUser: { .tester })
    }
}


// MARK: - Requests to a saved set
extension SavedMuteSet {
    /// Send a request as a caller with `access`, and wait for the reply, failing the test if none comes.
    ///
    /// - Parameters:
    ///   - request: The request.
    ///   - access: What the caller may do.
    ///   - file: The caller's file.
    ///   - line: The caller's line.
    /// - Returns: The reply, as sending its bytes returns it.
    @discardableResult
    func send(_ request: MuteRequest, access: MuteAccess = .write, file: StaticString = #filePath,
              line: UInt = #line) -> MuteReply {
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
              line: UInt = #line) -> MuteReply {
        var reply: MuteReply?
        handle(data, access: access, caller: "Test") { reply = MuteReply.decode($0) }
        waitUntilIdle()
        guard let reply else {
            XCTFail("No reply, or one that doesn't read", file: file, line: line)
            return MuteReply(status: .unsupported, mutes: [], problems: ["No reply."])
        }
        return reply
    }
}
