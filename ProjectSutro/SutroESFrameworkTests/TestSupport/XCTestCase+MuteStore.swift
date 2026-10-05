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
    /// A fresh 0700 directory, removed (whatever a test did to its mode) when the test ends.
    ///
    /// - Returns: The directory.
    /// - Throws: If it can't be created.
    func makeMuteDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("MuteStoreTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        addTeardownBlock {
            chmod(directory.path, 0o700)
            try? FileManager.default.removeItem(at: directory)
        }
        return directory
    }
    
    /// A store in a fresh directory, owned by the user running the test as root owns the real one.
    ///
    /// - Returns: The store.
    /// - Throws: If its directory can't be created.
    func makeMuteStore() throws -> MuteStore {
        MuteStore(directory: try makeMuteDirectory(), owner: getuid())
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
