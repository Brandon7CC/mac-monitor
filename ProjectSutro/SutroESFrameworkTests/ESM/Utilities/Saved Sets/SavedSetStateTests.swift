//
//  SavedSetStateTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Whether a saved set can be changed
/// Pins the state the saved mute set keeps for its file: writable when it's its own, read-only at a newer file's
/// version until a Reset takes it back, and unavailable with the reason when the directory can't be trusted.
final class SavedSetStateTests: XCTestCase {
    /// A saved set's state once it has loaded.
    ///
    /// - Parameter saved: The set.
    /// - Returns: Its state, read on its queue.
    private func state(of saved: SavedMuteSet) -> SavedSetState {
        saved.load()
        return saved.queue.sync { saved.state }
    }
    
    /// The first run is writable.
    func testTheFirstRunIsWritable() throws {
        XCTAssertEqual(state(of: SavedMuteSet(testing: try makeMuteStore())), .writable)
    }
    
    /// A newer file is read-only at its version, and writable again after Reset.
    func testANewerFileIsReadOnlyUntilReset() throws {
        let store = try makeMuteStore()
        try writeSavedFile(#"{"version": 3, "mutes": []}"#, in: store)
        let saved = SavedMuteSet(testing: store)
        XCTAssertEqual(state(of: saved), .readOnly(version: 3))
        XCTAssertEqual(saved.send(MuteRequest(.reset)).status, .ok)
        XCTAssertEqual(state(of: saved), .writable)
    }
    
    /// A directory others can write is unavailable, saying why.
    func testAnUntrustedDirectoryIsUnavailable() throws {
        let store = try makeMuteStore()
        chmod(store.directory.path, 0o777)
        guard case .unavailable(let reason) = state(of: SavedMuteSet(testing: store)) else {
            return XCTFail("not unavailable")
        }
        XCTAssertTrue(reason.contains("Others can write to"), reason)
    }
}
