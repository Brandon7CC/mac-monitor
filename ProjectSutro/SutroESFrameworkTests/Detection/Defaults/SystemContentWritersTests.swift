//
//  SystemContentWritersTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/9/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - macOS's own content writers
/// Pins what Archive written and AppleScript written leave out, on the closes `macmonitor stream` recorded on the
/// SIP-off macOS 27 test VM (`Fixtures/macmonitor-3.1-system-writers.jsonl`): fseventsd writing a volume's gzipped
/// file system event log in `.fseventsd`, twice, then Spotlight's mds_stores caching the text of a
/// `#!/usr/bin/osascript` script it indexed, as a `.tmp` and then the `.txt` it's renamed to. Build 86 matched each of
/// them, as it would all day.
///
/// None matches now, nor the same close by any of macOS's own ``Indicator/contentKeepers``, a copy of one elsewhere
/// included. A process that only takes one's signing ID, which isn't a platform binary, or is one but adhoc signed, as
/// every process is a platform binary with the code signing checks off, still matches, as does another platform
/// binary. The Security Extension's compiled set and Mac Monitor's own matching agree on every case.
final class SystemContentWritersTests: XCTestCase {
    /// The fixture's closes, in the order they ran.
    private static let fixture = "macmonitor-3.1-system-writers.jsonl"
    /// The code signing flags macOS 27.2 reports, through Endpoint Security, for a program re-signed adhoc with
    /// `codesign -s -` on a Mac with its checks on: `CS_VALID`, `CS_ADHOC`, `CS_KILL`, `CS_NO_UNTRUSTED_HELPERS` and
    /// `CS_SIGNED`.
    private static let adhocFlags: Int64 = 0x2200_0203

    /// Each recorded close is in the rule's scope, its file named an archive or AppleScript by its content, and none
    /// matches either indicator.
    func testRecordedSystemWritesDontMatch() throws {
        let messages = try fixtureMessages(Self.fixture)
        XCTAssertEqual(messages.map(\.process.signing_id), ["com.apple.fseventsd", "com.apple.fseventsd",
                                                            "com.apple.mds_stores", "com.apple.mds_stores"])
        XCTAssertEqual(messages.map(fileType), ["org.gnu.gnu-zip-archive", "org.gnu.gnu-zip-archive",
                                                "com.apple.applescript.text", "com.apple.applescript.text"])
        for message in messages {
            try assertContentIndicators(message, match: false, message.target_path ?? "")
        }
    }

    /// The same closes by a process that only takes the daemon's signing ID and name, adhoc signed and not a platform
    /// binary, from a folder anyone can write, each match the indicator its file's type is in.
    func testLookalikesMatch() throws {
        for message in try fixtureMessages(Self.fixture) {
            let name = message.process.executable?.name ?? ""
            let lookalike = written(message, by: "/Users/Shared/" + name, flags: Self.adhocFlags, platform: false)
            try assertContentIndicators(lookalike, match: true, "a lookalike " + name)
        }
    }

    /// The same lookalikes on a Mac with its code signing checks off (`amfi_get_out_of_my_way`), where macOS makes
    /// every process a platform binary but still reports `CS_ADHOC`, each match too: only a copy of the daemon, which
    /// isn't adhoc signed, is left out there.
    func testAdhocLookalikesMatchWithChecksOff() throws {
        for message in try fixtureMessages(Self.fixture) {
            let name = message.process.executable?.name ?? ""
            let lookalike = written(message, by: "/Users/Shared/" + name, flags: Self.adhocFlags, platform: true)
            XCTAssertTrue(lookalike.process.is_adhoc_signed, name)
            try assertContentIndicators(lookalike, match: true, "an adhoc lookalike " + name + " with checks off")
        }
    }

    /// A copy of the daemon, renamed and elsewhere, keeps its signature and stays a platform binary, so it's left out,
    /// as it is on a Mac with its code signing checks off, where every process is a platform binary.
    func testCopiesAreLeftOut() throws {
        for message in try fixtureMessages(Self.fixture) {
            let copy = written(message, by: "/private/tmp/copy/renamed", flags: message.process.codesigning_flags,
                               platform: true)
            try assertContentIndicators(copy, match: false, "a copy of " + (message.process.signing_id ?? ""))
        }
    }

    /// Each of macOS's own content writers is left out, of both indicators, by its signing ID as a platform binary,
    /// and each other platform binary still matches: the rest of Spotlight's processes, Archive Utility, ditto and
    /// Script Editor among them.
    func testOnlyTheKeepersAreLeftOut() throws {
        XCTAssertEqual(Indicator.contentKeepers, ["com.apple.backupd", "com.apple.fseventsd", "com.apple.mds_stores",
                                                  "com.apple.corespotlightd", "com.apple.managedcorespotlightd"])
        let others = ["com.apple.mds", "com.apple.mdworker_shared", "com.apple.mdworker", "com.apple.archiveutility",
                      "com.apple.ditto", "com.apple.ScriptEditor2", "com.apple.fseventsd.helper", "com.apple.mds_store"]
        let types = ["org.gnu.gnu-zip-archive", FileType.compiledAppleScript.identifier]
        for type in types {
            for keeper in Indicator.contentKeepers {
                let close = try derivedClose(at: "/Users/marcus/loot", type: type, by: (keeper, true))
                try assertContentIndicators(close, match: false, keeper + " " + type)
                let lookalike = try derivedClose(at: "/Users/marcus/loot", type: type, by: (keeper, false))
                try assertContentIndicators(lookalike, match: true, "a lookalike " + keeper + " " + type)
            }
            for other in others {
                let close = try derivedClose(at: "/Users/marcus/loot", type: type, by: (other, true))
                try assertContentIndicators(close, match: true, other + " " + type)
            }
        }
    }
}


// MARK: - Deriving and checking closes
extension SystemContentWritersTests {
    /// - Parameter message: A close.
    /// - Returns: The type its file's content is named by, if it was read.
    private func fileType(_ message: Message) -> String? {
        guard case .close(let close) = message.event else { return nil }
        return close.file_type
    }

    /// A close with its process changed, and what Mac Monitor derives from its signing derived again, as the
    /// Security Extension derives it from what Endpoint Security reports. Its signing ID stays the recorded one.
    ///
    /// - Parameters:
    ///   - message: The close.
    ///   - path: The process's executable.
    ///   - flags: Its code signing flags.
    ///   - platform: Is it a platform binary?
    /// - Returns: The close.
    private func written(_ message: Message, by path: String, flags: Int64, platform: Bool) -> Message {
        var message = message
        message.process.executable?.path = path
        message.process.codesigning_flags = flags
        message.process.is_platform_binary = platform
        message.process.team_id = nil
        message.process.enrich()
        return message
    }

    /// Check a close matches the content indicator its file's type is in as expected, and never the other, with the
    /// extension and the app agreeing (``assertShippedMatch(_:_:id:_:)``).
    ///
    /// - Parameters:
    ///   - message: The close.
    ///   - matches: Should it match the indicator its type is in?
    ///   - label: What the case is.
    /// - Throws: The error storing the event, or a failure when the type is in neither indicator.
    private func assertContentIndicators(_ message: Message, match matches: Bool, _ label: String) throws {
        let type = try XCTUnwrap(fileType(message), label)
        let archive = Indicator.archiveTypes.contains { $0.identifier == type }
        let script = [FileType.compiledAppleScript, .appleScriptText].contains { $0.identifier == type }
        XCTAssertTrue(archive || script, "\(label): \(type) is in neither indicator")
        try assertShippedMatch(message, matches && archive, id: try shippedID("Archive written"), label)
        try assertShippedMatch(message, matches && script, id: try shippedID("AppleScript written"), label)
    }
}
