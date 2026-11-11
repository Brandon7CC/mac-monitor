//
//  SavedIndicatorSetTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Loading the Mac's indicator set
/// Pins how the Security Extension loads the Mac's indicator set: the first run, a saved file, a damaged one, a newer
/// one, one past a limit, an untrusted directory, a load that never finished, and the self-test of the shipped
/// indicators.
final class SavedIndicatorSetTests: XCTestCase {
    /// Every exec.
    private static let exec = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#

    /// A saved set in a fresh directory, and the directory.
    private var directory: URL!

    /// A fresh directory for each test.
    ///
    /// - Throws: If it can't be created.
    override func setUpWithError() throws {
        try super.setUpWithError()
        directory = try makeIndicatorDirectory()
    }

    /// A loaded set in the test's directory.
    ///
    /// - Parameter defaults: The shipped indicators.
    /// - Returns: The set.
    /// - Throws: If it can't be made.
    private func loaded(defaults: [Indicator] = Indicator.defaults) throws -> SavedIndicatorSet {
        let set = try makeSavedIndicatorSet(in: directory, defaults: defaults)
        set.load()
        return set
    }

    /// The first run starts from the shipped indicators, compiled, and saves them, with nothing to tell.
    func testTheFirstRunSavesTheShippedIndicators() throws {
        let set = try loaded()
        let reply = set.send(IndicatorRequest(.list))
        XCTAssertEqual(reply.status, .ok)
        XCTAssertEqual(reply.indicators, Indicator.defaults)
        XCTAssertNil(reply.notice)
        XCTAssertFalse(reply.readOnly)
        XCTAssertEqual(set.current.count, Self.shippedIndicators.count)
        XCTAssertEqual(try savedIndicators(in: directory), Indicator.defaults)
        XCTAssertEqual(names(in: directory), [IndicatorFile.layout.fileName], "No marker or temporary file is left")
    }

    /// A saved file is the set: its own indicators, with their severities, and the shipped ones it changed.
    func testASavedFileIsTheSet() throws {
        var indicators = Indicator.defaults
        indicators[0].isEnabled = false
        indicators.append(ownIndicator("Mine", Self.exec, severity: .high))
        try writeIndicatorFile(XCTUnwrap(IndicatorFile(SavedIndicators(indicators)).encoded()), in: directory)
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.list)).indicators, indicators)
        XCTAssertEqual(set.current.count, CompiledIndicators(indicators).count)
        XCTAssertNil(set.send(IndicatorRequest(.list)).notice)
    }

    /// A file an earlier build saved, with that build's shipped severities, takes this build's for every shipped
    /// indicator nobody edited, and keeps the severity someone chose, and an edited rule's, which no longer follows
    /// the build. Only a choice is saved with an unedited one, so it outlasts the next change and a later build's.
    func testShippedSeveritiesFollowTheBuildUnlessChanged() throws {
        let earlierSeverities: [String: IndicatorSeverity] = [
            "Reflective loading": .high, "Dylib inserted": .high, "Login hook set": .high,
            "Quarantine removed": .medium, "Keychain opened": .medium, "Shell startup file modified": .medium,
        ]
        let earlier = Indicator.defaults.map { shipped in
            var indicator = shipped
            indicator.severity = earlierSeverities[shipped.name] ?? shipped.severity
            return indicator
        }
        XCTAssertEqual(zip(earlier, Indicator.defaults).filter { $0.severity != $1.severity }.count,
                       earlierSeverities.count, "Each is a shipped indicator whose severity this build changed")
        var indicators = earlier
        let chosen = try XCTUnwrap(indicators.firstIndex { $0.name == "Login hook set" })
        indicators[chosen].severity = .low
        let edited = try XCTUnwrap(indicators.firstIndex { $0.name == "Dylib inserted" })
        indicators[edited].predicate += " AND process.pid > 1"
        try writeIndicatorFile(XCTUnwrap(IndicatorFile(SavedIndicators(indicators, defaults: earlier)).encoded()),
                               in: directory)
        var expected = Indicator.defaults
        expected[chosen].severity = .low
        expected[edited] = indicators[edited]
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.list)).indicators, expected)
        let mine = ownIndicator("Mine", Self.exec)
        XCTAssertEqual(set.send(IndicatorRequest(.add, indicators: [mine])).status, .ok)
        XCTAssertEqual(try savedIndicators(in: directory), expected + [mine])
        var later = earlier + [mine]
        later[chosen].severity = .low
        later[edited] = indicators[edited]
        XCTAssertEqual(try savedIndicators(in: directory, defaults: earlier), later, "A later build's apply")
    }

    /// A file that can't be read, is too large, isn't an indicator file, or breaks a limit, is moved aside: the
    /// shipped indicators are restored and saved, and the notice says where the file went. Too large is a sound file
    /// padded to one byte past 4 MiB.
    func testADamagedFileIsMovedAside() throws {
        let twin = ownIndicator("Twin", Self.exec)
        let twins = try XCTUnwrap(IndicatorFile(SavedIndicators([twin, twin])).encoded())
        let files = [Data("nope".utf8), Data(#"{"version": 1}"#.utf8), twins,
                     try paddedFile([twin], to: IndicatorLimits.maxFileBytes + 1)]
        for contents in files {
            directory = try makeIndicatorDirectory()
            try writeIndicatorFile(contents, in: directory)
            let set = try loaded()
            let reply = set.send(IndicatorRequest(.list))
            XCTAssertEqual(reply.indicators, Indicator.defaults)
            XCTAssertTrue(reply.notice?.contains(IndicatorFile.layout.unreadableFileName) == true,
                          reply.notice ?? "No notice")
            XCTAssertEqual(indicatorFile(named: IndicatorFile.layout.unreadableFileName, in: directory), contents)
            XCTAssertEqual(try savedIndicators(in: directory), Indicator.defaults)
            XCTAssertEqual(set.send(IndicatorRequest(.add, indicators: [twin])).status, .ok, "It can be changed")
        }
    }

    /// A saved file of exactly 4 MiB is the set. One byte more is moved aside, and the notice says how large it was.
    func testTheFileSizeLimitIsExact() throws {
        let mine = ownIndicator("Mine", Self.exec)
        let atLimit = try paddedFile([mine], to: IndicatorLimits.maxFileBytes)
        try writeIndicatorFile(atLimit, in: directory)
        XCTAssertEqual(try loaded().send(IndicatorRequest(.list)).indicators, [mine])
        XCTAssertEqual(indicatorFile(named: IndicatorFile.layout.fileName, in: directory), atLimit)

        directory = try makeIndicatorDirectory()
        let over = try paddedFile([mine], to: IndicatorLimits.maxFileBytes + 1)
        try writeIndicatorFile(over, in: directory)
        let reply = try loaded().send(IndicatorRequest(.list))
        XCTAssertEqual(reply.indicators, Indicator.defaults)
        let notice = try XCTUnwrap(reply.notice)
        XCTAssertTrue(notice.contains("It's \(IndicatorLimits.maxFileBytes + 1) bytes, larger than 4 MiB."), notice)
        XCTAssertEqual(indicatorFile(named: IndicatorFile.layout.unreadableFileName, in: directory), over)
    }

    /// A sound indicator file with spaces after it.
    ///
    /// - Parameters:
    ///   - indicators: The set.
    ///   - size: The file's size.
    /// - Returns: The file's bytes.
    /// - Throws: An `XCTest` failure if the set can't be encoded.
    private func paddedFile(_ indicators: [Indicator], to size: Int) throws -> Data {
        let json = try XCTUnwrap(IndicatorFile(SavedIndicators(indicators)).encoded())
        return json + Data(repeating: UInt8(ascii: " "), count: size - json.count)
    }

    /// A newer file is kept as it is and the shipped indicators apply. Every change is refused, Restore Defaults
    /// (a replace with the shipped indicators) included, so the newer file is never overwritten.
    func testANewerFileIsReadOnly() throws {
        let newer = Data(#"{"version": 2, "saved": {"entries": [], "sequences": []}}"#.utf8)
        try writeIndicatorFile(newer, in: directory)
        let set = try loaded()
        let listed = set.send(IndicatorRequest(.list))
        XCTAssertEqual(listed.indicators, Indicator.defaults)
        XCTAssertTrue(listed.notice?.contains("newer Mac Monitor") == true)
        XCTAssertTrue(listed.readOnly, "Every reply says so, a list too")
        XCTAssertEqual(set.current.count, Self.shippedIndicators.count)
        let first = try XCTUnwrap(Indicator.defaults.first)
        let changes = [IndicatorRequest(.replace, indicators: Indicator.defaults),
                       IndicatorRequest(.add, indicators: [ownIndicator("Mine", Self.exec)]),
                       IndicatorRequest(.remove, ids: [first.id]),
                       IndicatorRequest(.setEnabled, ids: [first.id], enabled: false)]
        for request in changes {
            let reply = set.send(request)
            XCTAssertEqual(reply.status, .readOnly, request.operation.rawValue)
            XCTAssertFalse(reply.changed)
            XCTAssertNotNil(reply.failure)
            XCTAssertTrue(reply.readOnly)
        }
        XCTAssertEqual(indicatorFile(in: directory), newer, "Untouched")
    }

    /// A directory others can write is never read or written: the shipped indicators apply, and every change is
    /// refused.
    func testAnUntrustedDirectoryKeepsNothing() throws {
        chmod(directory.path, 0o777)
        let set = try loaded()
        let listed = set.send(IndicatorRequest(.list))
        XCTAssertEqual(listed.indicators, Indicator.defaults)
        XCTAssertNotNil(listed.notice)
        XCTAssertEqual(set.send(IndicatorRequest(.add, indicators: [ownIndicator("Mine", Self.exec)])).status,
                       .storageFailed)
        XCTAssertEqual(names(in: directory), [])
    }

    /// A marker left by a load that never finished, as when compiling the saved file stopped the Security Extension,
    /// moves the file aside and restores the shipped indicators, saved. The marker goes.
    func testALoadThatNeverFinishedRecovers() throws {
        let indicators = Indicator.defaults + [ownIndicator("Crashes", Self.exec)]
        let saved = try XCTUnwrap(IndicatorFile(SavedIndicators(indicators)).encoded())
        try writeIndicatorFile(saved, in: directory)
        try writeIndicatorFile(Data(), named: IndicatorFile.loadingLayout.fileName, in: directory)
        let set = try loaded()
        let reply = set.send(IndicatorRequest(.list))
        XCTAssertEqual(reply.indicators, Indicator.defaults)
        XCTAssertTrue(reply.notice?.contains("stopped while it loaded") == true, reply.notice ?? "No notice")
        XCTAssertEqual(indicatorFile(named: IndicatorFile.layout.unreadableFileName, in: directory), saved)
        XCTAssertEqual(try savedIndicators(in: directory), Indicator.defaults)
        XCTAssertNil(indicatorFile(named: IndicatorFile.loadingLayout.fileName, in: directory))
    }

    /// A load that finishes leaves no marker, so the next start loads the saved file again.
    func testALoadThatFinishesLeavesNoMarker() throws {
        let indicators = Indicator.defaults + [ownIndicator("Mine", Self.exec)]
        try writeIndicatorFile(XCTUnwrap(IndicatorFile(SavedIndicators(indicators)).encoded()), in: directory)
        _ = try loaded()
        XCTAssertEqual(names(in: directory), [IndicatorFile.layout.fileName])
        XCTAssertEqual(try loaded().send(IndicatorRequest(.list)).indicators, indicators)
    }

    /// An entry this build can't read, such as a newer build's rule over several events, is kept, said, and written
    /// back after the next change.
    func testAnEntryThisBuildCantReadIsKept() throws {
        let sequence: [String: Any] = ["name": "Later", "predicate": "TRUEPREDICATE", "kind": "sequence"]
        let object: [String: Any] = ["version": 1, "saved": ["entries": [sequence], "deleted": []]]
        try writeIndicatorFile(JSONSerialization.data(withJSONObject: object), in: directory)
        let set = try loaded()
        let listed = set.send(IndicatorRequest(.list))
        XCTAssertEqual(listed.indicators, Indicator.defaults)
        XCTAssertTrue(listed.notice?.contains("1 saved indicator") == true, listed.notice ?? "No notice")
        XCTAssertEqual(set.send(IndicatorRequest(.add, indicators: [ownIndicator("Mine", Self.exec)])).status, .ok)
        let text = String(decoding: try XCTUnwrap(indicatorFile(in: directory)), as: UTF8.self)
        XCTAssertTrue(text.contains(#""kind":"sequence""#), text)
    }

    /// The self-test compiles every shipped indicator: none has a problem in this build. A build whose shipped
    /// indicator can't run says so, and still runs the rest.
    func testTheSelfTestCompilesTheShippedIndicators() throws {
        XCTAssertEqual(try loaded().defaultProblems, [])
        directory = try makeIndicatorDirectory()
        let broken = ownIndicator("Untyped", #"process.executable.name == "curl""#)
        let working = ownIndicator("Exec", Self.exec)
        let set = try loaded(defaults: [broken, working])
        XCTAssertEqual(set.defaultProblems.map(\.id), [broken.id])
        XCTAssertEqual(set.current.count, 1)
        XCTAssertEqual(set.send(IndicatorRequest(.list)).problems.map(\.id), [broken.id])
    }

    /// Loading a saved file reuses the shipped indicators' compiled rules: only the ones it adds are compiled.
    func testLoadingReusesTheShippedRules() throws {
        let indicators = Indicator.defaults + [ownIndicator("Mine", Self.exec)]
        try writeIndicatorFile(XCTUnwrap(IndicatorFile(SavedIndicators(indicators)).encoded()), in: directory)
        XCTAssertEqual(try loaded().current.compiledCount, 1)
    }
}
