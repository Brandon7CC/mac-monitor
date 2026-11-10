//
//  SavedIndicatorSetChangeTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Changing the Mac's indicator set
/// Pins each request to the Mac's indicator set: what add, remove, setEnabled and replace make of it, what's saved,
/// what's refused and why, who may change it, that an indicator that can't run is kept and listed, that a change
/// compiles only what it adds, and that a list is answered from one reply a change.
final class SavedIndicatorSetChangeTests: XCTestCase {
    /// Every exec.
    private static let exec = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#

    /// The test's directory.
    private var directory: URL!
    /// A loaded set in it.
    private var set: SavedIndicatorSet!

    /// A loaded set in a fresh directory for each test.
    ///
    /// - Throws: If the directory can't be created.
    override func setUpWithError() throws {
        try super.setUpWithError()
        directory = try makeIndicatorDirectory()
        set = try makeSavedIndicatorSet(in: directory)
        set.load()
    }

    /// Add merges: a new identity joins at the end, a known one is replaced in its place, severity and all. Each
    /// change is saved, and a set loaded from the file has it.
    func testAddMergesAndSaves() throws {
        let mine = ownIndicator("Mine", Self.exec, severity: .low)
        var edited = try XCTUnwrap(Indicator.defaults.first)
        edited.severity = .high
        edited.predicate += " AND process.is_platform_binary == NO"
        let reply = set.send(IndicatorRequest(.add, indicators: [mine, edited]))
        XCTAssertEqual(reply.status, .ok)
        XCTAssertTrue(reply.changed)
        XCTAssertEqual(reply.access, .write)
        let expected = [edited] + Indicator.defaults.dropFirst() + [mine]
        XCTAssertEqual(reply.indicators, expected)
        XCTAssertEqual(try savedIndicators(in: directory), expected)
        let reloaded = try makeSavedIndicatorSet(in: directory)
        XCTAssertEqual(reloaded.send(IndicatorRequest(.list)).indicators.map(\.severity), expected.map(\.severity))
    }

    /// Remove takes indicators out by identity, setEnabled turns them on or off, and replace makes the set exactly
    /// what it brings. Restore Defaults, a replace with the shipped indicators, brings back what was removed.
    func testRemoveSetEnabledAndReplace() throws {
        let (first, second) = (Indicator.defaults[0], Indicator.defaults[1])
        XCTAssertEqual(set.send(IndicatorRequest(.remove, ids: [first.id])).indicators,
                       Array(Indicator.defaults.dropFirst()))
        let off = set.send(IndicatorRequest(.setEnabled, ids: [second.id], enabled: false))
        XCTAssertEqual(off.indicators.first { $0.id == second.id }?.isEnabled, false)
        XCTAssertEqual(try savedIndicators(in: directory).first { $0.id == second.id }?.isEnabled, false)

        let mine = ownIndicator("Mine", Self.exec)
        XCTAssertEqual(set.send(IndicatorRequest(.replace, indicators: [mine])).indicators, [mine])
        XCTAssertEqual(set.current.count, 1)
        let restored = set.send(IndicatorRequest(.replace, indicators: Indicator.defaults))
        XCTAssertEqual(restored.indicators, Indicator.defaults)
        XCTAssertEqual(try savedIndicators(in: directory), Indicator.defaults)
    }

    /// A reset, which Restore Defaults sends, makes the set the indicators this Security Extension ships and not any
    /// the request brings: a Mac Monitor of another build can't put its own list in their place. It's saved as the
    /// shipped set, with nothing recorded as removed or edited.
    func testAResetIsTheExtensionsOwnDefaults() throws {
        let shipped = Array(Indicator.defaults.prefix(3)) + [ownIndicator("Only this build's", Self.exec)]
        let directory = try makeIndicatorDirectory()
        let set = try makeSavedIndicatorSet(in: directory, defaults: shipped)
        set.load()
        XCTAssertEqual(set.send(IndicatorRequest(.remove, ids: [shipped[0].id, shipped[3].id])).indicators.count, 2)
        let reset = set.send(IndicatorRequest(.reset, indicators: Array(Indicator.defaults.suffix(2))))
        XCTAssertEqual(reset.status, .ok)
        XCTAssertEqual(reset.indicators, shipped)
        let reloaded = try makeSavedIndicatorSet(in: directory, defaults: shipped)
        reloaded.load()
        XCTAssertEqual(reloaded.send(IndicatorRequest(.list)).indicators, shipped)
    }

    /// A request that names an identity the set doesn't have, none at all, or doesn't say on or off, is invalid, and
    /// so is one that brings an indicator past a limit. Nothing changes, on disk or in the followers' set.
    func testInvalidChangesChangeNothing() throws {
        let before = try XCTUnwrap(indicatorFile(in: directory))
        let compiled = set.current
        let unknown = ownIndicator("Unknown", #"es_event_type == "ES_EVENT_TYPE_NOTIFY_NOPE""#)
        var twin = ownIndicator("Twin", Self.exec)
        twin.id = Indicator.defaults[0].id
        let tooMany = (0...IndicatorLimits.maxRulesPerType).map {
            ownIndicator("\($0)", Self.exec + #" AND process.executable.name == "\#($0)""#)
        }
        let requests = [IndicatorRequest(.remove, ids: [UUID()]), IndicatorRequest(.remove),
                        IndicatorRequest(.setEnabled, ids: [Indicator.defaults[0].id]),
                        IndicatorRequest(.add, indicators: [unknown]),
                        IndicatorRequest(.replace, indicators: [twin, Indicator.defaults[0]]),
                        IndicatorRequest(.replace, indicators: tooMany)]
        for request in requests {
            let reply = set.send(request)
            XCTAssertEqual(reply.status, .invalid, request.operation.rawValue)
            XCTAssertFalse(reply.changed)
            XCTAssertNotNil(reply.failure)
            XCTAssertEqual(reply.indicators, Indicator.defaults)
        }
        XCTAssertEqual(indicatorFile(in: directory), before)
        XCTAssertTrue(set.current === compiled)
    }

    /// A change to nothing is answered without a save.
    func testANoOpChangeSavesNothing() throws {
        let path = directory.appendingPathComponent(IndicatorFile.layout.fileName).path
        let before = try FileManager.default.attributesOfItem(atPath: path)[.systemFileNumber] as? Int
        let reply = set.send(IndicatorRequest(.add, indicators: [Indicator.defaults[0]]))
        XCTAssertEqual(reply.status, .ok)
        XCTAssertFalse(reply.changed)
        let after = try FileManager.default.attributesOfItem(atPath: path)[.systemFileNumber] as? Int
        XCTAssertEqual(before, after, "A save replaces the file")
    }

    /// An indicator the Security Extension can't run joins and is kept, and every reply says why, in the set's
    /// order, until it's fixed.
    func testAnIndicatorThatCantRunIsKeptAndListed() throws {
        let untyped = ownIndicator("Untyped", #"process.executable.name == "curl""#)
        let added = set.send(IndicatorRequest(.add, indicators: [untyped]))
        XCTAssertEqual(added.status, .ok)
        XCTAssertEqual(added.indicators.last, untyped)
        XCTAssertEqual(added.problems.map(\.id), [untyped.id])
        XCTAssertEqual(added.problems.first?.reason, SensorProblem.untyped.description)
        XCTAssertEqual(set.send(IndicatorRequest(.list)).problems.map(\.id), [untyped.id])
        XCTAssertEqual(try savedIndicators(in: directory).last, untyped)

        var fixed = untyped
        fixed.predicate = Self.exec + #" AND process.executable.name == "curl""#
        XCTAssertEqual(set.send(IndicatorRequest(.add, indicators: [fixed])).problems, [])
    }

    /// A change compiles only the predicates it adds, and takes the rest from the set it replaces.
    func testAChangeCompilesOnlyWhatItAdds() {
        set.send(IndicatorRequest(.add, indicators: [ownIndicator("Mine", Self.exec)]))
        XCTAssertEqual(set.current.compiledCount, 1)
        set.send(IndicatorRequest(.setEnabled, ids: [Indicator.defaults[0].id], enabled: false))
        XCTAssertEqual(set.current.compiledCount, 0)
    }

    /// A list is answered from the reply cached for its access, encoded once a change, and a change empties the
    /// cache. A stand-in put in the cache is what the next list gets, so the answer can only have come from it.
    func testAListIsAnsweredFromItsCacheUntilTheNextChange() {
        let request = IndicatorRequest(.list).encoded()
        let first = set.respond(to: request, access: .write, caller: "Test")
        XCTAssertEqual(set.queue.sync { set.listReplies }, [.write: first])
        let standIn = Data("cached".utf8)
        set.queue.sync { set.listReplies[.write] = standIn }
        XCTAssertEqual(set.respond(to: request, access: .write, caller: "Test"), standIn)
        let listing = set.respond(to: request, access: .list, caller: "Test")
        XCTAssertEqual(IndicatorReply.decode(listing)?.access, .list)
        XCTAssertEqual(set.queue.sync { set.listReplies }, [.write: standIn, .list: listing])
        set.send(IndicatorRequest(.add, indicators: [ownIndicator("Mine", Self.exec)]))
        XCTAssertEqual(set.queue.sync { set.listReplies }, [:], "A change empties the cache")
        let after = set.respond(to: request, access: .write, caller: "Test")
        XCTAssertEqual(IndicatorReply.decode(after)?.indicators.last?.name, "Mine")
        XCTAssertEqual(set.queue.sync { set.listReplies }, [.write: after])
    }

    /// A caller that may only read is refused every change and told who can, one that may only list is pointed at
    /// the setting, and both may list. A refusal changes nothing.
    func testCallersThatMayOnlyReadOrListAreRefused() throws {
        let add = IndicatorRequest(.add, indicators: [ownIndicator("Mine", Self.exec)])
        let read = set.send(add, access: .read)
        XCTAssertEqual(read.status, .refused)
        XCTAssertEqual(read.access, .read)
        XCTAssertEqual(read.failure, MuteAccess.read.refusal(changing: "the indicators")?.problem)
        XCTAssertTrue(read.failure?.contains("owns the event stream") == true)
        let listed = set.send(IndicatorRequest(.replace, indicators: []), access: .list)
        XCTAssertEqual(listed.status, .refused)
        XCTAssertEqual(listed.failure, CommandLineAccess.needsChanges)
        for access in [MuteAccess.read, .list] {
            XCTAssertEqual(set.send(IndicatorRequest(.list), access: access).status, .ok)
        }
        XCTAssertEqual(try savedIndicators(in: directory), Indicator.defaults)
    }

    /// Bytes that aren't a request are invalid, and a newer request unsupported, each with the set as it stands.
    func testUnreadableRequests() {
        let invalid = set.send(Data("nope".utf8))
        XCTAssertEqual(invalid.status, .invalid)
        XCTAssertEqual(invalid.indicators, Indicator.defaults)
        XCTAssertEqual(set.send(Data(#"{"version": 9, "operation": "list"}"#.utf8)).status, .unsupported)
    }
}
