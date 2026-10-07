//
//  CommandLineToolLinkerTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The linker the Security Extension runs
/// Runs the linker against a pretend `/` in a temporary directory, as the user running the tests. Covers every way it
/// can change `/usr/local/bin/macmonitor`, every way it refuses to, and that Settings' plans predict it. Creating
/// `/usr/local/bin` as `root:wheel` needs root, so the VM covers that one.
final class CommandLineToolLinkerTests: XCTestCase {
    /// Install into an empty directory links the tool. Doing it again changes nothing.
    func testInstallLinksTheTool() throws {
        let fixture = try ToolLinkFixture(for: self)
        XCTAssertEqual(fixture.apply(.install, fixture.tool), .done)
        XCTAssertEqual(fixture.linkContents, fixture.tool)
        XCTAssertEqual(fixture.apply(.install, fixture.tool, expecting: fixture.tool), .done)
        XCTAssertEqual(fixture.linkContents, fixture.tool)
    }

    /// Install replaces Mac Monitor's link to another copy when it's the link Settings saw.
    func testInstallReplacesMacMonitorsLinkToAnotherCopy() throws {
        let fixture = try ToolLinkFixture(for: self)
        let old = fixture.root + "/Old/Mac Monitor.app/Contents/MacOS/macmonitor"
        try fixture.symlink(fixture.link, to: old)
        XCTAssertEqual(fixture.apply(.install, fixture.tool, expecting: old), .done)
        XCTAssertEqual(fixture.linkContents, fixture.tool)
    }

    /// If anything changed since Settings looked, nothing changes.
    func testAChangeSinceSettingsLookedChangesNothing() throws {
        let fixture = try ToolLinkFixture(for: self)
        let old = fixture.root + "/Old/Mac Monitor.app/Contents/MacOS/macmonitor"
        try fixture.symlink(fixture.link, to: old)
        XCTAssertEqual(fixture.apply(.install, fixture.tool), .changed)
        XCTAssertEqual(fixture.apply(.remove, expecting: fixture.tool), .changed)
        XCTAssertEqual(fixture.linkContents, old)
        try FileManager.default.removeItem(atPath: fixture.link)
        XCTAssertEqual(fixture.apply(.install, fixture.tool, expecting: old), .changed)
        XCTAssertNil(fixture.linkContents)
    }

    /// A file, a directory, or another program's link is never changed or removed, even when Settings expected it.
    func testForeignEntriesAreLeftAlone() throws {
        let fixture = try ToolLinkFixture(for: self)
        try Data("x".utf8).write(to: URL(fileURLWithPath: fixture.link))
        XCTAssertEqual(fixture.apply(.install, fixture.tool), .notMacMonitors)
        XCTAssertEqual(fixture.apply(.remove), .notMacMonitors)
        XCTAssertEqual(fixture.linkContents, "file")
        try FileManager.default.removeItem(atPath: fixture.link)

        try fixture.symlink(fixture.link, to: "/usr/bin/true")
        XCTAssertEqual(fixture.apply(.install, fixture.tool, expecting: "/usr/bin/true"), .notMacMonitors)
        XCTAssertEqual(fixture.apply(.remove, expecting: "/usr/bin/true"), .notMacMonitors)
        XCTAssertEqual(fixture.linkContents, "/usr/bin/true")
        try FileManager.default.removeItem(atPath: fixture.link)

        let directory = fixture.root + "/etc"
        try fixture.makeDirectory(directory)
        try fixture.symlink(fixture.link, to: directory)
        XCTAssertEqual(fixture.apply(.install, fixture.tool, expecting: directory), .notMacMonitors)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory), [])
    }

    /// Mac Monitor's link to a directory is replaced as a link. Nothing lands inside the directory.
    func testALinkToADirectoryIsNeverFollowed() throws {
        let fixture = try ToolLinkFixture(for: self)
        let planted = fixture.root + "/Planted.app/Contents/MacOS/macmonitor"
        try fixture.makeDirectory(planted)
        try fixture.symlink(fixture.link, to: planted)
        XCTAssertEqual(fixture.apply(.install, fixture.tool, expecting: planted), .done)
        XCTAssertEqual(fixture.linkContents, fixture.tool)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: planted), [])
    }

    /// A link directory that's a file or a symbolic link is refused, and nothing lands where the link points.
    func testALinkDirectoryThatIsntOneIsRefused() throws {
        let fixture = try ToolLinkFixture(for: self)
        try FileManager.default.removeItem(atPath: fixture.binDirectory)
        let elsewhere = fixture.root + "/elsewhere"
        try fixture.makeDirectory(elsewhere)
        try fixture.symlink(fixture.binDirectory, to: elsewhere)
        XCTAssertEqual(fixture.apply(.install, fixture.tool), .notADirectory)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: elsewhere), [])
        try FileManager.default.removeItem(atPath: fixture.binDirectory)
        try Data().write(to: URL(fileURLWithPath: fixture.binDirectory))
        XCTAssertEqual(fixture.apply(.install, fixture.tool), .notADirectory)
    }

    /// A tool that isn't an executable file in an app is refused before anything changes, so an Update with a bad
    /// tool keeps the old link.
    func testABadToolIsRefusedBeforeAnythingChanges() throws {
        let fixture = try ToolLinkFixture(for: self)
        let old = fixture.root + "/Old/Mac Monitor.app/Contents/MacOS/macmonitor"
        try fixture.symlink(fixture.link, to: old)
        let notInAnApp = fixture.root + "/Applications/Mac Monitor.app/Contents/MacOS/other"
        try fixture.makeTool(at: notInAnApp)
        let behindALink = fixture.root + "/Alias.app/Contents/MacOS/macmonitor"
        try fixture.makeDirectory((behindALink as NSString).deletingLastPathComponent)
        try fixture.symlink(behindALink, to: fixture.tool)
        let missing = fixture.root + "/Missing.app/Contents/MacOS/macmonitor"
        for tool in [notInAnApp, behindALink, missing, "relative.app/Contents/MacOS/macmonitor"] {
            XCTAssertEqual(fixture.apply(.install, tool, expecting: old), .badTool, tool)
            XCTAssertEqual(fixture.linkContents, old)
        }
        chmod(fixture.tool, 0o644)
        XCTAssertEqual(fixture.apply(.install, fixture.tool, expecting: old), .badTool)
    }

    /// A tool that fails the trust check is refused too, and the old link stays.
    func testAnUntrustedToolIsRefused() throws {
        let fixture = try ToolLinkFixture(for: self)
        let plan = CommandLineToolLink.Plan(action: .install, tool: fixture.tool, binDirectory: fixture.binDirectory,
                                            expected: "")
        XCTAssertEqual(CommandLineToolLinker { _ in false }.apply(plan), .badTool)
        XCTAssertNil(fixture.linkContents)
    }

    /// Our tool fails the full check outside a root-owned install. The test bundle's temporary directory belongs to
    /// the user running the tests.
    func testTheFullCheckNeedsARootOwnedInstall() throws {
        try XCTSkipIf(getuid() == 0, "Root owns everything root creates.")
        let fixture = try ToolLinkFixture(for: self)
        XCTAssertFalse(CommandLineToolLinker.isTrustedTool(fixture.tool))
    }

    /// Remove takes Mac Monitor's link wherever it points. It's done when there's nothing there, or no directory.
    func testRemoveTakesOnlyMacMonitorsLink() throws {
        let fixture = try ToolLinkFixture(for: self)
        for value in [fixture.tool, fixture.root + "/Gone.app/Contents/MacOS/macmonitor"] {
            try fixture.symlink(fixture.link, to: value)
            XCTAssertEqual(fixture.apply(.remove, expecting: value), .done)
            XCTAssertNil(fixture.linkContents)
        }
        XCTAssertEqual(fixture.apply(.remove), .done)
        try FileManager.default.removeItem(atPath: fixture.binDirectory)
        XCTAssertEqual(fixture.apply(.remove), .done)
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.binDirectory))
    }

    /// A missing link directory has to be handed to root:wheel. If that can't be done it's removed again.
    func testAMissingDirectoryNeedsRoot() throws {
        try XCTSkipIf(getuid() == 0, "As root the directory is created. The VM covers that.")
        let fixture = try ToolLinkFixture(for: self)
        try FileManager.default.removeItem(atPath: fixture.binDirectory)
        XCTAssertEqual(fixture.apply(.install, fixture.tool), .directoryNotCreated)
        XCTAssertNil(fixture.linkContents)
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.binDirectory))
    }

    /// A missing link directory is only created in a real directory our user owns. Never through a link, and never
    /// where someone else could swap in a link while we work.
    func testAMissingDirectoryIsOnlyCreatedInADirectoryItsUserOwns() throws {
        try XCTSkipIf(getuid() == 0, "Root owns the directory this test needs someone else to own.")
        let fixture = try ToolLinkFixture(for: self)
        let local = fixture.root + "/usr/local", elsewhere = fixture.root + "/elsewhere"
        try FileManager.default.removeItem(atPath: local)
        try fixture.makeDirectory(elsewhere)
        try fixture.symlink(local, to: elsewhere)
        XCTAssertEqual(fixture.apply(.install, fixture.tool), .notADirectory)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: elsewhere), [])

        /// `/usr` belongs to root, not to the user running the test.
        let foreign = "/usr/macmonitor-\(UUID().uuidString)"
        XCTAssertEqual(fixture.apply(.install, fixture.tool, in: foreign), .notADirectory)
        XCTAssertFalse(FileManager.default.fileExists(atPath: foreign))
    }

    /// Settings' plans predict the linker. Every plan Settings offers succeeds and leaves what it promised. Where
    /// Settings offers nothing, the linker changes nothing when asked anyway.
    func testSettingsPlansPredictTheLinker() throws {
        let fixture = try ToolLinkFixture(for: self)
        let other = fixture.root + "/Other/Mac Monitor.app/Contents/MacOS/macmonitor"
        try fixture.makeTool(at: other)
        let setups: [() throws -> Void] = [
            {},
            { try fixture.symlink(fixture.link, to: fixture.tool) },
            { try fixture.symlink(fixture.link, to: other) },
            { try fixture.symlink(fixture.link, to: fixture.root + "/Gone.app/Contents/MacOS/macmonitor") },
            { try fixture.symlink(fixture.link, to: "/usr/bin/true") },
            { try Data().write(to: URL(fileURLWithPath: fixture.link)) }
        ]
        for (index, setup) in setups.enumerated() {
            for action in [CommandLineToolLink.Action.install, .remove] {
                try? FileManager.default.removeItem(atPath: fixture.link)
                try setup()
                let inspection = fixture.linker().inspect()
                let plan = inspection.plan(action)
                let outcome = fixture.apply(action, plan?.tool ?? fixture.tool,
                                            expecting: plan?.expected ?? inspection.linkValue ?? "")
                let after = fixture.linker().inspect().link
                guard plan != nil else {
                    XCTAssertEqual(after, inspection.link, "\(index) \(action): \(outcome) changed it")
                    continue
                }
                XCTAssertEqual(outcome, .done, "\(index) \(action)")
                XCTAssertEqual(after, action == .install ? .current : .absent)
            }
        }
    }
}
