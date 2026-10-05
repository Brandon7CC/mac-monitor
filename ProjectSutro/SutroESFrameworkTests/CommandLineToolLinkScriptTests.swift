//
//  CommandLineToolLinkScriptTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The script root runs
/// Runs the link script, as shipped, against a pretend `/` in a temporary directory, as the user running the tests:
/// every way it can change `/usr/local/bin/macmonitor`, every way it refuses to, and that Settings' plans predict it.
/// Creating `/usr/local/bin` as `root:wheel` needs root, so the VM covers that one.
final class CommandLineToolLinkScriptTests: XCTestCase {
    /// Install into an empty directory links the tool; again with what's there now changes nothing.
    ///
    /// - Throws: An unexpected error.
    func testInstallLinksTheTool() throws {
        let fixture = try ToolLinkFixture(for: self)
        XCTAssertEqual(try fixture.runScript(["install", fixture.tool, fixture.binDirectory, ""]), 0)
        XCTAssertEqual(fixture.linkContents, fixture.tool)
        XCTAssertEqual(try fixture.runScript(["install", fixture.tool, fixture.binDirectory, fixture.tool]), 0)
        XCTAssertEqual(fixture.linkContents, fixture.tool)
    }
    
    /// Install replaces Mac Monitor's link to another copy, or to nothing, when it's the link Settings saw.
    ///
    /// - Throws: An unexpected error.
    func testInstallReplacesMacMonitorsLinkToAnotherCopy() throws {
        let fixture = try ToolLinkFixture(for: self)
        let old = fixture.root + "/Old/Mac Monitor.app/Contents/MacOS/macmonitor"
        try fixture.symlink(fixture.link, to: old)
        XCTAssertEqual(try fixture.runScript(["install", fixture.tool, fixture.binDirectory, old]), 0)
        XCTAssertEqual(fixture.linkContents, fixture.tool)
    }
    
    /// Anything that changed since Settings looked, in either direction, changes nothing.
    ///
    /// - Throws: An unexpected error.
    func testAChangeSinceSettingsLookedChangesNothing() throws {
        let fixture = try ToolLinkFixture(for: self)
        let old = fixture.root + "/Old/Mac Monitor.app/Contents/MacOS/macmonitor"
        try fixture.symlink(fixture.link, to: old)
        XCTAssertEqual(try fixture.runScript(["install", fixture.tool, fixture.binDirectory, ""]), 6)
        XCTAssertEqual(try fixture.runScript(["remove", "", fixture.binDirectory, fixture.tool]), 6)
        XCTAssertEqual(fixture.linkContents, old)
        try FileManager.default.removeItem(atPath: fixture.link)
        XCTAssertEqual(try fixture.runScript(["install", fixture.tool, fixture.binDirectory, old]), 6)
        XCTAssertNil(fixture.linkContents)
    }
    
    /// A file, a directory, or another program's link is never changed or removed, even when Settings expected it.
    ///
    /// - Throws: An unexpected error.
    func testForeignEntriesAreLeftAlone() throws {
        let fixture = try ToolLinkFixture(for: self)
        try Data("x".utf8).write(to: URL(fileURLWithPath: fixture.link))
        XCTAssertEqual(try fixture.runScript(["install", fixture.tool, fixture.binDirectory, ""]), 5)
        XCTAssertEqual(try fixture.runScript(["remove", "", fixture.binDirectory, ""]), 5)
        XCTAssertEqual(fixture.linkContents, "file")
        try FileManager.default.removeItem(atPath: fixture.link)
        
        try fixture.symlink(fixture.link, to: "/usr/bin/true")
        XCTAssertEqual(try fixture.runScript(["install", fixture.tool, fixture.binDirectory, "/usr/bin/true"]), 5)
        XCTAssertEqual(try fixture.runScript(["remove", "", fixture.binDirectory, "/usr/bin/true"]), 5)
        XCTAssertEqual(fixture.linkContents, "/usr/bin/true")
        try FileManager.default.removeItem(atPath: fixture.link)
        
        let directory = fixture.root + "/etc"
        try fixture.makeDirectory(directory)
        try fixture.symlink(fixture.link, to: directory)
        XCTAssertEqual(try fixture.runScript(["install", fixture.tool, fixture.binDirectory, directory]), 5)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory), [])
    }
    
    /// Mac Monitor's link to a directory is replaced as a link: nothing lands inside the directory.
    ///
    /// - Throws: An unexpected error.
    func testALinkToADirectoryIsNeverFollowed() throws {
        let fixture = try ToolLinkFixture(for: self)
        let planted = fixture.root + "/Planted.app/Contents/MacOS/macmonitor"
        try fixture.makeDirectory(planted)
        try fixture.symlink(fixture.link, to: planted)
        XCTAssertEqual(try fixture.runScript(["install", fixture.tool, fixture.binDirectory, planted]), 0)
        XCTAssertEqual(fixture.linkContents, fixture.tool)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: planted), [])
    }
    
    /// A link directory that's a file or a symbolic link is refused, and nothing lands where the link points.
    ///
    /// - Throws: An unexpected error.
    func testALinkDirectoryThatIsntOneIsRefused() throws {
        let fixture = try ToolLinkFixture(for: self)
        try FileManager.default.removeItem(atPath: fixture.binDirectory)
        let elsewhere = fixture.root + "/elsewhere"
        try fixture.makeDirectory(elsewhere)
        try fixture.symlink(fixture.binDirectory, to: elsewhere)
        XCTAssertEqual(try fixture.runScript(["install", fixture.tool, fixture.binDirectory, ""]), 4)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: elsewhere), [])
        try FileManager.default.removeItem(atPath: fixture.binDirectory)
        try Data().write(to: URL(fileURLWithPath: fixture.binDirectory))
        XCTAssertEqual(try fixture.runScript(["install", fixture.tool, fixture.binDirectory, ""]), 4)
    }
    
    /// A tool that isn't an executable file in an app is refused before anything changes, so an Update with a bad
    /// tool keeps the old link.
    ///
    /// - Throws: An unexpected error.
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
            XCTAssertEqual(try fixture.runScript(["install", tool, fixture.binDirectory, old]), 7, tool)
            XCTAssertEqual(fixture.linkContents, old)
        }
        chmod(fixture.tool, 0o644)
        XCTAssertEqual(try fixture.runScript(["install", fixture.tool, fixture.binDirectory, old]), 7)
    }
    
    /// Remove takes Mac Monitor's link wherever it points, and is done when there's nothing, or no directory.
    ///
    /// - Throws: An unexpected error.
    func testRemoveTakesOnlyMacMonitorsLink() throws {
        let fixture = try ToolLinkFixture(for: self)
        for value in [fixture.tool, fixture.root + "/Gone.app/Contents/MacOS/macmonitor"] {
            try fixture.symlink(fixture.link, to: value)
            XCTAssertEqual(try fixture.runScript(["remove", "", fixture.binDirectory, value]), 0)
            XCTAssertNil(fixture.linkContents)
        }
        XCTAssertEqual(try fixture.runScript(["remove", "", fixture.binDirectory, ""]), 0)
        try FileManager.default.removeItem(atPath: fixture.binDirectory)
        XCTAssertEqual(try fixture.runScript(["remove", "", fixture.binDirectory, ""]), 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.binDirectory))
    }
    
    /// Creating a missing link directory hands it to root:wheel, and fails closed when that can't be done.
    ///
    /// - Throws: An unexpected error.
    func testAMissingDirectoryNeedsRoot() throws {
        try XCTSkipIf(getuid() == 0, "As root the directory is created; the VM covers that.")
        let fixture = try ToolLinkFixture(for: self)
        try FileManager.default.removeItem(atPath: fixture.binDirectory)
        XCTAssertEqual(try fixture.runScript(["install", fixture.tool, fixture.binDirectory, ""]), 3)
        XCTAssertNil(fixture.linkContents)
    }
    
    /// A missing link directory is only created in a real directory the script's user owns: never through a link,
    /// and never where someone else could swap in a link between the checks and the `chown`.
    ///
    /// - Throws: An unexpected error.
    func testAMissingDirectoryIsOnlyCreatedInADirectoryItsUserOwns() throws {
        try XCTSkipIf(getuid() == 0, "Root owns the directory this test needs someone else to own.")
        let fixture = try ToolLinkFixture(for: self)
        let local = fixture.root + "/usr/local", elsewhere = fixture.root + "/elsewhere"
        try FileManager.default.removeItem(atPath: local)
        try fixture.makeDirectory(elsewhere)
        try fixture.symlink(local, to: elsewhere)
        XCTAssertEqual(try fixture.runScript(["install", fixture.tool, fixture.binDirectory, ""]), 4)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: elsewhere), [])
        
        /// `/usr` belongs to root, not to the user running the test.
        let foreign = "/usr/macmonitor-\(UUID().uuidString)"
        XCTAssertEqual(try fixture.runScript(["install", fixture.tool, foreign, ""]), 4)
        XCTAssertFalse(FileManager.default.fileExists(atPath: foreign))
    }
    
    /// Wrong arguments are refused.
    ///
    /// - Throws: An unexpected error.
    func testWrongArgumentsAreRefused() throws {
        let fixture = try ToolLinkFixture(for: self)
        XCTAssertEqual(try fixture.runScript(["install", fixture.tool, fixture.binDirectory]), 2)
        XCTAssertEqual(try fixture.runScript(["replace", fixture.tool, fixture.binDirectory, ""]), 2)
        XCTAssertNil(fixture.linkContents)
    }
    
    /// The script's `ours` and ``CommandLineToolLink/isMacMonitorLink(_:)`` agree.
    func testTheScriptAndSettingsAgreeOnWhatsMacMonitors() throws {
        let fixture = try ToolLinkFixture(for: self)
        let ours = try XCTUnwrap(CommandLineToolLinkScript.source.split(separator: "\n").first {
            $0.hasPrefix("ours()")
        })
        let values = ["/Applications/Mac Monitor.app/Contents/MacOS/macmonitor", "/.app/Contents/MacOS/macmonitor",
                      "/a b/It's \"x\".app/Contents/MacOS/macmonitor", "Mac Monitor.app/Contents/MacOS/macmonitor",
                      "/Applications/Mac Monitor.app/Contents/MacOS/macmonitor2", "/usr/bin/true", "",
                      "/Applications/Mac Monitor.app/Contents/MacOS/macmonitor/", "/x.app/Contents/MacOS/macmonitor\n"]
        for value in values {
            let status = try fixture.runScript([value], source: "\(ours)\nours \"$1\"")
            XCTAssertEqual(status == 0, CommandLineToolLink.isMacMonitorLink(value), value)
        }
    }
    
    /// Settings' plans predict the script: every plan Settings offers succeeds and leaves what it promised, and the
    /// script, asked anyway, changes nothing where Settings offers nothing.
    ///
    /// - Throws: An unexpected error.
    func testSettingsPlansPredictTheScript() throws {
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
                let arguments = plan?.arguments
                    ?? [action.rawValue, fixture.tool, fixture.binDirectory, inspection.linkValue ?? ""]
                let status = try fixture.runScript(arguments)
                let after = fixture.linker().inspect().link
                guard plan != nil else {
                    XCTAssertEqual(after, inspection.link, "\(index) \(action): \(status) changed it")
                    continue
                }
                XCTAssertEqual(status, 0, "\(index) \(action)")
                XCTAssertEqual(after, action == .install ? .current : .absent)
            }
        }
    }
}
