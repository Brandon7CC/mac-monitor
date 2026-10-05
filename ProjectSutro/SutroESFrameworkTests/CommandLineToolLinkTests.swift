//
//  CommandLineToolLinkTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - What Settings sees
/// Pins what Settings ▸ Command Line sees at `/usr/local/bin/macmonitor` and what it may do there, against a pretend
/// `/` in a temporary directory: only Mac Monitor's own links are ever changed, and only a tool root alone can change
/// is ever linked.
final class CommandLineToolLinkTests: XCTestCase {
    /// Nothing there: Install links this copy's tool, and there's nothing to remove.
    ///
    /// - Throws: An unexpected error.
    func testNothingThereCanBeInstalled() throws {
        let fixture = try ToolLinkFixture(for: self)
        let inspection = fixture.linker().inspect()
        XCTAssertEqual(inspection.link, .absent)
        XCTAssertEqual(inspection.tool, .success(fixture.tool))
        XCTAssertEqual(inspection.plan(.install), CommandLineToolLink.Plan(
            action: .install, tool: fixture.tool, binDirectory: fixture.binDirectory, expected: ""))
        XCTAssertNil(inspection.plan(.remove))
        XCTAssertNil(inspection.binDirectoryWarning)
    }
    
    /// No link directory yet is nothing there: the script creates it.
    ///
    /// - Throws: An unexpected error.
    func testNoDirectoryIsNothingThere() throws {
        let fixture = try ToolLinkFixture(for: self)
        try FileManager.default.removeItem(atPath: fixture.binDirectory)
        let inspection = fixture.linker().inspect()
        XCTAssertEqual(inspection.link, .absent)
        XCTAssertNotNil(inspection.plan(.install))
        XCTAssertNil(inspection.binDirectoryWarning)
    }
    
    /// Mac Monitor's link to this copy: nothing to install, and Remove expects exactly that link.
    ///
    /// - Throws: An unexpected error.
    func testALinkToThisCopyIsCurrent() throws {
        let fixture = try ToolLinkFixture(for: self)
        try fixture.symlink(fixture.link, to: fixture.tool)
        let inspection = fixture.linker().inspect()
        XCTAssertEqual(inspection.link, .current)
        XCTAssertNil(inspection.plan(.install))
        XCTAssertEqual(inspection.plan(.remove), CommandLineToolLink.Plan(
            action: .remove, tool: "", binDirectory: fixture.binDirectory, expected: fixture.tool))
    }
    
    /// Mac Monitor's link to another copy, or to one that's gone: Update or Repair replaces exactly that link.
    ///
    /// - Throws: An unexpected error.
    func testALinkToAnotherCopyOrToNothingCanBeReplaced() throws {
        let fixture = try ToolLinkFixture(for: self)
        let other = fixture.root + "/Users/Shared/Mac Monitor.app/Contents/MacOS/macmonitor"
        try fixture.makeTool(at: other)
        let gone = fixture.root + "/Old/Mac Monitor 2.1.app/Contents/MacOS/macmonitor"
        for (value, state) in [(other, CommandLineToolLink.LinkState.elsewhere(other)), (gone, .broken(gone))] {
            try? FileManager.default.removeItem(atPath: fixture.link)
            try fixture.symlink(fixture.link, to: value)
            let inspection = fixture.linker().inspect()
            XCTAssertEqual(inspection.link, state)
            XCTAssertEqual(inspection.plan(.install)?.expected, value)
            XCTAssertEqual(inspection.plan(.install)?.tool, fixture.tool)
            XCTAssertEqual(inspection.plan(.remove)?.expected, value)
        }
    }
    
    /// A file, a directory, another program's link (absolute or relative, as Homebrew's are): never touched.
    ///
    /// - Throws: An unexpected error.
    func testForeignEntriesAreNeverTouched() throws {
        let fixture = try ToolLinkFixture(for: self)
        let entries: [(make: () throws -> Void, state: CommandLineToolLink.LinkState)] = [
            ({ try Data("x".utf8).write(to: URL(fileURLWithPath: fixture.link)) }, .foreign("a file")),
            ({ try fixture.makeDirectory(fixture.link) }, .foreign("a directory")),
            ({ try fixture.symlink(fixture.link, to: "/usr/bin/true") }, .foreign("a symbolic link to /usr/bin/true")),
            ({ try fixture.symlink(fixture.link, to: "../Cellar/macmonitor/1.0/bin/macmonitor") },
             .foreign("a symbolic link to ../Cellar/macmonitor/1.0/bin/macmonitor"))
        ]
        for entry in entries {
            try? FileManager.default.removeItem(atPath: fixture.link)
            try entry.make()
            let inspection = fixture.linker().inspect()
            XCTAssertEqual(inspection.link, entry.state)
            XCTAssertNil(inspection.plan(.install))
            XCTAssertNil(inspection.plan(.remove))
        }
    }
    
    /// A link directory that's a file, or a symbolic link: nothing may be done there.
    ///
    /// - Throws: An unexpected error.
    func testALinkDirectoryThatIsntOneIsUnusable() throws {
        let fixture = try ToolLinkFixture(for: self)
        try FileManager.default.removeItem(atPath: fixture.binDirectory)
        try Data().write(to: URL(fileURLWithPath: fixture.binDirectory))
        XCTAssertEqual(fixture.linker().inspect().link, .unusableDirectory("isn't a directory"))
        try FileManager.default.removeItem(atPath: fixture.binDirectory)
        try fixture.makeDirectory(fixture.root + "/elsewhere")
        try fixture.symlink(fixture.binDirectory, to: fixture.root + "/elsewhere")
        let inspection = fixture.linker().inspect()
        XCTAssertEqual(inspection.link, .unusableDirectory("is a symbolic link"))
        XCTAssertNil(inspection.plan(.install))
    }
    
    /// A bundle reached through a symbolic link links the real tool, not the path through the link.
    ///
    /// - Throws: An unexpected error.
    func testTheRealPathIsLinked() throws {
        let fixture = try ToolLinkFixture(for: self)
        let alias = fixture.root + "/Mac Monitor.app"
        try fixture.symlink(alias, to: fixture.bundle)
        XCTAssertEqual(fixture.linker(fixture.layout(bundle: alias)).inspect().tool, .success(fixture.tool))
    }
    
    /// A tool that can't be linked: missing, not an executable file, behind a link, not in an app, or translocated.
    /// Install is refused, but Remove still works on Mac Monitor's link.
    ///
    /// - Throws: An unexpected error.
    func testAToolThatIsntAnExecutableInAnAppIsRefused() throws {
        let fixture = try ToolLinkFixture(for: self)
        try fixture.symlink(fixture.link, to: fixture.tool)
        chmod(fixture.tool, 0o644)
        let notExecutable = fixture.linker().inspect()
        XCTAssertEqual(notExecutable.tool, .failure(.toolNotExecutable(fixture.tool)))
        XCTAssertNotNil(notExecutable.plan(.remove))
        try FileManager.default.removeItem(atPath: fixture.tool)
        XCTAssertEqual(fixture.linker().inspect().tool, .failure(.toolMissing(fixture.tool)))
        try fixture.makeDirectory(fixture.tool)
        XCTAssertEqual(fixture.linker().inspect().tool, .failure(.toolNotExecutable(fixture.tool)))
        try FileManager.default.removeItem(atPath: fixture.tool)
        try fixture.makeTool(at: fixture.root + "/real-macmonitor")
        try fixture.symlink(fixture.tool, to: fixture.root + "/real-macmonitor")
        XCTAssertEqual(fixture.linker().inspect().tool, .failure(.notCanonical(fixture.tool)))
        
        let products = fixture.root + "/Build/Products/Community"
        try fixture.makeTool(at: products + "/Contents/MacOS/macmonitor")
        XCTAssertEqual(fixture.linker(fixture.layout(bundle: products)).inspect().tool,
                       .failure(.notAnApplication(products)))
        let translocated = fixture.root + "/private/var/folders/x/T/AppTranslocation/1234/d/Mac Monitor.app"
        try fixture.makeTool(at: translocated + "/Contents/MacOS/macmonitor")
        XCTAssertEqual(fixture.linker(fixture.layout(bundle: translocated)).inspect().tool, .failure(.translocated))
    }
    
    /// A tool someone other than root can change, or that sits in a directory they can change, is refused: sudo would
    /// run it as root.
    ///
    /// - Throws: An unexpected error.
    func testAToolOthersCanChangeIsRefused() throws {
        let fixture = try ToolLinkFixture(for: self)
        let me = CommandLineToolLink.userName(getuid())
        var rootOwned = fixture.layout()
        rootOwned.trustedOwner = 0
        XCTAssertEqual(fixture.linker(rootOwned).inspect().tool,
                       .failure(.untrustedChain(path: fixture.tool, writer: me)))
        
        let applications = fixture.root + "/Applications"
        chmod(applications, 0o777)
        XCTAssertEqual(fixture.linker().inspect().tool,
                       .failure(.untrustedChain(path: applications, writer: "everyone")))
        let staff: gid_t = 20
        XCTAssertEqual(chown(applications, uid_t.max, staff), 0)
        chmod(applications, 0o775)
        XCTAssertEqual(fixture.linker().inspect().tool,
                       .failure(.untrustedChain(path: applications, writer: "the group staff")))
        var staffIsAdmin = fixture.layout()
        staffIsAdmin.adminGroup = staff
        XCTAssertEqual(fixture.linker(staffIsAdmin).inspect().tool, .success(fixture.tool),
                       "/Applications is root:admin 0775")
        chmod(fixture.tool, 0o757)
        XCTAssertEqual(fixture.linker(staffIsAdmin).inspect().tool,
                       .failure(.untrustedChain(path: fixture.tool, writer: "everyone")))
    }
    
    /// A tool not signed as `macmonitor` is refused.
    ///
    /// - Throws: An unexpected error.
    func testAnUnsignedToolIsRefused() throws {
        let fixture = try ToolLinkFixture(for: self)
        XCTAssertEqual(fixture.linker(signed: false).inspect().tool, .failure(.signatureMismatch(fixture.tool)))
        XCTAssertNil(fixture.linker(signed: false).inspect().plan(.install))
    }
    
    /// A link directory others can change gets a warning, not a refusal; so does the nearest directory above a missing
    /// one.
    ///
    /// - Throws: An unexpected error.
    func testALinkDirectoryOthersCanChangeIsAWarning() throws {
        let fixture = try ToolLinkFixture(for: self)
        chmod(fixture.binDirectory, 0o777)
        let shared = fixture.linker().inspect()
        XCTAssertEqual(shared.binDirectoryWarning, """
            \(fixture.binDirectory) can be changed by everyone, so everyone could put another program at \
            \(fixture.link) for sudo to run. Run the tool by its full path instead.
            """)
        XCTAssertNotNil(shared.plan(.install))
        try FileManager.default.removeItem(atPath: fixture.binDirectory)
        chmod(fixture.root + "/usr/local", 0o777)
        XCTAssertTrue(fixture.linker().inspect().binDirectoryWarning?.hasPrefix(fixture.root + "/usr/local ") == true)
    }
    
    /// The live signature check: an Apple tool satisfies its own requirement and not `macmonitor`'s; an unsigned file
    /// and a missing one satisfy nothing.
    ///
    /// - Throws: An unexpected error.
    func testTheSignatureCheckReadsTheRealSignature() throws {
        let ls = "anchor apple and identifier \"com.apple.ls\""
        XCTAssertTrue(CommandLineToolLink.signature(of: "/bin/ls", satisfies: ls))
        XCTAssertFalse(CommandLineToolLink.signature(of: "/bin/ls", satisfies: SensorXPC.commandLineRequirement))
        XCTAssertFalse(CommandLineToolLink.isSignedAsTool("/bin/ls"))
        let fixture = try ToolLinkFixture(for: self)
        XCTAssertFalse(CommandLineToolLink.signature(of: fixture.tool, satisfies: "identifier \"com.apple.ls\""))
        XCTAssertFalse(CommandLineToolLink.signature(of: fixture.root + "/nothing", satisfies: "anchor apple"))
    }
    
    /// Every state has a sentence for Settings that names the link, and a hint only for what may be done.
    ///
    /// - Throws: An unexpected error.
    func testEverySummaryNamesTheLinkAndHintsOnlyAtWhatMayBeDone() throws {
        let fixture = try ToolLinkFixture(for: self)
        let other = "/a.app/Contents/MacOS/macmonitor"
        let hints: [(CommandLineToolLink.LinkState, String?, String?)] = [
            (.absent, "Install… links it to this copy's tool, so sudo macmonitor works in any terminal.", nil),
            (.current, nil, nil),
            (.elsewhere(other), "Update… points it at this copy.", nil),
            (.broken(other), "Repair… points it at this copy.", nil),
            (.foreign("a file"), "Run the tool by its full path instead.", "Run the tool by its full path instead.")
        ]
        for (state, linkable, refused) in hints {
            for (tool, hint) in [(Result.success(fixture.tool), linkable),
                                 (.failure(CommandLineToolLink.Refusal.translocated), refused)] {
                let inspection = CommandLineToolLink.Inspection(
                    link: state, linkValue: nil, tool: tool, linkPath: fixture.link,
                    binDirectory: fixture.binDirectory, binDirectoryWarning: nil)
                XCTAssertTrue(inspection.summary.hasPrefix(fixture.link), inspection.summary)
                XCTAssertEqual(inspection.hint, hint, "\(state)")
            }
        }
    }
}
