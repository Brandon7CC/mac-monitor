//
//  CommandLineToolInstallTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The AppleScript that runs the script
/// Pins how Settings runs the link script: the shipped AppleScript compiles, hands every parameter to the script
/// verbatim however hostile a path is, and reports the script's exit status as its error number. The tests run the
/// handler without its administrator privileges, so it runs as the user: everything else is the shipped handler.
final class CommandLineToolInstallTests: XCTestCase {
    /// What the tests take out of the shipped handler.
    private let privileges = " with prompt promptText with administrator privileges"
    
    /// The shipped handler, run as the user running the tests.
    ///
    /// - Returns: The handler.
    /// - Throws: If it doesn't compile.
    private func unprivilegedHandler() throws -> AppleScriptHandler {
        let source = CommandLineToolLinkScript.appleScriptSource
        XCTAssertEqual(source.components(separatedBy: privileges).count, 2, "the handler asks for privileges once")
        return try XCTUnwrap(AppleScriptHandler(source: source.replacingOccurrences(of: privileges, with: ""),
                                                handler: CommandLineToolLinkScript.handlerName))
    }
    
    /// The shipped handler compiles, and one that doesn't compile is refused.
    func testTheShippedHandlerCompiles() {
        XCTAssertNotNil(AppleScriptHandler(source: CommandLineToolLinkScript.appleScriptSource,
                                           handler: CommandLineToolLinkScript.handlerName))
        XCTAssertNil(AppleScriptHandler(source: "on broken(", handler: "broken"))
    }
    
    /// A bundle whose name holds quotes, a command substitution, backquotes, a variable and a glob is linked by
    /// exactly that name: no shell ever reads a parameter as code.
    ///
    /// - Throws: An unexpected error.
    func testParametersReachTheScriptVerbatim() throws {
        let fixture = try ToolLinkFixture(for: self)
        let bundle = fixture.root + "/Applications/It's \"$(echo x)\" `echo y`; $HOME * ¬.app"
        let tool = bundle + "/Contents/MacOS/macmonitor"
        try fixture.makeTool(at: tool)
        let inspection = fixture.linker(fixture.layout(bundle: bundle)).inspect()
        let plan = try XCTUnwrap(inspection.plan(.install))
        XCTAssertEqual(plan.tool, tool)
        let result = try unprivilegedHandler().call(CommandLineToolLinkScript.parameters(for: plan))
        guard case .success = result else { return XCTFail("\(result)") }
        XCTAssertEqual(fixture.linkContents, tool)
        
        let removal = try XCTUnwrap(fixture.linker(fixture.layout(bundle: bundle)).inspect().plan(.remove))
        guard case .success = try unprivilegedHandler().call(CommandLineToolLinkScript.parameters(for: removal)) else {
            return XCTFail("remove")
        }
        XCTAssertNil(fixture.linkContents)
    }
    
    /// The script's exit status comes back as the error number, and becomes the outcome Settings reports.
    ///
    /// - Throws: An unexpected error.
    func testTheExitStatusIsTheOutcome() throws {
        let fixture = try ToolLinkFixture(for: self)
        try Data().write(to: URL(fileURLWithPath: fixture.link))
        let plan = CommandLineToolLink.Plan(action: .install, tool: fixture.tool, binDirectory: fixture.binDirectory,
                                            expected: "")
        let result = try unprivilegedHandler().call(CommandLineToolLinkScript.parameters(for: plan))
        guard case .failure(let failure) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(CommandLineToolLinkScript.Outcome(status: failure.number), .notMacMonitors)
        XCTAssertEqual(fixture.linkContents, "file")
    }
    
    /// Every status maps to its outcome, and every outcome but done and cancelled tells the user something about the
    /// link.
    func testEveryOutcomeIsReported() {
        let plan = CommandLineToolLink.Plan(action: .install, tool: "/A.app/Contents/MacOS/macmonitor",
                                            binDirectory: "/usr/local/bin", expected: "")
        let outcomes: [Int: CommandLineToolLinkScript.Outcome] = [
            0: .done, -128: .cancelled, 2: .misused, 3: .directoryNotCreated, 4: .notADirectory, 5: .notMacMonitors,
            6: .changed, 7: .badTool, 8: .fileSystemError, 1: .failed(1), -1: .failed(-1)
        ]
        for (status, outcome) in outcomes {
            XCTAssertEqual(CommandLineToolLinkScript.Outcome(status: status), outcome)
            let message = outcome.message(for: plan)
            if outcome == .done || outcome == .cancelled {
                XCTAssertNil(message)
            } else {
                XCTAssertTrue(message?.contains("/usr/local/bin") == true || message?.contains(plan.tool) == true,
                              "\(status): \(message ?? "nil")")
            }
        }
    }
    
    /// The password prompt says what Mac Monitor is about to do: install, point the link at this copy, or remove.
    func testThePromptSaysWhatChanges() {
        let install = CommandLineToolLink.Plan(action: .install, tool: "/A.app/Contents/MacOS/macmonitor",
                                               binDirectory: "/usr/local/bin", expected: "")
        let update = CommandLineToolLink.Plan(action: .install, tool: install.tool, binDirectory: "/usr/local/bin",
                                              expected: "/B.app/Contents/MacOS/macmonitor")
        let remove = CommandLineToolLink.Plan(action: .remove, tool: "", binDirectory: "/usr/local/bin",
                                              expected: install.tool)
        XCTAssertEqual(CommandLineToolLinkScript.prompt(for: install),
                       "Mac Monitor wants to install its command line tool at /usr/local/bin/macmonitor.")
        XCTAssertEqual(CommandLineToolLinkScript.prompt(for: update),
                       "Mac Monitor wants to point /usr/local/bin/macmonitor at this copy of Mac Monitor.")
        XCTAssertEqual(CommandLineToolLinkScript.prompt(for: remove),
                       "Mac Monitor wants to remove its command line tool from /usr/local/bin/macmonitor.")
        XCTAssertEqual(CommandLineToolLinkScript.parameters(for: install), [
            CommandLineToolLinkScript.source, CommandLineToolLinkScript.name, "install", install.tool,
            "/usr/local/bin", "", CommandLineToolLinkScript.prompt(for: install)
        ])
    }
}
