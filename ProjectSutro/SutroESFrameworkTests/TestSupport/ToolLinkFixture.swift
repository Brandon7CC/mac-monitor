//
//  ToolLinkFixture.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Tool link fixture
/// A pretend `/` in a temporary directory, owned by the user running the tests as root owns the real one:
/// `Applications/Mac Monitor.app/Contents/MacOS/macmonitor` (0755) and `usr/local/bin`.
struct ToolLinkFixture {
    /// The pretend `/`, by its real path.
    let root: String
    
    /// Mac Monitor's bundle.
    var bundle: String { root + "/Applications/Mac Monitor.app" }
    /// Its tool.
    var tool: String { bundle + "/Contents/MacOS/macmonitor" }
    /// The link's directory.
    var binDirectory: String { root + "/usr/local/bin" }
    /// The link.
    var link: String { binDirectory + "/macmonitor" }
    
    /// Build it.
    ///
    /// - Parameter testCase: Removes it when the test ends.
    /// - Throws: If it can't be built.
    init(for testCase: XCTestCase) throws {
        let base = FileManager.default.temporaryDirectory.appendingPathComponent("ToolLink-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o755])
        root = CommandLineToolLink.realPath(base.path) ?? base.path
        testCase.addTeardownBlock { [root] in
            /// Undo any mode a test set, so everything can be removed.
            let walker = FileManager.default.enumerator(atPath: root)
            while let path = walker?.nextObject() as? String { chmod(root + "/" + path, 0o755) }
            try? FileManager.default.removeItem(atPath: root)
        }
        try makeTool(at: tool)
        try makeDirectory(binDirectory)
    }
    
    /// A directory and its parents, 0755.
    ///
    /// - Parameter path: The directory.
    /// - Throws: If it can't be created.
    func makeDirectory(_ path: String) throws {
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o755])
    }
    
    /// An executable file and its directories.
    ///
    /// - Parameter path: The file.
    /// - Throws: If it can't be created.
    func makeTool(at path: String) throws {
        try makeDirectory((path as NSString).deletingLastPathComponent)
        XCTAssertTrue(FileManager.default.createFile(atPath: path, contents: Data("#!/bin/sh\n".utf8),
                                                     attributes: [.posixPermissions: 0o755]))
    }
    
    /// A symbolic link.
    ///
    /// - Parameters:
    ///   - path: The link.
    ///   - value: What it holds.
    /// - Throws: If it can't be created.
    func symlink(_ path: String, to value: String) throws {
        try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: value)
    }
    
    /// The layout for this root, trusting the user running the tests.
    ///
    /// - Parameter bundle: The bundle, if not ``bundle``.
    /// - Returns: The layout.
    func layout(bundle: String? = nil) -> CommandLineToolLink.Layout {
        CommandLineToolLink.Layout(bundle: URL(fileURLWithPath: bundle ?? self.bundle), binDirectory: binDirectory,
                                   root: root, trustedOwner: getuid())
    }
    
    /// A ``CommandLineToolLink`` for this root whose signature check always answers `signed`.
    ///
    /// - Parameters:
    ///   - layout: The layout, if not ``layout(bundle:)``.
    ///   - signed: What the signature check says.
    /// - Returns: The link.
    func linker(_ layout: CommandLineToolLink.Layout? = nil, signed: Bool = true) -> CommandLineToolLink {
        CommandLineToolLink(layout: layout ?? self.layout(), signatureCheck: { _ in signed })
    }
    
    /// What's at the link's path: its value for a symbolic link, "file", or `nil` for nothing.
    var linkContents: String? {
        if let value = try? FileManager.default.destinationOfSymbolicLink(atPath: link) { return value }
        return FileManager.default.fileExists(atPath: link) ? "file" : nil
    }
    
    /// Run the link script as the user running the tests.
    ///
    /// - Parameters:
    ///   - arguments: Its arguments.
    ///   - source: The script, if not the shipped one.
    /// - Returns: Its exit status.
    /// - Throws: If it can't be run.
    @discardableResult
    func runScript(_ arguments: [String], source: String = CommandLineToolLinkScript.source) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", source, CommandLineToolLinkScript.name] + arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }
}
