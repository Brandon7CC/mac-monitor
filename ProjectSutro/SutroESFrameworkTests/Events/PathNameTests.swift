//
//  PathNameTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Names from paths
/// Pins how a file's name is read from its path: as a path, with spaces, and never through `URL(string:)`, which on
/// macOS 13 has no URL for a path with a space. Every exec of `/Applications/Mac Monitor.app/Contents/MacOS/macmonitor`
/// showed no process name there.
final class PathNameTests: XCTestCase {
    /// A path's last component, with spaces or without, a folder's without its slash, and "" for "".
    func testLastPathComponent() {
        let names = [("/Applications/Mac Monitor.app/Contents/MacOS/macmonitor", "macmonitor"),
                     ("/Users/alice/My Scripts/run me.sh", "run me.sh"), ("/usr/bin/true", "true"),
                     ("/Library/Caches/", "Caches"), ("relative/name", "name"), ("", "")]
        for (path, name) in names {
            XCTAssertEqual(path.lastPathComponent, name, path)
        }
    }

    /// No source reads a file path with `URL(string:)`. A URL's own string, such as a launch item's `item_url` or an
    /// API's address and path, is fine.
    func testNoPathIsReadWithURLString() throws {
        let project = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
        /// The argument up to the call's parenthesis, unless it starts with a string literal, a URL as written.
        let call = try NSRegularExpression(pattern: #"URL\(\s*string:\s*([^"\s)][^)]*)\)"#)
        var offenders: [String] = [], scanned = 0
        for folder in ["ProjectSutro", "SutroESFramework", "SecurityExtension", "macmonitor"] {
            let root = project.appendingPathComponent(folder)
            guard let files = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil) else {
                continue
            }
            for case let file as URL in files where file.pathExtension == "swift" {
                let source = try String(contentsOf: file, encoding: .utf8)
                scanned += 1
                let range = NSRange(source.startIndex..., in: source)
                for match in call.matches(in: source, range: range) {
                    guard let argument = Range(match.range(at: 1), in: source).map({ source[$0].lowercased() }),
                          argument.contains("path"), !argument.contains("url"), !argument.contains("api") else {
                        continue
                    }
                    offenders.append("\(file.lastPathComponent): \(source[Range(match.range, in: source)!])")
                }
            }
        }
        /// The sources are beside the tests: a run without them reads none and finds nothing.
        XCTAssertGreaterThan(scanned, 200, "Read \(scanned) Swift files under \(project.path)")
        XCTAssertEqual(offenders, [], "Read a path with lastPathComponent or URL(fileURLWithPath:), not URL(string:)")
    }
}
