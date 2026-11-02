//
//  ClassColorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/25/26.
//

import XCTest


// MARK: - Class colors
/// Pins where a class of telemetry gets its color: the app's event catalog (`EventCatalog.swift`), with its title,
/// symbol and events, and nowhere else. Settings ▸ Subscriptions and Event Facts' correlation once kept tables of
/// their own that disagreed (IPC and kernel was cyan in one and pink in the other).
final class ClassColorTests: XCTestCase {
    /// The app's sources, beside the tests.
    private let app = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().appendingPathComponent("ProjectSutro")

    /// The catalog names each class once, with a color, and no other source puts a class's title beside a color.
    func testClassesAreColoredOnlyInTheCatalog() throws {
        let catalog = try String(contentsOf: app.appendingPathComponent("Settings Views/EventCatalog.swift"),
                                 encoding: .utf8)
        let entry = try NSRegularExpression(pattern: #"^\s*\("([^"]+)", "[^"]+", \.(\w+), \["#,
                                            options: .anchorsMatchLines)
        let titles = entry.matches(in: catalog, range: NSRange(catalog.startIndex..., in: catalog)).map {
            String(catalog[Range($0.range(at: 1), in: catalog)!])
        }
        XCTAssertEqual(titles.count, 10, "The catalog's classes, each with its symbol and color")

        /// A table's entry: `"Memory": .purple`, or `case "Memory": return .purple`.
        let colors = "red|orange|yellow|green|mint|teal|cyan|blue|indigo|purple|pink|brown|gray"
        let table = try NSRegularExpression(pattern: "\"(" + titles.map(NSRegularExpression.escapedPattern)
            .joined(separator: "|") + #")"\s*:[^"\n]*(\.("# + colors + #")\b|Color\()"#)
        var offenders: [String] = []
        let files = try XCTUnwrap(FileManager.default.enumerator(at: app, includingPropertiesForKeys: nil))
        for case let file as URL in files where file.pathExtension == "swift" {
            guard file.lastPathComponent != "EventCatalog.swift" else { continue }
            let lines = try String(contentsOf: file, encoding: .utf8).components(separatedBy: .newlines)
            for (number, line) in lines.enumerated()
            where table.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)) != nil {
                let entry = line.trimmingCharacters(in: .whitespaces)
                offenders.append("\(file.lastPathComponent):\(number + 1): \(entry)")
            }
        }
        XCTAssertEqual(offenders, [], "Color a class through EventCatalog.Group.tint")
    }
}
