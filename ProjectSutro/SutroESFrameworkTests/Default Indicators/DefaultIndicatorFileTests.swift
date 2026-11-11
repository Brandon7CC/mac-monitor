//
//  DefaultIndicatorFileTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/9/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The default indicators' file
/// Pins `SutroESFramework/Detection/DefaultIndicators.json`: it's what the source generates
/// (``DefaultIndicatorSource``), the framework's binary holds it, and it's what ``Indicator/defaults`` is. A retired
/// number is never given to another indicator.
///
/// `ProjectSutro/Scripts/generate-default-indicators.sh` regenerates it: it runs ``testCommittedFileIsGenerated()``
/// with `MM_WRITE_DEFAULT_INDICATORS=1`, which writes the file instead of comparing it.
final class DefaultIndicatorFileTests: XCTestCase {
    /// The environment variable that makes ``testCommittedFileIsGenerated()`` write the file.
    static let writeVariable = "MM_WRITE_DEFAULT_INDICATORS"

    /// The committed file.
    static var fileURL: URL {
        repositoryURL.appendingPathComponent("ProjectSutro/SutroESFramework/Detection/DefaultIndicators.json")
    }

    /// The committed file lists what the source generates, indicator for indicator. With
    /// `MM_WRITE_DEFAULT_INDICATORS=1` it's written instead.
    func testCommittedFileIsGenerated() throws {
        if ProcessInfo.processInfo.environment[Self.writeVariable] == "1" {
            try Data(try DefaultIndicatorSource.text.utf8).write(to: Self.fileURL, options: .atomic)
            return
        }
        let committed = try DefaultIndicators.decode(Data(contentsOf: Self.fileURL))
        assertGenerated(committed.indicators, Indicator.sourceDefaults, "indicators")
    }

    /// The framework's binary holds the committed file, byte for byte: a stale or missing section fails.
    func testBinaryHoldsTheCommittedFile() throws {
        XCTAssertEqual(DefaultIndicators.embedded(), try Data(contentsOf: Self.fileURL))
    }

    /// The defaults are the file's, and the New executable predicate is the source's, whose age is
    /// ``ESProcessExecEvent/newExecutableAge``.
    func testDefaultsAreTheFile() {
        XCTAssertEqual(Indicator.defaults, Indicator.sourceDefaults)
        XCTAssertEqual(Indicator.newExecutablePredicate, Indicator.newExecutableSource)
    }

    /// No default or built-in mark has a retired number, and every one of them is known as Mac Monitor's.
    func testRetiredNumbersAreNeverGivenAgain() {
        let retired = Set(Indicator.retiredNumbers.map(Indicator.uuid))
        XCTAssertTrue(retired.isDisjoint(with: (Indicator.defaults + Indicator.builtInMarks).map(\.id)))
        XCTAssertTrue((Indicator.defaults + Indicator.builtInMarks).map(\.id).allSatisfy(Indicator.isShippedIdentity))
        XCTAssertTrue(retired.allSatisfy(Indicator.isShippedIdentity))
        XCTAssertFalse(Indicator.isShippedIdentity(UUID()))
    }

    /// Every default a built-in mark is a twin of is one the file lists: making the marks finds each.
    func testMarksNameShippedDefaults() {
        XCTAssertFalse(Indicator.builtInMarks.isEmpty)
        XCTAssertEqual(Indicator.shipped(9).name, "New executable")
    }

    /// A file of another format, a newer version, with no indicators, or with an identity twice isn't used, and one
    /// that isn't the file's JSON doesn't decode.
    func testUnusableFilesAreRefused() throws {
        let indicator = try jsonObject(JSONEncoder().encode(Indicator.sourceDefaults[0]))
        let file: [String: Any] = ["format": IndicatorExchange.format, "version": IndicatorExchange.version,
                                   "indicators": [indicator]]
        XCTAssertEqual(try DefaultIndicators.decode(data(file)).indicators, [Indicator.sourceDefaults[0]])
        let refused: [(change: [String: Any], problem: String)] = [
            (["format": "another"], "It's a another file."),
            (["version": IndicatorExchange.version + 1],
             "It's version \(IndicatorExchange.version + 1), newer than this build reads."),
            (["indicators": [Any]()], "It lists no indicators."),
            (["indicators": [indicator, indicator]], "Two of its indicators share an identity."),
        ]
        for (change, problem) in refused {
            let changed = file.merging(change) { _, new in new }
            XCTAssertThrowsError(try DefaultIndicators.decode(data(changed)), problem) { error in
                XCTAssertEqual((error as? DefaultIndicators.Problem)?.description, problem)
            }
        }
        XCTAssertThrowsError(try DefaultIndicators.decode(Data("[]".utf8)))
        XCTAssertThrowsError(try DefaultIndicators.decode(data(file.filter { $0.key != "indicators" })))
    }

    /// - Parameter object: A JSON object.
    /// - Returns: Its data.
    /// - Throws: The serializer's error.
    private func data(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object)
    }

    /// Fails, naming the first indicator that differs, when the file's list isn't the source's.
    ///
    /// - Parameters:
    ///   - committed: The file's indicators.
    ///   - source: The source's.
    ///   - key: The file's key for them.
    private func assertGenerated(_ committed: [Indicator], _ source: [Indicator], _ key: String) {
        guard committed != source else { return }
        let difference = zip(committed, source).first { $0 != $1 }.map { "“\($1.name)” differs" }
            ?? "it lists \(committed.count) and the source \(source.count)"
        XCTFail("""
            DefaultIndicators.json's \(key) aren't what the source generates: \(difference). Regenerate the file \
            with ProjectSutro/Scripts/generate-default-indicators.sh.
            """)
    }
}
