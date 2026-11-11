//
//  ComparePerformanceScriptTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest


// MARK: - Comparing results files
/// Runs `Scripts/compare-performance.js` from the source checkout on results files ``PerformanceReport`` writes, and
/// checks that it gates only on optimized builds: two `-O` files get a verdict per benchmark, a file from an
/// unoptimized build (or one that doesn't say) is refused with a non-zero exit, and `--unoptimized` lists the times
/// with no verdict.
final class ComparePerformanceScriptTests: XCTestCase {
    /// What one run of the script printed, and how it exited.
    private struct ScriptRun {
        let status: Int32
        let output: String
        let error: String
    }

    /// The script, in the checkout these tests were built from.
    private static let scriptURL = repositoryURL.appendingPathComponent("ProjectSutro/Scripts/compare-performance.js")

    /// Each file's benchmarks: the same three names, with the after file's times halved, kept and doubled.
    private static let before: [String: UInt64] = ["bench.faster": 100, "bench.same": 100, "bench.slower": 100]
    private static let after: [String: UInt64] = ["bench.faster": 50, "bench.same": 100, "bench.slower": 200]

    /// A folder of this test's own, removed after it.
    private var folder: URL!

    /// Make a temporary folder for this test's results files, and remove it after the test.
    override func setUpWithError() throws {
        try super.setUpWithError()
        folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let folder = folder!
        addTeardownBlock { try? FileManager.default.removeItem(at: folder) }
    }

    /// Two `-O` files exit zero with a faster, unchanged or slower verdict per benchmark, and no unoptimized note.
    func testGatesTwoOptimizedFiles() throws {
        let run = try compare(try resultsFile("before", Self.before, optimized: true),
                              try resultsFile("after", Self.after, optimized: true))
        XCTAssertEqual(run.status, 0, run.error)
        XCTAssertEqual(verdict(of: "bench.faster", in: run), "faster")
        XCTAssertEqual(verdict(of: "bench.same", in: run), "~")
        XCTAssertEqual(verdict(of: "bench.slower", in: run), "slower")
        XCTAssertFalse(run.output.contains("unoptimized"), run.output)
    }

    /// An unoptimized before file is refused with a non-zero exit that names it, and no verdicts.
    func testRefusesAnUnoptimizedBefore() throws {
        let before = try resultsFile("before", Self.before, optimized: false)
        let after = try resultsFile("after", Self.after, optimized: true)
        try assertRefused(compare(before, after), naming: before, not: after)
    }

    /// An unoptimized after file is refused with a non-zero exit that names it, and no verdicts.
    func testRefusesAnUnoptimizedAfter() throws {
        let before = try resultsFile("before", Self.before, optimized: true)
        let after = try resultsFile("after", Self.after, optimized: false)
        try assertRefused(compare(before, after), naming: after, not: before)
    }

    /// A file whose build has no `optimized` key is refused as if it were unoptimized.
    func testRefusesAFileThatDoesntSayItWasOptimized() throws {
        let before = try resultsFile("before", Self.before, optimized: nil)
        let after = try resultsFile("after", Self.after, optimized: true)
        try assertRefused(compare(before, after), naming: before, not: after)
    }

    /// With `--unoptimized`, an unoptimized file's times and changes are listed as not gated, with a note.
    func testListsUnoptimizedTimesWithoutVerdictsWhenAsked() throws {
        let run = try compare(try resultsFile("before", Self.before, optimized: false),
                              try resultsFile("after", Self.after, optimized: true), options: ["--unoptimized"])
        XCTAssertEqual(run.status, 0, run.error)
        for name in Self.before.keys { XCTAssertEqual(verdict(of: name, in: run), "not gated", run.output) }
        XCTAssertTrue(run.output.contains("Before is an unoptimized build"), run.output)
        XCTAssertTrue(run.output.contains("+100.0%"), run.output)
    }

    // MARK: Helpers

    /// Write a results file of one benchmark per entry, each of three equal samples, then set its build's
    /// `optimized` key.
    ///
    /// - Parameters:
    ///   - name: The file's name, without its extension.
    ///   - wallNanoseconds: Each benchmark's wall time per sample, by name.
    ///   - optimized: The key's value, or `nil` to leave the key out.
    /// - Returns: The file.
    /// - Throws: The error writing or rewriting it.
    private func resultsFile(_ name: String, _ wallNanoseconds: [String: UInt64], optimized: Bool?) throws -> URL {
        let url = folder.appendingPathComponent("\(name).json")
        let report = PerformanceReport(destination: url)
        for (benchmark, wall) in wallNanoseconds.sorted(by: { $0.key < $1.key }) {
            let sample = PerformanceSample(wallNs: wall, cpuNs: wall, footprintDeltaBytes: 0)
            try report.add(PerformanceResult(name: benchmark, test: "-[\(name) test]", unit: "event", operations: 1,
                                             samples: Array(repeating: sample, count: 3)))
        }
        var document = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        var environment = try XCTUnwrap(document["environment"] as? [String: Any])
        var build = try XCTUnwrap(environment["build"] as? [String: Any])
        build["optimized"] = optimized
        environment["build"] = build
        document["environment"] = environment
        try JSONSerialization.data(withJSONObject: document).write(to: url)
        return url
    }

    /// Run the script on two files with `osascript`.
    ///
    /// - Parameters:
    ///   - before: The earlier file.
    ///   - after: The later file.
    ///   - options: Options before the paths, such as `--unoptimized`.
    /// - Returns: What it printed to standard output and standard error, and its exit status.
    /// - Throws: The error launching it.
    private func compare(_ before: URL, _ after: URL, options: [String] = []) throws -> ScriptRun {
        let process = Process()
        let (output, error) = (Pipe(), Pipe())
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-l", "JavaScript", Self.scriptURL.path] + options + [before.path, after.path]
        process.standardOutput = output
        process.standardError = error
        try process.run()
        let text = { (pipe: Pipe) in String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self) }
        let (printed, complained) = (text(output), text(error))
        process.waitUntilExit()
        return ScriptRun(status: process.terminationStatus, output: printed, error: complained)
    }

    /// The verdict on a benchmark's row: the words between its change and its unit.
    ///
    /// - Parameters:
    ///   - name: The benchmark.
    ///   - run: The script's run.
    /// - Returns: `faster`, `slower`, `~` or `not gated`, or `nil` if there's no such row.
    private func verdict(of name: String, in run: ScriptRun) -> String? {
        guard let row = run.output.split(separator: "\n").first(where: { $0.hasPrefix("\(name) ") }),
              let percent = row.range(of: "% "), let unit = row.range(of: " (per ") else { return nil }
        return String(row[percent.upperBound..<unit.lowerBound])
    }

    /// Assert that a run was refused for one file's build, and didn't name the other.
    ///
    /// - Parameters:
    ///   - run: The script's run.
    ///   - refused: The file it should name.
    ///   - accepted: The file it shouldn't.
    ///   - file: The calling test's file, for the failure.
    ///   - line: The calling test's line, for the failure.
    private func assertRefused(_ run: ScriptRun, naming refused: URL, not accepted: URL,
                               file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertNotEqual(run.status, 0, run.output, file: file, line: line)
        XCTAssertTrue(run.error.contains("Won't gate on an unoptimized build"), run.error, file: file, line: line)
        XCTAssertTrue(run.error.contains(refused.path), run.error, file: file, line: line)
        XCTAssertFalse(run.error.contains(accepted.path), run.error, file: file, line: line)
        let verdicts = run.output.contains("slower") || run.output.contains("faster")
        XCTAssertFalse(verdicts, run.output, file: file, line: line)
    }
}
