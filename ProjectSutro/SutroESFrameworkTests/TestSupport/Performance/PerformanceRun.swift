//
//  PerformanceRun.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest


// MARK: - Performance run
/// How this test process measures, from its environment. `Scripts/test-performance.sh` sets every variable (through
/// xcodebuild's `TEST_RUNNER_` prefix), and the Performance test plan sets `SUTRO_PERFORMANCE`.
///
/// | Variable | Meaning |
/// |---|---|
/// | `SUTRO_PERFORMANCE` | `1` runs the ``PerformanceTestCase``s. Otherwise they're skipped |
/// | `SUTRO_PERFORMANCE_SAMPLES` | Samples per benchmark, 10 by default |
/// | `SUTRO_PERFORMANCE_RESULTS` | The results file, by default a new one in `ProjectSutro/build/Performance` |
/// | `SUTRO_PERFORMANCE_CONFIGURATION` | The build configuration, as the script built it |
/// | `SUTRO_PERFORMANCE_COMMIT` | The source's commit, else `git describe` of the checkout |
enum PerformanceRun {
    /// The variables.
    private static let environment = ProcessInfo.processInfo.environment

    /// Run the benchmarks?
    static let isEnabled = environment["SUTRO_PERFORMANCE"] == "1"

    /// Why a benchmark is skipped when the run isn't enabled.
    static let skipReason = "Benchmarks run with SUTRO_PERFORMANCE=1: Scripts/test-performance.sh, or the Performance "
        + "test plan in Xcode"

    /// Samples per benchmark.
    static let sampleCount = environment["SUTRO_PERFORMANCE_SAMPLES"].flatMap(Int.init).map { max(1, $0) } ?? 10

    /// The build configuration the script built, or `Xcode` when the tests were built some other way.
    static let configuration = environment["SUTRO_PERFORMANCE_CONFIGURATION"] ?? "Xcode"

    /// The commit the tests were built from: the script's, else the checkout's `git describe`, `-dirty` with local
    /// changes. `nil` without git.
    static let commit: String? = environment["SUTRO_PERFORMANCE_COMMIT"] ?? describeCheckout()

    /// The results file: the script's, or `ProjectSutro/build/Performance/<time>-<model>.json` (`build` isn't
    /// committed).
    static let resultsURL: URL = {
        if let path = environment["SUTRO_PERFORMANCE_RESULTS"] { return URL(fileURLWithPath: path) }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        let model = PerformanceEnvironment.Machine.current.model.replacingOccurrences(of: ",", with: "-")
        return XCTestCase.repositoryURL.appendingPathComponent("ProjectSutro/build/Performance", isDirectory: true)
            .appendingPathComponent("\(formatter.string(from: Date()))-\(model).json")
    }()

    /// `git describe --always --dirty` of the checkout these tests were built from.
    ///
    /// - Returns: The description, or `nil` if git can't say.
    private static func describeCheckout() -> String? {
        let git = Foundation.Process()
        let output = Pipe()
        git.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        git.arguments = ["-C", XCTestCase.repositoryURL.path, "describe", "--always", "--dirty", "--abbrev=12"]
        git.standardOutput = output
        git.standardError = FileHandle.nullDevice
        guard (try? git.run()) != nil else { return nil }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        git.waitUntilExit()
        let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        return git.terminationStatus == 0 && !text.isEmpty ? text : nil
    }
}
