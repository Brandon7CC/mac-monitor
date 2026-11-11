//
//  PerformanceReport.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation


// MARK: - Results file
/// The results of one test run, written after every benchmark so a run that stops part way keeps what it measured.
///
/// The JSON (`format` 1) holds the ``PerformanceEnvironment`` once and every ``PerformanceResult`` with its samples, in
/// snake case. A CSV beside it (same name, `.csv`) holds a row per benchmark with the machine on every row, so the
/// CSVs of several Macs can be pasted into one sheet. `Scripts/compare-performance.js` compares two JSON files.
///
/// **Threading:** the main thread only, as XCTest runs the tests.
final class PerformanceReport {
    /// A results file.
    struct Document: Codable {
        /// The file's layout. Bump it when a key changes meaning.
        var format = 1
        /// When the run started.
        let started: Date
        let environment: PerformanceEnvironment
        var results: [PerformanceResult] = []
    }

    /// The run's report, written to ``PerformanceRun/resultsURL``.
    static let shared = PerformanceReport(destination: PerformanceRun.resultsURL)

    /// The JSON file, and the CSV beside it.
    let destination: URL
    var csvDestination: URL { destination.deletingPathExtension().appendingPathExtension("csv") }
    private(set) var document = Document(started: Date(), environment: .current)

    /// - Parameter destination: The JSON file to write.
    init(destination: URL) {
        self.destination = destination
    }

    /// Add a benchmark's result, and write the files again.
    ///
    /// - Parameter result: The result.
    /// - Throws: The error writing a file.
    func add(_ result: PerformanceResult) throws {
        if document.results.isEmpty { print("[performance] Results: \(destination.path)") }
        document.results.removeAll { $0.name == result.name }
        document.results.append(result)
        try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(document).write(to: destination, options: .atomic)
        try Data(csv.utf8).write(to: csvDestination, options: .atomic)
    }

    /// The CSV: a header row, then a row per benchmark.
    var csv: String {
        let environment = document.environment
        let machine = [environment.machine.model, environment.machine.chip, environment.system.version,
                       environment.system.build, environment.build.macMonitorVersion, environment.build.commit ?? "",
                       environment.build.configuration, "\(environment.build.optimized)"]
        let header = ["name", "unit", "operations", "samples", "wall_median_ns", "wall_min_ns", "wall_mean_ns",
                      "wall_stddev_ns", "cpu_median_ns", "cpu_mean_ns", "footprint_delta_median_bytes", "model", "chip",
                      "macos", "macos_build", "mac_monitor_version", "commit", "configuration", "optimized"]
        let rows = document.results.map { result in
            [result.name, result.unit, "\(result.operations)", "\(result.samples.count)",
             Self.number(result.wallNs.median), Self.number(result.wallNs.min), Self.number(result.wallNs.mean),
             Self.number(result.wallNs.stddev), Self.number(result.cpuNs.median), Self.number(result.cpuNs.mean),
             Self.number(result.footprintDeltaBytes.median)] + machine
        }
        return ([header] + rows).map { $0.map(Self.field).joined(separator: ",") }.joined(separator: "\n") + "\n"
    }

    /// A number with one decimal, in the POSIX locale.
    ///
    /// - Parameter value: The number.
    /// - Returns: Its text.
    private static func number(_ value: Double) -> String {
        String(format: "%.1f", locale: Locale(identifier: "en_US_POSIX"), value)
    }

    /// A CSV field, quoted when it holds a comma, a quote or a line break (RFC 4180).
    ///
    /// - Parameter text: The field's text.
    /// - Returns: The field.
    private static func field(_ text: String) -> String {
        guard text.contains(where: { $0 == "," || $0 == "\"" || $0.isNewline }) else { return text }
        return "\"" + text.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }
}
