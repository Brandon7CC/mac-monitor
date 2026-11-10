//
//  XCTestCase+Macath.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - macath recordings
extension XCTestCase {
    /// The events the macath harnesses recorded: every `*.events.jsonl` in its `runs` folder, which is
    /// `SUTRO_MACATH_RUNS`, or `research/macOS/mac-atomic-test-harnesses/runs` in a folder holding this checkout.
    ///
    /// - Returns: The recordings, in path order.
    /// - Throws: `XCTSkip` without them.
    func macathRecordings() throws -> [URL] {
        let named = ProcessInfo.processInfo.environment["SUTRO_MACATH_RUNS"].map { URL(fileURLWithPath: $0) }
        var folder = Self.repositoryURL
        var candidates: [URL] = named.map { [$0] } ?? []
        while folder.pathComponents.count > 1 {
            folder.deleteLastPathComponent()
            candidates.append(folder.appendingPathComponent("research/macOS/mac-atomic-test-harnesses/runs"))
        }
        guard let runs = candidates.first(where: { FileManager.default.fileExists(atPath: $0.path) }),
              let files = FileManager.default.enumerator(at: runs, includingPropertiesForKeys: nil) else {
            throw XCTSkip("No macath recordings: set SUTRO_MACATH_RUNS to its runs folder")
        }
        let recordings = files.compactMap { $0 as? URL }.filter { $0.lastPathComponent.hasSuffix(".events.jsonl") }
        guard !recordings.isEmpty else { throw XCTSkip("No macath recordings in \(runs.path)") }
        return recordings.sorted { $0.path < $1.path }
    }

    /// Each macath recording's events, as File > Open Trace... reads them.
    ///
    /// - Returns: Each recording's file name and events, in path order.
    /// - Throws: `XCTSkip` without them, or the error reading one.
    func macathEvents() throws -> [(name: String, messages: [Message])] {
        try macathRecordings().map { recording in
            let lines = String(decoding: try Data(contentsOf: recording), as: UTF8.self).split(separator: "\n")
            return (recording.lastPathComponent, try lines.map { try importRecord(String($0)) })
        }
    }
}
