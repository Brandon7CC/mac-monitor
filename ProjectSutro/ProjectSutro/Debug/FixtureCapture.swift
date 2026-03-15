//
//  FixtureCapture.swift
//  ProjectSutro
//
//  Captures and loads event fixtures for stress testing.
//
//  Fixtures are binary plist-encoded arrays of Message objects.
//  They can be captured from a live recording session (via the Debug menu)
//  and replayed during stress tests to exercise the full pipeline with
//  realistic event data.
//
//  DEBUG ONLY — compiled out for release builds.
//

#if DEBUG

import Foundation
import AppKit
import SutroESFramework
import OSLog

/// Utility for capturing and loading event fixtures for stress testing.
enum FixtureCapture {
    private static let logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "FixtureCapture")

    // MARK: - Capture

    /// Captures events from the current EventStore to a binary plist file.
    ///
    /// - Parameters:
    ///   - maxEvents: Maximum number of events to capture (most recent first). Default 5000.
    ///   - url: Destination file URL.
    /// - Returns: The number of events captured, or 0 on failure.
    @discardableResult
    static func captureFixture(maxEvents: Int = 5000, to url: URL) -> Int {
        let store = EventStore.shared
        let snapshot = store.getIndexSnapshot()

        guard !snapshot.isEmpty else {
            logger.warning("No events in EventStore to capture")
            return 0
        }

        // Take the most recent N events (they're in chronological order)
        let startIdx = max(0, snapshot.count - maxEvents)
        let indicesToCapture = Array(startIdx..<snapshot.count)
        let events = store.getEventsWindow(indicesToCapture)

        guard !events.isEmpty else {
            logger.warning("Failed to decode any events for fixture capture")
            return 0
        }

        do {
            let encoder = PropertyListEncoder()
            encoder.outputFormat = .binary
            let data = try encoder.encode(events)
            try data.write(to: url, options: .atomic)
            logger.info("Captured \(events.count) events to fixture: \(url.path)")
            return events.count
        } catch {
            logger.error("Failed to encode fixture: \(error)")
            return 0
        }
    }

    /// Presents an NSSavePanel for interactive fixture capture.
    ///
    /// Call from the Debug menu. Captures events from the current EventStore.
    ///
    /// - Parameter maxEvents: Maximum number of events to capture. Default 5000.
    static func captureWithSavePanel(maxEvents: Int = 5000) {
        let panel = NSSavePanel()
        panel.title = "Save Event Fixture"
        panel.message = "Save captured events as a stress test fixture"
        panel.nameFieldLabel = "Fixture file name:"
        panel.nameFieldStringValue = "stress-fixture.plist"
        panel.allowedContentTypes = [.propertyList]
        panel.canCreateDirectories = true

        let response = panel.runModal()
        guard response == .OK, let url = panel.url else { return }

        let count = captureFixture(maxEvents: maxEvents, to: url)
        if count > 0 {
            logger.info("User captured \(count) events to \(url.path)")
        }
    }

    // MARK: - Load

    /// Loads a fixture file and returns the decoded events.
    ///
    /// - Parameter url: The fixture file URL (binary plist of `[Message]`).
    /// - Returns: The decoded events, or an empty array on failure.
    static func loadFixture(from url: URL) -> [Message] {
        do {
            let data = try Data(contentsOf: url)
            let decoder = PropertyListDecoder()
            let messages = try decoder.decode([Message].self, from: data)
            logger.info("Loaded \(messages.count) events from fixture: \(url.path)")
            return messages
        } catch {
            logger.error("Failed to load fixture from \(url.path): \(error)")
            return []
        }
    }
}

#endif
