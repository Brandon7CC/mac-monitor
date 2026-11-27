//
//  CaptureSession+Scanning.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
import EndpointSecurity


// MARK: - Scanning
extension CaptureSession {
    /// The events whose files are scanned: a close's written file, and the script an exec runs.
    static let scannedEvents = [ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_EXEC]

    /// Scan written files and the scripts execs run from the next close or exec on, or stop. A session made without a
    /// scanner can't scan.
    ///
    /// - Parameter scans: Whether to scan.
    /// - Returns: `false` when the session has no scanner, or has stopped.
    @discardableResult
    public func setScansWrittenFiles(_ scans: Bool) -> Bool {
        guard scanner != nil, !isStopped else { return false }
        scansWrittenFiles = scans
        lanes.forEach { $0.setScansWrittenFiles(scans) }
        updateScanning()
        Self.logger.log("""
            \(self.label, privacy: .public): scanning written files and scripts \
            \(scans ? "on" : "off", privacy: .public).
            """)
        return true
    }

    /// Acquire the scanner while the session subscribes to closes or execs and hasn't stopped, and release it
    /// otherwise, so Apple's rules are loaded only while there are files to scan.
    func updateScanning() {
        guard let scanner else { return }
        let wanted = scansWrittenFiles && !isStopped && subscribedEvents.contains { Self.scannedEvents.contains($0) }
        guard wanted != isScanning else { return }
        isScanning = wanted
        if wanted { scanner.acquire() } else { scanner.release() }
    }
}
