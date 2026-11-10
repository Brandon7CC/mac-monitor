//
//  UpdateError.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Update error
/// Why the Security Extension didn't offer or install a release (Security Extension context). Logged in full, and
/// told to Mac Monitor as an ``UpdateFailure``.
public enum UpdateError: LocalizedError, Equatable {
    case releaseLookupFailed
    case noNewerRelease
    case insecureDownload(URL)
    case downloadFailed
    case unreadableAssessment
    case rejectedByGatekeeper(reason: String)
    case invalidTeamID(found: String?)
    case installFailed(exitCode: Int32, errorLog: String)

    /// What the log says.
    public var errorDescription: String? {
        switch self {
        case .releaseLookupFailed:
            return "The latest release could not be fetched from GitHub."
        case .noNewerRelease:
            return "There is no release newer than the installed version."
        case .insecureDownload(let url):
            return "Refusing to download the update package over a non-HTTPS URL: \(url.absoluteString)"
        case .downloadFailed:
            return "The update package download failed or returned a non-200 status code."
        case .unreadableAssessment:
            return "The Gatekeeper assessment of the package could not be read."
        case .rejectedByGatekeeper(let reason):
            return "Gatekeeper rejected the package. Reason: \(reason)"
        case .invalidTeamID(let found):
            return "The Team ID of the package was invalid. "
                + "Found: \(found ?? "none"), expected: \(SensorXPC.teamID)"
        case .installFailed(let exitCode, let errorLog):
            return "The installer process failed with exit code \(exitCode). Log: \(errorLog)"
        }
    }

    /// What Mac Monitor is told.
    public var failure: UpdateFailure {
        switch self {
        case .releaseLookupFailed, .insecureDownload, .downloadFailed: return .download
        case .noNewerRelease: return .noNewerRelease
        case .unreadableAssessment, .rejectedByGatekeeper: return .gatekeeper
        case .invalidTeamID: return .teamID
        case .installFailed: return .installer
        }
    }
}
