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
    /// GitHub's latest release couldn't be fetched or read, it has no package, or the running version is unknown.
    case releaseLookupFailed
    /// The latest release isn't newer than the running version.
    case noNewerRelease
    /// The package's URL isn't HTTPS.
    case insecureDownload(URL)
    /// The package's download failed or didn't answer 200.
    case downloadFailed
    /// Gatekeeper's assessment of the package couldn't be read.
    case unreadableAssessment
    /// Gatekeeper rejected the package, for `reason`.
    case rejectedByGatekeeper(reason: String)
    /// The package isn't signed by ``SensorXPC/teamID``: `found` is the Team ID it has, if any.
    case invalidTeamID(found: String?)
    /// The installer exited with `exitCode`, having written `errorLog`.
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
