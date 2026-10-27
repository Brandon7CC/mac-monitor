//
//  UpdateInstaller.swift
//  SecurityExtension
//
//  Created by Brandon Dalton on 10/1/26.
//

import Foundation
import OSLog
import os
import SutroESFramework


// MARK: - Update installer
/// Checks GitHub for Mac Monitor releases and installs them as root (Security Extension context).
///
/// Nothing about the package comes from Mac Monitor. ``install(reply:)`` resolves the latest release itself, refuses
/// anything that isn't newer than the running version, and only installs a package that:
/// 1. Was downloaded over HTTPS
/// 2. Gatekeeper accepts with assessments enforced (`spctl --enforce-assessment` exits `0` with `assessment:verdict` =
///    `true` and no `assessment:authority:override`), which implies notarization even if Gatekeeper is turned off
/// 3. Is signed by `SensorXPC.teamID`
///
/// Updates are disabled in Community builds: they're adhoc signed for SIP-off development VMs, only enforce the
/// signing identifier on XPC peers, and shouldn't be replaced by a release build.
final class UpdateInstaller {
    private static let latestReleaseURL: URL =
        URL(string: "https://api.github.com/repos/Brandon7CC/mac-monitor/releases/latest")!
    
    private let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension", category: "UpdateInstaller")
    /// Only one install may run at a time.
    private let isInstalling = OSAllocatedUnfairLock(initialState: false)
    
    // MARK: - Check for updates
    /// Check GitHub for a newer release.
    ///
    /// - Parameter reply: A JSON encoded `UpdateCheck`. A failed lookup is `.failed`, never `.upToDate`.
    func check(reply: @escaping (Data?) -> Void) {
#if COMMUNITY_BUILD
        logger.log("Update checks are disabled in Community builds.")
        reply(nil)
#else
        logger.log("Mac Monitor requested an update check.")
        Task {
            let outcome: UpdateCheck
            do {
                outcome = try await newerRelease().map { .newer($0) } ?? .upToDate
            } catch {
                logger.error("Update check failed: \(error.localizedDescription, privacy: .public)")
                outcome = .failed
            }
            reply(try? JSONEncoder().encode(outcome))
        }
#endif
    }
    
    // MARK: - Install updates
    /// Download, verify, and install the latest release.
    ///
    /// - Parameters:
    ///   - progress: Called as each step starts, and as the download goes.
    ///   - reply: `nil` if the update was installed, else why not.
    func install(progress: @escaping (UpdateProgress) -> Void, reply: @escaping (UpdateFailure?) -> Void) {
#if COMMUNITY_BUILD
        logger.error("Updates are disabled in Community builds.")
        reply(.unavailable)
#else
        let claimed: Bool = isInstalling.withLock { installing in
            guard !installing else { return false }
            installing = true
            return true
        }
        guard claimed else {
            logger.error("An update is already being installed.")
            return reply(.alreadyInstalling)
        }
        
        Task {
            defer { isInstalling.withLock { $0 = false } }
            do {
                try await installLatestRelease(progress: progress)
                logger.log("🎉 Update installation complete!")
                reply(nil)
            } catch {
                logger.error("❌ Update failed: \(error.localizedDescription, privacy: .public)")
                reply((error as? UpdateError)?.failure ?? (error is URLError ? .download : .installer))
            }
        }
#endif
    }
    
    /// Securely downloads, validates, and installs the latest release.
    ///
    /// - Parameter progress: Called as each step starts, and as the download goes.
    private func installLatestRelease(progress: @escaping (UpdateProgress) -> Void) async throws {
        guard let release = try await newerRelease() else { throw UpdateError.noNewerRelease }
        guard release.downloadURL.scheme == "https" else { throw UpdateError.insecureDownload(release.downloadURL) }
        
        /// 1. Download the update package into a fresh directory that's removed when we're done
        logger.log("1. Downloading update from \(release.downloadURL.absoluteString, privacy: .public)")
        let fm = FileManager.default
        let workDirectory = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try fm.createDirectory(at: workDirectory, withIntermediateDirectories: true)
        defer {
            try? fm.removeItem(at: workDirectory)
            logger.log("🧹 Cleaned up temporary directory at \(workDirectory.path, privacy: .public)")
        }
        
        progress(.downloading(fraction: 0))
        let (downloadedURL, response) = try await URLSession.shared.download(from: release.downloadURL,
                                                                             delegate: DownloadProgress(progress))
        /// We don't trust the server's file name: the package always lands at a fixed name inside our directory.
        let package = workDirectory.appendingPathComponent("MacMonitorUpdate.pkg")
        try fm.moveItem(at: downloadedURL, to: package)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw UpdateError.downloadFailed }
        
        /// 2. Validate the package with Gatekeeper and pin the Team ID
        logger.log("2. Validating the package signature")
        progress(.verifying)
        try await verifySignature(of: package)
        
        /// 3. Install the update package
        logger.log("3. Installing update...")
        progress(.installing)
        let (status, errors) = try await run("/usr/sbin/installer", ["-pkg", package.path, "-target", "/"],
                                             capturing: .standardError)
        guard status == 0 else {
            throw UpdateError.installFailed(exitCode: status, errorLog: String(decoding: errors, as: UTF8.self))
        }
    }
    
    // MARK: - Release lookup
    /// Fetch the latest GitHub release and keep it only if it's newer than this build.
    ///
    /// - Returns: What Mac Monitor shows in its update sheet about the newer release, or `nil` if we're up-to-date.
    ///   The update package is the release's first asset whose name ends in `.pkg`.
    /// - Throws: ``UpdateError/releaseLookupFailed`` for a failed lookup or a release without a package, or why the
    ///   release couldn't be downloaded or read.
    private func newerRelease() async throws -> UpdateDetails? {
        let (data, response) = try await URLSession.shared.data(from: Self.latestReleaseURL)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw UpdateError.releaseLookupFailed }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let release = try decoder.decode(GitHubRelease.self, from: data)
        
        guard let package = release.assets.first(where: \.isPackage)?.browserDownloadUrl,
              let currentVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String else {
            throw UpdateError.releaseLookupFailed
        }
        logger.log("""
            (Mac Monitor Update) Latest version found: \(release.version, privacy: .public). \
            Current version: \(currentVersion, privacy: .public)
            """)
        guard release.version.compare(currentVersion, options: .numeric) == .orderedDescending else { return nil }
        return UpdateDetails(version: release.tagName, downloadURL: package, releaseNotes: release.body,
                             releaseDate: release.publishedAt)
    }
    
    // MARK: - Signature validation
    /// Ask Gatekeeper to assess the package, then require our Team ID.
    ///
    /// Leverages `spctl --assess --type install --raw`, which prints the assessment as a property list on stdout and
    /// exits non-zero when the package is rejected. `--enforce-assessment` keeps a disabled Gatekeeper from turning a
    /// rejection into an acceptance; we also refuse any result that carries an `assessment:authority:override`.
    ///
    /// - Parameter package: The downloaded package.
    private func verifySignature(of package: URL) async throws {
        let arguments = ["--assess", "--type", "install", "--enforce-assessment", "-v", "-v", "--raw", package.path]
        let (status, output) = try await run("/usr/sbin/spctl", arguments, capturing: .standardOutput)
        let assessment: [String: Any] = try Self.assessment(from: output)
        let authority = assessment["assessment:authority"] as? [String: Any]
        
        guard status == 0, assessment["assessment:verdict"] as? Bool == true else {
            let source = authority?["assessment:authority:source"] as? String
            throw UpdateError.rejectedByGatekeeper(reason: source ?? "spctl exited with \(status)")
        }
        if let override = authority?["assessment:authority:override"] {
            throw UpdateError.rejectedByGatekeeper(reason: "assessment was overridden (\(override))")
        }
        
        /// Extract the Team Id from e.g. `Developer ID Installer: Brandon Dalton (4HMJQ7V3SX)`
        guard let originator = assessment["assessment:originator"] as? String,
              let match = originator.range(of: #"\(([A-Z0-9]{10})\)$"#, options: .regularExpression) else {
            throw UpdateError.invalidTeamID(found: nil)
        }
        let teamID = String(originator[match]).trimmingCharacters(in: CharacterSet(charactersIn: "()"))
        guard teamID == SensorXPC.teamID else { throw UpdateError.invalidTeamID(found: teamID) }
        logger.log("✅ Gatekeeper accepted the package and the Team ID matches: \(teamID, privacy: .public)")
    }
    
    /// Pull the property list out of `spctl --raw` output.
    ///
    /// - Parameter output: `spctl`'s stdout.
    /// - Returns: The assessment dictionary.
    private static func assessment(from output: Data) throws -> [String: Any] {
        let text = String(decoding: output, as: UTF8.self)
        guard let start = text.range(of: "<?xml"),
              let end = text.range(of: "</plist>", options: .backwards),
              start.lowerBound < end.upperBound,
              let plist = try PropertyListSerialization.propertyList(
                from: Data(text[start.lowerBound..<end.upperBound].utf8), format: nil) as? [String: Any] else {
            throw UpdateError.unreadableAssessment
        }
        return plist
    }
    
    // MARK: - Process helper
    /// Run a tool to completion off the Swift concurrency thread pool (``ToolRunner``).
    ///
    /// - Parameters:
    ///   - tool: Absolute path to the executable.
    ///   - arguments: Its arguments.
    ///   - stream: The stream to capture.
    /// - Returns: The exit status and the captured output.
    private func run(_ tool: String, _ arguments: [String],
                     capturing stream: ToolRunner.Stream) async throws -> (status: Int32, output: Data) {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                continuation.resume(with: Result { try ToolRunner.run(tool, arguments, capturing: stream) })
            }
        }
    }
}


// MARK: - Errors
extension UpdateInstaller {
    enum UpdateError: LocalizedError {
        case releaseLookupFailed
        case noNewerRelease
        case insecureDownload(URL)
        case downloadFailed
        case unreadableAssessment
        case rejectedByGatekeeper(reason: String)
        case invalidTeamID(found: String?)
        case installFailed(exitCode: Int32, errorLog: String)
        
        var errorDescription: String? {
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
        var failure: UpdateFailure {
            switch self {
            case .releaseLookupFailed, .insecureDownload, .downloadFailed: return .download
            case .noNewerRelease: return .noNewerRelease
            case .unreadableAssessment, .rejectedByGatekeeper: return .gatekeeper
            case .invalidTeamID: return .teamID
            case .installFailed: return .installer
            }
        }
    }
}


// MARK: - Download progress
/// Reports a download's progress, at most once a percent.
private final class DownloadProgress: NSObject, URLSessionTaskDelegate {
    private let report: (UpdateProgress) -> Void
    private let lastPercent = OSAllocatedUnfairLock(initialState: -1)
    private var observation: NSKeyValueObservation?
    
    /// - Parameter report: Called with each new percent.
    init(_ report: @escaping (UpdateProgress) -> Void) {
        self.report = report
    }
    
    func urlSession(_ session: URLSession, didCreateTask task: URLSessionTask) {
        observation = task.progress.observe(\.fractionCompleted) { [weak self] progress, _ in
            self?.update(progress.fractionCompleted)
        }
    }
    
    /// Report a fraction when its percent is new.
    ///
    /// - Parameter fraction: How much is downloaded, from 0 to 1.
    private func update(_ fraction: Double) {
        let percent = Int(fraction * 100)
        let isNew = lastPercent.withLock { last in
            defer { last = percent }
            return percent != last
        }
        if isNew { report(.downloading(fraction: fraction)) }
    }
}


// MARK: - GitHub Release JSON Decoder
/// The fields Mac Monitor reads from GitHub's latest release. The decoder converts GitHub's snake_case keys.
private struct GitHubRelease: Decodable {
    /// A file attached to the release. Releases also attach the telemetry schema.
    struct Asset: Decodable {
        let name: String
        let browserDownloadUrl: URL
        
        /// Is this the installer package?
        var isPackage: Bool { name.lowercased().hasSuffix(".pkg") }
    }
    
    let tagName: String
    let assets: [Asset]
    /// The release notes. GitHub sends `null` for a release without any.
    let body: String?
    /// When the release was published. `null` for a draft.
    let publishedAt: String?
    
    /// The release version without the tag's `v` prefix.
    var version: String { String(tagName.trimmingPrefix("v")) }
}
