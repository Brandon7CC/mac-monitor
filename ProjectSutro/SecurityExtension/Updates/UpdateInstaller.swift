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
/// Updates are disabled in Community builds: they're ad-hoc signed for SIP-off development VMs, only enforce the
/// signing identifier on XPC peers, and shouldn't be replaced by a release build.
final class UpdateInstaller {
    private static let latestReleaseURL: URL = URL(string: "https://api.github.com/repos/Brandon7CC/mac-monitor/releases/latest")!
    
    private let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension", category: "UpdateInstaller")
    /// Only one install may run at a time.
    private let isInstalling = OSAllocatedUnfairLock(initialState: false)
    
    // MARK: - Check for updates
    /// Check GitHub for a newer release.
    ///
    /// - Parameter reply: A JSON encoded `UpdateDetails`, or `nil` if there is no newer release or the check failed.
    func check(reply: @escaping (Data?) -> Void) {
#if COMMUNITY_BUILD
        logger.log("Update checks are disabled in Community builds.")
        reply(nil)
#else
        logger.log("Mac Monitor requested an update check.")
        Task {
            do {
                guard let release = try await newerRelease() else { return reply(nil) }
                reply(try JSONEncoder().encode(release.details))
            } catch {
                logger.error("Update check failed: \(error.localizedDescription, privacy: .public)")
                reply(nil)
            }
        }
#endif
    }
    
    // MARK: - Install updates
    /// Download, verify, and install the latest release.
    ///
    /// - Parameter reply: `true` if the update was installed.
    func install(reply: @escaping (Bool) -> Void) {
#if COMMUNITY_BUILD
        logger.error("Updates are disabled in Community builds.")
        reply(false)
#else
        let claimed: Bool = isInstalling.withLock { installing in
            guard !installing else { return false }
            installing = true
            return true
        }
        guard claimed else {
            logger.error("An update is already being installed.")
            return reply(false)
        }
        
        Task {
            defer { isInstalling.withLock { $0 = false } }
            do {
                try await installLatestRelease()
                logger.log("🎉 Update installation complete!")
                reply(true)
            } catch {
                logger.error("❌ Update failed: \(error.localizedDescription, privacy: .public)")
                reply(false)
            }
        }
#endif
    }
    
    /// Securely downloads, validates, and installs the latest release.
    private func installLatestRelease() async throws {
        guard let release = try await newerRelease() else { throw UpdateError.noNewerRelease }
        guard release.updatePkgURL.scheme == "https" else { throw UpdateError.insecureDownload(release.updatePkgURL) }
        
        /// 1. Download the update package into a fresh directory that's removed when we're done
        logger.log("1. Downloading update from \(release.updatePkgURL.absoluteString, privacy: .public)")
        let fm = FileManager.default
        let workDirectory = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try fm.createDirectory(at: workDirectory, withIntermediateDirectories: true)
        defer {
            try? fm.removeItem(at: workDirectory)
            logger.log("🧹 Cleaned up temporary directory at \(workDirectory.path, privacy: .public)")
        }
        
        let (downloadedURL, response) = try await URLSession.shared.download(from: release.updatePkgURL)
        /// We don't trust the server's file name: the package always lands at a fixed name inside our directory.
        let package = workDirectory.appendingPathComponent("MacMonitorUpdate.pkg")
        try fm.moveItem(at: downloadedURL, to: package)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw UpdateError.downloadFailed }
        
        /// 2. Validate the package with Gatekeeper and pin the Team ID
        logger.log("2. Validating the package signature")
        try await verifySignature(of: package)
        
        /// 3. Install the update package
        logger.log("3. Installing update...")
        let (status, errors) = try await run("/usr/sbin/installer", ["-pkg", package.path, "-target", "/"], capturing: .standardError)
        guard status == 0 else {
            throw UpdateError.installFailed(exitCode: status, errorLog: String(decoding: errors, as: UTF8.self))
        }
    }
    
    // MARK: - Release lookup
    /// Fetch the latest GitHub release and keep it only if it's newer than this build.
    ///
    /// - Returns: The newer release, or `nil` if we're up-to-date.
    private func newerRelease() async throws -> GitHubRelease? {
        let (data, response) = try await URLSession.shared.data(from: Self.latestReleaseURL)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw UpdateError.releaseLookupFailed }
        let release = try JSONDecoder().decode(GitHubRelease.self, from: data)
        
        guard let currentVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String else {
            throw UpdateError.releaseLookupFailed
        }
        logger.log("(Mac Monitor Update) Latest version found: \(release.version, privacy: .public). Current version: \(currentVersion, privacy: .public)")
        return release.version.compare(currentVersion, options: .numeric) == .orderedDescending ? release : nil
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
        let (status, output) = try await run("/usr/sbin/spctl", ["--assess", "--type", "install", "--enforce-assessment", "-v", "-v", "--raw", package.path], capturing: .standardOutput)
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
              let plist = try PropertyListSerialization.propertyList(from: Data(text[start.lowerBound..<end.upperBound].utf8), format: nil) as? [String: Any] else {
            throw UpdateError.unreadableAssessment
        }
        return plist
    }
    
    // MARK: - Process helper
    /// Which output stream ``run(_:_:capturing:)`` returns. The other is discarded.
    private enum OutputStream {
        case standardOutput
        case standardError
    }
    
    /// Run a tool to completion off the Swift concurrency thread pool.
    ///
    /// The captured stream is drained before waiting on the process so a chatty tool can't fill the pipe and deadlock.
    ///
    /// - Parameters:
    ///   - tool: Absolute path to the executable.
    ///   - arguments: Its arguments.
    ///   - stream: The stream to capture.
    /// - Returns: The exit status and the captured output.
    private func run(_ tool: String, _ arguments: [String], capturing stream: OutputStream) async throws -> (status: Int32, output: Data) {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                let process = Foundation.Process()
                process.executableURL = URL(fileURLWithPath: tool)
                process.arguments = arguments
                let pipe = Pipe()
                process.standardOutput = stream == .standardOutput ? pipe : FileHandle.nullDevice
                process.standardError = stream == .standardError ? pipe : FileHandle.nullDevice
                
                do {
                    try process.run()
                    let output = pipe.fileHandleForReading.readDataToEndOfFile()
                    process.waitUntilExit()
                    continuation.resume(returning: (process.terminationStatus, output))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}


// MARK: - Errors
extension UpdateInstaller {
    enum UpdateError: Error, LocalizedError {
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
                return "The Team ID of the package was invalid. Found: \(found ?? "none"), expected: \(SensorXPC.teamID)"
            case .installFailed(let exitCode, let errorLog):
                return "The installer process failed with exit code \(exitCode). Log: \(errorLog)"
            }
        }
    }
}


// MARK: - GitHub Release JSON Decoder
/// Decode the relevant fields from the GitHub API response.
private struct GitHubRelease: Decodable {
    let tagName: String
    let updatePkgURL: URL
    let body: String
    let publishedAt: String
    
    /// The release version without the tag's `v` prefix.
    var version: String { String(tagName.trimmingPrefix("v")) }
    
    /// What Mac Monitor shows in its update sheet.
    var details: UpdateDetails {
        UpdateDetails(version: tagName, downloadURL: updatePkgURL, releaseNotes: body, releaseDate: publishedAt)
    }
    
    private struct Asset: Decodable {
        let browserDownloadURL: URL
        
        enum CodingKeys: String, CodingKey {
            case browserDownloadURL = "browser_download_url"
        }
    }
    
    enum CodingKeys: String, CodingKey {
        case tagName = "tag_name"
        case assets
        case body
        case publishedAt = "published_at"
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        tagName = try container.decode(String.self, forKey: .tagName)
        body = try container.decode(String.self, forKey: .body)
        publishedAt = try container.decode(String.self, forKey: .publishedAt)
        
        // Decode the 'assets' array and extract the URL from the first element.
        var assetsContainer = try container.nestedUnkeyedContainer(forKey: .assets)
        guard let firstAsset = try assetsContainer.decodeIfPresent(Asset.self) else {
            throw DecodingError.dataCorruptedError(
                in: assetsContainer,
                debugDescription: "The 'assets' array is empty or missing the expected object."
            )
        }
        updatePkgURL = firstAsset.browserDownloadURL
    }
}
