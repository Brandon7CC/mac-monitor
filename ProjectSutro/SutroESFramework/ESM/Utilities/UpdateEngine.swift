//
//  UpdateEngine.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 8/5/25.
//

import Foundation
import OSLog

// MARK: - Update Details Data Structure
/// A structure to hold details about an available application update.
/// This is sent from the System Extension to the main app via XPC.
public struct UpdateDetails: Codable, Identifiable {
    public var id: String { version }
    public let version: String
    public let downloadURL: URL
    /// The release's notes in Markdown. `nil` when the release has none.
    public let releaseNotes: String?
    /// When the release was published, as GitHub gives it. `nil` when GitHub leaves it out.
    public let releaseDate: String?

    public init(version: String, downloadURL: URL, releaseNotes: String?, releaseDate: String?) {
        self.version = version
        self.downloadURL = downloadURL
        self.releaseNotes = releaseNotes
        self.releaseDate = releaseDate
    }

    /// The version without the tag's `v`, such as "2.1.0".
    public var number: String { String(version.trimmingPrefix("v")) }

    /// The day the release was published, in this Mac's calendar, such as "November 21, 2025".
    ///
    /// - Parameter timeZone: The time zone the day is in. Tests pass one.
    /// - Returns: The day, or `nil` when GitHub gave no date or one that isn't ISO 8601.
    public func releaseDay(in timeZone: TimeZone = .current) -> String? {
        guard let releaseDate, let date = ISO8601DateFormatter().date(from: releaseDate) else { return nil }
        var style = Date.FormatStyle(date: .long, time: .omitted)
        style.timeZone = timeZone
        return date.formatted(style)
    }
}


// MARK: - Update check
/// How an update check went. The Security Extension sends it to Mac Monitor as JSON.
public enum UpdateCheck: Codable {
    /// A newer release is out.
    case newer(UpdateDetails)
    /// This is the latest release.
    case upToDate
    /// GitHub couldn't be reached or its answer couldn't be read.
    case failed

    /// Read the Security Extension's reply.
    ///
    /// A reply that isn't an `UpdateCheck` is read as a bare ``UpdateDetails``, which is what the Security Extension
    /// sent before it said why there was no update.
    ///
    /// - Parameter reply: The reply's bytes, or `nil` when the request failed.
    /// - Returns: The outcome. A missing or unreadable reply is `.failed`.
    public static func decode(_ reply: Data?) -> UpdateCheck {
        guard let reply else { return .failed }
        let decoder = JSONDecoder()
        if let check = try? decoder.decode(UpdateCheck.self, from: reply) { return check }
        if let details = try? decoder.decode(UpdateDetails.self, from: reply) { return .newer(details) }
        os_log(OSLogType.error, "Mac Monitor couldn't read the Security Extension's update check reply.")
        return .failed
    }
}


// MARK: - Install progress
/// Where an update's install is. The Security Extension sends it to Mac Monitor as JSON while it works.
public enum UpdateProgress: Codable, Equatable {
    /// Downloading the package, `fraction` of it so far, from 0 to 1.
    case downloading(fraction: Double)
    /// Gatekeeper and the team ID are checked.
    case verifying
    /// `installer` runs.
    case installing
    /// Installed. Mac Monitor quits and reopens.
    case reopening

    /// The step it's on, from 0 (downloading) to 3 (reopening), as the update sheet lists them.
    public var step: Int {
        switch self {
        case .downloading: return 0
        case .verifying: return 1
        case .installing: return 2
        case .reopening: return 3
        }
    }

    /// How far along the whole install is, from 0 to 1. The download is most of it.
    public var fraction: Double {
        switch self {
        case .downloading(let fraction): return 0.7 * min(max(fraction, 0), 1)
        case .verifying: return 0.75
        case .installing: return 0.9
        case .reopening: return 1
        }
    }
}


// MARK: - Install failure
/// Why an update wasn't installed. The Security Extension replies with its raw value.
public enum UpdateFailure: String, Codable, Error, CaseIterable {
    /// The user running Mac Monitor isn't an administrator.
    case notAdministrator
    /// Another Mac Monitor owns the event stream.
    case streamOwned
    /// An install is already running.
    case alreadyInstalling
    /// The latest release isn't newer than this one.
    case noNewerRelease
    /// GitHub couldn't be reached, or the package couldn't be downloaded.
    case download
    /// Gatekeeper didn't accept the package.
    case gatekeeper
    /// The package isn't signed by Swiftly Detecting's team.
    case teamID
    /// `installer` failed.
    case installer
    /// The Security Extension couldn't be reached, or this build doesn't update itself.
    case unavailable

    /// What Mac Monitor tells the user, without the release's version.
    public var message: String {
        switch self {
        case .notAdministrator:
            return "The installer runs as root, so only an administrator's Mac Monitor can install updates."
        case .streamOwned:
            return "Another Mac Monitor is recording. Install the update from the Mac Monitor that's recording."
        case .alreadyInstalling:
            return "An update is already being installed."
        case .noNewerRelease:
            return "There's no newer release to install."
        case .download:
            return "Mac Monitor couldn't download the update. Check the internet connection."
        case .gatekeeper:
            return "Gatekeeper didn't accept the package, so nothing changed."
        case .teamID:
            return "The package isn't signed by Swiftly Detecting, so nothing changed."
        case .installer:
            return "The installer couldn't install the package."
        case .unavailable:
            return "Mac Monitor couldn't reach its Security Extension."
        }
    }

    /// Read the Security Extension's reply to an install.
    ///
    /// - Parameter reply: `nil` when the request failed, `.some(nil)` when the update was installed, or the failure's
    ///   raw value.
    /// - Returns: `nil` when the update was installed, else why not. A raw value this build doesn't know is
    ///   `.installer`.
    public static func decode(_ reply: String??) -> UpdateFailure? {
        guard let reply else { return .unavailable }
        guard let reply else { return nil }
        return UpdateFailure(rawValue: reply) ?? .installer
    }
}


// MARK: - Release notes
/// A release's notes, as the update sheet and Release Notes show them.
public enum ReleaseNotesText {
    /// GitHub's Markdown with its line breaks kept. A heading's `#`s are dropped and the heading is bold. GitHub's
    /// `\r\n` line endings count as one break.
    ///
    /// - Parameter markdown: The release's body.
    /// - Returns: The text to show.
    public static func attributed(_ markdown: String) -> AttributedString {
        let lines = markdown.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n")
            .map { line -> String in
                let heading = line.drop { $0 == "#" }
                guard heading.count < line.count, heading.first == " " else { return line }
                return "**" + heading.trimmingCharacters(in: .whitespaces) + "**"
            }
        let text = lines.joined(separator: "\n")
        let options = AttributedString.MarkdownParsingOptions(interpretedSyntax: .inlineOnlyPreservingWhitespace)
        return (try? AttributedString(markdown: text, options: options)) ?? AttributedString(text)
    }
}


extension EndpointSecurityManager {
    /// Can this build update itself? `false` for Community builds, which are adhoc signed for SIP-off development VMs
    /// and shouldn't be replaced by a release build (the Security Extension refuses to check or install).
#if COMMUNITY_BUILD
    public static let supportsUpdates: Bool = false
#else
    public static let supportsUpdates: Bool = true
#endif

    // MARK: Step #2 in checking for updates
    /// Ask the Security Extension whether a newer release is out.
    ///
    /// - Parameter completion: Called on the main thread with the outcome. A failed request is `.failed`.
    public func checkForUpdates(completion: @escaping (UpdateCheck) -> Void) {
        sensor.call { $0.checkForUpdate(reply: $1) } completion: { response in
            completion(UpdateCheck.decode(response ?? nil))
        }
    }

    // MARK: Step #2 in installing updates
    /// Ask the Security Extension to install the latest release. Its progress arrives in ``installProgress``.
    ///
    /// The Security Extension resolves, downloads, and verifies the package itself.
    ///
    /// - Parameter completion: Called on the main thread with `nil` if the update was installed, else why not.
    public func installUpdate(completion: @escaping (UpdateFailure?) -> Void) {
        installProgress = .downloading(fraction: 0)
        sensor.call { $0.installUpdate(reply: $1) } completion: { [weak self] reply in
            let failure = UpdateFailure.decode(reply)
            self?.installProgress = failure == nil ? .reopening : nil
            completion(failure)
        }
    }

    /// The Security Extension's progress on an update's install (``AppAgentProtocol``).
    ///
    /// - Parameter progress: A JSON encoded ``UpdateProgress``.
    public func updateProgress(_ progress: Data) {
        guard let progress = try? JSONDecoder().decode(UpdateProgress.self, from: progress) else { return }
        DispatchQueue.main.async { [weak self] in
            guard self?.installProgress != nil else { return }
            self?.installProgress = progress
        }
    }
}
