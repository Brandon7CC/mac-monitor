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
    /// Ask the Security Extension to install the latest release.
    ///
    /// The Security Extension resolves, downloads, and verifies the package itself.
    ///
    /// - Parameter completion: Called on the main thread with `true` if the update was installed.
    public func installUpdate(completion: @escaping (Bool) -> Void) {
        sensor.call { $0.installUpdate(reply: $1) } completion: { installed in
            completion(installed ?? false)
        }
    }
}
