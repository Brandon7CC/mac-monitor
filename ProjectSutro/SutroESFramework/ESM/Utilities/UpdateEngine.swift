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
    public let releaseNotes: String
    public let releaseDate: String
    
    public init(version: String, downloadURL: URL, releaseNotes: String, releaseDate: String) {
        self.version = version
        self.downloadURL = downloadURL
        self.releaseNotes = releaseNotes
        self.releaseDate = releaseDate
    }
}


extension EndpointSecurityManager {
    /// Can this build update itself? `false` for Community builds, which are ad-hoc signed for SIP-off development VMs
    /// and shouldn't be replaced by a release build (the Security Extension refuses to check or install).
#if COMMUNITY_BUILD
    public static let supportsUpdates: Bool = false
#else
    public static let supportsUpdates: Bool = true
#endif
    
    // MARK: Step #2 in checking for updates
    /// Initiates an asynchronous check for updates.
    /// - Parameter completion: A closure that will be called on the main thread with the result.
    ///                       It receives an optional `UpdateDetails` object or `nil` if no update is found or an error occurs.
    public func checkForUpdates(completion: @escaping (UpdateDetails?) -> Void) {
        sensor.call { $0.checkForUpdate(reply: $1) } completion: { response in
            guard let data = response ?? nil else { return completion(nil) }
            
            do {
                completion(try JSONDecoder().decode(UpdateDetails.self, from: data))
            } catch {
                os_log(OSLogType.error, "Failed to decode UpdateDetails from XPC data: \(error.localizedDescription)")
                completion(nil)
            }
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
