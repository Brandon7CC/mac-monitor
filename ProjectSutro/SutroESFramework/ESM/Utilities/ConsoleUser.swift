//
//  ConsoleUser.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import SystemConfiguration


// MARK: - Console user
/// The user logged in at the console: whose home folder Mac Monitor's default mute set mutes the caches of
/// (``MuteList/shippedDefault(for:)``).
///
/// The Security Extension runs as root, so its own home folder is `/var/root`. It asks the system who's at the console
/// (`SCDynamicStoreCopyConsoleUser`) and the user database for their home folder (`getpwuid_r`), rather than guessing
/// `/Users/<name>`.
public struct ConsoleUser: Equatable, Sendable {
    /// The short name, such as "alice".
    public let name: String
    /// The user ID.
    public let uid: uid_t
    /// The home folder, such as "/Users/alice".
    public let home: String
    
    /// - Parameters:
    ///   - name: The short name.
    ///   - uid: The user ID.
    ///   - home: The home folder.
    public init(name: String, uid: uid_t, home: String) {
        self.name = name
        self.uid = uid
        self.home = home
    }
    
    /// Who's logged in at the console now.
    ///
    /// - Parameter source: Where to ask: the system, unless a test passes its own.
    /// - Returns: The user, or `nil` when no one is: at the login window (`loginwindow`), in Setup Assistant
    ///   (`_mbsetupuser`, like every account whose name starts with `_`, is a service account), or with only SSH
    ///   sessions. Also `nil` when the user's home folder can't be found or isn't an absolute path other than `/`.
    public static func current(_ source: ConsoleUserSource = .system) -> ConsoleUser? {
        guard let session = source.session(), !session.name.isEmpty, session.name != "loginwindow",
              !session.name.hasPrefix("_"), let home = source.homeFolder(session.uid), home.hasPrefix("/"),
              home != "/" else { return nil }
        return ConsoleUser(name: session.name, uid: session.uid, home: home)
    }
}


// MARK: - Where to ask
/// Where ``ConsoleUser/current(_:)`` asks who's at the console, and for their home folder.
public struct ConsoleUserSource: Sendable {
    /// The console session's user, by short name and ID, if there's one.
    let session: @Sendable () -> (name: String, uid: uid_t)?
    /// A user's home folder from the user database, if it has one.
    let homeFolder: @Sendable (uid_t) -> String?
    
    /// - Parameters:
    ///   - session: The console session's user, by short name and ID, if there's one.
    ///   - homeFolder: A user's home folder, if it has one.
    public init(session: @escaping @Sendable () -> (name: String, uid: uid_t)?,
                homeFolder: @escaping @Sendable (uid_t) -> String?) {
        self.session = session
        self.homeFolder = homeFolder
    }
    
    /// The system: `SCDynamicStoreCopyConsoleUser` for the session, `getpwuid_r` for the home folder.
    public static let system = ConsoleUserSource(session: {
        var uid: uid_t = 0
        guard let name = SCDynamicStoreCopyConsoleUser(nil, &uid, nil) as String? else { return nil }
        return (name, uid)
    }, homeFolder: { ConsoleUserSource.homeFolder(of: $0) })
    
    /// A user's home folder from the user database, which may be anywhere (`/Users`, another volume, a network home).
    ///
    /// - Parameter uid: The user ID.
    /// - Returns: `pw_dir`, or `nil` if there's no such user or the lookup fails.
    static func homeFolder(of uid: uid_t) -> String? {
        var size = max(sysconf(_SC_GETPW_R_SIZE_MAX), 4_096)
        /// `getpwuid_r` asks for a larger buffer with `ERANGE`; a record never needs more than 1 MiB.
        while size <= 1 << 20 {
            var entry = passwd(), found: UnsafeMutablePointer<passwd>?
            var buffer = [CChar](repeating: 0, count: size)
            let (code, home) = buffer.withUnsafeMutableBufferPointer { bytes in
                let code = getpwuid_r(uid, &entry, bytes.baseAddress, bytes.count, &found)
                /// `pw_dir` points into `bytes`, so it's read before they go.
                return (code, found == nil ? nil : entry.pw_dir.map { String(cString: $0) })
            }
            guard code == ERANGE else { return code == 0 ? home : nil }
            size *= 2
        }
        return nil
    }
}
