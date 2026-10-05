//
//  CommandLineToolLink+Trust.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import Security


// MARK: - Refusals
extension CommandLineToolLink {
    /// Why this copy's tool can't be linked.
    public enum Refusal: Error, Equatable, CustomStringConvertible {
        /// Mac Monitor isn't running from an application bundle, such as a build products folder's.
        case notAnApplication(String)
        /// Mac Monitor is running from the read-only copy macOS makes of an app opened where it was downloaded.
        case translocated
        /// The bundle has no tool.
        case toolMissing(String)
        /// The tool isn't an executable file.
        case toolNotExecutable(String)
        /// The tool, or a directory in the bundle, is a symbolic link.
        case notCanonical(String)
        /// Someone other than root, described, can change the tool or a directory above it.
        case untrustedChain(path: String, writer: String)
        /// The tool isn't signed as Mac Monitor's command line tool.
        case signatureMismatch(String)
        
        public var description: String {
            switch self {
            case .notAnApplication(let path):
                return "Mac Monitor isn't running from an application (\(path)), so it has no tool to link."
            case .translocated:
                return "Mac Monitor is running from the temporary copy macOS made when it was opened from where it "
                    + "was downloaded. Move it to /Applications, or install it with its installer package, then open "
                    + "it again."
            case .toolMissing(let path):
                return "This copy of Mac Monitor has no command line tool at \(path)."
            case .toolNotExecutable(let path):
                return "\(path) isn't an executable file."
            case .notCanonical(let path):
                return "\(path) is reached through a symbolic link inside Mac Monitor."
            case .untrustedChain(let path, let writer):
                return "\(path) can be changed by \(writer), so \(writer) could replace the tool sudo macmonitor runs "
                    + "as root. Install Mac Monitor with its installer package, which gives it to root."
            case .signatureMismatch(let path):
                return "\(path) isn't signed as Mac Monitor's command line tool."
            }
        }
    }
}


// MARK: - Checks
extension CommandLineToolLink {
    /// This copy's tool, by its real path: the bundle's real path, then `/Contents/MacOS/macmonitor`.
    ///
    /// - Returns: The path, or `nil` if the bundle isn't there.
    func toolCandidate() -> String? {
        Self.realPath(layout.bundle.path).map { $0 + Self.toolInBundle }
    }
    
    /// Can this tool be linked? The checks in ``CommandLineToolLink``'s overview, cheapest first.
    ///
    /// - Parameter candidate: This copy's tool, by its real path, if the bundle is there.
    /// - Returns: The tool, or why not.
    func validate(_ candidate: String?) -> Result<String, Refusal> {
        guard let tool = candidate else { return .failure(.toolMissing(layout.bundle.path)) }
        let bundle = String(tool.dropLast(Self.toolInBundle.count))
        guard Self.isMacMonitorLink(tool) else { return .failure(.notAnApplication(bundle)) }
        guard !bundle.contains("/AppTranslocation/") else { return .failure(.translocated) }
        var info = stat()
        guard lstat(tool, &info) == 0 else { return .failure(.toolMissing(tool)) }
        guard Self.realPath(tool) == tool else { return .failure(.notCanonical(tool)) }
        guard info.st_mode & S_IFMT == S_IFREG, info.st_mode & S_IXUSR != 0 else {
            return .failure(.toolNotExecutable(tool))
        }
        if case let (path, writer)? = firstWriter(from: tool) {
            return .failure(.untrustedChain(path: path, writer: writer))
        }
        return signatureCheck(tool) ? .success(tool) : .failure(.signatureMismatch(tool))
    }
    
    /// Who else can change the link's directory, or the nearest directory above it that's there.
    ///
    /// - Returns: A sentence for Settings, or `nil` if only root (and admins) can.
    func binDirectoryWarning() -> String? {
        var path = layout.binDirectory
        var info = stat()
        while lstat(path, &info) != 0, path != "/" { path = (path as NSString).deletingLastPathComponent }
        guard let real = Self.realPath(path), case let (changeable, writer)? = firstWriter(from: real) else {
            return nil
        }
        return "\(changeable) can be changed by \(writer), so \(writer) could put another program at "
            + "\(layout.linkPath) for sudo to run. Run the tool by its full path instead."
    }
    
    /// The first of a file and the directories above it, up to the layout's root, that someone other than the trusted
    /// owner can change.
    ///
    /// Each must belong to the trusted owner and be writable by no one else, except the admin group (`/Applications`
    /// is `root:admin 0775`).
    ///
    /// - Parameter path: A real path.
    /// - Returns: That path and who else can change it, or `nil` if no one can.
    func firstWriter(from path: String) -> (String, String)? {
        let root = Self.realPath(layout.root) ?? layout.root
        var current = path
        while true {
            var info = stat()
            guard lstat(current, &info) == 0 else { return (current, "someone Mac Monitor can't identify") }
            if let writer = writer(of: info) { return (current, writer) }
            guard current != root, current != "/" else { return nil }
            current = (current as NSString).deletingLastPathComponent
        }
    }
    
    /// Who, besides the trusted owner and the admin group, can change a file or directory.
    ///
    /// - Parameter info: Its `lstat`.
    /// - Returns: Such as "everyone", or `nil` for no one.
    func writer(of info: stat) -> String? {
        if info.st_uid != layout.trustedOwner { return Self.userName(info.st_uid) }
        if info.st_mode & S_IWOTH != 0 { return "everyone" }
        if info.st_mode & S_IWGRP != 0, info.st_gid != layout.adminGroup {
            return "the group \(Self.groupName(info.st_gid))"
        }
        return nil
    }
}


// MARK: - System
extension CommandLineToolLink {
    /// Does a file's code signature satisfy ``SensorXPC/commandLineRequirement``? Checked statically: the file
    /// isn't run.
    ///
    /// - Parameter path: The file.
    /// - Returns: `true` if it's signed as `macmonitor`, for this build's requirement.
    public static func isSignedAsTool(_ path: String) -> Bool {
        signature(of: path, satisfies: SensorXPC.commandLineRequirement)
    }
    
    /// Does a file's code signature satisfy a requirement, every architecture of it?
    ///
    /// - Parameters:
    ///   - path: The file.
    ///   - requirement: A code signing requirement string.
    /// - Returns: `true` if the signature is valid and satisfies it.
    public static func signature(of path: String, satisfies requirement: String) -> Bool {
        var code: SecStaticCode?
        var compiled: SecRequirement?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code, SecRequirementCreateWithString(requirement as CFString, [], &compiled) == errSecSuccess,
              let compiled else {
            return false
        }
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate)
        return SecStaticCodeCheckValidity(code, flags, compiled) == errSecSuccess
    }
    
    /// A path with every symbolic link resolved.
    ///
    /// - Parameter path: The path.
    /// - Returns: Its real path, or `nil` if it isn't there.
    static func realPath(_ path: String) -> String? {
        guard let resolved = realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }
    
    /// A user's name.
    ///
    /// - Parameter uid: The user.
    /// - Returns: Such as "brandon", or "user 501" if it has none.
    static func userName(_ uid: uid_t) -> String {
        getpwuid(uid).flatMap { $0.pointee.pw_name.map { String(cString: $0) } } ?? "user \(uid)"
    }
    
    /// A group's name.
    ///
    /// - Parameter gid: The group.
    /// - Returns: Such as "staff", or "group 20" if it has none.
    static func groupName(_ gid: gid_t) -> String {
        getgrgid(gid).flatMap { $0.pointee.gr_name.map { String(cString: $0) } } ?? "group \(gid)"
    }
}
