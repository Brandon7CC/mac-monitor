//
//  CommandLineToolLinker.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/6/26.
//

import Foundation


// MARK: - Command line tool linker
/// Installs or removes `/usr/local/bin/macmonitor` as root (Security Extension context).
///
/// Everything is checked again before a change, and all changes go through an `O_NOFOLLOW` directory descriptor.
public struct CommandLineToolLinker {
    let trusts: (String) -> Bool

    /// - Parameter trusts: Extra check on the tool. Defaults to root ownership and Mac Monitor's signature.
    public init(trusts: @escaping (String) -> Bool = CommandLineToolLinker.isTrustedTool) {
        self.trusts = trusts
    }

    /// The ownership and signature check (``CommandLineToolLink/validate(_:)``).
    ///
    /// - Parameter tool: The tool's path.
    /// - Returns: `true` if Mac Monitor would link it.
    public static func isTrustedTool(_ tool: String) -> Bool {
        let bundle = URL(fileURLWithPath: String(tool.dropLast(CommandLineToolLink.toolInBundle.count)))
        let link = CommandLineToolLink(layout: CommandLineToolLink.Layout(bundle: bundle))
        return (try? link.validate(tool).get()) == tool
    }

    /// Make the change.
    ///
    /// - Parameter plan: What Settings asked for.
    /// - Returns: What happened.
    public func apply(_ plan: CommandLineToolLink.Plan) -> Outcome {
        if plan.action == .install && !isLinkable(plan.tool) { return .badTool }
        let directory: Int32
        switch openDirectory(plan.binDirectory, creating: plan.action == .install) {
        case .success(let descriptor): directory = descriptor
        case .failure(let outcome): return outcome
        }
        defer { close(directory) }

        let name = CommandLineToolLink.toolName
        var info = stat()
        if fstatat(directory, name, &info, AT_SYMLINK_NOFOLLOW) == 0 {
            guard info.st_mode & S_IFMT == S_IFLNK else { return .notMacMonitors }
            guard let current = Self.readLink(name, in: directory) else { return .fileSystemError }
            guard current == plan.expected else { return .changed }
            guard CommandLineToolLink.isMacMonitorLink(current) else { return .notMacMonitors }
            if plan.action == .install && current == plan.tool { return .done }
            guard unlinkat(directory, name, 0) == 0 else { return .fileSystemError }
        } else if errno == ENOENT {
            guard plan.expected.isEmpty else { return .changed }
        } else {
            return .fileSystemError
        }
        if plan.action == .remove { return .done }
        return symlinkat(plan.tool, directory, name) == 0 ? .done : .fileSystemError
    }

    /// Is this a regular, executable `….app/Contents/MacOS/macmonitor` that passes ``trusts``?
    ///
    /// - Parameter tool: The tool's path.
    /// - Returns: `true` if we can link it.
    func isLinkable(_ tool: String) -> Bool {
        var info = stat()
        guard CommandLineToolLink.isMacMonitorLink(tool), lstat(tool, &info) == 0,
              info.st_mode & S_IFMT == S_IFREG, info.st_mode & S_IXUSR != 0 else { return false }
        return trusts(tool)
    }

    /// Open the link's directory, creating it if needed.
    ///
    /// - Parameters:
    ///   - path: The link's directory.
    ///   - creating: Create it if it's missing?
    /// - Returns: A descriptor, or the outcome to report.
    func openDirectory(_ path: String, creating: Bool) -> Result<Int32, Outcome> {
        let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        if descriptor >= 0 { return .success(descriptor) }
        guard errno == ENOENT else { return .failure(.notADirectory) }
        guard creating else { return .failure(.done) }
        return createDirectory(path)
    }

    /// Create the link's directory as `root:wheel` 0755, inside a directory we own.
    ///
    /// - Parameter path: The link's directory.
    /// - Returns: An open descriptor for it, or the outcome to report.
    func createDirectory(_ path: String) -> Result<Int32, Outcome> {
        let parentPath = (path as NSString).deletingLastPathComponent
        let name = (path as NSString).lastPathComponent
        var info = stat()
        if lstat(parentPath, &info) != 0 {
            guard errno == ENOENT, mkdir(parentPath, 0o755) == 0 else { return .failure(.directoryNotCreated) }
        }
        let parent = open(parentPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard parent >= 0 else { return .failure(.notADirectory) }
        defer { close(parent) }
        guard fstat(parent, &info) == 0, info.st_uid == geteuid() else { return .failure(.notADirectory) }
        guard mkdirat(parent, name, 0o755) == 0 else { return .failure(.directoryNotCreated) }
        let directory = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard directory >= 0 else { return .failure(.notADirectory) }
        guard fchown(directory, 0, 0) == 0 else {
            close(directory)
            unlinkat(parent, name, AT_REMOVEDIR)
            return .failure(.directoryNotCreated)
        }
        return .success(directory)
    }

    /// Read a symbolic link inside a directory.
    ///
    /// - Parameters:
    ///   - name: The link's name.
    ///   - directory: An open descriptor for the directory.
    /// - Returns: The link's value, or `nil` if it can't be read.
    static func readLink(_ name: String, in directory: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        let count = readlinkat(directory, name, &buffer, buffer.count - 1)
        guard count >= 0 else { return nil }
        return String(decoding: buffer[..<count].map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}


// MARK: - Outcomes
extension CommandLineToolLinker {
    /// What a change did. The raw value goes over XPC.
    public enum Outcome: Int, Error, Equatable, CaseIterable {
        case done = 0
        case cancelled = 1
        case directoryNotCreated = 3
        case notADirectory = 4
        case notMacMonitors = 5
        /// Something changed since Settings looked
        case changed = 6
        case badTool = 7
        case fileSystemError = 8
        case notAuthorized = 9
        /// The Security Extension couldn't be reached
        case unavailable = 10

        /// What to tell the user.
        ///
        /// - Parameter plan: The change.
        /// - Returns: A sentence, or `nil` for done or cancelled.
        public func message(for plan: CommandLineToolLink.Plan) -> String? {
            let link = plan.linkPath
            switch self {
            case .done, .cancelled: return nil
            case .directoryNotCreated: return "\(plan.binDirectory) couldn't be created."
            case .notADirectory: return "\(plan.binDirectory) isn't a directory, so Mac Monitor left it alone."
            case .notMacMonitors: return "\(link) isn't Mac Monitor's link, so Mac Monitor left it alone."
            case .changed: return "\(link) changed while you were deciding. Nothing changed. Look again, then retry."
            case .badTool: return "\(plan.tool) isn't a command line tool Mac Monitor links. Nothing changed."
            case .fileSystemError: return "The file system refused to change \(link)."
            case .notAuthorized: return "An administrator has to approve changes to \(link). Nothing changed."
            case .unavailable: return "Mac Monitor couldn't reach its Security Extension, so \(link) didn't change."
            }
        }
    }
}
