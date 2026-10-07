//
//  CommandLineToolLinker.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/6/26.
//

import Foundation


// MARK: - Command line tool linker
/// Installs or removes `/usr/local/bin/macmonitor` (Security Extension context).
///
/// The Security Extension runs this as root once an administrator has authorized the change
/// (``CommandLineToolAuthorization``). It doesn't trust what Mac Monitor saw. Before changing anything we check again
/// that the directory is a real directory, that the entry is Mac Monitor's link and still what Settings showed, and
/// that the tool is one Mac Monitor would link.
///
/// **How we change things:**
///   - Every change is made relative to an open descriptor for the link's directory, opened with `O_NOFOLLOW`. A
///     symbolic link swapped in for the directory is refused, never followed.
///   - We never follow the link we find, and we never replace anything that isn't Mac Monitor's link.
///   - A missing directory is only created inside a real directory our own user owns, then handed to `root:wheel`.
public struct CommandLineToolLinker {
    /// The extra check a tool must pass before we link it
    let trusts: (String) -> Bool

    /// - Parameter trusts: The extra check a tool must pass. By default the tool and every directory above it must
    ///   belong to root, and it must be signed as Mac Monitor's command line tool.
    public init(trusts: @escaping (String) -> Bool = CommandLineToolLinker.isTrustedTool) {
        self.trusts = trusts
    }

    /// The full check the Security Extension runs on a tool (``CommandLineToolLink/validate(_:)``).
    ///
    /// - Parameter tool: The tool's path.
    /// - Returns: `true` if Mac Monitor would link it.
    public static func isTrustedTool(_ tool: String) -> Bool {
        let bundle = URL(fileURLWithPath: String(tool.dropLast(CommandLineToolLink.toolInBundle.count)))
        let link = CommandLineToolLink(layout: CommandLineToolLink.Layout(bundle: bundle))
        return (try? link.validate(tool).get()) == tool
    }

    /// Carry out a plan.
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

    /// Is this a tool we'd link? It must look like an app's command line tool, be a regular executable file and not a
    /// symbolic link, and pass ``trusts``.
    ///
    /// - Parameter tool: The tool's path.
    /// - Returns: `true` if we can link it.
    func isLinkable(_ tool: String) -> Bool {
        var info = stat()
        guard CommandLineToolLink.isMacMonitorLink(tool), lstat(tool, &info) == 0,
              info.st_mode & S_IFMT == S_IFREG, info.st_mode & S_IXUSR != 0 else { return false }
        return trusts(tool)
    }

    /// Open the link's directory, creating it for an install when it's missing.
    ///
    /// - Parameters:
    ///   - path: The link's directory.
    ///   - creating: Create it if it's missing?
    /// - Returns: An open descriptor, or the outcome to report. A missing directory on a removal is `.done`.
    func openDirectory(_ path: String, creating: Bool) -> Result<Int32, Outcome> {
        let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        if descriptor >= 0 { return .success(descriptor) }
        guard errno == ENOENT else { return .failure(.notADirectory) }
        guard creating else { return .failure(.done) }
        return createDirectory(path)
    }

    /// Create the link's directory, owned by `root:wheel` with mode 0755.
    ///
    /// The directory above it is created first if it's missing. It must be a real directory that our own user owns, so
    /// nobody else can swap anything in while we work. If we can't hand the new directory to root we remove it again.
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
    /// What a change did. The raw value is what travels over XPC.
    public enum Outcome: Int, Error, Equatable, CaseIterable {
        /// Done
        case done = 0
        /// The user cancelled the password prompt.
        case cancelled = 1
        /// The link's directory couldn't be created.
        case directoryNotCreated = 3
        /// The link's directory isn't a real directory. Or it's missing and the directory above it isn't one we own.
        case notADirectory = 4
        /// What's at the link's path isn't Mac Monitor's link.
        case notMacMonitors = 5
        /// What's at the link's path changed since Settings looked.
        case changed = 6
        /// The tool isn't one Mac Monitor links.
        case badTool = 7
        /// The file system refused a change.
        case fileSystemError = 8
        /// No administrator authorized the change.
        case notAuthorized = 9
        /// We couldn't reach the Security Extension.
        case unavailable = 10

        /// What to tell the user.
        ///
        /// - Parameter plan: The plan we tried.
        /// - Returns: A sentence, or `nil` when there's nothing to say (done or cancelled).
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
