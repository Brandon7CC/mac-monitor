//
//  CommandLineToolLink.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Command line tool link
/// `/usr/local/bin/macmonitor` (app context): what's there, whether this copy of Mac Monitor can link its command line
/// tool there, and the plan Settings ▸ Command Line sends to the Security Extension.
///
/// It only looks, with `lstat`, `readlink`, `realpath` and a static code signature check. The Security Extension
/// makes the change as root with ``CommandLineToolLinker``, which checks everything again first.
///
/// **Mac Monitor's link:** a symbolic link whose value is an absolute path ending in `.app/Contents/MacOS/macmonitor`
/// (``isMacMonitorLink(_:)``). Anything else there, a file, a directory or another program's link,
/// is never touched.
///
/// **What can be linked:** this copy's own tool, by its real path, when the tool and every directory from it up to `/`
/// can be changed only by root (and, for a directory such as `/Applications`, admins), and its code signature
/// satisfies ``SensorXPC/commandLineRequirement``. `sudo macmonitor` runs the tool as root, so a tool anyone else can
/// replace is never linked.
public struct CommandLineToolLink {
    /// The tool's name, in the bundle and in the link's directory.
    public static let toolName = "macmonitor"
    /// Where the tool is in an app bundle.
    public static let toolInBundle = "/Contents/MacOS/\(toolName)"
    /// How every path Mac Monitor links to ends.
    public static let toolSuffix = ".app" + toolInBundle
    
    /// Where things are. The tests point it into a temporary directory.
    public struct Layout: Equatable {
        /// Mac Monitor's bundle.
        public var bundle: URL
        /// The directory the link goes in.
        public var binDirectory: String
        /// Where the ownership checks stop: `/`, or a test's temporary directory.
        public var root: String
        /// Who must own the tool and the directories above it: root, or the user running a test.
        public var trustedOwner: uid_t
        /// The group that may also write a directory or file on the way: admin.
        public var adminGroup: gid_t
        
        /// - Parameters:
        ///   - bundle: Mac Monitor's bundle.
        ///   - binDirectory: The directory the link goes in.
        ///   - root: Where the ownership checks stop.
        ///   - trustedOwner: Who must own the tool and the directories above it.
        ///   - adminGroup: The group that may also write them.
        public init(bundle: URL, binDirectory: String = "/usr/local/bin", root: String = "/", trustedOwner: uid_t = 0,
                    adminGroup: gid_t = 80) {
            self.bundle = bundle
            self.binDirectory = binDirectory
            self.root = root
            self.trustedOwner = trustedOwner
            self.adminGroup = adminGroup
        }
        
        /// The link's path, such as `/usr/local/bin/macmonitor`.
        public var linkPath: String { binDirectory + "/" + CommandLineToolLink.toolName }
    }
    
    /// What's at the link's path.
    public enum LinkState: Equatable {
        /// Nothing, or no directory yet.
        case absent
        /// Mac Monitor's link to this copy's tool.
        case current
        /// Mac Monitor's link to another copy's tool, which is there.
        case elsewhere(String)
        /// Mac Monitor's link to a tool that isn't there any more: Mac Monitor was moved, renamed or deleted.
        case broken(String)
        /// Something Mac Monitor didn't make, such as "a file": never touched.
        case foreign(String)
        /// The link's directory isn't a directory, such as "is a symbolic link": never touched.
        case unusableDirectory(String)
    }
    
    /// What Install…, Update… and Remove… ask for
    public enum Action: String, Equatable {
        /// Link this copy's tool, replacing Mac Monitor's link to another copy.
        case install
        /// Remove Mac Monitor's link.
        case remove
    }
    
    /// One change, based on what Settings showed
    public struct Plan: Equatable {
        /// Install or remove.
        public let action: Action
        /// The tool to link, by its real path, or empty for a removal.
        public let tool: String
        /// The link's directory.
        public let binDirectory: String
        /// What must be at the link's path for the change to go ahead. It's the link's value Settings showed, or empty
        /// for nothing. If something else is there now, nothing changes.
        public let expected: String

        /// - Parameters:
        ///   - action: Install or remove.
        ///   - tool: The tool to link, or empty for a removal.
        ///   - binDirectory: The link's directory.
        ///   - expected: What Settings saw at the link's path, or empty for nothing.
        public init(action: Action, tool: String, binDirectory: String, expected: String) {
            self.action = action
            self.tool = tool
            self.binDirectory = binDirectory
            self.expected = expected
        }

        /// The link's path, such as `/usr/local/bin/macmonitor`.
        public var linkPath: String { binDirectory + "/" + CommandLineToolLink.toolName }
    }
    
    /// The layout looked at.
    public let layout: Layout
    /// Does a tool's code signature satisfy ``SensorXPC/commandLineRequirement``? Injected by the tests.
    let signatureCheck: (String) -> Bool
    
    /// - Parameters:
    ///   - layout: Where things are.
    ///   - signatureCheck: Does a tool's code signature satisfy ``SensorXPC/commandLineRequirement``?
    public init(layout: Layout, signatureCheck: @escaping (String) -> Bool = CommandLineToolLink.isSignedAsTool) {
        self.layout = layout
        self.signatureCheck = signatureCheck
    }
    
    /// The link for the running copy of Mac Monitor: its bundle, `/usr/local/bin`, owned by root.
    ///
    /// - Returns: The link.
    public static func forThisApp() -> CommandLineToolLink {
        CommandLineToolLink(layout: Layout(bundle: Bundle.main.bundleURL))
    }
    
    /// Is a link's value Mac Monitor's? It must be an absolute path ending in ``toolSuffix``.
    ///
    /// - Parameter value: The link's value.
    /// - Returns: `true` if Mac Monitor made it, or would.
    public static func isMacMonitorLink(_ value: String) -> Bool {
        value.hasPrefix("/") && value.hasSuffix(toolSuffix)
    }
    
    /// Look at the link and at this copy's tool.
    ///
    /// - Returns: What's there, and what may be done.
    public func inspect() -> Inspection {
        let candidate = toolCandidate()
        let (link, value) = linkState(comparedWith: candidate)
        return Inspection(link: link, linkValue: value, tool: validate(candidate), linkPath: layout.linkPath,
                          binDirectory: layout.binDirectory, binDirectoryWarning: binDirectoryWarning())
    }
    
    /// What's at the link's path, and the link's value when it's a symbolic link.
    ///
    /// - Parameter tool: This copy's tool, by its real path, if it has one.
    /// - Returns: The state and the value.
    func linkState(comparedWith tool: String?) -> (LinkState, String?) {
        var info = stat()
        guard lstat(layout.binDirectory, &info) == 0 else {
            return errno == ENOENT ? (.absent, nil) : (.unusableDirectory("can't be read"), nil)
        }
        switch info.st_mode & S_IFMT {
        case S_IFDIR: break
        case S_IFLNK: return (.unusableDirectory("is a symbolic link"), nil)
        default: return (.unusableDirectory("isn't a directory"), nil)
        }
        guard lstat(layout.linkPath, &info) == 0 else {
            return errno == ENOENT ? (.absent, nil) : (.foreign("something that can't be read"), nil)
        }
        switch info.st_mode & S_IFMT {
        case S_IFLNK:
            guard let value = try? FileManager.default.destinationOfSymbolicLink(atPath: layout.linkPath) else {
                return (.foreign("a symbolic link that can't be read"), nil)
            }
            guard Self.isMacMonitorLink(value) else { return (.foreign("a symbolic link to \(value)"), value) }
            if value == tool { return (.current, value) }
            return (stat(value, &info) == 0 ? .elsewhere(value) : .broken(value), value)
        case S_IFREG: return (.foreign("a file"), nil)
        case S_IFDIR: return (.foreign("a directory"), nil)
        default: return (.foreign("something other than a symbolic link"), nil)
        }
    }
}


// MARK: - Inspection
extension CommandLineToolLink {
    /// What Settings shows, and what Install…, Update… and Remove… may do.
    public struct Inspection: Equatable {
        /// What's at the link's path.
        public let link: LinkState
        /// The link's value, when it's a symbolic link.
        public let linkValue: String?
        /// This copy's tool, by its real path, or why it can't be linked.
        public let tool: Result<String, Refusal>
        /// The link's path, such as `/usr/local/bin/macmonitor`.
        public let linkPath: String
        /// The link's directory.
        public let binDirectory: String
        /// Who else can change the link's directory, if anyone: they could put another program there for `sudo` to
        /// run. A warning, not a refusal (Homebrew gives `/usr/local/bin` to the user on Intel Macs).
        public let binDirectoryWarning: String?
        
        /// The plan for an action, if it may be done now.
        ///
        /// - Install: when nothing is there, or Mac Monitor's link points at another copy or at nothing, and this
        ///   copy's tool can be linked.
        /// - Remove: when Mac Monitor's link is there, wherever it points.
        ///
        /// - Parameter action: Install or remove.
        /// - Returns: The plan, or `nil` if the action can't, or needn't, be done.
        public func plan(_ action: Action) -> Plan? {
            switch (action, link) {
            case (.install, .absent), (.install, .elsewhere), (.install, .broken):
                guard case .success(let tool) = tool else { return nil }
                return Plan(action: .install, tool: tool, binDirectory: binDirectory, expected: linkValue ?? "")
            case (.remove, .current), (.remove, .elsewhere), (.remove, .broken):
                return Plan(action: .remove, tool: "", binDirectory: binDirectory, expected: linkValue ?? "")
            default:
                return nil
            }
        }
        
        /// What's at the link's path, in a sentence for Settings.
        public var summary: String {
            switch link {
            case .absent:
                return "\(linkPath) isn't installed."
            case .current:
                return "\(linkPath) links to this copy of Mac Monitor."
            case .elsewhere(let value):
                return "\(linkPath) links to another copy of Mac Monitor: \(value)."
            case .broken(let value):
                return "\(linkPath) links to \(value), which isn't there any more. Was Mac Monitor moved or renamed?"
            case .foreign(let what):
                return "\(linkPath) is \(what), which Mac Monitor didn't make, so it leaves it alone."
            case .unusableDirectory(let what):
                return "\(binDirectory) \(what), so Mac Monitor can't link its tool there."
            }
        }
        
        /// What Settings can do about it, in a sentence: what Install…, Update… or Repair… would do, or how to run
        /// the tool without the link.
        public var hint: String? {
            switch link {
            case .absent where plan(.install) != nil:
                return "Install… links it to this copy's tool, so sudo macmonitor works in any terminal."
            case .elsewhere where plan(.install) != nil:
                return "Update… points it at this copy."
            case .broken where plan(.install) != nil:
                return "Repair… points it at this copy."
            case .foreign, .unusableDirectory:
                return "Run the tool by its full path instead."
            default:
                return nil
            }
        }
    }
}
