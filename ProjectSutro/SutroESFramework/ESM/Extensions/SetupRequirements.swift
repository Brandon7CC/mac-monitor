//
//  SetupRequirements.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/22/26.
//

import Foundation


// MARK: - Requirements
/// What Mac Monitor needs before it can talk to Endpoint Security, and how each stands: where Mac Monitor runs from,
/// the Security Extension, and Full Disk Access (agent context).
///
/// It's made from what the app knows (``EndpointSecurityManager/requirements``) and decides nothing on its own: the
/// requirements checklist, the toolbar and Settings ▸ Security Extension all show the same rows.
public struct SetupRequirements: Equatable {
    /// Where Mac Monitor is running from.
    public enum Location: Equatable {
        /// `/Applications`.
        case applications
        /// The read-only copy macOS makes of an app opened where it was downloaded.
        case translocated
        /// Anywhere else, by path. Fine with system extension developer mode.
        case elsewhere(String)

        /// Where an app bundle is running from.
        ///
        /// - Parameter path: The bundle's path.
        /// - Returns: The location.
        public static func of(_ path: String) -> Location {
            if path.contains("/AppTranslocation/") { return .translocated }
            return path.hasPrefix("/Applications/") ? .applications : .elsewhere(path)
        }
    }

    /// The Security Extension, as macOS and the activation request report it.
    public enum ExtensionState: Equatable {
        /// Not known yet.
        case checking
        /// Not installed, or uninstalled.
        case notInstalled
        /// Waiting for the user to allow it in System Settings.
        case awaitingApproval
        /// Installed but turned off in System Settings.
        case disabled
        /// Updated, and macOS finishes when the Mac restarts.
        case needsRestart
        /// Activated, with its version, such as "3.0.0 (1)".
        case running(version: String?)
        /// macOS refused it because Mac Monitor isn't in `/Applications`.
        case wrongLocation
        /// Activation failed, with macOS's reason.
        case failed(String)

        /// The state macOS's report of its installed copies says, from a properties request.
        ///
        /// What the last activation request said wins over the report: a restart it asked for, a location or failure
        /// it refused for. Otherwise an enabled copy is running, else one awaits approval, else one is turned off.
        ///
        /// - Parameters:
        ///   - reports: Each installed copy, including old ones waiting to be removed.
        ///   - current: The state so far.
        /// - Returns: The state.
        public static func reported(_ reports: [ExtensionReport], current: ExtensionState) -> ExtensionState {
            switch current {
            case .needsRestart, .wrongLocation, .failed: return current
            default: break
            }
            let installed = reports.filter { !$0.isUninstalling }
            if let enabled = installed.first(where: \.isEnabled) { return .running(version: enabled.version) }
            if installed.contains(where: \.isAwaitingApproval) { return .awaitingApproval }
            return installed.isEmpty ? .notInstalled : .disabled
        }

        /// Should Mac Monitor ask macOS to activate the Security Extension as it opens, in this state? Only when it's
        /// running, to update it or connect to it. Activating one that isn't installed or allowed yet makes macOS show
        /// its prompt to open System Settings, so that waits for the user to click Install in the checklist.
        public var activatesAtLaunch: Bool {
            if case .running = self { return true }
            return false
        }
    }

    /// One installed copy of the Security Extension, as a properties request reports it.
    public struct ExtensionReport: Equatable {
        /// Activated and turned on.
        public let isEnabled: Bool
        /// Waiting for the user in System Settings.
        public let isAwaitingApproval: Bool
        /// Being removed, at the next restart.
        public let isUninstalling: Bool
        /// Its version and build, such as "3.0.0 (1)".
        public let version: String
    }

    /// One requirement.
    public enum Kind: String, CaseIterable {
        case location, securityExtension, fullDiskAccess
    }

    /// How a requirement stands.
    public enum Status: Equatable {
        /// Done: a check.
        case done
        /// It needs the user: a cross.
        case needed
        /// It needs a restart.
        case restart
        /// It can't be checked until an earlier one is done.
        case pending
    }

    /// What a requirement's button does.
    public enum Action: Equatable {
        /// Show Mac Monitor in the Finder, to move it.
        case showInFinder
        /// Ask macOS to install the Security Extension, which then asks the user to allow it.
        case installExtension
        /// Open the System Settings pane where the Security Extension is allowed.
        case openExtensions
        /// Open System Settings ▸ Privacy & Security ▸ Full Disk Access.
        case openFullDiskAccess
    }

    /// One requirement, as the checklist shows it.
    public struct Row: Equatable, Identifiable {
        public let kind: Kind
        public let status: Status
        public let title: String
        public let detail: String
        /// The button, if the user can do something about it from here.
        public let action: Action?

        public var id: Kind { kind }
    }

    /// Where Mac Monitor is running from.
    public let location: Location
    /// The Security Extension.
    public let extensionState: ExtensionState
    /// What the Security Extension's Endpoint Security client said, `.waiting` until it says.
    public let client: NewClientResult
    /// Is System Integrity Protection off? Then Endpoint Security doesn't ask for Full Disk Access.
    public let sipDisabled: Bool
    /// Does System Settings have General ▸ Login Items & Extensions (macOS 15 and later)?
    public let hasExtensionsPane: Bool

    /// Every requirement, in the order they're done.
    public var rows: [Row] {
        [locationRow, extensionRow, fullDiskAccessRow]
    }

    /// Is everything done?
    public var isReady: Bool {
        rows.allSatisfy { $0.status == .done }
    }

    /// The first requirement that isn't done.
    public var nextStep: Row? {
        rows.first { $0.status != .done }
    }

    /// Is enough known to say what's missing? Not while the Security Extension is being checked, or while it runs
    /// and its Endpoint Security client hasn't answered.
    public var isSettled: Bool {
        switch extensionState {
        case .checking: return false
        case .running: return client != .waiting
        default: return true
        }
    }

    /// Is the Security Extension running? Its Endpoint Security client answering says so too.
    var extensionRuns: Bool {
        if case .running = extensionState { return true }
        return ![.waiting, .internalSubsystem].contains(client)
    }
}


// MARK: - Rows
extension SetupRequirements {
    /// Where to allow the Security Extension, in a sentence.
    private var approval: String {
        hasExtensionsPane
            ? "Turn on Mac Monitor in System Settings ▸ General ▸ Login Items & Extensions ▸ Endpoint Security "
                + "Extensions."
            : "Open System Settings ▸ Privacy & Security and click Allow under the message about Mac Monitor."
    }

    private var locationRow: Row {
        switch location {
        case .applications:
            return Row(kind: .location, status: .done, title: "Mac Monitor is in Applications",
                       detail: "/Applications/Mac Monitor.app", action: nil)
        case .translocated:
            return Row(kind: .location, status: .needed, title: "Move Mac Monitor to Applications",
                       detail: "macOS is running a temporary copy because Mac Monitor was opened where it was "
                        + "downloaded, and won't run its Security Extension from there. Move it to Applications, then "
                        + "open it from there.", action: nil)
        case .elsewhere(let path) where extensionState == .wrongLocation:
            return Row(kind: .location, status: .needed, title: "Move Mac Monitor to Applications",
                       detail: "macOS won't run its Security Extension from \(path). Move it to Applications, then "
                        + "open it from there.", action: .showInFinder)
        case .elsewhere(let path):
            return Row(kind: .location, status: .done, title: "Mac Monitor's location", detail: path, action: nil)
        }
    }

    private var extensionRow: Row {
        if location == .translocated || extensionState == .wrongLocation {
            return Row(kind: .securityExtension, status: .pending, title: "Security Extension",
                       detail: "Checked once Mac Monitor is in Applications.", action: nil)
        }
        if extensionRuns {
            let version = { if case .running(let version?) = extensionState { return "Version \(version)" }
                            return "Running" }()
            return Row(kind: .securityExtension, status: .done, title: "Security Extension is running",
                       detail: version, action: nil)
        }
        switch extensionState {
        case .checking:
            return Row(kind: .securityExtension, status: .pending, title: "Security Extension",
                       detail: "Checking…", action: nil)
        case .disabled:
            return Row(kind: .securityExtension, status: .needed, title: "Turn the Security Extension back on",
                       detail: "It was turned off in System Settings, so Mac Monitor can't see any events. "
                        + approval, action: .openExtensions)
        case .needsRestart:
            return Row(kind: .securityExtension, status: .restart,
                       title: "Restart to finish updating the Security Extension",
                       detail: "macOS replaces the old Security Extension when your Mac restarts. Until then, the "
                        + "old one keeps running.", action: nil)
        case .failed(let reason):
            return Row(kind: .securityExtension, status: .needed, title: "The Security Extension couldn't be installed",
                       detail: "macOS said: \(reason) Try Reinstall in Settings ▸ Security Extension.", action: nil)
        case .notInstalled:
            return Row(kind: .securityExtension, status: .needed, title: "Install the Security Extension",
                       detail: "Mac Monitor communicates with Endpoint Security via a System Extension.",
                       action: .installExtension)
        case .awaitingApproval, .running, .wrongLocation:
            return Row(kind: .securityExtension, status: .needed, title: "Allow the Security Extension",
                       detail: approval, action: .openExtensions)
        }
    }

    private var fullDiskAccessRow: Row {
        guard extensionRuns else {
            return Row(kind: .fullDiskAccess, status: .pending, title: "Full Disk Access",
                       detail: "Checked once the Security Extension is running.", action: nil)
        }
        switch client {
        case .waiting:
            return Row(kind: .fullDiskAccess, status: .pending, title: "Full Disk Access", detail: "Checking…",
                       action: nil)
        case .success where sipDisabled, .streamOwned where sipDisabled:
            return Row(kind: .fullDiskAccess, status: .done, title: "Full Disk Access isn't needed",
                       detail: "System Integrity Protection is off, so Endpoint Security doesn't ask for it. Allow "
                        + "it before you turn SIP back on.", action: .openFullDiskAccess)
        case .success, .streamOwned:
            return Row(kind: .fullDiskAccess, status: .done, title: "Full Disk Access is allowed",
                       detail: "Endpoint Security can see every process and file.", action: nil)
        case .notPermitted:
            return Row(kind: .fullDiskAccess, status: .needed, title: "Allow Full Disk Access",
                       detail: "Endpoint Security requires it. Turn on Mac Monitor Security Extension in System "
                        + "Settings ▸ Privacy & Security ▸ Full Disk Access.", action: .openFullDiskAccess)
        case .tooManyClients:
            return Row(kind: .fullDiskAccess, status: .needed, title: "Endpoint Security has too many clients",
                       detail: "Other security tools are using every client macOS allows. Quit one, or end a "
                        + "macmonitor stream, then check again.", action: nil)
        case .notEntitled, .notPrivileged, .invalidArgument, .internalSubsystem:
            return Row(kind: .fullDiskAccess, status: .needed, title: "Endpoint Security refused Mac Monitor",
                       detail: "Try Reinstall in Settings ▸ Security Extension. If it keeps happening, Mac "
                        + "Monitor's log in Console says more.", action: nil)
        }
    }
}
