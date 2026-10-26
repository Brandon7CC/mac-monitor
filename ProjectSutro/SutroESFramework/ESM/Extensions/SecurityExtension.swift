//
//  SecurityExtension.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/7/23.
//

import Foundation
import SystemExtensions
import OSLog


// MARK: - System Extension install / uninstall
/// Extension of the ESM which enables System Extension functionality
///
/// **Functionality Covers:**
///   - Updating the Security Extension
///   - Activating the Security Extension
///   - Deactivating the Security Extension
///   - Reporting how it stands (``extensionState`` and ``requirements``)
///
extension EndpointSecurityManager {
    /// The Security Extension's bundle identifier.
    static let extensionIdentifier = "com.swiftlydetecting.agent.securityextension"

    // MARK: - Agent Context
    /// Look at the Security Extension as Mac Monitor opens, once, and activate it only if it's running: to update it,
    /// or to connect to it (``SetupRequirements/ExtensionState/activatesAtLaunch``). Otherwise the requirements
    /// checklist shows, and its Install button activates it, when macOS's prompt to open System Settings makes sense.
    public func checkExtensionAtLaunch() {
        guard !checkedAtLaunch else { return }
        checkedAtLaunch = true
        decidesActivation = true
        refreshExtensionState()
    }

    /// Activate the Security Extension (Mac Monitor agent context). macOS shows its prompt to open System Settings
    /// while it isn't allowed, so only at the points ``checkExtensionAtLaunch()`` describes, or when the user asks.
    public func activateSystemExtension() {
        os_log("🥁 Installing the Mac Monitor Endpoint Security System Extension")
        let activationRequest = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier, queue: .main)
        activationRequest.delegate = self
        OSSystemExtensionManager.shared.submitRequest(activationRequest)
    }

    /// Deactivate the Security Extension (Mac Monitor agent context)
    public func uninstallSystemExtension() {
        os_log("🛑 Requesting Security Extension deactivation")
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier, queue: .main)
        request.delegate = self
        deactivationRequest = request
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Ask macOS how the Security Extension stands, changing nothing. The answer comes to
    /// ``request(_:foundProperties:)``.
    public func refreshExtensionState() {
        let request = OSSystemExtensionRequest.propertiesRequest(forExtensionWithIdentifier: Self.extensionIdentifier,
                                                                 queue: .main)
        request.delegate = self
        propertiesRequest = request
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Look again at every requirement: macOS's view of the Security Extension and, once Mac Monitor has handshaked,
    /// whether Endpoint Security now accepts it (Full Disk Access granted since, say). Call when Mac Monitor comes to
    /// the front, and from Check Again.
    public func refreshRequirements() {
        refreshExtensionState()
        guard ![.waiting, .success, .streamOwned].contains(connectionResult) else { return }
        kickoffXPCCommunication()
    }

    /// What Mac Monitor needs before it can talk to Endpoint Security, as it stands now.
    public var requirements: SetupRequirements {
        SetupRequirements(location: .of(Bundle.main.bundlePath), extensionState: extensionState,
                          client: connectionResult, sipDisabled: Self.isSIPDisabled,
                          hasExtensionsPane: ProcessInfo.processInfo.isOperatingSystemAtLeast(
                            OperatingSystemVersion(majorVersion: 15, minorVersion: 0, patchVersion: 0)))
    }

    /// Is System Integrity Protection's file system protection off? Then Endpoint Security doesn't ask for Full Disk
    /// Access.
    public static var isSIPDisabled: Bool {
        csr_check(csr_config_t(CSR_ALLOW_UNRESTRICTED_FS)) == 0
    }


    // MARK: - Sensor Context
    /// Replace the running Security Extension only with a different version or build of it.
    ///
    /// Every launch of Mac Monitor asks to activate the extension. Replacing an identical extension restarts it, which
    /// ends the event stream of any other Mac Monitor that's recording. The request is cancelled instead, and
    /// ``request(_:didFailWithError:)`` treats that cancellation as "already installed".
    ///
    /// - Parameters:
    ///   - request: The activation request.
    ///   - existing: The extension that's installed and running.
    ///   - ext: The extension in this copy of Mac Monitor.
    /// - Returns: `.replace` for another version or build, otherwise `.cancel`.
    public func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        let sameBuild = existing.bundleVersion == ext.bundleVersion
            && existing.bundleShortVersion == ext.bundleShortVersion
        guard !sameBuild else {
            os_log("✅ The Mac Monitor Security Extension %{public}@ (%{public}@) is already running",
                   ext.bundleShortVersion, ext.bundleVersion)
            return .cancel
        }
        os_log("🔄 Updating the Mac Monitor Security Extension from %{public}@ (%{public}@) to %{public}@ (%{public}@)",
               existing.bundleShortVersion, existing.bundleVersion, ext.bundleShortVersion, ext.bundleVersion)
        return .replace
    }

    /// A request finished: an activation, a deactivation, or a properties request.
    public func request(_ request: OSSystemExtensionRequest,
                        didFinishWithResult result: OSSystemExtensionRequest.Result) {
        if request === propertiesRequest { return }
        if request === deactivationRequest {
            os_log("Security Extension deactivated!")
            deactivationRequest = nil
            extensionState = .notInstalled
            return
        }
        if result == .completed {
            os_log("🥳 Mac Monitor Security Extension has been successfully installed!")
            extensionState = .running(version: nil)
            refreshExtensionState()
        } else {
            extensionState = .needsRestart
        }
        kickoffXPCCommunication()
    }

    /// A request failed. For an activation, macOS says why: most often that Mac Monitor isn't in `/Applications`.
    public func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        if request === propertiesRequest {
            /// macOS couldn't say how it stands: activate, as Mac Monitor always did.
            if decidesActivation {
                decidesActivation = false
                activateSystemExtension()
            }
            return
        }
        if request === deactivationRequest {
            os_log(OSLogType.error, "Security Extension deactivation failed: %{public}@", error.localizedDescription)
            deactivationRequest = nil
            refreshExtensionState()
            return
        }
        let code = (error as? OSSystemExtensionError)?.code
        /// The same extension is already running: the replacement was cancelled on purpose.
        if code == .requestCanceled {
            refreshExtensionState()
            kickoffXPCCommunication()
            return
        }
        os_log(OSLogType.error, "☠️ The Security Extension couldn't be activated: %{public}@",
               error.localizedDescription)
        extensionState = code == .unsupportedParentBundleLocation ? .wrongLocation
            : .failed(Self.reason(for: code) ?? error.localizedDescription)
    }

    /// Waiting for the user to allow the extension in System Settings.
    public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        os_log(OSLogType.error, "⏳ System Extension needs user approval in System Settings.")
        extensionState = .awaitingApproval
    }

    /// macOS's view of the Security Extension, from ``refreshExtensionState()``. As Mac Monitor opens, it decides
    /// whether to activate. Later, an extension the user just allowed or turned back on is connected to.
    public func request(_ request: OSSystemExtensionRequest,
                        foundProperties properties: [OSSystemExtensionProperties]) {
        let reports = properties.map { SetupRequirements.ExtensionReport(
            isEnabled: $0.isEnabled, isAwaitingApproval: $0.isAwaitingUserApproval, isUninstalling: $0.isUninstalling,
            version: "\($0.bundleShortVersion) (\($0.bundleVersion))") }
        let wasRunning = extensionState.activatesAtLaunch
        extensionState = .reported(reports, current: extensionState)
        if decidesActivation {
            decidesActivation = false
            if extensionState.activatesAtLaunch { activateSystemExtension() }
        } else if extensionState.activatesAtLaunch, !wasRunning, connectionResult == .waiting {
            kickoffXPCCommunication()
        }
    }

    /// Why macOS refused an activation, in a sentence, for the errors a user can act on.
    ///
    /// - Parameter code: The error's code.
    /// - Returns: The sentence, or `nil` to use the error's own description.
    static func reason(for code: OSSystemExtensionError.Code?) -> String? {
        switch code {
        case .codeSignatureInvalid: return "Its code signature isn't valid."
        case .forbiddenBySystemPolicy: return "A configuration profile or system policy forbids it."
        case .authorizationRequired: return "It needs an administrator to approve it."
        case .validationFailed: return "macOS couldn't validate it."
        case .extensionNotFound: return "This copy of Mac Monitor doesn't contain it."
        case .missingEntitlement: return "Mac Monitor lacks the entitlement to install it."
        default: return nil
        }
    }
}
