//
//  RCXPC.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/11/22.
//
//  Refactored: Eliminated duplicated connection boilerplate by extracting
//  `ensureSensorProxy()` and `withSensorProxy()` helpers. Changed event
//  transport from JSON String to binary Data for performance.
//

import Foundation
import OSLog
import SutroESFramework
import AppKit

// MARK: - EventProtocol
/// XPC protocol enabling the Security Extension (sensor) to send events to Mac Monitor.
@objc public protocol EventProtocol {
    /// Send a binary-encoded event to Mac Monitor.
    ///
    /// The payload is a `PropertyList`-encoded `Message` struct — the shared model
    /// used by both the extension and the app. No more JSON round-tripping.
    func surfaceEvent(eventData data: Data)
}


// MARK: - SensorProtocol
/// XPC protocol enabling the agent to communicate with the Security Extension.
@objc public protocol SensorProtocol {
    func start(_ completionHandler: @escaping (NewClientResult) -> Void)
    func rebootAgentWithTimeDelay()

    // Path muting
    func getMutedPaths(withData response: @escaping (Set<String>) -> Void)
    func mutePath(pathToMute: String, muteCase: es_mute_path_type_t, pathEvents: [String])
    func unmutePath(pathToUnmute: String, type: String, events: [String])
    func resetMutedPathsXPC()
    func getAppleMuteSet(withData response: @escaping (Set<String>) -> Void)

    // Event subscriptions
    func getEventSubscriptions(withData response: @escaping (Set<String>) -> Void)
    func subscribeToEvent(eventToSubscribeTo: String)
    func unsubscribeFromEvent(eventToUnsubscribeFrom: String)

    // Miscellaneous
    func openFinder(filePath: String)

    // Updates
    func xpcCheckForUpdates(with reply: @escaping (Data?) -> Void)
    func xpcInstallUpdate(from pkgURL: URL) async throws
}


// MARK: - RCXPCConnection

/// Manages the XPC connection between the Mac Monitor app and the Security Extension.
///
/// This class serves two roles depending on context:
/// - **Security Extension context**: Acts as the XPC listener, accepts connections,
///   and implements `SensorProtocol`.
/// - **Agent (app) context**: Connects to the extension and calls `SensorProtocol` methods.
///
/// The previous implementation duplicated connection-setup boilerplate ~10 times.
/// This refactored version extracts that into `ensureSensorProxy()`.
public class RCXPCConnection: NSObject, EventProtocol {
    public static let rcXPCConnection = RCXPCConnection()

    private let logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "RCXPCConnection")

    /// XPC listener (Security Extension context only)
    var listener: NSXPCListener?

    /// Current XPC connection (both contexts)
    var currentNSXPCConnection: NSXPCConnection?

    /// Event delegate for forwarding events to the app
    weak var epDelegate: EventProtocol?

    /// The connected ES client (Security Extension context only)
    var connectedESClient: OpaquePointer?
    var esManager: EndpointSecurityManager?

    /// Binary encoder for event transport (replaces JSON serialization)
    private let encoder: PropertyListEncoder = {
        let e = PropertyListEncoder()
        e.outputFormat = .binary
        return e
    }()

    // MARK: - Service Name Resolution

    private static let extensionRelativePath = "Contents/Library/SystemExtensions/com.swiftlydetecting.agent.securityextension.systemextension"

    private func getServiceName(from bundle: Bundle) -> String {
        guard let name = bundle.object(forInfoDictionaryKey: "NSEndpointSecurityMachServiceName") as? String else {
            logger.error("NSEndpointSecurityMachServiceName missing from Info.plist!")
            return ""
        }
        return name
    }

    private func extensionBundle() -> Bundle? {
        let url = URL(
            fileURLWithPath: Self.extensionRelativePath,
            relativeTo: Bundle.main.bundleURL
        )
        return Bundle(url: url)
    }

    // MARK: - Connection Management (Agent Context)

    /// Ensures an active XPC connection to the Security Extension and returns a `SensorProtocol` proxy.
    ///
    /// This is the **single** place where agent-side connection setup happens.
    /// All agent-to-extension calls go through this method.
    ///
    /// - Parameter epDelegate: The `EventProtocol` implementor (typically `EndpointSecurityManager`).
    /// - Returns: A `SensorProtocol` proxy, or `nil` if connection setup failed.
    private func ensureSensorProxy(epDelegate: EventProtocol? = nil) -> SensorProtocol? {
        if let ep = epDelegate {
            self.epDelegate = ep
        }

        // Create connection if needed
        if currentNSXPCConnection == nil {
            guard let extBundle = extensionBundle() else {
                logger.error("Failed to locate system extension bundle.")
                return nil
            }
            let serviceName = getServiceName(from: extBundle)
            guard !serviceName.isEmpty else { return nil }

            let conn = NSXPCConnection(machServiceName: serviceName, options: [])
            conn.exportedInterface = NSXPCInterface(with: EventProtocol.self)
            conn.exportedObject = self.epDelegate
            conn.remoteObjectInterface = NSXPCInterface(with: SensorProtocol.self)
            currentNSXPCConnection = conn
            conn.resume()
        }

        guard let conn = currentNSXPCConnection else { return nil }

        return conn.remoteObjectProxyWithErrorHandler { [weak self] error in
            self?.logger.error("XPC proxy error: \(error.localizedDescription)")
            self?.currentNSXPCConnection?.invalidate()
            self?.currentNSXPCConnection = nil
        } as? SensorProtocol
    }

    /// Convenience: get a proxy and execute work, handling nil gracefully.
    private func withSensorProxy(epDelegate: EventProtocol? = nil, _ work: (SensorProtocol) -> Void) {
        guard let proxy = ensureSensorProxy(epDelegate: epDelegate) else {
            logger.error("Could not obtain SensorProtocol proxy.")
            return
        }
        work(proxy)
    }

    // MARK: - XPC Listener (Security Extension Context)

    public func startXPCListener(esManager: EndpointSecurityManager) {
        let serviceName = getServiceName(from: Bundle.main)
        let xpcListener = NSXPCListener(machServiceName: serviceName)
        xpcListener.delegate = self
        xpcListener.resume()

        self.listener = xpcListener
        self.esManager = esManager
    }

    // MARK: - Event Transport (Security Extension → Agent)

    /// Send a binary-encoded event to the agent.
    ///
    /// Called from the Security Extension side. The data is a `PropertyList`-encoded `Message`.
    @objc public func surfaceEvent(eventData data: Data) {
        guard let conn = currentNSXPCConnection else { return }

        guard let proxy = conn.remoteObjectProxyWithErrorHandler({ [weak self] error in
            self?.logger.error("Could not send event to agent: \(error.localizedDescription)")
            self?.currentNSXPCConnection = nil
        }) as? EventProtocol else {
            logger.error("Failed to create EventProtocol proxy!")
            return
        }

        proxy.surfaceEvent(eventData: data)
    }

    /// Convenience: encode a `Message` and send it.
    func sendEventData(message: Message) {
        guard let data = try? encoder.encode(message) else {
            logger.error("Failed to encode Message for XPC transport.")
            return
        }
        surfaceEvent(eventData: data)
    }

    // MARK: - Agent Registration

    func register(withExtension bundle: Bundle, epDelegate: EventProtocol, completionHandler: @escaping (NewClientResult) -> Void) {
        self.epDelegate = epDelegate

        let serviceName = getServiceName(from: bundle)
        let conn = NSXPCConnection(machServiceName: serviceName, options: [])
        conn.exportedInterface = NSXPCInterface(with: EventProtocol.self)
        conn.exportedObject = epDelegate
        conn.remoteObjectInterface = NSXPCInterface(with: SensorProtocol.self)
        currentNSXPCConnection = conn
        conn.resume()

        guard let proxy = conn.remoteObjectProxyWithErrorHandler({ [weak self] error in
            self?.logger.error("Failed to register with provider: \(error.localizedDescription)")
            self?.currentNSXPCConnection?.invalidate()
            self?.currentNSXPCConnection = nil
            completionHandler(.internalSubsystem)
        }) as? SensorProtocol else {
            logger.error("Failed to create remote object proxy!")
            return
        }

        proxy.start(completionHandler)
    }

    func killClinet() {
        if connectedESClient != nil {
            esManager?.cleanup()
        }
    }

    // MARK: - Agent-to-Extension Calls (Simplified)

    // All of these used to duplicate 20+ lines of connection boilerplate.
    // Now they're one-liners via `withSensorProxy`.

    public func openFinderWidowSE(filePath: String) {
        withSensorProxy { $0.openFinder(filePath: filePath) }
    }

    @objc public func getEventSubscriptions(epDelegate: EventProtocol, withData response: @escaping (Set<String>) -> Void) {
        withSensorProxy(epDelegate: epDelegate) { $0.getEventSubscriptions(withData: response) }
    }

    func unsubscribeFromEvent(eventToUnsubscribeFrom: String, epDelegate: EventProtocol) {
        withSensorProxy(epDelegate: epDelegate) { $0.unsubscribeFromEvent(eventToUnsubscribeFrom: eventToUnsubscribeFrom) }
    }

    func subscribeToEvent(eventToSubscribeTo: String, epDelegate: EventProtocol) {
        withSensorProxy(epDelegate: epDelegate) { $0.subscribeToEvent(eventToSubscribeTo: eventToSubscribeTo) }
    }

    func getMutedPaths(epDelegate: EventProtocol, withData response: @escaping (Set<String>) -> Void) {
        withSensorProxy(epDelegate: epDelegate) { $0.getMutedPaths(withData: response) }
    }

    func getAppleMuteSet(epDelegate: EventProtocol, withData response: @escaping (Set<String>) -> Void) {
        withSensorProxy(epDelegate: epDelegate) { $0.getAppleMuteSet(withData: response) }
    }

    func mutePath(pathToMute: String, muteCase: es_mute_path_type_t, pathEvents: [String], epDelegate: EventProtocol) {
        withSensorProxy(epDelegate: epDelegate) { $0.mutePath(pathToMute: pathToMute, muteCase: muteCase, pathEvents: pathEvents) }
    }

    public func resetMutePaths(epDelegate: EventProtocol) {
        withSensorProxy(epDelegate: epDelegate) { $0.resetMutedPathsXPC() }
    }

    public func unmutePaths(pathToUnmute: String, type: String, events: [String], epDelegate: EventProtocol) {
        withSensorProxy(epDelegate: epDelegate) { $0.unmutePath(pathToUnmute: pathToUnmute, type: type, events: events) }
    }

    public func xpcReboot() {
        withSensorProxy { $0.rebootAgentWithTimeDelay() }
    }

    // MARK: - Update Support (Agent Context)

    func checkForUpdates(epDelegate: EventProtocol, completion: @escaping (UpdateDetails?) -> Void) {
        guard let proxy = ensureSensorProxy(epDelegate: epDelegate) else {
            completion(nil)
            return
        }

        proxy.xpcCheckForUpdates { data in
            guard let data = data else {
                completion(nil)
                return
            }
            do {
                let details = try JSONDecoder().decode(UpdateDetails.self, from: data)
                completion(details)
            } catch {
                self.logger.error("Failed to decode UpdateDetails: \(error)")
                completion(nil)
            }
        }
    }

    func installUpdate(from pkgURL: URL, epDelegate: EventProtocol, completion: @escaping (Bool) -> Void) {
        guard let proxy = ensureSensorProxy(epDelegate: epDelegate) else {
            completion(false)
            return
        }

        Task {
            do {
                try await proxy.xpcInstallUpdate(from: pkgURL)
                completion(true)
            } catch {
                self.logger.error("Update failed: \(error.localizedDescription)")
                completion(false)
            }
        }
    }
}


// MARK: - XPC Listener Delegate

extension RCXPCConnection: NSXPCListenerDelegate {
    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        let requirementString = "anchor apple generic and identifier \"com.swiftlydetecting.agent\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"4HMJQ7V3SX\""
        newConnection.setCodeSigningRequirement(requirementString)
        logger.log("Validating XPC connection with CS requirements.")

        newConnection.exportedInterface = NSXPCInterface(with: SensorProtocol.self)
        newConnection.exportedObject = self
        newConnection.remoteObjectInterface = NSXPCInterface(with: EventProtocol.self)

        newConnection.invalidationHandler = { [weak self] in
            self?.logger.error("XPC connection invalidated.")
            self?.currentNSXPCConnection = nil
            self?.killClinet()
        }

        newConnection.interruptionHandler = { [weak self] in
            self?.logger.error("XPC connection interrupted.")
            self?.currentNSXPCConnection = nil
        }

        currentNSXPCConnection = newConnection
        newConnection.resume()
        return true
    }
}


// MARK: - SensorProtocol Implementation (Security Extension Context)

extension RCXPCConnection: SensorProtocol {

    // MARK: Event subscriptions
    public func getEventSubscriptions(withData response: @escaping (Set<String>) -> Void) {
        guard let client = esManager else {
            logger.error("No ES client for fetching event subscriptions.")
            return
        }
        response(client.seGetEventSubscriptionsAsString())
    }

    public func unsubscribeFromEvent(eventToUnsubscribeFrom: String) {
        guard let client = esManager else {
            logger.error("No ES client for unsubscribe.")
            return
        }
        client.unsubscribeFromEvent(eventToUnsubscribeFrom: eventToUnsubscribeFrom)
    }

    public func subscribeToEvent(eventToSubscribeTo: String) {
        guard let client = esManager else {
            logger.error("No ES client for subscribe.")
            return
        }
        client.subscribeToEvent(eventToSubscribeTo: eventToSubscribeTo)
    }

    // MARK: Finder
    public func openFinder(filePath: String) {
        let url = URL(filePath: filePath)
        guard let finder = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.open") else { return }
        NSWorkspace.shared.open([url], withApplicationAt: finder, configuration: NSWorkspace.OpenConfiguration())
    }

    // MARK: Path muting
    public func resetMutedPathsXPC() {
        guard let client = esManager, let esClient = client.esClient else {
            logger.error("No ES client for mute reset.")
            return
        }
        MutingEngine.applyDefaultMuteSet(client: esClient)
    }

    public func getAppleMuteSet(withData response: @escaping (Set<String>) -> Void) {
        guard let client = esManager else {
            logger.error("No ES client for Apple mute set.")
            return
        }
        response(client.seGetAppleMuteSet())
    }

    public func mutePath(pathToMute: String, muteCase: es_mute_path_type_t, pathEvents: [String]) {
        guard let client = esManager else {
            logger.error("No ES client for mute request.")
            return
        }
        client.mutePath(pathToMute: pathToMute, muteCase: muteCase, pathEvents: pathEvents)
    }

    public func getMutedPaths(withData response: @escaping (Set<String>) -> Void) {
        guard let client = esManager else {
            logger.error("No ES client for muted paths.")
            return
        }
        response(client.seGetGlobalMutedPaths())
    }

    public func unmutePath(pathToUnmute: String, type: String, events: [String]) {
        guard let client = esManager else {
            logger.error("No ES client for unmute.")
            return
        }
        client.unmutePath(pathToUnmute: pathToUnmute, type: type, events: events)
    }

    // MARK: Event sending (SE → Agent)
    func sendEvent(eventData: Data) {
        RCXPCConnection.rcXPCConnection.surfaceEvent(eventData: eventData)
    }

    // MARK: Client start
    public func start(_ completionHandler: @escaping (NewClientResult) -> Void) {
        logger.info("Mac Monitor Agent connected.")

        guard let manager = esManager else {
            completionHandler(.waiting)
            return
        }

        let (client, result) = manager.kickstartClient(completion: sendEvent)
        connectedESClient = client

        if client == nil {
            completionHandler(result)
            return
        }

        completionHandler(result)
    }

    // MARK: Agent reboot
    public func rebootAgentWithTimeDelay() {
        EndpointSecurityManager.seRequestAgentReboot()
    }

    // MARK: - Update checking (executed in Security Extension)

    /// GitHub release decoder
    fileprivate struct GitHubRelease: Decodable {
        let tagName: String
        let updatePkgURL: URL
        let body: String
        let publishedAt: String

        private struct Asset: Decodable {
            let browserDownloadURL: URL
            enum CodingKeys: String, CodingKey {
                case browserDownloadURL = "browser_download_url"
            }
        }

        enum CodingKeys: String, CodingKey {
            case tagName = "tag_name"
            case assets, body
            case publishedAt = "published_at"
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            tagName = try container.decode(String.self, forKey: .tagName)
            body = try container.decode(String.self, forKey: .body)
            publishedAt = try container.decode(String.self, forKey: .publishedAt)
            var assetsContainer = try container.nestedUnkeyedContainer(forKey: .assets)
            guard let firstAsset = try assetsContainer.decodeIfPresent(Asset.self) else {
                throw DecodingError.dataCorruptedError(in: assetsContainer, debugDescription: "Empty assets array.")
            }
            updatePkgURL = firstAsset.browserDownloadURL
        }
    }

    public func xpcCheckForUpdates(with reply: @escaping (Data?) -> Void) {
        logger.log("System Extension received request to check for updates.")

        let updateURLString = "https://api.github.com/repos/Brandon7CC/mac-monitor/releases/latest"
        guard let updateURL = URL(string: updateURLString) else {
            reply(nil)
            return
        }

        URLSession.shared.dataTask(with: updateURL) { data, _, error in
            guard let data = data, error == nil else {
                os_log("(Mac Monitor Update) Update check failed: \(error?.localizedDescription ?? "No data")")
                reply(nil)
                return
            }
            do {
                let release = try JSONDecoder().decode(GitHubRelease.self, from: data)
                guard let currentVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String else {
                    reply(nil)
                    return
                }

                let latestVersion = release.tagName
                if latestVersion.trimmingPrefix("v").compare(currentVersion, options: .numeric) == .orderedDescending {
                    let details = UpdateDetails(
                        version: release.tagName,
                        downloadURL: release.updatePkgURL,
                        releaseNotes: release.body,
                        releaseDate: release.publishedAt
                    )
                    reply(try? JSONEncoder().encode(details))
                } else {
                    reply(nil)
                }
            } catch {
                os_log("(Mac Monitor Update) Failed to decode: \(error.localizedDescription)")
                reply(nil)
            }
        }.resume()
    }

    // MARK: - Update installation

    enum UpdateError: Error, LocalizedError {
        case downloadFailed
        case signatureCheckFailed
        case installFailed(exitCode: Int32, errorLog: String)

        var errorDescription: String? {
            switch self {
            case .downloadFailed: return "Update package download failed."
            case .signatureCheckFailed: return "Package signature check failed."
            case .installFailed(let code, let log): return "Install failed (exit \(code)): \(log)"
            }
        }
    }

    public func xpcInstallUpdate(from pkgURL: URL) async throws {
        os_log("1. Downloading update from %{public}s", pkgURL.absoluteString)
        let (tmpURL, response) = try await URLSession.shared.download(from: pkgURL)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw UpdateError.downloadFailed
        }

        let fm = FileManager.default
        let tempDir = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try fm.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let localPkgURL = tempDir.appendingPathComponent(pkgURL.lastPathComponent)
        _ = try? fm.removeItem(at: localPkgURL)
        try fm.moveItem(at: tmpURL, to: localPkgURL)
        defer { try? fm.removeItem(at: tempDir) }

        // Validate Team ID
        let expectedTeamID = "4HMJQ7V3SX"
        let updateTeamId = try getTeamId(from: localPkgURL.path)
        guard updateTeamId == expectedTeamID else {
            throw UpdateError.signatureCheckFailed
        }

        // Install
        let proc = Foundation.Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/sbin/installer")
        proc.arguments = ["-pkg", localPkgURL.path, "-target", "/"]
        let errorPipe = Pipe()
        proc.standardError = errorPipe
        try proc.run()
        proc.waitUntilExit()

        guard proc.terminationStatus == 0 else {
            let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
            let errorLog = String(data: errorData, encoding: .utf8) ?? "Unknown error"
            throw UpdateError.installFailed(exitCode: proc.terminationStatus, errorLog: errorLog)
        }
    }

    func getTeamId(from pkgPath: String) throws -> String {
        let process = Foundation.Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/spctl")
        process.arguments = ["--assess", "--type", "install", "-v", "-v", "--raw", pkgPath]
        let outPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = Pipe()
        try process.run()
        process.waitUntilExit()

        guard let output = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) else {
            throw NSError(domain: "Parser", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to read spctl output"])
        }

        let lines = output.components(separatedBy: .newlines)
        guard
            let start = lines.firstIndex(where: { $0.hasPrefix("<?xml") }),
            let end = lines.firstIndex(where: { $0.hasPrefix("</plist>") })
        else {
            throw NSError(domain: "Parser", code: 2, userInfo: [NSLocalizedDescriptionKey: "Could not find plist block"])
        }

        let plistBlock = lines[start...end].joined(separator: "\n")
        guard let data = plistBlock.data(using: .utf8) else {
            throw NSError(domain: "Parser", code: 3, userInfo: [NSLocalizedDescriptionKey: "Invalid plist encoding"])
        }

        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard
            let dict = plist as? [String: Any],
            let origin = dict["assessment:originator"] as? String,
            let match = origin.range(of: #"\(([A-Z0-9]{10})\)$"#, options: .regularExpression)
        else {
            throw NSError(domain: "Parser", code: 4, userInfo: [NSLocalizedDescriptionKey: "Team ID not found"])
        }

        return String(origin[match]).trimmingCharacters(in: CharacterSet(charactersIn: "()"))
    }
}
