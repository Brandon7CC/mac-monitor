//
//  RCXPC.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/11/22.
//
//  Based on the Filtering Web Traffic example: https://developer.apple.com/documentation/networkextension/filtering_network_traffic
//

import Foundation
import OSLog
import SutroESFramework
import AppKit

// MARK: - EventProtocol prototypes
/// Our XPC prorocol enabling the Security Extension (sensor) to send events to Mac Monitor.
@objc public protocol EventProtocol {
    /// Send a JSON event to Mac Monitor
    func surfaceEvent(jsonEvent event: String)
}


// MARK: - SensorProtocol prototypes
/// Our XPC protocol enabling the agent to communicate with the Security Extension.
///
/// Functionaliy includes:
///   - **Starting**: Creates a new ES client, subscribes to events, and establishes the ES callback
///   - **Rebooting** the agent / app
///   - **Resetting the mute set** back to the default
///   - **Get muted paths**
///   - **Mute a path**
///   - **Unmute a path**
///   - **Get the event subscriptions**
///   - **Subscribing to events**
///   - **Unsubscribing from events**
///   - *Opening a Finder window -- not implemented*
///
@objc public protocol SensorProtocol {
    func start(_ completionHandler: @escaping (NewClientResult) -> Void)
    
    /// Reboot the agent after 1 second
    func rebootAgentWithTimeDelay()
    
    // MARK: Path muting
    func getMutedPaths(withData response: @escaping (Set<String>) -> Void)
    func mutePath(pathToMute: String, muteCase: es_mute_path_type_t, pathEvents: [String])
    func unmutePath(pathToUnmute: String, type: String, events: [String])
    func resetMutedPathsXPC()
    func getAppleMuteSet(withData response: @escaping (Set<String>) -> Void)
    
    // MARK: Event subscriptions
    func getEventSubscriptions(withData response: @escaping (Set<String>) -> Void)
    func subscribeToEvent(eventToSubscribeTo: String)
    func unsubscribeFromEvent(eventToUnsubscribeFrom: String)
    
    // Miscellaneous
    func openFinder(filePath: String)
    
    // MARK: Updates
    /// Asynchronously checks for updates and returns the details via a reply block.
    /// - Parameter reply: The completion handler to call with the update details or nil if no update is available.
    func xpcCheckForUpdates(with reply: @escaping (Data?) -> Void)
    func xpcInstallUpdate(from pkgURL: URL) async throws
}


// MARK: - Listener Delegate
/// XPC Listener Delegate
///
/// Reponsible for securing the XPC connection. In other words, only allow Mac Monitor to connect.
extension RCXPCConnection: NSXPCListenerDelegate {
    /// Secure the XPC connection
    ///
    /// **Using the following resources:**
    /// - [Developer Forums](https://developer.apple.com/forums/thread/681053)
    /// - [Dev docs nsxpclistener](https://developer.apple.com/documentation/foundation/nsxpclistener/3943310-setconnectioncodesigningrequirem?changes=__8_5)
    ///
    /// We're going to check for the following in our requirements string:
    /// (1) `anchor apple generic`: Any code signed with any code signing identity issued by Apple (AND)
    /// (2) `\"com.swiftlydetecting.agent\"`: Code signing identifier (AND)
    /// (3) `1[field.1.2.840.113635.100.6.2.6]`: Issued by an Apple Developer ID (AND)
    /// (4) `leaf[field.1.2.840.113635.100.6.1.13]`: Leaf certificate is a Developer ID App (AND)
    /// (5) `certificate leaf[subject.OU] = 4HMJQ7V3SX`: Swiftly Detecting team ID
    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        let shouldAcceptLogger: Logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "RCXPCConnection.shouldAcceptNewConnection")
        
#if COMMUNITY_BUILD
        /// Community builds are ad-hoc signed (see `Community.xcconfig`), so there is no certificate chain or
        /// team ID to pin against. Only the signing identifier is enforced. Never ship a build with this branch.
        let requirementString: String = "identifier \"com.swiftlydetecting.agent\""
#else
        let requirementString: String = "anchor apple generic and identifier \"com.swiftlydetecting.agent\" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"4HMJQ7V3SX\""
#endif
        newConnection.setCodeSigningRequirement(requirementString)
        shouldAcceptLogger.log("🔒 Validating XPC connection with CS requirements!")
        
        newConnection.exportedInterface = NSXPCInterface(with: SensorProtocol.self)
        newConnection.exportedObject = self
        newConnection.remoteObjectInterface = NSXPCInterface(with: EventProtocol.self)
        newConnection.invalidationHandler = {
            shouldAcceptLogger.error("Within invalidation handler for the new XPC connection")
            // @discussion I'm thinking we'll leave this unimplemented for now
            self.currentNSXPCConnection = nil
            // @note killing the client. Invalid connection request.
            self.killClinet()
        }
        
        newConnection.interruptionHandler = {
            shouldAcceptLogger.error("Within the interrupt handler for the new XPC connection")
            self.currentNSXPCConnection = nil
        }
        
        currentNSXPCConnection = newConnection
        newConnection.resume()
        return true
    }
}

// MARK: - EventProtocol implementation
/// Manage the `EventProtocol` side of the XPC connection
public class RCXPCConnection: NSObject, EventProtocol {
    /// Our shared XPC wrapper
    public static let rcXPCConnection = RCXPCConnection()
    
    private let logger = Logger.init(subsystem: "com.swiftlydetecting.agent", category: "RCXPCConnection.EventProtocol")
    
    /// Listen for incoming XPC connection requests
    ///
    /// **Security Extension context:** Our XPC listener that waits for incoming connection requests and then passes them off to
    /// the `NSXPCListenerDelegate`.
    var listener: NSXPCListener?
    
    /// **Agent context:** The current connection to the Secrity Extension
    ///
    /// Our connection request will be enabled only after a successful call to
    /// `setCodeSigningRequirement(requirementString)`
    ///
    var currentNSXPCConnection: NSXPCConnection?
    
    /// Handles the sending of events on the sensor (Security Extension) side
    weak var epDelegate: EventProtocol?
    
    /// The connected `es_clinet_t`
    var connectedESClient: OpaquePointer?
    var esManager: EndpointSecurityManager?
    
    /// Returns the `NSEndpointSecurityMachServiceName` from the Security Extension
    private func getServiceName(from bundle: Bundle) -> String {
        guard let serviceName = bundle.object(forInfoDictionaryKey: "NSEndpointSecurityMachServiceName") as? String else {
            self.logger.error("The XPC service name is missing from the `Info.plist`!")
            return ""
        }
        return serviceName
    }
    
    /// Start the XPC listener
    public func startXPCListener(esManager: EndpointSecurityManager) {
        let xpcServiceName = getServiceName(from: Bundle.main)
        
        let nsXPCListener = NSXPCListener(machServiceName: xpcServiceName)
        nsXPCListener.delegate = self
        nsXPCListener.resume()
        
        self.listener = nsXPCListener
        self.esManager = esManager
    }
    
    /// Establishes a connection to the System Extension.
    private func connectToExtension(epDelegate: EventProtocol, andThen work: @escaping (SensorProtocol?, Error?) -> Void) {
        // If a connection already exists, use it.
        if let existingConnection = self.currentNSXPCConnection {
            guard let proxy = existingConnection.remoteObjectProxyWithErrorHandler({ error in
                work(nil, error)
            }) as? SensorProtocol else {
                self.logger.error("Failed to create remote object proxy from existing connection.")
                return
            }
            work(proxy, nil)
            return
        }
        
        // Otherwise, create a new connection.
        self.epDelegate = epDelegate
        
        // Correctly locate the system extension bundle using a relative path.
        // This is more robust for finding the extension post-installation.
        let extensionURL = URL(fileURLWithPath: "Contents/Library/SystemExtensions/com.swiftlydetecting.agent.securityextension.systemextension", relativeTo: Bundle.main.bundleURL)
        guard let extensionBundle = Bundle(url: extensionURL) else {
            self.logger.error("Failed to load the system extension bundle at path: \(extensionURL.path)")
            work(nil, NSError(domain: "RCXPCConnection", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to load system extension bundle."]))
            return
        }
        
        let serviceName = getServiceName(from: extensionBundle)
        if serviceName.isEmpty { return }
        
        let connection = NSXPCConnection(machServiceName: serviceName, options: [])
        connection.exportedInterface = NSXPCInterface(with: EventProtocol.self)
        connection.exportedObject = epDelegate
        connection.remoteObjectInterface = NSXPCInterface(with: SensorProtocol.self)
        self.currentNSXPCConnection = connection
        
        connection.resume()
        
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
            self.logger.error("Failed to register with the provider! \(error.localizedDescription)")
            self.currentNSXPCConnection?.invalidate()
            self.currentNSXPCConnection = nil
            work(nil, error)
        }) as? SensorProtocol else {
            self.logger.error("Failed to create remote object proxy!")
            return
        }
        
        work(proxy, nil)
    }
    
    /// Register a new XPC connextion from the agent to the Security Extension
    ///
    /// - Parameters:
    ///   - withExtension: A reference to the Security Extension's app bundle. See `kickoffXPCCommunication()` in `ESManager.swift`
    ///   - epDelegate: A reference to an implementation of `EventProtocol`. For us, that will be the `ESManager` class,
    ///   - completionHandler: To pass
    func register(withExtension bundle: Bundle, epDelegate: EventProtocol, completionHandler: @escaping (NewClientResult) -> Void) {
        self.epDelegate = epDelegate
//        guard currentNSXPCConnection == nil else {
//            self.logger.warning("Already registered with the XPC provider")
//            completionHandler(.success)
//            return
//        }
        
        /// Attempt to get the `NSEndpointSecurityMachServiceName` from the Security Extension's `Info.plist`
        let serviceName: String = getServiceName(from: bundle)
        
        /// Set up the XPC connection:
        /// 1) Set the `exportedInterface` as our `EventProtocol`
        /// 2) Set the `remoteObjectInterface` as our `SensorProtocol`
        /// 3) Resume the connection
        let newNSXPCConn: NSXPCConnection = NSXPCConnection(machServiceName: serviceName, options: [])
        newNSXPCConn.exportedInterface = NSXPCInterface(with: EventProtocol.self)
        newNSXPCConn.exportedObject = epDelegate
        newNSXPCConn.remoteObjectInterface = NSXPCInterface(with: SensorProtocol.self)
        
        /// Set the current XPC connection in the agent!
        currentNSXPCConnection = newNSXPCConn
        
        newNSXPCConn.resume()
        
        /// Error handler for the `newNSXPCConn` `NSXPCConnection`
        guard let proxyProvider = newNSXPCConn.remoteObjectProxyWithErrorHandler({ err in
            self.logger.error("Failed to register with the provider! \(err.localizedDescription)")
            self.currentNSXPCConnection?.invalidate()
            self.currentNSXPCConnection = nil
            
            completionHandler(.internalSubsystem)
        }) as? SensorProtocol else {
            self.logger.error("Failed to create remote object proxy!")
            return
        }
        
        /// If all goes well call into ``start(_:)`` and pass the
        proxyProvider.start(completionHandler)
    }
    
    /// Call into `cleanup()` to kill the ES client
    ///
    /// This is only used within the XPC Listener Delegate if something goes wrong (i.e. invalidation handler).
    func killClinet() {
        if connectedESClient != nil {
            // Attempt to kill the ES client
            esManager?.cleanup()
        }
    }
    
    /// Send an JSON serializartion of an RC event to the agent
    ///
    /// To do this, we call into the `surfaceEvent()` implementation defined in ``EndpointSecurityManager``
    @objc public func surfaceEvent(jsonEvent event: String) {
        guard let xpcConn = currentNSXPCConnection else {
            return
        }
        
        guard let agentXPCProxy = xpcConn.remoteObjectProxyWithErrorHandler({ err in
            self.logger.error("Could not send RC event to the agent! \(err.localizedDescription)")
            self.currentNSXPCConnection = nil
        }) as? EventProtocol else {
            self.logger.error("Failed to create the remote proxy to communicate with the agent!")
            return
        }
        
        /// The `surfaceEvent()` implementation in ``EndpointSecurityManager``
        agentXPCProxy.surfaceEvent(jsonEvent: event)
    }
    
    public func openFinderWidowSE(filePath: String) {
        let xpcConn = currentNSXPCConnection
        if xpcConn != nil {
            // If the connection is already established then just get the object proxy
            guard let proxyProvider = currentNSXPCConnection!.remoteObjectProxyWithErrorHandler({ err in
                self.logger.error("Failed to register with the provider! \(err.localizedDescription)")
                self.currentNSXPCConnection?.invalidate()
                self.currentNSXPCConnection = nil
            }) as? SensorProtocol else {
                self.logger.error("Failed to create remote object proxy!")
                return
            }
            self.logger.info("Proxying the open request to the SE!")
            proxyProvider.openFinder(filePath: filePath)
        }
    }
    
    
    // MARK: - START of XPC support for dynamic event subscriptions
    @objc public func getEventSubscriptions(epDelegate: EventProtocol, withData response: @escaping (Set<String>) -> Void) {
        var xpcConn = currentNSXPCConnection
        if xpcConn == nil {
            let bundleExtension: Bundle = Bundle(url: URL(fileURLWithPath: "Contents/Library/SystemExtensions/com.swiftlydetecting.agent.securityextension.systemextension", relativeTo: Bundle.main.bundleURL))!
            let serviceName: String = getServiceName(from: bundleExtension)
            self.logger.info("Attempting to connect to the service: \(serviceName)")
            
            let newNSXPCConn: NSXPCConnection = NSXPCConnection(machServiceName: serviceName, options: [])
            newNSXPCConn.exportedInterface = NSXPCInterface(with: EventProtocol.self)
            newNSXPCConn.exportedObject = epDelegate
            newNSXPCConn.remoteObjectInterface = NSXPCInterface(with: SensorProtocol.self)
            currentNSXPCConnection = newNSXPCConn
            xpcConn = currentNSXPCConnection
            newNSXPCConn.resume()
        }
        
        self.epDelegate = epDelegate
        
        guard let agentXPCProxy = xpcConn!.remoteObjectProxyWithErrorHandler({ err in
            self.logger.error("Could not get the event subscriptions! \(err.localizedDescription)")
            self.currentNSXPCConnection = nil
        }) as? SensorProtocol else {
            self.logger.error("Failed to create the remote proxy to communicate with the agent!")
            return
        }
        
        agentXPCProxy.getEventSubscriptions(withData: response)
    }
    
    // MARK: Step #3 in unsubscribing from ES events
    func unsubscribeFromEvent(eventToUnsubscribeFrom: String, epDelegate: EventProtocol) {
        var xpcConn = currentNSXPCConnection
        if xpcConn != nil {
            // If the connection is already established then just get the object proxy
            guard let proxyProvider = currentNSXPCConnection!.remoteObjectProxyWithErrorHandler({ err in
                self.logger.error("Failed to register with the provider! \(err.localizedDescription)")
                self.currentNSXPCConnection?.invalidate()
                self.currentNSXPCConnection = nil
            }) as? SensorProtocol else {
                self.logger.error("Failed to create remote object proxy!")
                return
            }
            //            os_log("Connected to SE via XPC over SensorProtocol to unsubscribe from event!")
            proxyProvider.unsubscribeFromEvent(eventToUnsubscribeFrom: eventToUnsubscribeFrom)
            
        } else {
            let bundleExtension: Bundle = Bundle(url: URL(fileURLWithPath: "Contents/Library/SystemExtensions/com.swiftlydetecting.agent.securityextension.systemextension", relativeTo: Bundle.main.bundleURL))!
            let serviceName: String = getServiceName(from: bundleExtension)
            self.logger.info("Attempting to connect to the service: \(serviceName)")
            
            let newNSXPCConn: NSXPCConnection = NSXPCConnection(machServiceName: serviceName, options: [])
            newNSXPCConn.exportedInterface = NSXPCInterface(with: EventProtocol.self)
            newNSXPCConn.exportedObject = epDelegate
            newNSXPCConn.remoteObjectInterface = NSXPCInterface(with: SensorProtocol.self)
            currentNSXPCConnection = newNSXPCConn
            xpcConn = currentNSXPCConnection
            newNSXPCConn.resume()
            
            guard let proxyProvider = currentNSXPCConnection!.remoteObjectProxyWithErrorHandler({ err in
                self.logger.error("Failed to register with the provider! \(err.localizedDescription)")
                self.currentNSXPCConnection?.invalidate()
                self.currentNSXPCConnection = nil
            }) as? SensorProtocol else {
                self.logger.error("Failed to create remote object proxy!")
                return
            }
            //            os_log("Connected to SE via XPC over SensorProtocol to unsubscribe from event!")
            proxyProvider.unsubscribeFromEvent(eventToUnsubscribeFrom: eventToUnsubscribeFrom)
        }
    }
    
    // MARK: Step #3 in subscribing tp ES events
    func subscribeToEvent(eventToSubscribeTo: String, epDelegate: EventProtocol) {
        var xpcConn = currentNSXPCConnection
        if xpcConn != nil {
            // If the connection is already established then just get the object proxy
            guard let proxyProvider = currentNSXPCConnection!.remoteObjectProxyWithErrorHandler({ err in
                self.logger.error("Failed to register with the provider! \(err.localizedDescription)")
                self.currentNSXPCConnection?.invalidate()
                self.currentNSXPCConnection = nil
            }) as? SensorProtocol else {
                self.logger.error("Failed to create remote object proxy!")
                return
            }
            //            os_log("Connected to SE via XPC over SensorProtocol to unsubscribe from event!")
            proxyProvider.subscribeToEvent(eventToSubscribeTo: eventToSubscribeTo)
            
        } else {
            let bundleExtension: Bundle = Bundle(url: URL(fileURLWithPath: "Contents/Library/SystemExtensions/com.swiftlydetecting.agent.securityextension.systemextension", relativeTo: Bundle.main.bundleURL))!
            let serviceName: String = getServiceName(from: bundleExtension)
            self.logger.info("Attempting to connect to the service: \(serviceName)")
            
            let newNSXPCConn: NSXPCConnection = NSXPCConnection(machServiceName: serviceName, options: [])
            newNSXPCConn.exportedInterface = NSXPCInterface(with: EventProtocol.self)
            newNSXPCConn.exportedObject = epDelegate
            newNSXPCConn.remoteObjectInterface = NSXPCInterface(with: SensorProtocol.self)
            currentNSXPCConnection = newNSXPCConn
            xpcConn = currentNSXPCConnection
            newNSXPCConn.resume()
            
            guard let proxyProvider = currentNSXPCConnection!.remoteObjectProxyWithErrorHandler({ err in
                self.logger.error("Failed to register with the provider! \(err.localizedDescription)")
                self.currentNSXPCConnection?.invalidate()
                self.currentNSXPCConnection = nil
            }) as? SensorProtocol else {
                self.logger.error("Failed to create remote object proxy!")
                return
            }
            //            os_log("Connected to SE via XPC over SensorProtocol to unsubscribe from event!")
            proxyProvider.subscribeToEvent(eventToSubscribeTo: eventToSubscribeTo)
        }
    }
    
    
    // MARK: - START of XPC support for dynamic path muting
    
    // MARK: Step #2 in getting the list of muted paths from Endpoint Security
    func getMutedPaths(epDelegate: EventProtocol, withData response: @escaping (Set<String>) -> Void) {
        var xpcConn = currentNSXPCConnection
        if xpcConn == nil {
            let bundleExtension: Bundle = Bundle(url: URL(fileURLWithPath: "Contents/Library/SystemExtensions/com.swiftlydetecting.agent.securityextension.systemextension", relativeTo: Bundle.main.bundleURL))!
            let serviceName: String = getServiceName(from: bundleExtension)
            self.logger.info("Attempting to connect to the service: \(serviceName)")
            
            let newNSXPCConn: NSXPCConnection = NSXPCConnection(machServiceName: serviceName, options: [])
            newNSXPCConn.exportedInterface = NSXPCInterface(with: EventProtocol.self)
            newNSXPCConn.exportedObject = epDelegate
            newNSXPCConn.remoteObjectInterface = NSXPCInterface(with: SensorProtocol.self)
            currentNSXPCConnection = newNSXPCConn
            xpcConn = currentNSXPCConnection
            newNSXPCConn.resume()
        }
        
        self.epDelegate = epDelegate
        
        guard let agentXPCProxy = xpcConn!.remoteObjectProxyWithErrorHandler({ err in
            self.logger.error("Could not get the muted paths! \(err.localizedDescription)")
            self.currentNSXPCConnection = nil
        }) as? SensorProtocol else {
            self.logger.error("Failed to create the remote proxy to communicate with the agent!")
            return
        }
        
        agentXPCProxy.getMutedPaths(withData: response)
    }
    
    // MARK: Step #2 Get Apple muted paths
    func getAppleMuteSet(epDelegate: EventProtocol, withData response: @escaping (Set<String>) -> Void) {
        var xpcConn = currentNSXPCConnection
        if xpcConn == nil {
            let bundleExtension = Bundle(url: URL(fileURLWithPath: "Contents/Library/SystemExtensions/com.swiftlydetecting.agent.securityextension.systemextension", relativeTo: Bundle.main.bundleURL))!
            let serviceName = getServiceName(from: bundleExtension)
            let newNSXPCConn = NSXPCConnection(machServiceName: serviceName, options: [])
            newNSXPCConn.exportedInterface = NSXPCInterface(with: EventProtocol.self)
            newNSXPCConn.exportedObject = epDelegate
            newNSXPCConn.remoteObjectInterface = NSXPCInterface(with: SensorProtocol.self)
            currentNSXPCConnection = newNSXPCConn
            xpcConn = currentNSXPCConnection
            newNSXPCConn.resume()
        }

        self.epDelegate = epDelegate

        guard let agentXPCProxy = xpcConn!.remoteObjectProxyWithErrorHandler({ err in
            self.logger.error("Could not get the Apple mute set! \(err.localizedDescription)")
            self.currentNSXPCConnection = nil
        }) as? SensorProtocol else {
            self.logger.error("Failed to create the remote proxy to communicate with the agent!")
            return
        }

        agentXPCProxy.getAppleMuteSet(withData: response)
    }
    
    
    // MARK: Step #3 in muting paths
    // @note Suppress all events from executables that match a given path
    func mutePath(pathToMute: String, muteCase: es_mute_path_type_t, pathEvents: [String], epDelegate: EventProtocol) {
        if currentNSXPCConnection != nil {
            // If the connection is already established then just get the object proxy
            guard let proxyProvider = currentNSXPCConnection!.remoteObjectProxyWithErrorHandler({ err in
                self.logger.error("Failed to register with the provider! \(err.localizedDescription)")
                self.currentNSXPCConnection?.invalidate()
                self.currentNSXPCConnection = nil
            }) as? SensorProtocol else {
                self.logger.error("Failed to create remote object proxy!")
                return
            }
            
            proxyProvider.mutePath(pathToMute: pathToMute, muteCase: muteCase, pathEvents: pathEvents)
        } else {
            self.epDelegate = epDelegate
            
            guard let proxyProvider = currentNSXPCConnection!.remoteObjectProxyWithErrorHandler({ err in
                self.logger.error("Could not mute paths! \(err.localizedDescription)")
                self.currentNSXPCConnection = nil
            }) as? SensorProtocol else {
                self.logger.error("Failed to create the remote proxy to communicate with the agent!")
                return
            }
            //            os_log("Connected to SE via XPC over SensorProtocol to mute paths!")
            proxyProvider.mutePath(pathToMute: pathToMute, muteCase: muteCase, pathEvents: pathEvents)
        }
    }
    
    // MARK: Step #3 in reseting mute paths
    public func resetMutePaths(epDelegate: EventProtocol) {
        var xpcConn = currentNSXPCConnection
        if xpcConn != nil {
            // If the connection is already established then just get the object proxy
            guard let proxyProvider = currentNSXPCConnection!.remoteObjectProxyWithErrorHandler({ err in
                self.logger.error("Failed to register with the provider! \(err.localizedDescription)")
                self.currentNSXPCConnection?.invalidate()
                self.currentNSXPCConnection = nil
            }) as? SensorProtocol else {
                self.logger.error("Failed to create remote object proxy!")
                return
            }
            proxyProvider.resetMutedPathsXPC()
            
        } else {
            let bundleExtension: Bundle = Bundle(url: URL(fileURLWithPath: "Contents/Library/SystemExtensions/com.swiftlydetecting.agent.securityextension.systemextension", relativeTo: Bundle.main.bundleURL))!
            let serviceName: String = getServiceName(from: bundleExtension)
            self.logger.info("Attempting to connect to the service: \(serviceName)")
            
            let newNSXPCConn: NSXPCConnection = NSXPCConnection(machServiceName: serviceName, options: [])
            newNSXPCConn.exportedInterface = NSXPCInterface(with: EventProtocol.self)
            newNSXPCConn.exportedObject = epDelegate
            newNSXPCConn.remoteObjectInterface = NSXPCInterface(with: SensorProtocol.self)
            currentNSXPCConnection = newNSXPCConn
            xpcConn = currentNSXPCConnection
            newNSXPCConn.resume()
            
            guard let proxyProvider = currentNSXPCConnection!.remoteObjectProxyWithErrorHandler({ err in
                self.logger.error("Failed to register with the provider! \(err.localizedDescription)")
                self.currentNSXPCConnection?.invalidate()
                self.currentNSXPCConnection = nil
            }) as? SensorProtocol else {
                self.logger.error("Failed to create remote object proxy!")
                return
            }
            proxyProvider.resetMutedPathsXPC()
        }
    }
    
    
    // MARK: Step #3 in unmuting paths
    // Releases all events from executables that match a given path
    public func unmutePaths(pathToUnmute: String, type: String, events: [String], epDelegate: EventProtocol) {
        var xpcConn = currentNSXPCConnection
        if xpcConn != nil {
            // If the connection is already established then just get the object proxy
            guard let proxyProvider = currentNSXPCConnection!.remoteObjectProxyWithErrorHandler({ err in
                self.logger.error("Failed to register with the provider! \(err.localizedDescription)")
                self.currentNSXPCConnection?.invalidate()
                self.currentNSXPCConnection = nil
            }) as? SensorProtocol else {
                self.logger.error("Failed to create remote object proxy!")
                return
            }
            proxyProvider.unmutePath(pathToUnmute: pathToUnmute, type: type, events: events)
            
        } else {
            let bundleExtension: Bundle = Bundle(url: URL(fileURLWithPath: "Contents/Library/SystemExtensions/com.swiftlydetecting.agent.securityextension.systemextension", relativeTo: Bundle.main.bundleURL))!
            let serviceName: String = getServiceName(from: bundleExtension)
            self.logger.info("Attempting to connect to the service: \(serviceName)")
            
            let newNSXPCConn: NSXPCConnection = NSXPCConnection(machServiceName: serviceName, options: [])
            newNSXPCConn.exportedInterface = NSXPCInterface(with: EventProtocol.self)
            newNSXPCConn.exportedObject = epDelegate
            newNSXPCConn.remoteObjectInterface = NSXPCInterface(with: SensorProtocol.self)
            currentNSXPCConnection = newNSXPCConn
            xpcConn = currentNSXPCConnection
            newNSXPCConn.resume()
            
            guard let proxyProvider = currentNSXPCConnection!.remoteObjectProxyWithErrorHandler({ err in
                self.logger.error("Failed to register with the provider! \(err.localizedDescription)")
                self.currentNSXPCConnection?.invalidate()
                self.currentNSXPCConnection = nil
            }) as? SensorProtocol else {
                self.logger.error("Failed to create remote object proxy!")
                return
            }
            proxyProvider.unmutePath(pathToUnmute: pathToUnmute, type: type, events: events)
        }
    }
    
    // MARK: Step #3 in rebooting Mac Monitor for TCC
    /// Request that Mac Monitor reboot.
    ///
    /// The **only** important bit is defined in
    /// ```swift
    /// proxyProvider.rebootAgentWithTimeDelay()
    /// ```
    ///
    public func xpcReboot() {
        var xpcConn = currentNSXPCConnection
        if xpcConn != nil {
            // If the connection is already established then just get the object proxy
            guard let proxyProvider = currentNSXPCConnection!.remoteObjectProxyWithErrorHandler({ err in
                self.logger.error("Failed to register with the provider! \(err.localizedDescription)")
                self.currentNSXPCConnection?.invalidate()
                self.currentNSXPCConnection = nil
            }) as? SensorProtocol else {
                self.logger.error("Failed to create remote object proxy!")
                return
            }
            // @note Reboot Mac Monitor with time delay
            proxyProvider.rebootAgentWithTimeDelay()
            
        } else {
            let bundleExtension: Bundle = Bundle(url: URL(fileURLWithPath: "Contents/Library/SystemExtensions/com.swiftlydetecting.agent.securityextension.systemextension", relativeTo: Bundle.main.bundleURL))!
            let serviceName: String = getServiceName(from: bundleExtension)
            self.logger.info("Attempting to connect to the service: \(serviceName)")
            
            let newNSXPCConn: NSXPCConnection = NSXPCConnection(machServiceName: serviceName, options: [])
            newNSXPCConn.exportedInterface = NSXPCInterface(with: EventProtocol.self)
            newNSXPCConn.exportedObject = epDelegate
            newNSXPCConn.remoteObjectInterface = NSXPCInterface(with: SensorProtocol.self)
            currentNSXPCConnection = newNSXPCConn
            xpcConn = currentNSXPCConnection
            newNSXPCConn.resume()
            
            guard let proxyProvider = currentNSXPCConnection!.remoteObjectProxyWithErrorHandler({ err in
                self.logger.error("Failed to register with the provider! \(err.localizedDescription)")
                self.currentNSXPCConnection?.invalidate()
                self.currentNSXPCConnection = nil
            }) as? SensorProtocol else {
                self.logger.error("Failed to create remote object proxy!")
                return
            }
            // @note Reboot Mac Monitor with time delay
            proxyProvider.rebootAgentWithTimeDelay()
        }
    }
    
    
    // MARK: - GitHub Release JSON Decoder
    /// Decode the relevant fields from the GitHub API response.
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
            case assets
            case body
            case publishedAt = "published_at"
        }
        
        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            tagName = try container.decode(String.self, forKey: .tagName)
            body = try container.decode(String.self, forKey: .body)
            publishedAt = try container.decode(String.self, forKey: .publishedAt)
            
            // Decode the 'assets' array and extract the URL from the first element.
            var assetsContainer = try container.nestedUnkeyedContainer(forKey: .assets)
            guard let firstAsset = try assetsContainer.decodeIfPresent(Asset.self) else {
                throw DecodingError.dataCorruptedError(
                    in: assetsContainer,
                    debugDescription: "The 'assets' array is empty or missing the expected object."
                )
            }
            updatePkgURL = firstAsset.browserDownloadURL
        }
    }
    
    // MARK: Step #3 in checking for updates (Client Side)
    /// This is called from the main app. It connects to the extension and calls the corresponding XPC method.
    func checkForUpdates(epDelegate: EventProtocol, completion: @escaping (UpdateDetails?) -> Void) {
        connectToExtension(epDelegate: epDelegate) { proxy, error in
            guard let proxy = proxy, error == nil else {
                self.logger.error("Failed to get XPC proxy for update check: \(error?.localizedDescription ?? "Unknown error")")
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
                    self.logger.error("Failed to decode UpdateDetails from XPC data: \(error)")
                    completion(nil)
                }
            }
        }
    }
    
    // MARK: Step #3 in installing updates (Client Side)
    /// This is called from the main app. It connects to the extension and calls the corresponding XPC method.
    func installUpdate(from pkgURL: URL, epDelegate: EventProtocol, completion: @escaping (Bool) -> Void) {
        connectToExtension(epDelegate: epDelegate) { proxy, error in
            guard let proxy = proxy, error == nil else {
                self.logger.error("Failed to get XPC proxy to install update: \(error?.localizedDescription ?? "Unknown error")")
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

}



/// Manage the `SensorProtocol` side of the XPC connection
extension RCXPCConnection: SensorProtocol {
    
    // MARK: - START XPC dynamic event subscriptions
    public func getEventSubscriptions(withData response: @escaping (Set<String>) -> Void) {
        guard let client = self.esManager else {
            self.logger.error("We couldn't find the client to fetch the event subscriptions from!")
            return
        }
        
        response(client.seGetEventSubscriptionsAsString())
    }
    
    public func unsubscribeFromEvent(eventToUnsubscribeFrom: String) {
        guard let client = self.esManager else {
            self.logger.error("We couldn't find the client to send the unsubscribe request to!")
            return
        }
        client.unsubscribeFromEvent(eventToUnsubscribeFrom: eventToUnsubscribeFrom)
    }
    
    public func subscribeToEvent(eventToSubscribeTo: String) {
        guard let client = self.esManager else {
            self.logger.error("We couldn't find the client to send the subscribe request to!")
            return
        }
        client.subscribeToEvent(eventToSubscribeTo: eventToSubscribeTo)
    }
    
    
    // MARK: - START XPC Finder window open
    public func openFinder(filePath: String) {
        guard self.esManager != nil else {
            self.logger.error("We couldn't find the client to send the AWS credentials to!")
            return
        }
        
        let url = URL(filePath: filePath)
        
        guard let finder = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.open") else { return }
        NSWorkspace.shared.open([url], withApplicationAt: finder, configuration: NSWorkspace.OpenConfiguration())
    }
    
    
    // MARK: - START XPC dynamic path muting support
    public func resetMutedPathsXPC() {
        guard let client = self.esManager else {
            self.logger.error("We couldn't find the client to send the mute request to!")
            return
        }
        MutingEngine.applyDefaultMuteSet(client: client.esClient!)
    }
    
    // Apple's default mute set
    public func getAppleMuteSet(withData response: @escaping (Set<String>) -> Void) {
        guard let client = self.esManager else {
            self.logger.error("We couldn't find the client to fetch the Apple mute set from!")
            return
        }
        response(client.seGetAppleMuteSet())
    }
    
    public func mutePath(pathToMute: String, muteCase: es_mute_path_type_t, pathEvents: [String]) {
        guard let client = self.esManager else {
            self.logger.error("We couldn't find the client to send the mute request to!")
            return
        }
        client.mutePath(pathToMute: pathToMute, muteCase: muteCase, pathEvents: pathEvents)
    }
    
    public func getMutedPaths(withData response: @escaping (Set<String>) -> Void) {
        guard let client = self.esManager else {
            self.logger.error("We couldn't find the client to fetch the muted paths from!")
            return
        }
        
        response(client.seGetGlobalMutedPaths())
    }
    
    public func unmutePath(pathToUnmute: String, type: String, events: [String]) {
        guard let client = self.esManager else {
            self.logger.error("We couldn't find the client to send the unmute requests to!")
            return
        }
        client.unmutePath(pathToUnmute: pathToUnmute, type: type, events: events)
    }
    
    func sendEvent(jsonEvent: String) {
        RCXPCConnection.rcXPCConnection.surfaceEvent(jsonEvent: jsonEvent)
    }
    
    /// First entry point from the agent asking the Security Extension to bootup
    public func start(_ completionHandler: @escaping (NewClientResult) -> Void) {
        self.logger.info("Mac Monitor Agent connected.")
        
        var startResult: NewClientResult = .waiting
        if esManager != nil {
            (connectedESClient, startResult) = esManager!.kickstartClient(completion: sendEvent)
            if connectedESClient == nil {
                completionHandler(startResult)
                return
            }
        }
        
        completionHandler(startResult)
    }
    
    // MARK: Agent reboot
    public func rebootAgentWithTimeDelay() {
        EndpointSecurityManager.seRequestAgentReboot()
    }
    
    // MARK: - Check for updates
    /// This is executed within the System Extension when called from the main app.
    public func xpcCheckForUpdates(with reply: @escaping (Data?) -> Void) {
        logger.log("System Extension received request to check for updates.")
        
        let updateURLString = "https://api.github.com/repos/Brandon7CC/mac-monitor/releases/latest"
        
//        let testingUpdateURL = "https://api.github.com/repos/redcanaryco/mac-monitor/releases/latest"
//        updateURLString = testingUpdateURL
        
        guard let updateURL = URL(string: updateURLString) else {
            reply(nil)
            return
        }
        
        let task = URLSession.shared.dataTask(with: updateURL) { data, response, error in
            guard let data = data, error == nil else {
                os_log("(Mac Monitor Update) Update check failed with network error: \(error?.localizedDescription ?? "No data")")
                reply(nil)
                return
            }
            
            do {
                let release = try JSONDecoder().decode(GitHubRelease.self, from: data)
                guard let currentVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String else {
                    reply(nil)
                    return
                }
                
                os_log("(Mac Monitor Update) Latest version found: \(release.tagName.trimmingPrefix("v")). Current version: \(currentVersion)")
                let latestVersion = release.tagName
                if latestVersion.trimmingPrefix("v").compare(currentVersion, options: .numeric) == .orderedDescending {
                    let details = UpdateDetails(
                        version: release.tagName,
                        downloadURL: release.updatePkgURL,
                        releaseNotes: release.body,
                        releaseDate: release.publishedAt
                    )
                    // Encode the details to Data before sending back.
                    let encodedDetails = try? JSONEncoder().encode(details)
                    reply(encodedDetails)
                } else {
                    reply(nil)
                }
            } catch {
                os_log("(Mac Monitor Update) Failed to decode update JSON at \(updateURL): \(error.localizedDescription)")
                reply(nil)
            }
        }
        task.resume()
    }
    
    enum UpdateError: Error, LocalizedError {
        case downloadFailed
        case invalidTeamID(reason: String)
        case signatureCheckFailed
        case installFailed(exitCode: Int32, errorLog: String)
        
        var errorDescription: String? {
            switch self {
            case .downloadFailed:
                return "The update package download failed or returned a non-200 status code."
            case .invalidTeamID(let reason):
                return "The Team ID of the package was invalid. Reason: \(reason)"
            case .signatureCheckFailed:
                return "The low-level signature check failed."
            case .installFailed(let exitCode, let errorLog):
                return "The installer process failed with exit code \(exitCode). Log: \(errorLog)"
            }
        }
    }
    
    /**
     * Securely downloads, validates, and installs a package update via an XPC service.
     * The Team ID of the package is verified against an expected value before installation.
     */
    public func xpcInstallUpdate(from pkgURL: URL) async throws {
        /// 1. Download the update package
        os_log("1. Downloading update from %{public}s", pkgURL.absoluteString)
        let (tmpURL, response) = try await URLSession.shared.download(from: pkgURL)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw UpdateError.downloadFailed
        }
        
        // Create a temporary directory for the downloaded package
        let fm = FileManager.default
        let tempDir = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try fm.createDirectory(at: tempDir, withIntermediateDirectories: true)
        
        let localPkgURL = tempDir.appendingPathComponent(pkgURL.lastPathComponent)
        _ = try? fm.removeItem(at: localPkgURL)
        try fm.moveItem(at: tmpURL, to: localPkgURL)
        
        // Ensure the temporary directory is cleaned up when the function exits
        defer {
            try? fm.removeItem(at: tempDir)
            os_log("🧹 Cleaned up temporary directory at %{public}s", tempDir.path)
        }
        
        /// 2. Validate the Team ID
        os_log("2. Team ID validation: %{public}s", localPkgURL.path)
        let expectedTeamID = "4HMJQ7V3SX"
        let updateTeamId = try getTeamId(from: localPkgURL.path)
        
        if updateTeamId != expectedTeamID {
            os_log("❌ Team IDs do not match! \(updateTeamId) != \(expectedTeamID)")
            throw UpdateError.signatureCheckFailed
        }
        os_log("✅ Team ID validation pass \(updateTeamId) == \(expectedTeamID)")
        
        /// 3. Install the update package
        os_log("3. Installing update...")
        let proc = Foundation.Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/sbin/installer")
        proc.arguments = ["-pkg", localPkgURL.path, "-target", "/"]
        
        let errorPipe = Pipe()
        proc.standardError = errorPipe
        try proc.run()
        proc.waitUntilExit()
        
        guard proc.terminationStatus == 0 else {
            let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
            let errorLog = String(data: errorData, encoding: .utf8) ?? "Could not read installer error log."
            os_log("❌ Install failed %d. Error: %{public}s", proc.terminationStatus, errorLog)
            throw UpdateError.installFailed(exitCode: proc.terminationStatus, errorLog: errorLog)
        }
        
        os_log("🎉 Update installation complete!")
    }
    
    func getTeamId(from pkgPath: String) throws -> String {
        /// Leverage `spctl` to pull the code signing info
        let process = Foundation.Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/spctl")
        process.arguments = ["--assess", "--type", "install", "-v", "-v", "--raw", pkgPath]
        let outPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = Pipe()
        try process.run(); process.waitUntilExit()
        guard let output = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) else {
            os_log("Failed to read spctl output")
            throw NSError(domain: "Parser", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to read spctl output"])
        }
        
        /// Extract the Team Id
        let lines = output.components(separatedBy: .newlines)
        guard
            let start = lines.firstIndex(where: { $0.hasPrefix("<?xml") }),
            let end = lines.firstIndex(where: { $0.hasPrefix("</plist>") })
        else {
            os_log("Could not find plist block")
            throw NSError(domain: "Parser", code: 2, userInfo: [NSLocalizedDescriptionKey: "Could not find plist block"])
        }
        let plistBlock = lines[start...end].joined(separator: "\n")
        guard let data = plistBlock.data(using: .utf8) else {
            os_log("Invalid encoding")
            throw NSError(domain: "Parser", code: 3, userInfo: [NSLocalizedDescriptionKey: "Invalid encoding for plist block"])
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

