//
//  SutroES.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 7/6/22.
//

import Foundation
import EndpointSecurity
import SystemExtensions
import OSLog
import AppKit
import CryptoKit

// TODO: Candidate for `@Observable`

/// Manages XPC, System Extension, and event producer functionality
///
///
/// The "Endpoint Security Manager" (ESM) exposes functionality to interact with the Mac Monitor Security Extension `com.swiftlydetecting.agent.securityextension`
///
///
public class EndpointSecurityManager: NSObject, ObservableObject, OSSystemExtensionRequestDelegate, EventProtocol {
    let decoder = JSONDecoder()
    
    // MARK: ES client properties: client and event subscriptions
    /// The Endpoint Security client we'll leverage for tracing system events
    public var esClient: OpaquePointer?
    
    /// The events we're subscribed to.
    ///
    /// These are defined by the `coreEventSubscriptions` in `ESTranslation.swift`. Core event subscriptions are a subset of the total supported
    /// subscriptions.
    @Published public var monitoredEvents: [es_event_type_t] = defaultEventSubscriptions
    @Published public var monitoredEventStrings: Set<String> = []
    
    /// When Project Sutro connects let's grab the current time so we can filter long running processes
    @Published public var clientConnectDT: Date = Date()
    
    // MARK: Muting Enging properties
    @Published public var emittedRCEventsByProcess: [Message: [Message]] = [:]
    @Published public var globallyMutedPaths: Set<String> = []
    @Published public var appleMuteSet = Set<String>()
    
    // MARK: Install properties
    @Published public var seIsInstalled: Bool = false
    @Published public var connectionResult: NewClientResult = .waiting
    
    /// Reference to the shared Core Data Controller
    public var coreDataContainer = CoreDataController.shared
    /// Should we stop tracing system events?
    private var stopSendingEvents: Bool = true
    /// Should we drop platform binaries?
    private var dropPlatformBinaries: Bool = false
    
    // MARK: - Batching Properties
    /// A temporary, thread-safe buffer for incoming events before they are sent to Core Data.
    private var eventBuffer: [Message] = []
    /// A dedicated serial queue to ensure thread-safe access to the eventBuffer.
    private let eventBufferQueue = DispatchQueue(label: "com.swiftlydetecting.agent.eventBufferQueue")
    /// A high-performance GCD timer to periodically flush the event buffer.
    private var flushTimer: DispatchSourceTimer?
    
    // MARK: - Dynamic Throttling Properties
    /// Dynamic throttle manager that adjusts based on event rate
    private let throttleManager = ThrottleManager()
    /// Calculate dynamic batch size based on current throttle state
    private var currentBatchSize: Int {
        let eventRate = throttleManager.eventRate
        if eventRate > 2000 {
            return 4000
        } else if eventRate > 1000 {
            return 3000
        } else {
            return 2000
        }
    }
    
    public override init() {
        super.init()
        setupFlushTimer()
    }
    
    /// Should we be dropping platform binaries?
    ///
    /// Utilizing the concept of "critical" eventing events see:  ``isEventCritical(message:)`` in `EventStreamControl.swift`.
    public func togglePlatformBinaries() {
        self.dropPlatformBinaries.toggle()
    }
    
    // MARK: - Incoming events
    
    /// Handle the incoming Endpoint Security event (`Message`) from the Security Extension by batching them for efficient processing.
    ///
    /// This function is the entry point for all events from the XPC service.
    /// Its job is to quickly decode the incoming JSON and add the resulting `Message` object to a buffer.
    /// A separate, timer-based process flushes this buffer to Core Data, preventing the UI from being blocked by high event volume.
    ///
    /// - Parameters:
    ///   - jsonEvent: The JSON string serialization of the `Message`
    public func surfaceEvent(jsonEvent event: String) {
        if !self.stopSendingEvents {
            // Quickly decode the JSON.
            guard let json = event.data(using: .utf8),
                  let message = try? decoder.decode(Message.self, from: json) else {
                return
            }
            
            // Track event rate for dynamic throttling
            throttleManager.registerEvent()
            
            let shouldInsert: Bool
            if self.dropPlatformBinaries {
                if !message.process.is_platform_binary || isEventCritical(message: message) {
                    shouldInsert = true
                } else if let exec = message.event.exec, !exec.target.is_platform_binary {
                    shouldInsert = true
                } else if let fork = message.event.fork, !fork.child.is_platform_binary {
                    shouldInsert = true
                } else {
                    shouldInsert = false
                }
            } else {
                shouldInsert = true
            }
            
            if shouldInsert {
                eventBufferQueue.async {
                    self.eventBuffer.append(message)
                    
                    let hardBufferLimit = 5000
                    if self.eventBuffer.count >= hardBufferLimit {
                        // Force flush at hard limit
                        self.flushEvents()
                        self.updateFlushTimer()
                    } else if self.eventBuffer.count >= self.currentBatchSize {
                        // Normal dynamic batching
                        self.flushEvents()
                        self.updateFlushTimer()
                    }
                }
            }

        }
    }
    
    /// Configures and starts a GCD timer to periodically flush the event buffer.
    /// This runs on a background queue to avoid impacting the main thread.
    private func setupFlushTimer() {
        flushTimer = DispatchSource.makeTimerSource(queue: eventBufferQueue)
        let initialInterval = throttleManager.saveInterval
        flushTimer?.schedule(deadline: .now() + initialInterval, repeating: initialInterval)
        flushTimer?.setEventHandler { [weak self] in
            self?.flushEvents()
            self?.updateFlushTimer()
        }
        flushTimer?.resume()
    }
    
    /// Updates the flush timer interval based on current throttle settings
    private func updateFlushTimer() {
        let newInterval = throttleManager.saveInterval
        flushTimer?.schedule(deadline: .now() + newInterval, repeating: newInterval)
    }
    
    /// Takes the current batch of events from the buffer and sends them to the CoreDataController.
    /// This function is always called on the `eventBufferQueue`.
    private func flushEvents() {
        guard !self.eventBuffer.isEmpty else { return }
        
        let batchToProcess = self.eventBuffer
        self.eventBuffer.removeAll(keepingCapacity: true) // Clear buffer for next batch
        
        // Pass the entire batch to Core Data for processing.
        self.coreDataContainer.insertSystemEvents(messages: batchToProcess)
    }
    
    // MARK: - XPC Entry
    
    /// Connect to the XPC service hosted by the Security Extension
    ///
    /// This function calls into `RCXPCConnection.rcXPCConnection.register()` which attempts to get the Mach Serivce name:
    /// `NSEndpointSecurityMachServiceName` from the Secruity Extension and connect to the server.
    ///
    /// The XPC service name we'll be connecting to is: `com.swiftlydetecting.agent.securityextension.xpc`
    ///
    public func kickoffXPCCommunication() {
        // Connect to the XPC service! Hopefully, it's up by now.
        let bundleExtension: Foundation.Bundle = Foundation.Bundle(url: URL(fileURLWithPath: "Contents/Library/SystemExtensions/com.swiftlydetecting.agent.securityextension.systemextension", relativeTo: Bundle.main.bundleURL))!
        RCXPCConnection.rcXPCConnection.register(withExtension: bundleExtension, epDelegate: self) { registerResult in
            DispatchQueue.main.async {
                self.connectionResult = registerResult
            }
        }
    }
    
    /// For a given ES message serialize it into a `Message` JSON string
    ///
    /// - Parameters:
    ///   - rawMessage: The `es_message_t` we want to model into an `Message`
    ///   - sensorID: The computed sensor ID of the Security Extension.
    ///
    public func getEventJSON(rawMessage: UnsafePointer<es_message_t>, sensorID: String) -> String {
        let notifyEvent: Message = Message(from: rawMessage, sensorID: sensorID, forcedQuarantineSigningIDs: ProcessHelpers.forcedQuarantineSigningIDs)
        return ProcessHelpers.eventToJSON(value: notifyEvent)
    }
    
    private var appleBaselineMutedPaths = Set<String>()
    
    public func seGetAppleMuteSet() -> Set<String> { appleBaselineMutedPaths }
    
    private func captureAppleMuteSet() {
        guard appleBaselineMutedPaths.isEmpty else { return }
        appleBaselineMutedPaths = seGetGlobalMutedPaths()
    }
    
    
    // MARK: - New ES client (SE context)
    /// Get a new Endpoint Security client off the ground!
    ///
    /// This function handles kicking a new ES client into gear:
    /// 1) Instantiates a new client using `es_new_client`
    /// 2) Validates the connection result using `validateClient(result: es_new_client_result_t)`
    /// 3) Subscribes to our initial event subscriptions
    /// 4) Applies the default Projcect Sutro mute set
    /// 5) Returns the newly created ES client and the result
    ///
    /// - Parameters:
    ///   - completion: A callback that takes a String as input (our JSON event serialization)
    /// - Returns: A new `es_new_client` and a `NewClientResult`
    ///
    public func kickstartClient(completion: @escaping (_: String) -> Void)
    -> (OpaquePointer?, NewClientResult) {
        var client: OpaquePointer?
        
        let result = es_new_client(&client) { [self] _, message in
            completion(getEventJSON(rawMessage: message, sensorID: self.sensorID))
        }
        let tempConnResult = validateClient(result: result)
        guard let client else { return (nil, tempConnResult) }
        self.esClient = client
        
        // Subscribe (order here doesn't affect the snapshot)
        guard es_subscribe(client, monitoredEvents, UInt32(monitoredEvents.count)) == ES_RETURN_SUCCESS else {
            es_delete_client(client); exit(EXIT_FAILURE)
        }
        
        // Capture Apple's default mute set
        captureAppleMuteSet()
        
        // Apply Mac Monitor default mute set
        MutingEngine.applyDefaultMuteSet(client: client)
        
        os_log("🚀 New ES client created: \(String(describing: self.esClient))")
        return (client, tempConnResult)
    }
    
}

// MARK: - Event producer control
/// Extension of the ESM which handles the event producer functionality
///
/// **Functionality Covers:**
///  - Starting a system trace
///  - Stoping a system trace
///  - **Cleaning up by:**
///      - Unsubscribing from events
///      - Deleting the ES client
///
extension EndpointSecurityManager {
    /// Start recording system events.
    ///
    /// If the result of ``kickstartClient(completion:)`` was successful we'll start the event producer. Otherwise, we'll open
    /// the Full Disk Access pane of System Settings.
    public func startRecordingEvents() {
        if self.connectionResult == .notPermitted {
            NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!)
        }
        self.stopSendingEvents = false
    }
    
    /// Stop recording system events
    public func stopRecordingEvents() {
        self.stopSendingEvents = true
        // Force a final flush to make sure no events are left in the buffer.
        eventBufferQueue.async {
            self.flushEvents()
        }
    }
    
    /// Unsubscribe from event subscriptions and delete the ES client
    ///
    /// We call the following functions here to support cleanup:
    /// - `es_unsubscribe`
    /// - `es_delete_client`
    ///
    public func cleanup() {
        self.stopSendingEvents = true
        if self.esClient != nil {
            // First unsubscribe
            let unsubscribeResult: es_return_t = es_unsubscribe(self.esClient!, monitoredEvents, UInt32(monitoredEvents.count))
            switch unsubscribeResult {
            case ES_RETURN_ERROR:
                os_log(OSLogType.error, "We were unable to unsubscribe from ES!")
                break
            case ES_RETURN_SUCCESS:
                os_log("Successfully unsubscribed from ES.")
                break
            default:
                os_log(OSLogType.error, "Error unsubscribing from event subscriptions!")
            }
            
            // Then delete the client
            let deleteClientResult: es_return_t = es_delete_client(self.esClient!)
            switch deleteClientResult {
            case ES_RETURN_ERROR:
                os_log(OSLogType.error, "We were unable to delete the ES client")
                break
            case ES_RETURN_SUCCESS:
                os_log("Successfully deleted the ES client")
                self.seIsInstalled = false
                self.esClient = nil
                break
            default:
                os_log(OSLogType.error, "An unknown error occured while trying to delete the ES clinet!")
            }
        }
    }
}


// MARK: - Computed properties
extension EndpointSecurityManager {
    /// Produce the Sensor ID for the Mac Monitor Security Extension
    public var sensorID: String {
        var serialUserComboHash: String {
            let platformExpert = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice") )
            let dateFormatter = DateFormatter()
            dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSS'Z'"
            
            guard platformExpert > 0 else {
                os_log("Error platformExpert")
                return "SENSOR-ID-ERROR-" + Date().description
            }
            
            
            guard let serialNumber = (IORegistryEntryCreateCFProperty(platformExpert, kIOPlatformSerialNumberKey as CFString, kCFAllocatorDefault, 0).takeUnretainedValue() as? String)?.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines) else {
                os_log("Error serialNumber")
                return "SENSOR-ID-ERROR-" +  Date().description
            }
            
            IOObjectRelease(platformExpert)
            
            let hashData = "\(serialNumber + FileManager.default.consoleUserHome!.lastPathComponent)".data(using: .utf8)!
            let sensorID: String = "\(SHA512.hash(data: hashData).description.trimmingPrefix("SHA512 digest: "))"
            return sensorID
        }
        
        return serialUserComboHash
    }
}


// MARK: - Agent reboot
/// Extension of the ESM which handles the app reboot functionality
///
/// **Functionality Covers:**
///  - Mac Monitor expoed XPC function:  `tccRequestAppReboot()`
///    - This function will call into `xpcReboot()` --> `seRequestAgentReboot()`
///  - Security Extension expoed XPC function: `seRequestAgentReboot()`
///    - When called this function will delay for 1 second and then open "Mac Monitor.app" using `NSWorkspace`
///
extension EndpointSecurityManager {
    public func tccRequestAppReboot() {
        RCXPCConnection.rcXPCConnection.xpcReboot()
    }
    
    public static func seRequestAgentReboot() {
        let signingID: String = "com.swiftlydetecting.agent"
        
        let appURLs = LSCopyApplicationURLsForBundleIdentifier(signingID as CFString, nil)?.takeRetainedValue() as? [URL]
        
        if let appURL = appURLs?.first {
            let workspace = NSWorkspace.shared
            let configuration = NSWorkspace.OpenConfiguration()
            
            // Request agent reboot after 1 second
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                workspace.openApplication(at: appURL, configuration: configuration, completionHandler: { (app, error) in
                    if let error = error {
                        os_log("Unable to open agent: \(error.localizedDescription)")
                    }
                })
            }
        } else {
            os_log("Agent not found")
        }
    }
}
