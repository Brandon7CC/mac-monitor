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
import os
import AppKit
import CryptoKit

// TODO: Candidate for `@Observable`

/// Manages XPC, System Extension, and event producer functionality
///
///
/// The "Endpoint Security Manager" (ESM) exposes functionality to interact with the Mac Monitor Security Extension `com.swiftlydetecting.agent.securityextension`
///
/// **Contexts:** the same class runs in both processes.
/// - Agent (Mac Monitor): talks to the Security Extension through `sensor` and receives events as an ``AgentProtocol``.
/// - Sensor (Security Extension): owns the Endpoint Security client. `SensorService` drives it over XPC.
///
public class EndpointSecurityManager: NSObject, ObservableObject, OSSystemExtensionRequestDelegate, AgentProtocol {
    /// Decodes incoming events. Only used on the XPC connection's serial queue.
    let decoder = JSONDecoder()
    
    // MARK: XPC
    /// Our connection to the Security Extension (agent context).
    ///
    /// Created on first use. The first use is always on the main thread (an XPC request from the UI or the System
    /// Extension activation delegate), before any connection handler can run.
    lazy var sensor = SensorClient(agent: self) { [weak self] signal in
        /// Anyone can post these signals, so one that arrives while the same kind is already pending is dropped: a flood
        /// of posts costs at most one handshake per kind per second.
        guard let self, self.pendingSignals.insert(signal).inserted else { return }
        /// Give launchd / sysextd a moment to settle, then decide whether to redo the `start` handshake:
        /// - Never if we haven't handshaked before: an app launched with `--deactivate-security-extension` (or one that only
        ///   checked for updates) must not start monitoring on its own.
        /// - `.restarted`: only the previous owner reclaims the stream, so a refused instance can't win the race.
        /// - `.released`: only an instance that was refused (`.tooManyClients`) competes for the free stream.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
            self?.pendingSignals.remove(signal)
            guard let self, self.connectionResult != .waiting else { return }
            let wasRefused = self.connectionResult == .tooManyClients
            switch signal {
            case .restarted where wasRefused, .released where !wasRefused:
                return
            case .restarted, .released:
                self.kickoffXPCCommunication()
            }
        }
    }
    
    /// Signals from ``sensor`` waiting out their one-second delay. Main thread only.
    private var pendingSignals: Set<SensorClient.Signal> = []
    
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
    
    /// Reference to the shared Core Data Controller (agent context).
    ///
    /// Lazy so the Security Extension, which never stores events, doesn't create a Core Data stack or store file as root.
    public lazy var coreDataContainer = CoreDataController.shared
    
    /// The Sensor ID for this Mac and console user, as shown in Mac Monitor (agent context). Computed on first use.
    public private(set) lazy var sensorID: String = EndpointSecurityManager.makeSensorID()
    
    /// The Sensor ID stamped on each event (sensor context).
    ///
    /// The Security Extension outlives logouts and user switches, so this is refreshed on every `start` handshake (see
    /// ``kickstartClient(emit:)``) rather than cached for the life of the process. Read by the ES handler, so it's locked.
    private let eventSensorID = OSAllocatedUnfairLock(initialState: "")
    
    /// Should events flow?
    ///
    /// - Agent context: whether the user is recording. Sent to the Security Extension with every handshake.
    /// - Sensor context: serialize Endpoint Security events at all. While `false` the ES handler returns immediately.
    ///
    /// Thread-safe. It's read from the XPC and Endpoint Security queues and written from the main thread or the
    /// Security Extension's service queue.
    public var isRecording: Bool {
        get { recordingState.withLock { $0 } }
        set { recordingState.withLock { $0 = newValue } }
    }
    private let recordingState = OSAllocatedUnfairLock(initialState: false)
    
    /// Should we drop platform binaries?
    private var dropPlatformBinaries: Bool = false
    
    // MARK: - Batching Properties
    /// A temporary, thread-safe buffer for incoming events before they are sent to Core Data.
    private var eventBuffer: [Message] = []
    /// XPC replies for the batches in ``eventBuffer``. Sent once those events are saved (see ``flushEvents()``).
    private var pendingReplies: [() -> Void] = []
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
    
    /// Handle a batch of incoming Endpoint Security events (`Message`) from the Security Extension (``AgentProtocol``).
    ///
    /// This function is the entry point for all events from the XPC service.
    /// Its job is to quickly decode the incoming JSON and add the resulting `Message` objects to a buffer.
    /// A separate, timer-based process flushes this buffer to Core Data, preventing the UI from being blocked by high event volume.
    ///
    /// The reply is held until the batch has been saved to Core Data. That's the back-pressure: when inserts fall behind,
    /// the Security Extension stops sending and spools to disk instead of this process growing without bound.
    ///
    /// Batches are accepted even after recording stops: the Security Extension stops serializing at the source, so anything
    /// still arriving was recorded before Stop and belongs in the trace. (A Clear discards older events by time instead;
    /// see ``CoreDataController/clearSystemEvents(source:)``.)
    ///
    /// - Parameters:
    ///   - events: JSON serializations of `Message`, oldest first.
    ///   - reply: Lets the Security Extension send its next batch.
    public func receive(events: [Data], reply: @escaping () -> Void) {
        // Quickly decode the JSON.
        let decoded: [Message] = events.compactMap { try? decoder.decode(Message.self, from: $0) }
        // Track event rate for dynamic throttling
        throttleManager.registerEvents(decoded.count)
        
        let messages: [Message] = decoded.filter(shouldInsert)
        guard !messages.isEmpty else { return reply() }
        
        eventBufferQueue.async {
            self.eventBuffer.append(contentsOf: messages)
            self.pendingReplies.append(reply)
            
            let hardBufferLimit = 5000
            if self.eventBuffer.count >= hardBufferLimit {
                // Force flush at hard limit
                self.flushEvents()
                self.updateFlushTimer()
            } else if self.eventBuffer.count >= self.currentBatchSize || self.pendingReplies.count >= SensorXPC.maxBatchesInFlight / 2 {
                // Normal dynamic batching, or half the Security Extension's window is waiting on us
                self.flushEvents()
                self.updateFlushTimer()
            }
        }
    }
    
    /// Should this event be kept given the "drop platform binaries" setting?
    ///
    /// - Parameter message: A decoded event.
    /// - Returns: `true` unless platform binaries are being dropped and this event is a non-critical one from a platform binary.
    private func shouldInsert(_ message: Message) -> Bool {
        guard self.dropPlatformBinaries else { return true }

        if !message.process.is_platform_binary || isEventCritical(message: message) {
            return true
        } else if let exec = message.event.exec, !exec.target.is_platform_binary {
            return true
        } else if let fork = message.event.fork, !fork.child.is_platform_binary {
            return true
        }
        return false
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
    
    /// Takes the current batch of events from the buffer and sends them to the CoreDataController, then acknowledges the
    /// XPC batches they came from once they're saved.
    /// This function is always called on the `eventBufferQueue`.
    private func flushEvents() {
        guard !self.eventBuffer.isEmpty || !self.pendingReplies.isEmpty else { return }
        
        let batchToProcess = self.eventBuffer
        let replies = self.pendingReplies
        /// Start over with fresh arrays. `removeAll(keepingCapacity:)` would hand each queued batch a full-size buffer
        /// (each `Message` is ~4 KB), which is how a backlog used to pin hundreds of GB of address space (#84).
        self.eventBuffer = []
        self.pendingReplies = []
        
        // Pass the entire batch to Core Data for processing.
        self.coreDataContainer.insertSystemEvents(messages: batchToProcess) {
            replies.forEach { $0() }
        }
    }
    
    // MARK: - XPC Entry
    
    /// Connect to the XPC service hosted by the Security Extension and run the `start` handshake.
    ///
    /// Safe to call any number of times: the Security Extension re-handshakes the connection that owns the event stream
    /// (refusing any other with `.tooManyClients`) and only creates an ES client when none exists. It's called when the System Extension activation finishes and again after the Security Extension
    /// restarts (see `sensor`). The current recording state rides along so a restarted extension resumes streaming.
    ///
    /// The XPC service name we'll be connecting to is ``SensorXPC/machServiceName``.
    ///
    public func kickoffXPCCommunication() {
        sensor.call { $0.start(recording: self.isRecording, reply: $1) } completion: { result in
            self.connectionResult = result ?? .internalSubsystem
        }
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
    /// 5) Returns the result
    ///
    /// Idempotent: when an ES client already exists it's reused and `emit` is **not** replaced. Callers should route
    /// events through state they own (as `SensorService` does) rather than capturing per-call state in `emit`.
    ///
    /// The ES handler does no work while ``isRecording`` is `false`. The sensor ID is refreshed here on every call (so it
    /// follows the console user across logouts and user switches) and read by the handler, never recomputed per event.
    ///
    /// - Parameters:
    ///   - emit: Receives each event's JSON serialization. Called serially on the Endpoint Security client's queue.
    /// - Returns: The `NewClientResult` of creating (or reusing) the client.
    ///
    public func kickstartClient(emit: @escaping (_ event: Data) -> Void) -> NewClientResult {
        let currentSensorID: String = EndpointSecurityManager.makeSensorID()
        eventSensorID.withLock { $0 = currentSensorID }
        guard self.esClient == nil else { return .success }
        
        /// Only used by the ES handler, which Endpoint Security calls serially for a client.
        let encoder = JSONEncoder()
        var client: OpaquePointer?
        
        let result = es_new_client(&client) { [self] _, message in
            guard self.isRecording else { return }
            let event = Message(from: message, sensorID: self.eventSensorID.withLock { $0 }, forcedQuarantineSigningIDs: ProcessHelpers.forcedQuarantineSigningIDs)
            guard let json = try? encoder.encode(event) else { return }
            emit(json)
        }
        let tempConnResult = validateClient(result: result)
        guard let client else { return tempConnResult }
        
        // Subscribe (order here doesn't affect the snapshot)
        guard es_subscribe(client, monitoredEvents, UInt32(monitoredEvents.count)) == ES_RETURN_SUCCESS else {
            os_log(OSLogType.error, "Failed to subscribe the new Endpoint Security client to its events!")
            es_delete_client(client)
            return .internalSubsystem
        }
        self.esClient = client
        
        // Capture Apple's default mute set
        captureAppleMuteSet()
        
        // Apply Mac Monitor default mute set
        MutingEngine.applyDefaultMuteSet(client: client)
        
        os_log("🚀 New ES client created: \(String(describing: self.esClient))")
        return tempConnResult
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
    /// If the result of ``kickstartClient(emit:)`` was successful we'll start the event producer. Otherwise, we'll open
    /// the Full Disk Access pane of System Settings.
    ///
    /// The Security Extension only serializes events while recording, so this is what turns the event stream on.
    public func startRecordingEvents() {
        if self.connectionResult == .notPermitted {
            NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!)
        }
        self.isRecording = true
        sensor.call { $0.setRecording(true, reply: $1) } completion: { hasClient in
            /// No ES client (e.g. the extension was re-enabled after we last handshaked): handshake again. `start` carries
            /// `isRecording`, so recording resumes as part of it.
            if hasClient != true { self.kickoffXPCCommunication() }
        }
    }
    
    /// Stop recording system events
    ///
    /// Also tells the Security Extension to stop serializing events, so an idle Mac Monitor costs it nothing per event.
    public func stopRecordingEvents() {
        self.isRecording = false
        sensor.call { $0.setRecording(false, reply: $1) }
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
    /// In the agent context there is no ES client, so this only clears the local ``isRecording`` flag; it's
    /// ``stopRecordingEvents()`` that tells the Security Extension to stop.
    ///
    public func cleanup() {
        self.isRecording = false
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
            /// The pointer is invalid either way: on `ES_RETURN_ERROR` ES has already torn the client down and leaked its
            /// resources (see `ESClient.h`). Keeping it would make ``kickstartClient(emit:)`` reuse a dead client.
            self.esClient = nil
            switch deleteClientResult {
            case ES_RETURN_ERROR:
                os_log(OSLogType.error, "We were unable to delete the ES client")
                break
            case ES_RETURN_SUCCESS:
                os_log("Successfully deleted the ES client")
                self.seIsInstalled = false
                break
            default:
                os_log(OSLogType.error, "An unknown error occured while trying to delete the ES clinet!")
            }
        }
    }
}


// MARK: - Sensor ID
extension EndpointSecurityManager {
    /// Produce the Sensor ID for the Mac Monitor Security Extension
    ///
    /// A SHA-512 of the platform serial number and the console user's short name. It's computed on every
    /// ``kickstartClient(emit:)`` handshake (sensor) and once for display (agent), never per event.
    ///
    /// - Returns: The hex digest, or `SENSOR-ID-ERROR-<date>` if the serial number can't be read. When no user is at the
    ///   console (e.g. `loginwindow`) only the serial number is hashed.
    static func makeSensorID() -> String {
        let platformExpert = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        guard platformExpert > 0 else {
            os_log("Error platformExpert")
            return "SENSOR-ID-ERROR-" + Date().description
        }
        defer { IOObjectRelease(platformExpert) }
        
        /// `IORegistryEntryCreateCFProperty` follows the Create rule, so we take ownership of the returned value.
        guard let serialNumber = (IORegistryEntryCreateCFProperty(platformExpert, kIOPlatformSerialNumberKey as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? String)?.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines) else {
            os_log("Error serialNumber")
            return "SENSOR-ID-ERROR-" + Date().description
        }
        
        let consoleUser: String = FileManager.default.consoleUserHome?.lastPathComponent ?? ""
        let hashData = Data((serialNumber + consoleUser).utf8)
        return "\(SHA512.hash(data: hashData).description.trimmingPrefix("SHA512 digest: "))"
    }
}


// MARK: - Agent relaunch
/// Extension of the ESM which handles the app relaunch functionality
///
/// Mac Monitor relaunches itself (e.g. after Full Disk Access is granted or an update is installed). This used to be
/// an XPC round trip asking the root Security Extension to find and open the app through Launch Services. Now the app
/// hands a tiny shell script the exact bundle path and its own PID before it quits.
///
extension EndpointSecurityManager {
    /// Waits up to 10 seconds (50 × 0.2s) for PID `$2` to exit, then opens the bundle at `$1`.
    ///
    /// If the app is still running after 10 seconds (the user cancelled the quit) nothing is opened.
    private static let relaunchScript: String = """
        i=0
        while /bin/kill -0 "$2" 2>/dev/null; do
            [ "$i" -ge 50 ] && exit 0
            /bin/sleep 0.2
            i=$((i + 1))
        done
        exec /usr/bin/open "$1"
        """
    
    /// Relaunch Mac Monitor once this process exits. Call it right before terminating the app.
    public func requestAgentRelaunch() {
        let relaunch = Foundation.Process()
        relaunch.executableURL = URL(fileURLWithPath: "/bin/sh")
        relaunch.arguments = ["-c", Self.relaunchScript, "relaunch", Bundle.main.bundlePath, String(getpid())]
        do {
            try relaunch.run()
        } catch {
            os_log(OSLogType.error, "Unable to schedule the Mac Monitor relaunch: \(error.localizedDescription)")
        }
    }
}
