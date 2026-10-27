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

/// Manages XPC, System Extension, and event producer functionality
///
///
/// The "Endpoint Security Manager" (ESM) exposes functionality to interact with the Mac Monitor Security Extension `com.swiftlydetecting.agent.securityextension`
///
/// **Context:** Mac Monitor (the agent). It talks to the Security Extension through `sensor` and receives events, and
/// an update's progress, as an ``AppAgentProtocol``. In the Security Extension (the sensor), `SensorService` runs
/// capture with a ``CaptureSession``.
///
public class EndpointSecurityManager: NSObject, ObservableObject, OSSystemExtensionRequestDelegate, AppAgentProtocol {
    /// Decodes incoming events. Only used on the XPC connection's serial queue.
    let decoder = JSONDecoder()
    /// Batch events that didn't decode since the last fault, and the first one's error. Only used on the XPC
    /// connection's serial queue.
    private var undecodable: (count: Int, firstError: Error?) = (0, nil)
    /// When that fault was last logged, in uptime nanoseconds. Only used on the XPC connection's serial queue.
    private var undecodableFaultTime: UInt64?
    
    // MARK: XPC
    /// Our connection to the Security Extension (agent context).
    ///
    /// Created on first use. The first use is always on the main thread (an XPC request from the UI or the System
    /// Extension activation delegate), before any connection handler can run. Its signals arrive on the main thread.
    lazy var sensor = SensorClient(agent: self) { [weak self] signal in
        /// Anyone can post these signals, so one that arrives while the same kind is already pending is dropped: a
        /// flood of posts costs at most one handshake per kind per second.
        guard let self, self.pendingSignals.insert(signal).inserted else { return }
        /// Give launchd / sysextd a moment to settle, then decide whether to redo the `start` handshake:
        /// - Never if we haven't handshaked before: an app launched with `--deactivate-security-extension` (or one that
        ///   only checked for updates) must not start monitoring on its own.
        /// - `.restarted`: the previous owner, or an instance Endpoint Security refused, takes the stream. An instance
        ///   the owner refused doesn't, so it can't win the race.
        /// - `.released`: only an instance that was refused, by the owner (`.streamOwned`) or by Endpoint Security
        ///   (`.tooManyClients`, which a closed `macmonitor` stream may have freed), tries again.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
            self?.pendingSignals.remove(signal)
            guard let self, self.connectionResult != .waiting else { return }
            let wasRefused = [.streamOwned, .tooManyClients].contains(self.connectionResult)
            switch signal {
            case .restarted where self.connectionResult == .streamOwned, .released where !wasRefused:
                return
            case .restarted, .released:
                self.kickoffXPCCommunication()
            }
        }
    }
    
    /// Signals from ``sensor`` waiting out their one-second delay. Main thread only.
    private var pendingSignals: Set<SensorClient.Signal> = []
    
    // MARK: Updates
    /// Where the update being installed is, or `nil` when none is (see ``installUpdate(completion:)``).
    @Published public var installProgress: UpdateProgress?
    
    // MARK: Event subscriptions
    /// The Security Extension's event subscriptions, as `ES_EVENT_TYPE_*` names (see ``requestEventSubscriptions()``).
    @Published public var monitoredEventStrings: Set<String> = []
    
    // MARK: Muting Enging properties
    /// The saved mute set, as the Security Extension last sent it (see ``requestMutes(_:from:completion:)``).
    @Published public var savedMutes: [ESMutedPath] = []
    /// Something to tell the user about the saved mute set: it was recovered, or can't be changed.
    @Published public var muteNotice: String?
    /// What the Security Extension last said this Mac Monitor may do with the saved mute set, or `nil` until it says.
    @Published public var savedMutesAccess: MuteAccess?
    /// What the Security Extension refused or left out of the last change asked for in Settings, which shows it.
    @Published public var muteProblems: [String] = []
    /// What the Security Extension refused or left out of the last mute asked for from an event's menu, which the
    /// main window shows.
    @Published public var eventMuteProblems: [String] = []
    @Published public var appleMuteSet = Set<String>()
    
    // MARK: Install properties
    /// The Security Extension, as macOS and the last activation request report it (see ``requirements``).
    @Published public var extensionState: SetupRequirements.ExtensionState = .checking
    @Published public var connectionResult: NewClientResult = .waiting
    /// The deactivation request in flight, whose delegate calls aren't an activation's. Main thread only.
    var deactivationRequest: OSSystemExtensionRequest?
    /// The properties request in flight, whose delegate calls aren't an activation's. Main thread only.
    var propertiesRequest: OSSystemExtensionRequest?
    /// Has ``checkExtensionAtLaunch()`` run? Main thread only.
    var checkedAtLaunch = false
    /// Does the properties request in flight decide whether to activate (``checkExtensionAtLaunch()``)? Main thread
    /// only.
    var decidesActivation = false
    
    /// Reference to the shared Core Data Controller (agent context).
    ///
    /// Lazy so the Security Extension, which never stores events, doesn't create a Core Data stack or store file as
    /// root.
    public lazy var coreDataContainer = CoreDataController.shared
    
    /// The Sensor ID for this Mac and console user, as shown in Mac Monitor (agent context). Computed on first use.
    public private(set) lazy var sensorID: String = EndpointSecurityManager.makeSensorID()
    
    /// Is the user recording? Sent to the Security Extension with every handshake, which only serializes events while
    /// it's `true`.
    ///
    /// Thread-safe. It's read from the XPC queue and written from the main thread.
    public var isRecording: Bool {
        get { recordingState.withLock { $0 } }
        set { recordingState.withLock { $0 = newValue } }
    }
    private let recordingState = OSAllocatedUnfairLock(initialState: false)
    
    /// Should we drop platform binaries?
    ///
    /// Thread-safe. It's read from the XPC queue and toggled from the main thread.
    private let dropPlatformBinaries = OSAllocatedUnfairLock(initialState: false)
    
    // MARK: - Batching Properties
    /// A temporary, thread-safe buffer for incoming events before they are sent to Core Data.
    private var eventBuffer: [Message] = []
    /// XPC replies for the batches in ``eventBuffer``. Sent once those events are saved (see ``flushEvents()``).
    private var pendingReplies: [() -> Void] = []
    /// A dedicated serial queue to ensure thread-safe access to the eventBuffer.
    private let eventBufferQueue = DispatchQueue(label: "com.swiftlydetecting.agent.eventBufferQueue")
    /// A high-performance GCD timer to periodically flush the event buffer.
    private var flushTimer: DispatchSourceTimer?
    /// How often buffered events are saved
    private static let flushInterval: TimeInterval = 0.1
    /// Save early once this many events are buffered
    private static let flushSize = 2_000
    
    public override init() {
        super.init()
        setupFlushTimer()
    }
    
    /// Should we be dropping platform binaries?
    ///
    /// Utilizing the concept of "critical" eventing events see: ``EventType/isCritical``.
    public func togglePlatformBinaries() {
        dropPlatformBinaries.withLock { $0.toggle() }
    }
    
    // MARK: - Incoming events
    
    /// Handle a batch of incoming Endpoint Security events (`Message`) from the Security Extension (``AgentProtocol``).
    ///
    /// This function is the entry point for all events from the XPC service.
    /// Its job is to quickly decode the incoming JSON and add the resulting `Message` objects to a buffer.
    /// A separate, timer-based process flushes this buffer to Core Data, preventing the UI from being blocked by high event volume.
    ///
    /// The reply is held until the batch has been saved to Core Data. That's the back-pressure: when inserts fall
    /// behind, the Security Extension stops sending and spools to disk instead of this process growing without bound.
    ///
    /// Execs and forks from an older Security Extension get their launched-by parent here.
    ///
    /// Batches are accepted even after recording stops: the Security Extension stops serializing at the source, so
    /// anything still arriving was recorded before Stop and belongs in the trace. A Clear discards older events by time
    /// instead. See ``CoreDataController/clearSystemEvents(source:)``.
    ///
    /// - Parameters:
    ///   - events: JSON serializations of `Message`, oldest first.
    ///   - reply: Lets the Security Extension send its next batch.
    public func receive(events: [Data], reply: @escaping () -> Void) {
        // Quickly decode the JSON.
        var firstError: Error?
        let decoded: [Message] = events.compactMap { event in
            do {
                return try decoder.decode(Message.self, from: event)
            } catch {
                firstError = firstError ?? error
                return nil
            }
        }
        if let firstError { noteUndecodable(events.count - decoded.count, firstError) }
        let dropping = dropPlatformBinaries.withLock { $0 }
        var messages: [Message] = decoded.filter { shouldInsert($0, droppingPlatformBinaries: dropping) }
        guard !messages.isEmpty else { return reply() }
        /// An exec or fork without a launched-by parent (from an older Security Extension) gets one, with its parent's
        /// path read now.
        for index in messages.indices { messages[index].resolveLaunchedByParent(by: .app, path: ProcessPath.live) }
        
        eventBufferQueue.async { [messages] in
            self.eventBuffer.append(contentsOf: messages)
            self.pendingReplies.append(reply)
            
            // Save early when the buffer is full or half the Security Extension's window is waiting on us.
            if self.eventBuffer.count >= Self.flushSize
                || self.pendingReplies.count >= SensorXPC.maxBatchesInFlight / 2 {
                self.flushEvents()
                self.restartFlushTimer()
            }
        }
    }
    
    /// Log a fault for batch events that didn't decode, at most once a minute. Call on the XPC connection's queue.
    ///
    /// The fault counts every event lost since the last one and gives the first error.
    ///
    /// - Parameters:
    ///   - count: This batch's events that didn't decode.
    ///   - error: The first one's error.
    private func noteUndecodable(_ count: Int, _ error: Error) {
        undecodable.count += count
        undecodable.firstError = undecodable.firstError ?? error
        let now = DispatchTime.now().uptimeNanoseconds
        if let last = undecodableFaultTime, now - last < 60_000_000_000 { return }
        undecodableFaultTime = now
        let (lost, first) = (undecodable.count, String(describing: undecodable.firstError ?? error))
        Logger(subsystem: "com.swiftlydetecting.agent", category: "EndpointSecurityManager").fault("""
            \(lost) events from the Security Extension didn't decode and were dropped. The first error: \
            \(first, privacy: .public)
            """)
        undecodable = (0, nil)
    }
    
    /// Should this event be kept given the "drop platform binaries" setting?
    ///
    /// - Parameters:
    ///   - message: A decoded event.
    ///   - dropping: Are platform binaries being dropped?
    /// - Returns: `true` unless platform binaries are being dropped and this event is a non-critical one from a
    ///   platform binary.
    private func shouldInsert(_ message: Message, droppingPlatformBinaries dropping: Bool) -> Bool {
        guard dropping, message.process.is_platform_binary, !message.event.isCritical else {
            return true
        }
        if let exec = message.event.exec { return !exec.target.is_platform_binary }
        if let fork = message.event.fork { return !fork.child.is_platform_binary }
        return false
    }
    
    /// Configures and starts a GCD timer to periodically flush the event buffer.
    /// This runs on a background queue to avoid impacting the main thread.
    private func setupFlushTimer() {
        flushTimer = DispatchSource.makeTimerSource(queue: eventBufferQueue)
        flushTimer?.schedule(deadline: .now() + Self.flushInterval, repeating: Self.flushInterval)
        flushTimer?.setEventHandler { [weak self] in
            self?.flushEvents()
        }
        flushTimer?.resume()
    }
    
    /// Start the timer's interval over after an early save.
    private func restartFlushTimer() {
        flushTimer?.schedule(deadline: .now() + Self.flushInterval, repeating: Self.flushInterval)
    }
    
    /// Takes the current batch of events from the buffer and sends them to the CoreDataController, then acknowledges
    /// the XPC batches they came from once they're saved.
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
    /// (refusing any other with `.streamOwned`) and only starts capture when it isn't running. It's called when the
    /// System Extension activation finishes and again after the Security Extension restarts (see `sensor`). The current
    /// recording state rides along so a restarted extension resumes streaming.
    ///
    /// The XPC service name we'll be connecting to is ``SensorXPC/machServiceName``.
    ///
    public func kickoffXPCCommunication() {
        sensor.call { $0.start(recording: self.isRecording, reply: $1) } completion: { result in
            self.connectionResult = result ?? .internalSubsystem
        }
    }
    
}

// MARK: - Event producer control
/// Extension of the ESM which handles the event producer functionality
///
/// **Functionality Covers:**
///  - Starting a system trace
///  - Stoping a system trace
///
extension EndpointSecurityManager {
    /// Start recording system events.
    ///
    /// If the Security Extension couldn't start capture for lack of Full Disk Access (`.notPermitted`), we'll open the
    /// Full Disk Access pane of System Settings.
    ///
    /// The Security Extension only serializes events while recording, so this is what turns the event stream on.
    public func startRecordingEvents() {
        if self.connectionResult == .notPermitted {
            NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!)
        }
        self.isRecording = true
        sensor.call { $0.setRecording(true, reply: $1) } completion: { hasClient in
            /// No ES client (e.g. the extension was re-enabled after we last handshaked): handshake again. `start`
            /// carries `isRecording`, so recording resumes as part of it.
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
}


// MARK: - Sensor ID
extension EndpointSecurityManager {
    /// Produce the Sensor ID for the Mac Monitor Security Extension
    ///
    /// A SHA-512 of the platform serial number and the console user's short name. It's computed by a
    /// ``CaptureSession`` as it starts and on every `start` handshake (sensor), and once for display (agent), never per
    /// event.
    ///
    /// - Returns: The hex digest, or `SENSOR-ID-ERROR-<date>` if the serial number can't be read. When no user is at
    ///   the console (e.g. `loginwindow`) only the serial number is hashed.
    static func makeSensorID() -> String {
        let platformExpert = IOServiceGetMatchingService(
            kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice")
        )
        defer { IOObjectRelease(platformExpert) }
        /// `IORegistryEntryCreateCFProperty` follows the Create rule, so we take ownership of the returned value.
        guard platformExpert > 0, let serialNumber = (IORegistryEntryCreateCFProperty(
            platformExpert, kIOPlatformSerialNumberKey as CFString, kCFAllocatorDefault, 0
        )?.takeRetainedValue() as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) else {
            os_log("Error reading the platform serial number")
            return "SENSOR-ID-ERROR-" + Date().description
        }
        
        let name = ConsoleUserSource.system.session()?.name ?? ""
        let consoleUser = name == "loginwindow" ? "" : name
        let hashData = Data((serialNumber + consoleUser).utf8)
        return SHA512.hash(data: hashData).withUnsafeBytes { ESLogger.hex(bytes: $0, uppercase: false) }
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
