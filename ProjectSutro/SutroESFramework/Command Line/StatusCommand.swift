//
//  StatusCommand.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/9/26.
//

import Foundation


// MARK: - Invocation
/// `macmonitor status [--json]`.
public struct StatusInvocation: Equatable {
    /// Write JSON, for a script, rather than text? `--json`.
    public var json: Bool

    /// - Parameter json: Write JSON rather than text?
    public init(json: Bool = false) {
        self.json = json
    }
}


// MARK: - Status
/// What `macmonitor status` shows: the versions of `macmonitor`, Mac Monitor and its Security Extension, what the
/// Security Extension needs to run (activated, and Full Disk Access), and who is capturing through it (Mac Monitor
/// and `macmonitor` streams).
///
/// It needs neither root nor Mac Monitor: every part it can't learn says so, and the rest is still shown. It never
/// changes anything.
public struct StatusReport: Encodable, Equatable {
    /// The versions, each such as "3.1.0 (1)".
    public struct Versions: Equatable {
        /// `macmonitor`'s own.
        public var macmonitor: String
        /// Mac Monitor's, the app `macmonitor` is part of, or `nil` when it isn't in one.
        public var mac_monitor: String?
        /// The running Security Extension's, or `nil` when it didn't answer.
        public var security_extension: String?
    }

    /// What the Security Extension needs to run.
    public struct Requirements: Equatable {
        /// What macOS says of the System Extension, such as "activated enabled", or `nil` when it lists none.
        public var system_extension: String?
        /// Is it activated and enabled?
        public var activated: Bool
        /// Does it have Full Disk Access? `nil` when it couldn't be asked, or Endpoint Security refused it for another
        /// reason.
        public var full_disk_access: Bool?
        /// What Endpoint Security answers it (``SensorReport/EndpointSecurity-swift.enum``), or `nil` when it
        /// couldn't be asked.
        public var endpoint_security: String?
        /// Why it couldn't be asked, or `nil`.
        public var problem: String?
    }

    /// Who is capturing through the Security Extension. `nil` fields when it couldn't be asked.
    public struct Capturing: Equatable {
        /// Is a Mac Monitor connected?
        public var mac_monitor_connected: Bool?
        /// Is it recording?
        public var mac_monitor_recording: Bool?
        /// How many `macmonitor` streams are running.
        public var streams: Int?
        /// The most at once.
        public var stream_capacity: Int?
    }

    public var versions: Versions
    public var security_extension: Requirements
    public var capturing: Capturing

    /// - Parameters:
    ///   - tool: `macmonitor`'s version.
    ///   - app: Mac Monitor's version, or `nil` when `macmonitor` isn't in the app.
    ///   - systemExtension: What macOS says of the System Extension (``SystemExtensionList/state(of:in:)``).
    ///   - answer: The Security Extension's answer to a status request, or why there's none.
    public init(tool: String, app: String?, systemExtension: String?,
                answer: Result<StreamReply, CommandLineFailure>) {
        let reply = try? answer.get()
        let report = reply?.status == .ok ? reply?.report : nil
        versions = Versions(macmonitor: tool, mac_monitor: app,
                            security_extension: reply.map(\.sensorVersion).flatMap { $0.isEmpty ? nil : $0 })
        security_extension = Requirements(
            system_extension: systemExtension, activated: systemExtension == SystemExtensionList.activated,
            full_disk_access: Self.fullDiskAccess(report?.endpointSecurity),
            endpoint_security: report?.endpointSecurity.rawValue, problem: Self.problem(answer))
        capturing = Capturing(mac_monitor_connected: report?.app.connected,
                              mac_monitor_recording: report?.app.recording, streams: report?.streams,
                              stream_capacity: report?.streamCapacity)
    }

    /// Every key, with `null` for what isn't known, so a script always finds the same keys.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: When a value can't be encoded.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: Key.self)
        var versions = container.nestedContainer(keyedBy: Key.self, forKey: Key("versions"))
        try versions.encode(self.versions.macmonitor, forKey: Key("macmonitor"))
        try versions.encode(self.versions.mac_monitor, forKey: Key("mac_monitor"))
        try versions.encode(self.versions.security_extension, forKey: Key("security_extension"))
        var needs = container.nestedContainer(keyedBy: Key.self, forKey: Key("security_extension"))
        try needs.encode(security_extension.system_extension, forKey: Key("system_extension"))
        try needs.encode(security_extension.activated, forKey: Key("activated"))
        try needs.encode(security_extension.full_disk_access, forKey: Key("full_disk_access"))
        try needs.encode(security_extension.endpoint_security, forKey: Key("endpoint_security"))
        try needs.encode(security_extension.problem, forKey: Key("problem"))
        var capturing = container.nestedContainer(keyedBy: Key.self, forKey: Key("capturing"))
        try capturing.encode(self.capturing.mac_monitor_connected, forKey: Key("mac_monitor_connected"))
        try capturing.encode(self.capturing.mac_monitor_recording, forKey: Key("mac_monitor_recording"))
        try capturing.encode(self.capturing.streams, forKey: Key("streams"))
        try capturing.encode(self.capturing.stream_capacity, forKey: Key("stream_capacity"))
    }

    /// A key of the JSON, by its name.
    private struct Key: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }

        /// - Parameter name: The key.
        init(_ name: String) {
            stringValue = name
        }

        init?(stringValue: String) {
            self.stringValue = stringValue
        }

        init?(intValue: Int) {
            nil
        }
    }

    /// - Parameter answer: What Endpoint Security answers the Security Extension, or `nil` when it couldn't be asked.
    /// - Returns: Whether it has Full Disk Access: `true` when Endpoint Security allows it a client, `false` when it's
    ///   refused for Full Disk Access, and `nil` when it's refused for another reason or couldn't be asked.
    private static func fullDiskAccess(_ answer: SensorReport.EndpointSecurity?) -> Bool? {
        switch answer {
        case .ok?: return true
        case .notPermitted?: return false
        case .notEntitled?, .tooManyClients?, .failed?, nil: return nil
        }
    }

    /// - Parameter answer: The Security Extension's answer to a status request, or why there's none.
    /// - Returns: Why it says nothing of itself, or `nil` when it does.
    private static func problem(_ answer: Result<StreamReply, CommandLineFailure>) -> String? {
        switch answer {
        case .failure(let failure):
            return failure.message
        case .success(let reply) where reply.status == .ok && reply.report != nil:
            return nil
        case .success(let reply) where reply.status == .refused:
            return "This Security Extension only tells root: it's older than macmonitor. Run 'sudo macmonitor status'."
        case .success:
            return "The Security Extension is older than macmonitor and can't say. Open Mac Monitor to update it."
        }
    }

    /// Is the Security Extension ready to capture: activated, answering, and allowed an Endpoint Security client?
    public var isReady: Bool {
        security_extension.activated
            && security_extension.endpoint_security == SensorReport.EndpointSecurity.ok.rawValue
    }
}


// MARK: - Writing
/// Writes a ``StatusReport`` as text or JSON.
public enum StatusCommand {
    /// - Parameters:
    ///   - report: The status.
    ///   - json: Write JSON rather than text?
    /// - Returns: What `macmonitor status` prints, ending in a newline.
    public static func output(_ report: StatusReport, json: Bool) -> String {
        json ? self.json(report) : text(report)
    }

    /// - Parameter report: The status.
    /// - Returns: It as pretty JSON with sorted keys, ending in a newline. A part that isn't known is `null`.
    static func json(_ report: StatusReport) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = (try? encoder.encode(report)) ?? Data("{}".utf8)
        return String(decoding: data, as: UTF8.self) + "\n"
    }

    /// - Parameter report: The status.
    /// - Returns: It as text: a titled group for each part, one fact a line.
    static func text(_ report: StatusReport) -> String {
        let needs = report.security_extension, capturing = report.capturing
        var groups: [(title: String, rows: [(String, String)])] = [
            ("Versions", [("macmonitor", report.versions.macmonitor),
                          ("Mac Monitor", report.versions.mac_monitor ?? "not found"),
                          ("Security Extension", report.versions.security_extension ?? "no answer")]),
            ("Security Extension", [
                ("Activated", needs.activated ? "yes" : "no (\(needs.system_extension ?? "not installed"))"),
                ("Full Disk Access", fullDiskAccess(needs))]),
            ("Capturing", [("Mac Monitor", app(capturing)), ("macmonitor streams", streams(capturing))]),
        ]
        if let problem = needs.problem { groups[1].rows.append(("Note", problem)) }
        let width = groups.flatMap(\.rows).map(\.0.count).max() ?? 0
        let lines = groups.map { group in
            ([group.title] + group.rows.map { name, value in
                "  \(name.padding(toLength: width, withPad: " ", startingAt: 0))   \(TerminalSafeText.text(value))"
            }).joined(separator: "\n")
        }
        return lines.joined(separator: "\n\n") + "\n"
    }

    /// - Parameter needs: What the Security Extension needs.
    /// - Returns: Whether it has Full Disk Access, or what else Endpoint Security answered, or that it isn't known.
    private static func fullDiskAccess(_ needs: StatusReport.Requirements) -> String {
        switch needs.endpoint_security.flatMap(SensorReport.EndpointSecurity.init(rawValue:)) {
        case .ok?: return "granted"
        case .notPermitted?: return "missing: allow Mac Monitor Security Extension in System Settings > Privacy & "
            + "Security > Full Disk Access"
        case .notEntitled?: return "unknown: the Security Extension isn't entitled to Endpoint Security"
        case .tooManyClients?: return "unknown: Endpoint Security has no client to spare"
        case .failed?: return "unknown: Endpoint Security refused a client"
        case nil: return "unknown"
        }
    }

    /// - Parameter capturing: Who is capturing.
    /// - Returns: Whether Mac Monitor is connected, and recording.
    private static func app(_ capturing: StatusReport.Capturing) -> String {
        guard let connected = capturing.mac_monitor_connected else { return "unknown" }
        guard connected else { return "not connected" }
        return capturing.mac_monitor_recording == true ? "connected, recording" : "connected, not recording"
    }

    /// - Parameter capturing: Who is capturing.
    /// - Returns: How many `macmonitor` streams are running, of how many at most.
    private static func streams(_ capturing: StatusReport.Capturing) -> String {
        guard let streams = capturing.streams, let capacity = capturing.stream_capacity else { return "unknown" }
        return "\(streams) of \(capacity)"
    }
}


// MARK: - System Extension
/// Reads what macOS says of Mac Monitor's System Extension from `systemextensionsctl list`, which any user may run.
public enum SystemExtensionList {
    /// The Security Extension's bundle identifier.
    public static let securityExtension = "com.swiftlydetecting.agent.securityextension"
    /// The state of a System Extension that's running.
    public static let activated = "activated enabled"

    /// - Parameters:
    ///   - identifier: A System Extension's bundle identifier.
    ///   - listing: What `systemextensionsctl list` printed.
    /// - Returns: Its state, such as "activated enabled" or "activated waiting for user": the running one's when one
    ///   of its versions runs, else the first that isn't waiting to be uninstalled, else `nil`.
    public static func state(of identifier: String = securityExtension, in listing: String) -> String? {
        let states = listing.split(separator: "\n").compactMap { line -> String? in
            guard line.contains(identifier), let open = line.lastIndex(of: "["), let close = line.lastIndex(of: "]"),
                  open < close else { return nil }
            return String(line[line.index(after: open)..<close])
        }
        return states.first { $0 == activated } ?? states.first { !$0.hasPrefix("terminated") }
    }
}
