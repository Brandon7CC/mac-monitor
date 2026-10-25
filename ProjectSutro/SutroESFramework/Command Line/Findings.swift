//
//  Findings.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/25/26.
//

import Foundation


// MARK: - Findings
/// What's worth a look among an event's related events: a predicate on each event's record, with what Event Facts
/// calls it. Correlation shows the findings among the events of the process an exec created, Groups among a group's
/// execs. Mac Monitor ships ``defaults``, and people add their own in Settings ▸ Findings.
public struct Finding: Codable, Identifiable, Hashable {
    /// A finding's color, by name, for its card and its rows' dots.
    public enum Color: String, Codable, CaseIterable {
        case red, orange, yellow, green, teal, blue, indigo, purple, pink, gray
    }

    public var id: UUID
    /// What its card is called, such as "Reflective loading".
    public var name: String
    /// Why it's worth a look, for the card's help and the inspector.
    public var explanation: String
    /// Its SF Symbol.
    public var symbol: String
    public var color: Color
    /// The predicate an event matches, on the event's record, as `macmonitor stream --predicate` takes one.
    public var predicate: String
    /// Does it show in Correlation, among the events of the process an exec created?
    public var showsInCorrelation: Bool
    /// Does it show in Groups, among a process group's or session's execs?
    public var showsInGroups: Bool
    /// Does its symbol mark its events in the event tables, as a script's exec is marked?
    public var showsInTables: Bool
    public var isEnabled: Bool

    /// - Parameters:
    ///   - id: Its identity, the same across launches.
    ///   - name: What its card is called.
    ///   - explanation: Why it's worth a look.
    ///   - symbol: Its SF Symbol.
    ///   - color: Its color.
    ///   - predicate: The predicate an event matches.
    ///   - correlation: Does it show in Correlation?
    ///   - groups: Does it show in Groups?
    ///   - tables: Does its symbol mark its events in the event tables?
    ///   - isEnabled: Is it on?
    public init(id: UUID = UUID(), name: String, explanation: String, symbol: String, color: Color, predicate: String,
                correlation: Bool, groups: Bool, tables: Bool = false, isEnabled: Bool = true) {
        self.id = id
        self.name = name
        self.explanation = explanation
        self.symbol = symbol
        self.color = color
        self.predicate = predicate
        showsInCorrelation = correlation
        showsInGroups = groups
        showsInTables = tables
        self.isEnabled = isEnabled
    }

    /// Why its predicate can't be used, or `nil` if it can. A finding compares one event at a time: no `SUBQUERY`.
    public var problem: String? {
        do {
            _ = try StreamFilter.Predicate(predicate, for: .finding)
            return nil
        } catch {
            return (error as? CommandLineUsageError)?.message ?? error.localizedDescription
        }
    }
}

extension Finding {
    /// A saved finding from before ``showsInTables``: a default takes Mac Monitor's choice, and one of its own doesn't
    /// mark the tables.
    ///
    /// - Parameter decoder: The saved findings.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let id = try container.decode(UUID.self, forKey: .id)
        self.id = id
        name = try container.decode(String.self, forKey: .name)
        explanation = try container.decode(String.self, forKey: .explanation)
        symbol = try container.decode(String.self, forKey: .symbol)
        color = try container.decode(Color.self, forKey: .color)
        predicate = try container.decode(String.self, forKey: .predicate)
        showsInCorrelation = try container.decode(Bool.self, forKey: .showsInCorrelation)
        showsInGroups = try container.decode(Bool.self, forKey: .showsInGroups)
        showsInTables = try container.decodeIfPresent(Bool.self, forKey: .showsInTables)
            ?? Self.defaults.first { $0.id == id }?.showsInTables ?? false
        isEnabled = try container.decode(Bool.self, forKey: .isEnabled)
    }
}


// MARK: - Defaults
public extension Finding {
    /// The findings Mac Monitor ships, each with an identity of its own, so Restore Defaults puts back the same ones.
    static let defaults: [Finding] = [
        Finding(id: uuid(1), name: "Reflective loading",
                explanation: "Wrote or mapped the image NSCreateObjectFileImageFromMemory makes of a Mach-O it loads "
                    + "from memory: reflective code loading (T1620).",
                symbol: "memorychip", color: .red,
                predicate: #"es_event_type IN {"ES_EVENT_TYPE_NOTIFY_CREATE", "ES_EVENT_TYPE_NOTIFY_WRITE", "#
                    + #""ES_EVENT_TYPE_NOTIFY_MMAP"} AND target_path CONTAINS "/NSCreateObjectFileImageFromMemory-""#,
                correlation: true, groups: false),
        Finding(id: uuid(2), name: "Not quarantined",
                explanation: "Written without the quarantine attribute by a process whose files macOS quarantines, so "
                    + "Gatekeeper won't check it when it's opened.",
                symbol: "exclamationmark.shield", color: .orange,
                predicate: #"es_event_type IN {"ES_EVENT_TYPE_NOTIFY_CREATE", "ES_EVENT_TYPE_NOTIFY_RENAME"} "#
                    + #"AND process.file_quarantine_type != "DISABLED" "#
                    + "AND (event.create.is_quarantined == 0 OR event.rename.is_quarantined == 0)",
                correlation: true, groups: false),
        Finding(id: uuid(3), name: "Quarantine removed",
                explanation: "Deleted com.apple.quarantine, so Gatekeeper won't check the file when it's opened.",
                symbol: "xmark.shield", color: .red,
                predicate: #"es_event_type == "ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR" "#
                    + #"AND event.deleteextattr.extattr == "com.apple.quarantine""#,
                correlation: true, groups: false),
        Finding(id: uuid(4), name: "Background item added",
                explanation: "Added a background item, which runs again at login.",
                symbol: "gearshape.2", color: .green,
                predicate: #"es_event_type == "ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD""#,
                correlation: true, groups: false),
        Finding(id: uuid(5), name: "XProtect detection",
                explanation: "XProtect detected or remediated malware.",
                symbol: "xmark.octagon", color: .red,
                predicate: #"es_event_type IN {"ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED", "#
                    + #""ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED"}"#,
                correlation: true, groups: false),
        Finding(id: uuid(6), name: "AppleScript loaded",
                explanation: "Mapped an Open Scripting Architecture component, as a process running AppleScript does.",
                symbol: "applescript", color: .purple,
                predicate: #"es_event_type == "ES_EVENT_TYPE_NOTIFY_MMAP" AND (target_path CONTAINS "#
                    + #""AppleScript.component" OR target_path CONTAINS "JavaScript.component" "#
                    + #"OR target_path CONTAINS ".osax")"#,
                correlation: true, groups: false),
        Finding(id: uuid(7), name: "Keychain opened",
                explanation: "Opened a keychain, which holds passwords and keys.",
                symbol: "key", color: .blue,
                predicate: #"es_event_type == "ES_EVENT_TYPE_NOTIFY_OPEN" AND target_path CONTAINS "/Keychains/""#,
                correlation: true, groups: false),
        Finding(id: uuid(8), name: "Login",
                explanation: "A login, by the login window, login(1), or SSH.",
                symbol: "person.badge.key", color: .blue,
                predicate: #"es_event_type IN {"ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN", "#
                    + #""ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN", "ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN"}"#,
                correlation: true, groups: false),
        Finding(id: uuid(9), name: "New executable",
                explanation: "Its executable was created less than five minutes before it ran, as a dropper's payload "
                    + "is.",
                symbol: "clock.badge.exclamationmark", color: .orange,
                predicate: #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" AND event.exec.executable_age_ms < 300000"#,
                correlation: false, groups: true, tables: true),
        Finding(id: uuid(10), name: "Adhoc or unsigned",
                explanation: "Ran code that isn't signed by a known developer: adhoc, as a freshly compiled or "
                    + "modified binary is, or not at all.",
                symbol: "xmark.seal", color: .orange,
                predicate: #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" "#
                    + #"AND event.exec.target.codesigning_type IN {"ADHOC", "UNSIGNED"}"#,
                correlation: false, groups: true),
        Finding(id: uuid(11), name: "Ran a script",
                explanation: "An interpreter ran a script Mac Monitor read. That exec's Script tab shows its content.",
                symbol: "scroll.fill", color: .purple,
                predicate: #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" AND event.exec.script_content != nil "#
                    + #"AND event.exec.script_content != """#,
                correlation: false, groups: true, tables: true),
        Finding(id: uuid(12), name: "osascript",
                explanation: "osascript ran AppleScript or JXA, which stealers use for fake password prompts and to "
                    + "drive other apps.",
                symbol: "applescript", color: .indigo,
                predicate: #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" "#
                    + #"AND event.exec.target.executable.name == "osascript""#,
                correlation: false, groups: true),
        Finding(id: uuid(13), name: "Download tool",
                explanation: "A command line download tool ran, as a dropper does to fetch its payload.",
                symbol: "arrow.down.circle", color: .blue,
                predicate: #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" AND event.exec.target.executable.name "#
                    + #"IN {"curl", "wget", "nscurl", "ftp", "tftp", "scp", "sftp"}"#,
                correlation: false, groups: true),
        Finding(id: uuid(14), name: "Non-Apple as root",
                explanation: "Ran as root without Apple's signature.",
                symbol: "bolt.shield", color: .red,
                predicate: #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" AND event.exec.target.euid == 0 "#
                    + #"AND event.exec.target.codesigning_type != "PLATFORM""#,
                correlation: false, groups: true),
    ]

    /// - Parameter number: A default finding's number.
    /// - Returns: Its identity: the same on every Mac, so a saved set knows which defaults it has.
    private static func uuid(_ number: Int) -> UUID {
        UUID(uuidString: String(format: "6D4D0F1D-0000-4000-8000-%012X", number))!
    }
}


// MARK: - Matching
/// The findings that are on, parsed once, to find which an event is part of. Not thread-safe: use one per queue, on
/// the events' context's queue.
public final class FindingMatcher {
    private let findings: [(finding: Finding, predicate: StreamFilter.Predicate, narrow: NSPredicate?)]

    /// The findings it looks for, in their cards' order.
    public var order: [Finding] { findings.map(\.finding) }

    /// - Parameter findings: The findings, in the order their cards show. Those off, or whose predicate can't be
    ///   used, are left out.
    public init(_ findings: [Finding]) {
        self.findings = findings.filter(\.isEnabled).compactMap { finding in
            guard let predicate = try? StreamFilter.Predicate(finding.predicate, for: .finding) else { return nil }
            return (finding, predicate, predicate.storePredicate)
        }
    }

    /// The findings an event is part of. The store's columns rule most out first
    /// (``StreamFilter/Predicate/storePredicate``): the event's record is encoded only when one might match.
    ///
    /// - Parameter message: The event.
    /// - Returns: Its findings, in order.
    public func matches(_ message: ESMessage) -> [Finding] {
        let candidates = findings.filter { item in
            guard let narrow = item.narrow else { return true }
            var result = ObjCBool(false)
            return (try? PredicateBridge.evaluate(narrow, with: message, matches: &result)) != nil && result.boolValue
        }
        guard !candidates.isEmpty,
              let record = try? JSONSerialization.jsonObject(with: JSONEncoder().encode(message)) as? NSDictionary
        else { return [] }
        return candidates.filter { (try? $0.predicate.evaluate(on: record)) == true }.map(\.finding)
    }
}
