//
//  Indicator+Tactic.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Tactics
public extension Indicator {
    /// The MITRE ATT&CK tactic an indicator is for: the adversary's goal, such as persistence. They're ATT&CK v19's,
    /// in its order, which split Defense Evasion into Stealth, which kept its identity, TA0005, and Defense
    /// Impairment.
    enum Tactic: String, Codable, CaseIterable {
        case reconnaissance, resourceDevelopment, initialAccess, execution, persistence, privilegeEscalation
        case stealth, defenseImpairment, credentialAccess, discovery, lateralMovement, collection, commandAndControl
        case exfiltration, impact

        /// The tactics ATT&CK retired, by the raw value Mac Monitor saved them as, with the tactic each is read as:
        /// Defense Evasion as Stealth, which kept its identity.
        public static let retired: [String: Tactic] = ["defenseEvasion": .stealth]

        /// The retired tactics' names, as records Mac Monitor wrote before ATT&CK v19 name them.
        public static let retiredNames = ["Defense Evasion"]

        /// A tactic by its raw value, or by the raw value of the one it replaced (``retired``), so an indicator saved
        /// or exported with Defense Evasion reads as Stealth.
        ///
        /// - Parameter rawValue: Such as `persistence` or `defenseEvasion`.
        /// - Returns: `nil` for a value that's neither.
        public init?(rawValue: String) {
            guard let tactic = Self.allCases.first(where: { $0.rawValue == rawValue }) ?? Self.retired[rawValue] else {
                return nil
            }
            self = tactic
        }

        /// Its name, as ATT&CK writes it.
        public var name: String {
            switch self {
            case .reconnaissance: return "Reconnaissance"
            case .resourceDevelopment: return "Resource Development"
            case .initialAccess: return "Initial Access"
            case .execution: return "Execution"
            case .persistence: return "Persistence"
            case .privilegeEscalation: return "Privilege Escalation"
            case .stealth: return "Stealth"
            case .defenseImpairment: return "Defense Impairment"
            case .credentialAccess: return "Credential Access"
            case .discovery: return "Discovery"
            case .lateralMovement: return "Lateral Movement"
            case .collection: return "Collection"
            case .commandAndControl: return "Command and Control"
            case .exfiltration: return "Exfiltration"
            case .impact: return "Impact"
            }
        }

        /// Its ATT&CK identity, such as `TA0003`.
        public var identifier: String {
            switch self {
            case .reconnaissance: return "TA0043"
            case .resourceDevelopment: return "TA0042"
            case .initialAccess: return "TA0001"
            case .execution: return "TA0002"
            case .persistence: return "TA0003"
            case .privilegeEscalation: return "TA0004"
            case .stealth: return "TA0005"
            case .defenseImpairment: return "TA0112"
            case .credentialAccess: return "TA0006"
            case .discovery: return "TA0007"
            case .lateralMovement: return "TA0008"
            case .collection: return "TA0009"
            case .commandAndControl: return "TA0011"
            case .exfiltration: return "TA0010"
            case .impact: return "TA0040"
            }
        }
    }
}


// MARK: - Tactics by name
public extension Indicator.Tactic {
    /// The tactic typed on a command line: its raw value (`defenseImpairment`), its ATT&CK identity (`TA0112`) or its
    /// name (`Defense Impairment`), ignoring case, spaces, hyphens and underscores. A retired tactic's raw value or
    /// name is read as the tactic that replaced it (``retired``).
    ///
    /// - Parameter text: What was typed.
    /// - Returns: The tactic, or `nil` for none of them.
    static func named(_ text: String) -> Indicator.Tactic? {
        let typed = folded(text)
        guard !typed.isEmpty else { return nil }
        let current = allCases.first { tactic in
            [tactic.rawValue, tactic.identifier, tactic.name].contains { folded($0) == typed }
        }
        return current ?? retired.first { folded($0.key) == typed }?.value
    }

    /// - Parameter text: A spelling of a tactic.
    /// - Returns: It in lowercase, without spaces, hyphens or underscores.
    private static func folded(_ text: String) -> String {
        String(text.lowercased().filter { !" -_".contains($0) })
    }
}
