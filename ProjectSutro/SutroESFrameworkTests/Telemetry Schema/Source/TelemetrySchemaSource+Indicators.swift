//
//  TelemetrySchemaSource+Indicators.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Indicators
extension TelemetrySchemaSource {
    /// An indicator a record lists: one of the saved set's predicates the event matched, with its severity and who
    /// matched it.
    static var indicator: SchemaObject {
        SchemaObject("An indicator from this Mac's saved set that the event matched.", [
            enrichment("id", .pattern(.uuid), "The indicator's identity, the same on every Mac for one Mac Monitor "
                        + "ships."),
            enrichment("name", .string, "What Settings > Indicators calls it, such as Background item added."),
            enrichment("tactic", .nullable(.values((Indicator.Tactic.allCases.map(\.name)
                                                     + Indicator.Tactic.retiredNames).sorted())),
                       "The MITRE ATT&CK tactic it's for, by name, or null for none. Stealth and Defense Impairment "
                       + "since telemetry 1.2.0, when ATT&CK v19 split Defense Evasion into them: Defense Evasion is "
                       + "only in records written before."),
            enrichment("tactic_id", .nullable(.values(Indicator.Tactic.allCases.map(\.identifier).sorted())),
                       "The tactic's ATT&CK identity, such as TA0003, or null for none. TA0005 is Stealth since "
                       + "telemetry 1.2.0, and Defense Evasion before. TA0112, Defense Impairment, since 1.2.0."),
            enrichment("technique", .nullable(.string),
                       "The ATT&CK technique it finds, such as T1543.001, or null for none."),
            enrichment("severity", .values(IndicatorSeverity.allCases.map(\.rawValue).sorted()),
                       "How closely a match is worth looking at: high for behavior that is rare in ordinary use, "
                        + "medium for less common behavior that has ordinary uses, low for context and common "
                        + "behavior. It never changes what matches."),
            enrichment("default", .boolean, "Whether it is one of Mac Monitor's default indicators, which Mac "
                        + "Monitor ships. edited says whether this Mac changed it."),
            enrichment("edited", .boolean, "Whether this Mac changed one Mac Monitor ships: its name, description, "
                        + "symbol, color, predicate, tactic, technique or severity. Always false when default is "
                        + "false."),
            enrichment("evaluated_by", .values(IndicatorEvaluator.known.map(\.rawValue).sorted()),
                       "Who matched it: security_extension, the Security Extension as it captured the event, or "
                        + "export, Mac Monitor as it wrote the record of an event the Security Extension did not "
                        + "evaluate."),
            enrichment("revision", .nullable(.integer),
                       "The indicator's revision, which its indicator pack raises whenever the indicator changes, or "
                        + "null for one without. An edited one keeps the revision it was edited from. Since "
                        + "telemetry 1.2.0."),
            enrichment("pack", .nullable(.integer),
                       "The indicator pack this Mac had when the indicator matched, by its sequence, for one Mac "
                        + "Monitor ships. With id and revision it says which rule fired. null for one this Mac "
                        + "added, and when Mac Monitor's indicators are its build's own rather than a pack's. Since "
                        + "telemetry 1.2.0."),
            enrichment("matched", .nullable(.array(.object(matchedField))),
                       "What made it match: the comparisons of its rule the event passed, at most 16. For a "
                        + "sequence, those of its steps this event matched, as it completed it. Only comparisons "
                        + "that say what the event has are listed, not a != a value outside ANY, or anything under "
                        + "NOT. ANY lists the first string of the array that matched, with != too since telemetry "
                        + "1.3.0. null when none of its comparisons is one of those, and when evaluated_by is export. "
                        + "Since telemetry 1.2.0."),
        ])
    }

    /// One comparison of an indicator's rule that the event passed.
    static var matchedField: SchemaObject {
        SchemaObject("One comparison of an indicator's rule that the event passed.", [
            enrichment("field", .string, "The key path the comparison read, as the rule names it, such as "
                        + "event.exec.target.executable.path, lineage.paths for one of the process's ancestors, or "
                        + "event.close.yara_scan.rules.@count for an array's size since telemetry 1.3.0."),
            enrichment("value", .either([.string, .integer, .boolean]),
                       "The value the event had there: for ANY, the one of the array's strings that matched, and for "
                        + ".@count, the array's size. A string's first 256 characters. A whole number past 2^53 is "
                        + "rounded."),
        ])
    }
    
    /// An indicator the Security Extension couldn't rule out for the event: an indicator's keys, and why.
    static var indicatorUndetermined: SchemaObject {
        SchemaObject("An indicator from this Mac's saved set that the Security Extension could not rule out for the "
                        + "event: it may or may not match.", indicator.keys.filter { $0.name != "matched" } + [
            enrichment("matched", .null, "Always null: an indicator that wasn't decided matched nothing. Since "
                        + "telemetry 1.2.0."),
            enrichment("reason", .values(UndeterminedReason.known.map(\.rawValue).sorted()),
                       "Why it wasn't decided: scan_budget when evaluating the event's values exceeded the Security "
                        + "Extension's per-event scan budget, or value_limit when a value that isn't ASCII was "
                        + "longer than the 64 KiB the Security Extension compares."),
        ])
    }
}
