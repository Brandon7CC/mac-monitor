//
//  IndicatorCommand+Edit.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Editing
/// `macmonitor indicators edit`: list the set, find the one indicator named, work out the edited copy from the
/// options, a file or this build's shipped version, check it as the Security Extension will, and send only the fields
/// that change (``IndicatorRequest/Operation/update``). The Security Extension takes those fields into the indicator
/// with that identity, so it keeps its place, its switch and each user's views, and one removed meanwhile is refused
/// rather than brought back. A rename onto another indicator's name is refused here, as `add` refuses one. An edit
/// from a file asks first, unless `--yes`.
///
/// An edit to a shipped indicator's rule, rather than its tactic, technique or severity, stops Mac Monitor's updates
/// changing it (``SavedIndicators``), so that's said on standard error, with the `--restore` that brings it back.
extension IndicatorCommand {
    /// Run `indicators edit`.
    ///
    /// - Parameters:
    ///   - edit: The edit.
    ///   - completion: Called once, on any thread: success, or why not.
    func edit(_ edit: IndicatorEdit, _ completion: @escaping (Result<Void, CommandLineFailure>) -> Void) {
        var file: (name: String, entry: [String: Any])?
        if case .file(let path, _) = edit.change {
            do {
                file = try editEntry(from: path)
            } catch {
                return completion(.failure(Self.failure(error)))
            }
        }
        listing(completion) { [self] reply in
            let lookup = IndicatorLookup(indicators: reply.indicators)
            guard let target = try lookup.unique([edit.reference]).first else { throw lookup.unknown(edit.reference) }
            let edited: Indicator
            switch edit.change {
            case .values(let values): edited = IndicatorEdit.applying(values, to: target)
            case .restore: edited = try Self.restored(target)
            case .file: edited = try Self.applying(file?.entry ?? [:], to: target, from: file?.name ?? "")
            }
            let fields = target.changedFields(to: edited)
            try Self.check(edited, fields: fields, among: reply.indicators)
            guard !fields.isEmpty else {
                let already = edit.change == .restore ? "is already Mac Monitor's own" : "already has that"
                return completion(output.writeResult(Data("\(TerminalSafeText.quoted(target.name)) \(already).\n"
                    .utf8)))
            }
            let send = { [self] in
                self.send(IndicatorRequest(.update, indicators: [edited], fields: fields), completion) { reply in
                    if let note = Self.shippedNote(target, edited: edited, fields: fields) { self.diagnose(note) }
                    let verb = edit.change == .restore ? "Restored" : "Changed"
                    return "\(verb) \(TerminalSafeText.quoted(target.name)) (\(target.id.uuidString)): "
                        + "\(Self.summary(of: fields, from: target, to: edited)). \(Self.count(reply)) now.\n"
                }
            }
            guard case .file(let path, confirmed: false) = edit.change else { return send() }
            let source = path == "-" ? "standard input" : TerminalSafeText.quoted(path)
            ask(about: .editing(target, to: edited, fields: fields, from: source), then: send,
                otherwise: completion)
        }
    }

    /// The one indicator a file to edit from has, as its JSON object.
    ///
    /// - Parameter path: The file, or `-` for standard input.
    /// - Returns: How messages name the file, and the indicator's object.
    /// - Throws: ``CommandLineFailure``: 66 for a file that can't be read, 65 for one that's too large, isn't
    ///   indicators, or has more than one.
    func editEntry(from path: String) throws -> (name: String, entry: [String: Any]) {
        let (name, data) = try input(from: path, for: "read")
        let entries: [[String: Any]]
        do {
            entries = try IndicatorExchange.entryObjects(from: data)
        } catch {
            throw Self.unusable(name, (error as? IndicatorExchange.ImportError)?.message ?? "\(error)")
        }
        guard let entry = entries.first, entries.count == 1 else {
            throw CommandLineFailure(.dataError, "An edit takes one indicator; \(name) has \(entries.count).")
        }
        return (name, entry)
    }

    /// An indicator with the editable keys a file's entry has in place of its own. The rest of the entry, whether
    /// it's on and its view switches included, is left out. The entry's values are read by the real decoder, so
    /// their types and limits are checked, and its tactic and severity more strictly than it reads them.
    ///
    /// - Parameters:
    ///   - entry: The file's indicator, as its JSON object.
    ///   - target: The indicator to edit.
    ///   - name: How messages name the file.
    /// - Returns: The indicator, edited.
    /// - Throws: ``CommandLineFailure`` (65) for another identity, another kind of rule, an unknown tactic or
    ///   severity, or a value that can't be read.
    static func applying(_ entry: [String: Any], to target: Indicator, from name: String) throws -> Indicator {
        if let id = entry["id"], (id as? String).flatMap(UUID.init(uuidString:)) != target.id {
            throw CommandLineFailure(.dataError, """
                edit keeps an indicator's ID; \(name)'s is \(TerminalSafeText.text("\(id)")).
                """)
        }
        if let tactic = entry["tactic"], !(tactic is NSNull),
           (tactic as? String).flatMap(Indicator.Tactic.init(rawValue:)) == nil {
            throw unusable(name, "Its tactic '\(tactic)' isn't an ATT&CK tactic.")
        }
        if let severity = entry["severity"], (severity as? String).flatMap(IndicatorSeverity.init) == nil {
            throw unusable(name, "Its severity must be low, medium or high, not '\(severity)'.")
        }
        let present = Indicator.EditableField.allCases.filter { entry[$0.rawValue] != nil }
        do {
            var object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(target)) as? [String: Any] ?? [:]
            for key in present.map(\.rawValue) + ["kind"] { object[key] = entry[key] }
            let data = try JSONSerialization.data(withJSONObject: object)
            let read = try IndicatorExchange.decoded { [try JSONDecoder().decode(Indicator.self, from: data)] }
            var edited = target
            edited.take(present, from: read[0])
            return edited
        } catch {
            throw unusable(name, (error as? IndicatorExchange.ImportError)?.message ?? "\(error)")
        }
    }

    /// An indicator with every editable field as this build ships it.
    ///
    /// - Parameter target: The indicator.
    /// - Returns: It, restored.
    /// - Throws: ``CommandLineFailure`` (65) for one Mac Monitor doesn't ship.
    static func restored(_ target: Indicator) throws -> Indicator {
        guard let shipped = CompiledIndicators.shippedDefaults[target.id] else {
            throw CommandLineFailure(.dataError, """
                \(TerminalSafeText.quoted(target.name)) isn't one of Mac Monitor's own, so it has nothing to restore.
                """)
        }
        var restored = target
        restored.take(Indicator.EditableField.allCases, from: shipped)
        return restored
    }

    /// Check the edited indicator, not only what was typed: every field within its limit, and a new name that isn't
    /// blank and no other indicator has, ignoring case. A change of case to its own name is allowed. So flags, a file
    /// and `--restore` are held to the same rules.
    ///
    /// - Parameters:
    ///   - edited: The indicator, edited.
    ///   - fields: The fields the edit changes.
    ///   - indicators: The set.
    /// - Throws: ``CommandLineFailure`` (65).
    static func check(_ edited: Indicator, fields: [Indicator.EditableField], among indicators: [Indicator]) throws {
        if let problem = edited.limitProblem {
            throw CommandLineFailure(.dataError, "The edit can't be made. \(problem)")
        }
        guard fields.contains(.name) else { return }
        if edited.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw CommandLineFailure(.dataError, "The name can't be empty.")
        }
        let others = indicators.filter { $0.id != edited.id }
        if let taken = IndicatorLookup(indicators: others).matches(edited.name).first {
            throw CommandLineFailure(.dataError, """
                An indicator is already named \(IndicatorTable.describe(taken)). Choose another name.
                """)
        }
    }

    /// What an edit changed, for the answer: each field by name, a tactic, technique and severity from and to.
    ///
    /// - Parameters:
    ///   - fields: The fields it changed, in order.
    ///   - target: The indicator before.
    ///   - edited: It after.
    /// - Returns: Such as "severity medium to high, predicate", escaped for a terminal.
    static func summary(of fields: [Indicator.EditableField], from target: Indicator, to edited: Indicator) -> String {
        let fromTo = { (field: Indicator.EditableField, value: (Indicator) -> String?) in
            "\(field.rawValue) \(TerminalSafeText.text(value(target) ?? "none")) to "
                + TerminalSafeText.text(value(edited) ?? "none")
        }
        return fields.map { field in
            switch field {
            case .severity: return fromTo(field) { $0.severity.rawValue }
            case .tactic: return fromTo(field) { $0.tactic?.name }
            case .technique: return fromTo(field) { $0.technique }
            default: return field.rawValue
            }
        }.joined(separator: ", ")
    }

    /// What to say when an edit stops Mac Monitor's updates changing one of its own indicators: it changed a rule
    /// field, and the rule is no longer this build's.
    ///
    /// - Parameters:
    ///   - target: The indicator before.
    ///   - edited: It after.
    ///   - fields: The fields the edit changed.
    /// - Returns: The line for standard error, or `nil`.
    static func shippedNote(_ target: Indicator, edited: Indicator, fields: [Indicator.EditableField]) -> String? {
        guard let shipped = CompiledIndicators.shippedDefaults[target.id], fields.contains(where: \.isRule),
              !shipped.hasSameRule(as: edited) else { return nil }
        return """
            macmonitor: \(TerminalSafeText.quoted(target.name)) is one of Mac Monitor's own. Mac Monitor updates no \
            longer change it: 'macmonitor indicators edit \(target.id.uuidString) --restore' brings back this \
            build's version.
            """
    }

    /// - Parameters:
    ///   - name: How messages name the file.
    ///   - reason: Why it can't be used.
    /// - Returns: The failure: exit 65.
    private static func unusable(_ name: String, _ reason: String) -> CommandLineFailure {
        CommandLineFailure(.dataError, "\(name) can't be used to edit an indicator. \(TerminalSafeText.text(reason))")
    }
}
