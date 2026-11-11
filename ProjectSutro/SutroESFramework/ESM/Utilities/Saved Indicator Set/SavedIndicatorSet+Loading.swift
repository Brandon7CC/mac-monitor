//
//  SavedIndicatorSet+Loading.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
import OSLog


// MARK: - Loading
extension SavedIndicatorSet {
    /// Read the saved set once. Call on ``queue``.
    ///
    /// - Self-test: compile the shipped indicators, and log a fault for each that doesn't compile.
    /// - A loading marker left by a crash: move the file aside, and start from the shipped indicators, saved.
    /// - Missing: start from the shipped indicators and save them (first run).
    /// - Unreadable, past a limit, or not an indicator file: move it aside, start from the shipped indicators, save
    ///   them, and say so.
    /// - Newer: keep the file, apply the shipped indicators, and refuse every change.
    /// - Untrusted directory: apply the shipped indicators and refuse every change, rather than write through it.
    func loadIfNeeded() {
        guard !isLoaded else { return }
        isLoaded = true
        let shippedSet = selfTest()
        guard !recoverFromCrashedLoad(shippedSet) else { return }
        do {
            switch try store.read() {
            case .missing:
                startFromDefaults(shippedSet, notice: nil)
                logger.log("Created the indicators from Mac Monitor's own (\(self.saved.indicators.count) indicators).")
            case .unreadable(let reason):
                recover(shippedSet, reason: reason)
            case .tooLarge(let bytes):
                recover(shippedSet, reason: "It's \(bytes) bytes, larger than \(store.maxSizeText).")
            case .read(let data):
                loadSaved(data, shippedSet: shippedSet)
            }
        } catch {
            saved = SavedIndicators(defaults, defaults: defaults)
            compiled = shippedSet
            state = .unavailable(reason: "The indicators can't be kept: \(error)")
            notice = """
                Mac Monitor can't keep its indicators. \(error) Its own indicators apply, and changes can't be saved.
                """
            logger.fault("The indicators can't be kept: \(String(describing: error), privacy: .public)")
        }
    }

    /// Compile the shipped indicators, as a startup self-test: one that doesn't compile is a build that can't run it,
    /// or a predicate check (``PredicateGuard``) that couldn't load what it checks against.
    ///
    /// - Returns: The shipped indicators, compiled: the set to fall back to, whose rules a saved set reuses.
    private func selfTest() -> CompiledIndicators {
        let shippedSet = CompiledIndicators(defaults, defaults: shipped)
        defaultProblems = shippedSet.problems
        for problem in shippedSet.problems {
            logger.fault("""
                A shipped indicator can't run in the Security Extension (\(problem.id.uuidString, privacy: .public)): \
                \(problem.reason, privacy: .public)
                """)
        }
        return shippedSet
    }

    /// Start from the shipped indicators if the last load never finished: the Security Extension stopped while it read
    /// or compiled the saved file, which might stop it again.
    ///
    /// - Parameter shippedSet: The shipped indicators, compiled.
    /// - Returns: `true` when it found the marker and recovered.
    private func recoverFromCrashedLoad(_ shippedSet: CompiledIndicators) -> Bool {
        guard let marker = try? loadingMarker.read(), marker != .missing else { return false }
        let kept = store.moveAside()
        loadingMarker.remove()
        startFromDefaults(shippedSet, notice: """
            The Security Extension stopped while it loaded your indicators. \(movedText(kept)) Mac Monitor's own \
            indicators were restored.
            """)
        logger.fault("The last load of the indicators never finished. Restored the shipped indicators.")
        return true
    }

    /// Read, check and compile a saved file, with the loading marker kept until it's done.
    ///
    /// - Parameters:
    ///   - data: The file's bytes.
    ///   - shippedSet: The shipped indicators, compiled, whose rules it reuses.
    private func loadSaved(_ data: Data, shippedSet: CompiledIndicators) {
        let marked = (try? loadingMarker.write(Data())) != nil
        defer { if marked { loadingMarker.remove() } }
        let file: IndicatorFile, loaded: CompiledIndicators
        do {
            file = try IndicatorFile.decode(data, defaults: defaults)
            try IndicatorFile.validate(file.saved.indicators)
            loaded = CompiledIndicators(file.saved.indicators, defaults: shipped, reusing: shippedSet)
            try IndicatorFile.validate(loaded)
        } catch IndicatorFileError.unsupportedVersion(let version) {
            saved = SavedIndicators(defaults, defaults: defaults)
            compiled = shippedSet
            state = .readOnly(version: version)
            notice = """
                Your indicators were saved by a newer Mac Monitor (indicator file version \(version)). They're kept \
                as they are, and Mac Monitor's own indicators apply until you update it.
                """
            logger.error("The indicators are file version \(version). Applying the shipped indicators.")
            return
        } catch {
            return recover(shippedSet, reason: "\(error)")
        }
        saved = file.saved
        compiled = loaded
        let undecodable = file.saved.undecodableCount
        if undecodable > 0 {
            notice = """
                \(String.counted(undecodable, "saved indicator")) can't be read by this Mac Monitor, such as a newer \
                one's. They're kept, and not run.
                """
        }
        logger.log("""
            Loaded the indicators (\(file.saved.indicators.count) indicators, \(loaded.count) run, \
            \(loaded.problems.count) can't run, \(undecodable) unreadable).
            """)
    }

    /// Move an unreadable file aside, and start from the shipped indicators, saved.
    ///
    /// - Parameters:
    ///   - shippedSet: The shipped indicators, compiled.
    ///   - reason: Why the file can't be used, as a sentence.
    private func recover(_ shippedSet: CompiledIndicators, reason: String) {
        let kept = store.moveAside()
        startFromDefaults(shippedSet, notice: """
            Your indicators couldn't be read. \(reason) \(movedText(kept)) Mac Monitor's own indicators were restored.
            """)
        logger.fault("The indicators couldn't be read: \(reason, privacy: .public)")
    }

    /// Start from the shipped indicators, and save them. A failed save is logged. The next change tries again.
    ///
    /// - Parameters:
    ///   - shippedSet: The shipped indicators, compiled.
    ///   - notice: What to tell the user, if anything.
    private func startFromDefaults(_ shippedSet: CompiledIndicators, notice: String?) {
        saved = SavedIndicators(defaults, defaults: defaults)
        compiled = shippedSet
        self.notice = notice
        do {
            guard let bytes = IndicatorFile(saved).encoded() else { throw IndicatorRequestProblem("Not encodable.") }
            try store.write(bytes)
        } catch {
            logger.fault("Couldn't save the shipped indicators: \(String(describing: error), privacy: .public)")
        }
    }

    /// Where an unreadable file went, as a sentence.
    ///
    /// - Parameter kept: Where it was moved, or `nil` if it couldn't be.
    /// - Returns: The sentence.
    private func movedText(_ kept: URL?) -> String {
        kept.map { "They were moved to \($0.path)." } ?? "They couldn't be moved aside."
    }

    /// Log a change once at the default level and each indicator it touched at info level: the set persists and
    /// every capture runs it, so this is its audit trail.
    ///
    /// - Parameters:
    ///   - operation: What was asked.
    ///   - caller: Who asked.
    ///   - old: The set before.
    ///   - new: The set after.
    ///   - fields: The fields an update named, which each indicator it changed lists after its state.
    func logChange(_ operation: IndicatorRequest.Operation, by caller: String, from old: [Indicator],
                   to new: [Indicator], fields: [Indicator.EditableField] = []) {
        let before = Dictionary(old.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        let after = Dictionary(new.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        let added = new.filter { before[$0.id] == nil }
        let removed = old.filter { after[$0.id] == nil }
        let changed = new.filter { indicator in before[indicator.id].map { $0 != indicator } ?? false }
        logger.log("""
            \(caller, privacy: .public) changed the indicators (\(operation.rawValue, privacy: .public)): \
            \(added.count) added, \(removed.count) removed, \(changed.count) changed. \(new.count) indicators now.
            """)
        let named = operation == .update ? " [" + fields.map(\.rawValue).joined(separator: ", ") + "]" : ""
        for (indicators, verb) in [(added, "added"), (changed, "changed"), (removed, "removed")] {
            for indicator in indicators {
                let listed = verb == "changed" ? named : ""
                logger.info("""
                    \(caller, privacy: .public) \(verb, privacy: .public) “\(indicator.name, privacy: .public)” \
                    (\(indicator.id.uuidString, privacy: .public), \(indicator.severity.rawValue, privacy: .public), \
                    \(indicator.isEnabled ? "on" : "off", privacy: .public))\(listed, privacy: .public): \
                    \(indicator.predicate, privacy: .public)
                    """)
            }
        }
    }
}
