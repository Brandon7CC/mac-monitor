//
//  IndicatorTestRun.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Testing a pack
/// `macmonitor indicators test PACK --plan PLAN`: a pack's indicators tested on recorded events with the Security
/// Extension's own code, so the indicators repository's CI decides nothing the Security Extension wouldn't. It needs
/// neither root nor the Security Extension.
///
/// - Every indicator this build can run is compiled as the Security Extension compiles it, and one that doesn't
///   compile fails the run.
/// - Each case replays its events (``IndicatorReplay``) and checks the indicator does what the case expects. A case
///   also fails when any record leaves its indicator undetermined.
/// - Each benign corpus capture replays against every indicator the cases test, and fails for one that hits it more
///   often than an override allows, or that it leaves undetermined.
/// - A sequence runs as the Security Extension runs it, and a case's `records` name the lines that complete a chain.
///
/// It exits 0 when everything passes, 65 when a case or capture fails or an indicator doesn't compile, and 66 when a
/// file can't be read.
public struct IndicatorTestRun {
    /// What a case or capture came to.
    enum Outcome: Equatable {
        case passed(String)
        case failed(String)
        /// It couldn't be run by this build, which fails the run as a failure does.
        case notRun(String)
    }

    /// The pack.
    let pack: IndicatorPack
    /// The cases and captures.
    let plan: IndicatorTestPlan
    /// The folder the plan's paths are relative to.
    let base: URL

    /// The most bytes a pack's payload or a plan may have.
    static let maxFileBytes = IndicatorLimits.maxFileBytes

    /// - Parameters:
    ///   - pack: The pack.
    ///   - plan: The cases and captures.
    ///   - base: The folder the plan's paths are relative to.
    init(pack: IndicatorPack, plan: IndicatorTestPlan, base: URL) {
        (self.pack, self.plan, self.base) = (pack, plan, base)
    }

    /// Read a pack's payload and a plan, as the command line names them.
    ///
    /// - Parameters:
    ///   - packPath: The pack's payload, as `tools/mmi build` writes it.
    ///   - planPath: The plan, as `tools/mmi test` writes it.
    ///   - base: The folder the plan's paths are relative to: the folder `macmonitor` runs in.
    /// - Returns: The run, or why it can't start: 66 for a file that can't be read, 65 for one that isn't a pack or
    ///   a plan.
    public static func reading(pack packPath: String, plan planPath: String, base: URL)
        -> Result<IndicatorTestRun, CommandLineFailure> {
        let packData: Data, planData: Data
        do {
            packData = try readFile(packPath)
            planData = try readFile(planPath)
        } catch {
            return .failure(error)
        }
        let pack: IndicatorPack
        do {
            pack = try IndicatorPack.decode(packData)
        } catch {
            return .failure(CommandLineFailure(.dataError, "\(TerminalSafeText.quoted(packPath)) isn't a pack Mac "
                                                + "Monitor can test: \(error.description)"))
        }
        do {
            let plan = try JSONDecoder().decode(IndicatorTestPlan.self, from: planData)
            return .success(IndicatorTestRun(pack: pack, plan: plan, base: base))
        } catch {
            return .failure(CommandLineFailure(.dataError, "\(TerminalSafeText.quoted(planPath)) isn't a test plan: "
                                                + "\(error)"))
        }
    }

    /// `indicators test`: read the pack and plan, run every case and capture, and write the report.
    ///
    /// - Parameters:
    ///   - pack: The pack's payload, by path.
    ///   - plan: The plan, by path. Its paths are relative to the folder `macmonitor` runs in.
    ///   - output: Standard output.
    /// - Returns: Success when everything passed, or the exit status and summary: 65 for a failure, 66 for a file
    ///   that can't be read, 74 for a report that can't be written.
    public static func command(pack: String, plan: String, output: StreamOutput) -> Result<Void, CommandLineFailure> {
        let base = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
        return reading(pack: pack, plan: plan, base: base).flatMap { run in
            let report = run.run()
            do {
                try output.write(Data(report.text.utf8))
            } catch {
                return .failure(CommandLineFailure(.ioError, "The report couldn't be written."))
            }
            return report.exit == .success ? .success(()) : .failure(CommandLineFailure(report.exit, report.summary))
        }
    }

    /// - Parameter path: A file's path.
    /// - Returns: Its bytes.
    /// - Throws: ``CommandLineFailure`` (66) when it can't be read or is past ``maxFileBytes``.
    private static func readFile(_ path: String) throws(CommandLineFailure) -> Data {
        let data: Data
        do {
            data = try FileInput.read(path, upTo: maxFileBytes)
        } catch {
            throw CommandLineFailure(.noInput, "\(TerminalSafeText.quoted(path)) can't be read: "
                                     + "\(error.localizedDescription)")
        }
        guard data.count <= maxFileBytes else {
            throw CommandLineFailure(.noInput, "\(TerminalSafeText.quoted(path)) is over \(maxFileBytes >> 20) MiB.")
        }
        return data
    }

    /// Run every case and capture.
    ///
    /// - Returns: The report.
    func run() -> IndicatorTestReport {
        var replay = IndicatorReplay(pack.indicators.filter(\.isSupported))
        let problems = compileProblems(replay.compiled)
        var report = IndicatorTestReport(pack: pack, problems: problems)
        let failing = Set(problems.map(\.indicator.id))
        let byID = Indicator.byID(pack.indicators)
        for testCase in plan.cases {
            let indicator = byID[testCase.id]
            let outcome = check(testCase, indicator: indicator, compiled: !failing.contains(testCase.id),
                                replay: &replay, report: &report)
            report.add(case: testCase, indicator: indicator, outcome)
        }
        let tested = Set(plan.cases.map(\.id)).subtracting(failing).filter { byID[$0]?.isSupported == true }
        for capture in plan.corpus {
            report.add(capture: capture, check(capture, tested: tested, byID: byID, replay: &replay, report: &report))
        }
        return report
    }

    /// Each indicator this build can run that the Security Extension can't, and why: a rule on one event, or a
    /// sequence, the set didn't compile.
    ///
    /// - Parameter compiled: The pack's indicators, compiled.
    /// - Returns: Each, in the pack's order.
    private func compileProblems(_ compiled: CompiledIndicators) -> [(indicator: Indicator, reason: String)] {
        let reasons = Dictionary(compiled.problems.map { ($0.id, $0.reason) }) { first, _ in first }
        return pack.indicators.filter(\.isSupported).compactMap { indicator in
            reasons[indicator.id].map { (indicator, $0) }
        }
    }

    /// - Parameters:
    ///   - testCase: The case.
    ///   - indicator: Its indicator, or `nil` when the pack hasn't one with its identity.
    ///   - compiled: Did the indicator compile?
    ///   - replay: The replay.
    ///   - report: The report, told when a file can't be read.
    /// - Returns: What it came to.
    private func check(_ testCase: IndicatorTestPlan.Case, indicator: Indicator?, compiled: Bool,
                       replay: inout IndicatorReplay, report: inout IndicatorTestReport) -> Outcome {
        guard let indicator else { return .failed("The pack has no indicator \(testCase.id.uuidString).") }
        if let minEngine = indicator.minEngine, !indicator.isSupported {
            return .notRun("It needs Mac Monitor \(minEngine) or later.")
        }
        guard compiled else { return .failed("It doesn't compile.") }
        var matched: [Int] = [], undetermined: [Int] = [], total = 0
        do throws(IndicatorReplay.Failure) {
            try replay.replay(base.appendingPathComponent(testCase.events)) { verdicts in
                total += 1
                if verdicts.matched.contains(indicator.id) { matched.append(verdicts.line) }
                if verdicts.undetermined.contains(indicator.id) { undetermined.append(verdicts.line) }
            }
        } catch {
            return failure(error, reading: testCase.events, report: &report)
        }
        guard undetermined.isEmpty else { return .failed("It was left undetermined on \(Self.lines(undetermined)).") }
        guard testCase.expect == .match else {
            return matched.isEmpty ? .passed("No match in \(Self.records(total)).")
                : .failed("It matched \(Self.lines(matched)).")
        }
        guard !matched.isEmpty else { return .failed("No match in \(Self.records(total)).") }
        if let count = testCase.count, matched.count != count {
            return .failed("It matched \(Self.records(matched.count)), not \(count): \(Self.lines(matched)).")
        }
        let missing = (testCase.records ?? []).filter { !matched.contains($0) }
        guard missing.isEmpty else {
            return .failed("\(Self.lines(missing).capitalizedFirst) didn't match. "
                           + "\(Self.lines(matched).capitalizedFirst) did.")
        }
        return .passed("It matched \(Self.lines(matched)).")
    }

    /// - Parameters:
    ///   - capture: The capture.
    ///   - tested: The indicators the cases test that run on one event.
    ///   - byID: The pack's indicators, by identity.
    ///   - replay: The replay.
    ///   - report: The report, told when a file can't be read.
    /// - Returns: What it came to.
    private func check(_ capture: IndicatorTestPlan.Capture, tested: Set<UUID>, byID: [UUID: Indicator],
                       replay: inout IndicatorReplay, report: inout IndicatorTestReport) -> Outcome {
        var hits: [UUID: Int] = [:], undetermined: [UUID: Int] = [:], total = 0
        do throws(IndicatorReplay.Failure) {
            try replay.replay(base.appendingPathComponent(capture.events)) { verdicts in
                total += 1
                verdicts.matched.intersection(tested).forEach { hits[$0, default: 0] += 1 }
                verdicts.undetermined.intersection(tested).forEach { undetermined[$0, default: 0] += 1 }
            }
        } catch {
            return failure(error, reading: capture.events, report: &report)
        }
        let name = { (id: UUID) in byID[id].map { TerminalSafeText.text($0.name) } ?? id.uuidString }
        let over = hits.filter { $0.value > capture.allowedHits[$0.key, default: 0] }.keys
            .sorted { name($0) < name($1) }
        let reasons = over.map { "\(name($0)) hit it \(Self.times(hits[$0, default: 0])), "
            + "\(capture.allowedHits[$0, default: 0]) allowed" }
            + undetermined.keys.sorted { name($0) < name($1) }.map {
                "\(name($0)) was left undetermined \(Self.times(undetermined[$0, default: 0]))"
            }
        guard reasons.isEmpty else { return .failed(reasons.joined(separator: ". ") + ".") }
        return .passed("\(Self.records(total).capitalizedFirst), none past an indicator's allowed hits.")
    }

    /// - Parameters:
    ///   - error: Why a file couldn't be replayed.
    ///   - path: The file, as the plan names it.
    ///   - report: The report, told when the file can't be read.
    /// - Returns: The failure.
    private func failure(_ error: IndicatorReplay.Failure, reading path: String,
                         report: inout IndicatorTestReport) -> Outcome {
        switch error {
        case .unreadable(let reason):
            report.couldNotRead = true
            return .failed("\(TerminalSafeText.quoted(path)) can't be read: \(reason)")
        case .badRecord(let line, let reason):
            return .failed("Line \(line) of \(TerminalSafeText.quoted(path)) can't be replayed: \(reason)")
        }
    }
}
