//
//  IndicatorTestReport.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Test reports
/// What `macmonitor indicators test` found, as it prints it: the indicators that didn't compile, each case and benign
/// capture with what it came to, and a summary, then the exit status it all comes to.
///
/// ```text
/// Pack 1 from commit f8911d2: 45 indicators, tested with Mac Monitor 3.2.0's engine.
///
/// Cases
///   ok       Archive written: zip writes an archive. It matched line 1.
///   FAILED   Login: A login at the login window. No match in 4 records.
///
/// 89 of 90 cases passed, and 1 failed. 1 of 1 benign capture passed. Every indicator compiled.
/// ```
struct IndicatorTestReport {
    /// The pack tested.
    let pack: IndicatorPack
    /// The indicators that didn't compile, and why.
    let problems: [(indicator: Indicator, reason: String)]
    /// Was there a file that couldn't be read? It exits 66 then.
    var couldNotRead = false
    /// Each case's line.
    private var caseLines: [String] = []
    /// Each capture's line.
    private var captureLines: [String] = []
    /// How many cases passed, failed and weren't run.
    private var passed = 0, failed = 0, notRun = 0
    /// How many captures passed and failed.
    private var capturesPassed = 0, capturesFailed = 0

    /// - Parameters:
    ///   - pack: The pack tested.
    ///   - problems: The indicators that didn't compile, and why.
    init(pack: IndicatorPack, problems: [(indicator: Indicator, reason: String)]) {
        (self.pack, self.problems) = (pack, problems)
    }

    /// Add a case's outcome.
    ///
    /// - Parameters:
    ///   - testCase: The case.
    ///   - indicator: Its indicator, or `nil` when the pack hasn't one.
    ///   - outcome: What it came to.
    mutating func add(case testCase: IndicatorTestPlan.Case, indicator: Indicator?,
                      _ outcome: IndicatorTestRun.Outcome) {
        let name = indicator.map(\.name) ?? testCase.id.uuidString
        caseLines.append(Self.line(TerminalSafeText.text("\(name): \(testCase.name)"), outcome))
        switch outcome {
        case .passed: passed += 1
        case .failed: failed += 1
        case .notRun: notRun += 1
        }
    }

    /// Add a capture's outcome.
    ///
    /// - Parameters:
    ///   - capture: The capture.
    ///   - outcome: What it came to.
    mutating func add(capture: IndicatorTestPlan.Capture, _ outcome: IndicatorTestRun.Outcome) {
        captureLines.append(Self.line(TerminalSafeText.text(capture.events), outcome))
        if case .passed = outcome { capturesPassed += 1 } else { capturesFailed += 1 }
    }

    /// The status it exits with: 66 when a file couldn't be read, 65 when anything else failed, and 0 when nothing
    /// did.
    var exit: CommandLineExit {
        if couldNotRead { return .noInput }
        return failed + notRun + capturesFailed + problems.count > 0 ? .dataError : .success
    }

    /// The last line: how many cases and captures passed, and whether every indicator compiled.
    var summary: String {
        let cases = passed + failed + notRun
        let others = [failed > 0 ? "\(failed) failed" : nil,
                      notRun > 0 ? "\(notRun) \(notRun == 1 ? "wasn't" : "weren't") run" : nil].compactMap { $0 }
        let caseText = "\(passed) of \(cases) \(cases == 1 ? "case" : "cases") passed"
            + (others.isEmpty ? "." : ", and " + others.joined(separator: " and ") + ".")
        let captures = capturesPassed + capturesFailed
        let captureText = captures == 0 ? "No benign capture was replayed."
            : "\(capturesPassed) of \(captures) benign \(captures == 1 ? "capture" : "captures") passed."
        let compileText = problems.isEmpty ? "Every indicator compiled."
            : "\(problems.count) \(problems.count == 1 ? "indicator doesn't" : "indicators don't") compile."
        return [caseText, captureText, compileText].joined(separator: " ")
    }

    /// The whole report, ending in a newline.
    var text: String {
        let header = "Pack \(pack.pack.sequence) from commit \(pack.pack.commit.prefix(7)): "
            + "\(pack.indicators.count) indicators, tested with Mac Monitor \(Indicator.engineVersion)'s engine."
            + (pack.newer.isEmpty ? "" : " \(pack.newer.count) need a newer Mac Monitor and weren't read.")
        var sections = [TerminalSafeText.text(header)]
        if !problems.isEmpty {
            sections.append((["Didn't compile"] + problems.map { problem in
                "  " + TerminalSafeText.text("\(problem.indicator.name) (\(problem.indicator.id.uuidString)): "
                                             + problem.reason)
            }).joined(separator: "\n"))
        }
        if !caseLines.isEmpty { sections.append((["Cases"] + caseLines).joined(separator: "\n")) }
        if !captureLines.isEmpty { sections.append((["Benign corpus"] + captureLines).joined(separator: "\n")) }
        sections.append(summary)
        return sections.joined(separator: "\n\n") + "\n"
    }

    /// - Parameters:
    ///   - label: What the outcome is for, made safe for a terminal.
    ///   - outcome: What it came to.
    /// - Returns: Its line: the status, padded, the label and what happened.
    private static func line(_ label: String, _ outcome: IndicatorTestRun.Outcome) -> String {
        let (status, detail): (String, String)
        switch outcome {
        case .passed(let text): (status, detail) = ("ok", text)
        case .failed(let text): (status, detail) = ("FAILED", text)
        case .notRun(let text): (status, detail) = ("NOT RUN", text)
        }
        return "  " + status.padding(toLength: 9, withPad: " ", startingAt: 0) + label + ". "
            + TerminalSafeText.text(detail)
    }
}


// MARK: - Counting in words
extension IndicatorTestRun {
    /// The most lines a message names before it says how many more.
    static let linesNamed = 8

    /// - Parameter lines: Line numbers, from 1.
    /// - Returns: Such as "line 3", "lines 3 and 7" or "lines 3, 7 and 9", naming at most ``linesNamed``.
    static func lines(_ lines: [Int]) -> String {
        let named = lines.prefix(linesNamed).map(String.init)
        let more = lines.count - named.count
        let list = more > 0 ? named + ["\(more) more"] : named
        guard list.count > 1 else { return "line \(list.first ?? "")" }
        return "lines " + list.dropLast().joined(separator: ", ") + " and " + (list.last ?? "")
    }

    /// - Parameter count: How many records.
    /// - Returns: Such as "1 record" or "4 records".
    static func records(_ count: Int) -> String {
        "\(count) \(count == 1 ? "record" : "records")"
    }

    /// - Parameter count: How many times.
    /// - Returns: Such as "once" or "3 times".
    static func times(_ count: Int) -> String {
        count == 1 ? "once" : "\(count) times"
    }
}


extension String {
    /// It with its first character uppercased, such as "Line 3" for "line 3".
    var capitalizedFirst: String {
        prefix(1).uppercased() + dropFirst()
    }
}
