//
//  IndicatorWeightTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Foundation's weights on hostile text
/// Checks each Foundation weight (``ScanCost``) on the text that costs Foundation most: every comparison that reads
/// characters, with no options, `[c]`, `[d]` and `[cd]`, of an exec's command line and of an `ANY` over its
/// environment, on values of 1 to 64 KiB of each ``HostileText``. Each is evaluated alone, with the event's budget,
/// and wherever it spends at least 10,000 units a unit has to take at most 3 ns: a weight that takes longer is raised,
/// the ceiling never relaxed. Each comparison's slowest unit is printed.
final class IndicatorWeightTests: PerformanceTestCase {
    /// The values' sizes, in bytes.
    static let sizes = [1 << 10, 4 << 10, 16 << 10, 64 << 10]
    /// The comparisons, each one that reads characters, with a constant the hostile text starts or nearly ends with.
    static let comparisons = [#"CONTAINS%@ "curlx""#, #"ENDSWITH%@ "x.plist""#, #"BEGINSWITH%@ "DYLD""#,
                              #"==%@ "D x""#, #"LIKE%@ "*curl*x""#]
    /// The options.
    static let options = ["", "[c]", "[d]", "[cd]"]

    /// Every comparison, on every text and size, of the command line and of the environment.
    func testEachFoundationWeightTakesAtMost3nsAUnit() throws {
        var worst: [String: Double] = [:]
        for text in HostileText.allCases {
            for size in Self.sizes {
                let value = text.value(size)
                let message = try corpusExec {
                    $0.command_line = value
                    $0.env = [value]
                }
                for comparison in Self.comparisons {
                    for option in Self.options {
                        let operation = String(format: comparison, option)
                        for field in ["event.exec.command_line ", "ANY event.exec.env "] {
                            let program = try execProgram(field + operation)
                            let (units, perUnit) = measure(program, on: message)
                            let name = "\(field)\(operation)"
                            guard units >= 10_000 else { continue }
                            worst[name] = max(worst[name] ?? 0, perUnit)
                            XCTAssertLessThanOrEqual(perUnit, 3, "\(name) on \(text) of \(size) B: \(units) units")
                        }
                    }
                }
            }
        }
        for (name, perUnit) in worst.sorted(by: { $0.key < $1.key }) {
            print(String(format: "[performance] indicators.weight %@: at most %.2f ns/unit", name, perUnit))
        }
    }
}


// MARK: - Measuring
extension IndicatorWeightTests {
    /// Text that costs Foundation most, each starting with "D" so `BEGINSWITH "DYLD"` matches its first letter.
    enum HostileText: String, CaseIterable {
        /// One run of U+0301, which `[d]` searches take quadratic time on.
        case marks
        /// U+0301 and U+0316 in turn, which NFKC reorders in quadratic time.
        case alternating
        /// Runs of 64 of those, each after an "a": `ENDSWITH` reorders each in quadratic time.
        case shortRuns
        /// "e" and U+0301 in turn, each pair of which NFKC composes.
        case decomposed
        /// "é", two bytes a scalar.
        case accented
        /// CJK ideographs, three bytes a scalar.
        case ideographs
        /// U+FDFA, which NFKC expands to eighteen scalars.
        case ligatures
        /// U+0390, which folding expands to three scalars.
        case iota
        /// Mostly ASCII, with an "é" every eleven bytes.
        case mixed

        /// What it repeats.
        var unit: String {
            switch self {
            case .marks: "\u{301}"
            case .alternating: "\u{301}\u{316}"
            case .shortRuns: "a" + String(repeating: "\u{301}\u{316}", count: 32)
            case .decomposed: "e\u{301}"
            case .accented: "\u{E9}"
            case .ideographs: "\u{4E2D}"
            case .ligatures: "\u{FDFA}"
            case .iota: "\u{390}"
            case .mixed: "--opt=v\u{E9} "
            }
        }

        /// - Parameter size: The most bytes.
        /// - Returns: "D" and the unit, repeated as often as fits, and " cur".
        func value(_ size: Int) -> String {
            "D" + String(repeating: unit, count: (size - 5) / unit.utf8.count) + " cur"
        }
    }

    /// Time a program on an exec, with the event's budget and a fresh cache each time.
    ///
    /// - Parameters:
    ///   - program: The program.
    ///   - message: The exec.
    /// - Returns: The units an evaluation spends, and the fewest nanoseconds a unit took over three runs.
    func measure(_ program: IndicatorProgram, on message: Message) -> (units: Int, perUnit: Double) {
        var values = MessageValueCache()
        _ = program.verdict(message, eventType: Self.execTypeNumber, values: &values)
        let units = values.scan.spent
        values.reset()
        guard units >= 10_000 else { return (units, 0) }
        let repetitions = max(3, 3_000_000 / (units * 3))
        let clock = ContinuousClock()
        let fastest = (0..<3).map { _ in
            clock.measure {
                for _ in 0..<repetitions {
                    _ = program.verdict(message, eventType: Self.execTypeNumber, values: &values)
                    values.reset()
                }
            }
        }.min() ?? .zero
        let nanoseconds = Double(fastest.components.seconds) * 1e9 + Double(fastest.components.attoseconds) / 1e9
        return (units, nanoseconds / Double(repetitions) / Double(units))
    }
}
