//
//  IndicatorPerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Evaluating indicators
/// Times what the Security Extension's indicators cost an event a capture lane builds: ``CompiledIndicators`` on
/// one event at a time, per event, for no rules, the shipped ones, 500 of one type and 2,048 path rules, and on
/// hostile execs (``AdversarialEvent``). Each also prints how many rules an event is evaluated against, and the
/// allocations an event makes, overall and when nothing matches.
///
/// Each also prints the scan units an event spends (``ScanBudget``), the pools it was refused, how many indicators it
/// left undetermined, and for a hostile exec the nanoseconds a unit took, which has to be at most 3: a weight that
/// takes longer is raised, the ceiling never relaxed. Ordinary events, and the benign guards, have to refuse nothing.
///
/// `<shipped>` is how many indicators Mac Monitor ships (32 in 3.1.0), so a benchmark of them names their count.
///
/// | Benchmark | Budget |
/// |---|---|
/// | `indicators.evaluate.<type>.0` | ≤ 0.1 µs |
/// | `indicators.evaluate.<type>.<shipped>` | ≤ 3 µs, no allocations when nothing matches |
/// | `indicators.evaluate.{exec,open}.<shipped>.record` | ≤ 4 µs: one walk of the event's encoding |
/// | `indicators.evaluate.open.<shipped>.record.guarded` | ≤ 3 µs, no allocations when nothing matches: no walk |
/// | `indicators.evaluate.{uipc_connect,xpc_connect}.<shipped>` | ≤ 3 µs, nothing matches, no allocations |
/// | `indicators.evaluate.<type>.500` | ≤ 60 µs |
/// | `indicators.evaluate.{open,close}.2048` | ≤ 250 µs |
/// | `indicators.evaluate.exec.adversarial.ascii` | ≤ 2 ms, nothing refused |
/// | `indicators.evaluate.exec.adversarial.nonascii` | ≤ 1 ms, Terminal startup and Login hook undetermined |
/// | `indicators.evaluate.exec.adversarial.{ascii,nonascii}.crafted`, `.nonascii.env` | ≤ 1 ms |
/// | `indicators.evaluate.exec.adversarial.{nonascii,ascii}.env.xcode`, `.ascii.crafted.500` | ≤ 1 ms |
/// | `indicators.evaluate.exec.adversarial.max` | ≤ 1 ms, ≤ 1,000 allocations |
/// | `indicators.evaluate.exec.adversarial.nonascii.16k` | ≤ 0.5 ms, nothing refused |
/// | `indicators.evaluate.exec.adversarial.marks` | ≤ 1 ms |
/// | `indicators.evaluate.close.nonascii.path256` | ≤ 0.25 ms, nothing refused |
/// | `indicators.evaluate.close.archive`, `.archive.band` | ≤ 3 µs |
/// | `indicators.evaluate.open.nonascii.2048` | reported, to tune the limits |
final class IndicatorPerformanceTests: PerformanceTestCase {
    /// Events per sample.
    private static let events = 10_000
    /// How many indicators Mac Monitor ships, which the shipped benchmarks' names say.
    private static let shipped = Indicator.defaults.count

    // MARK: No rules: an event's type is looked up, and nothing more
    /// An exec, no rules.
    func testExecNoRules() throws { try run("exec.0", .none, ES_EVENT_TYPE_NOTIFY_EXEC) }
    /// A close, no rules.
    func testCloseNoRules() throws { try run("close.0", .none, ES_EVENT_TYPE_NOTIFY_CLOSE) }
    /// A create, no rules.
    func testCreateNoRules() throws { try run("create.0", .none, ES_EVENT_TYPE_NOTIFY_CREATE) }
    /// An open, no rules.
    func testOpenNoRules() throws { try run("open.0", .none, ES_EVENT_TYPE_NOTIFY_OPEN) }

    // MARK: The shipped indicators
    /// An exec, the shipped rules.
    func testExecShipped() throws { try run("exec.\(Self.shipped)", .shipped, ES_EVENT_TYPE_NOTIFY_EXEC) }
    /// A close, the shipped rules.
    func testCloseShipped() throws { try run("close.\(Self.shipped)", .shipped, ES_EVENT_TYPE_NOTIFY_CLOSE) }
    /// A create, the shipped rules.
    func testCreateShipped() throws { try run("create.\(Self.shipped)", .shipped, ES_EVENT_TYPE_NOTIFY_CREATE) }
    /// An open, the shipped rules.
    func testOpenShipped() throws { try run("open.\(Self.shipped)", .shipped, ES_EVENT_TYPE_NOTIFY_OPEN) }
    /// A Unix domain socket connect that matches nothing, as nearly every one does, the shipped rules.
    func testUIPCConnectShipped() throws { try runConnects("uipc_connect", ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT) }
    /// An XPC connect that matches nothing, as nearly every one does, the shipped rules.
    func testXPCConnectShipped() throws { try runConnects("xpc_connect", ES_EVENT_TYPE_NOTIFY_XPC_CONNECT) }

    // MARK: 500 rules of the event's type, each a shipped one's made distinct
    /// An exec, 500 exec rules.
    func testExec500() throws { try run("exec.500", .distinct(500), ES_EVENT_TYPE_NOTIFY_EXEC) }
    /// A close, 500 close rules.
    func testClose500() throws { try run("close.500", .distinct(500), ES_EVENT_TYPE_NOTIFY_CLOSE) }
    /// A create, 500 create rules.
    func testCreate500() throws { try run("create.500", .distinct(500), ES_EVENT_TYPE_NOTIFY_CREATE) }
    /// An open, 500 open rules.
    func testOpen500() throws { try run("open.500", .distinct(500), ES_EVENT_TYPE_NOTIFY_OPEN) }

    // MARK: 2,048 path rules of the event's type: prefixes, suffixes, folders and patterns
    /// An open, 2,048 open path rules.
    func testOpen2048() throws { try run("open.2048", .paths(2_048), ES_EVENT_TYPE_NOTIFY_OPEN) }
    /// A close, 2,048 close path rules.
    func testClose2048() throws { try run("close.2048", .paths(2_048), ES_EVENT_TYPE_NOTIFY_CLOSE) }

    // MARK: Record fields: the shipped rules and two more that read an event's own encoding
    /// Exec, the shipped rules and two on record fields.
    func testExecRecordFields() throws {
        try run("exec.\(Self.shipped).record", .recordFields, ES_EVENT_TYPE_NOTIFY_EXEC)
    }
    /// Open, the shipped rules and two on record fields.
    func testOpenRecordFields() throws {
        try run("open.\(Self.shipped).record", .recordFields, ES_EVENT_TYPE_NOTIFY_OPEN)
    }
    /// Open, the shipped rules and one on a record field guarded by a path.
    func testOpenGuardedRecordField() throws {
        try run("open.\(Self.shipped).record.guarded", .guardedRecordField, ES_EVENT_TYPE_NOTIFY_OPEN)
    }

    // MARK: Hostile execs within ARG_MAX, against the shipped indicators (AdversarialEvent)
    /// A 1 MiB ASCII command line and script.
    func testAdversarialASCII() throws { try benchmarkAdversarial(.ascii) }
    /// The same with an "é", so Foundation compares 64 KiB of it.
    func testAdversarialNonASCII() throws { try benchmarkAdversarial(.nonascii) }
    /// A launchctl copy whose command line is crafted to make every search run its whole length.
    func testAdversarialCrafted() throws { try benchmarkAdversarial(.asciiCrafted) }
    /// The same, with a non-ASCII character.
    func testAdversarialCraftedNonASCII() throws { try benchmarkAdversarial(.nonasciiCrafted) }
    /// An environment of short non-ASCII variables filling ARG_MAX, which Dylib inserted's `ANY` reads.
    func testAdversarialNonASCIIEnvironment() throws { try benchmarkAdversarial(.nonasciiEnv) }
    /// The same with an ASCII `DYLD_INSERT_LIBRARIES` last, under `/Build/Products/`: Dylib inserted's Xcode branch.
    func testAdversarialNonASCIIEnvironmentXcode() throws { try benchmarkAdversarial(.nonasciiEnvXcode) }
    /// The same of ASCII variables.
    func testAdversarialASCIIEnvironmentXcode() throws { try benchmarkAdversarial(.asciiEnvXcode) }
    /// Every large field hostile at once.
    func testAdversarialMax() throws { try benchmarkAdversarial(.max) }
    /// A benign 16 KiB non-ASCII command line.
    func testAdversarialNonASCII16K() throws { try benchmarkAdversarial(.nonascii16k) }
    /// The crafted line against 500 rules, each searching it for a distinct literal at its end.
    func testAdversarialCrafted500() throws { try benchmarkAdversarial(.asciiCrafted500) }
    /// A run of combining marks in the command line and a variable, against `[c]`, `[d]` and `[cd]` comparisons.
    func testAdversarialMarks() throws { try benchmarkAdversarial(.marks) }

    // MARK: Closes named by their content, which Archive written's index looks up
    /// A modified close of a zip in a home folder, which Archive written matches, the shipped rules. Each close has
    /// native strings, as a capture lane builds it (``nativeCopy(of:)``).
    func testCloseArchive() throws {
        let zip = try nativeCopy(of: derivedClose(at: "/Users/marcus/Library/Caches/loot.zip",
                                                  type: "public.zip-archive"))
        try benchmarkEvaluation("indicators.evaluate.close.archive", CompiledIndicators(Indicator.defaults),
                                messages: Array(repeating: zip, count: Self.events), expecting: .decided)
    }

    /// A modified close of a sparse bundle's band that starts with a zip's bytes, by macOS's disk image daemon: the
    /// rule is evaluated to its last clause, the shipped rules.
    func testCloseArchiveBand() throws {
        let band = try nativeCopy(of: derivedClose(at: "/Users/marcus/Backups.sparsebundle/bands/1f",
                                                   type: "public.zip-archive", by: ("com.apple.diskimagesiod", true)))
        try benchmarkEvaluation("indicators.evaluate.close.archive.band", CompiledIndicators(Indicator.defaults),
                                messages: Array(repeating: band, count: Self.events), expecting: .decided)
    }

    // MARK: Benign paths that aren't ASCII
    /// A close of a 256-byte non-ASCII path in a home folder, the shipped rules.
    func testCloseNonASCIIPath() throws {
        try benchmarkEvaluation("indicators.evaluate.close.nonascii.path256", CompiledIndicators(Indicator.defaults),
                                messages: Array(repeating: nonASCIIPathEvent(ES_EVENT_TYPE_NOTIFY_CLOSE), count: 2_000),
                                expecting: .decided)
    }
    /// An open of it, 2,048 open path rules.
    func testOpenNonASCIIPath2048() throws {
        try benchmarkEvaluation("indicators.evaluate.open.nonascii.2048",
                                CompiledIndicators(pathRules(2_048, for: ES_EVENT_TYPE_NOTIFY_OPEN)),
                                messages: Array(repeating: nonASCIIPathEvent(ES_EVENT_TYPE_NOTIFY_OPEN), count: 200),
                                expecting: .anything)
    }
}


// MARK: - Measuring
extension IndicatorPerformanceTests {
    /// The rules a benchmark evaluates.
    enum Rules {
        /// None.
        case none
        /// The shipped indicators.
        case shipped
        /// Shipped rules of the event's type, made distinct (``XCTestCase/distinctRules(_:for:)``).
        case distinct(Int)
        /// Path rules of the event's type (``XCTestCase/pathRules(_:for:)``).
        case paths(Int)
        /// The shipped indicators, and two of the event's type on record fields (``recordFieldRules(for:in:)``).
        case recordFields
        /// The shipped indicators, and one on a record field and a path no event has, written record field first,
        /// which the compiler reverses (``IndicatorDraft/readingCheapestFirst``), so no event is walked.
        case guardedRecordField

        /// The rules.
        ///
        /// - Parameters:
        ///   - type: The events' type.
        ///   - test: The test making them.
        /// - Returns: The indicators.
        /// - Throws: A failure when a rule doesn't compile.
        func indicators(for type: es_event_type_t, in test: XCTestCase) throws -> [Indicator] {
            switch self {
            case .none: []
            case .shipped: Indicator.defaults
            case .distinct(let count): try test.distinctRules(count, for: type)
            case .paths(let count): test.pathRules(count, for: type)
            case .recordFields: try Indicator.defaults + Self.recordFieldRules(for: type, in: test)
            case .guardedRecordField:
                Indicator.defaults + [test.ownIndicator("Guarded record field", #"process.ppid == 1 AND "#
                    + #"target_path BEGINSWITH "/Library/Nowhere/" AND es_event_type == "ES_EVENT_TYPE_NOTIFY_OPEN""#)]
            }
        }

        /// Two rules of a type on record fields: the process's parent, and one of the event's own. No literal keeps
        /// them from an event of the type, so each event's encoding is walked once (``RecordPathTrie``).
        ///
        /// - Parameters:
        ///   - type: Exec, open, close, create or mmap.
        ///   - test: The test making them.
        /// - Returns: The rules.
        /// - Throws: A failure when one doesn't compile.
        static func recordFieldRules(for type: es_event_type_t, in test: XCTestCase) throws -> [Indicator] {
            let (name, own) = switch type {
            case ES_EVENT_TYPE_NOTIFY_EXEC: ("EXEC", #"event.exec.cwd.path BEGINSWITH "/private/tmp/""#)
            case ES_EVENT_TYPE_NOTIFY_OPEN: ("OPEN", "event.open.file.stat.st_uid == 0")
            case ES_EVENT_TYPE_NOTIFY_CLOSE: ("CLOSE", "event.close.target.stat.st_uid == 0")
            case ES_EVENT_TYPE_NOTIFY_CREATE: ("CREATE", "event.create.is_quarantined == 1")
            default: ("MMAP", "event.mmap.file_pos > 0")
            }
            let rules = ["process.ppid == 1", own].enumerated().map { position, predicate in
                let check = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_\#(name)" AND "#
                return test.ownIndicator("Record field \(position)", check + predicate)
            }
            let problems = CompiledIndicators(rules).problems
            guard problems.isEmpty else { throw BenchmarkFailure("\(problems.map(\.reason))") }
            return rules
        }
    }

    /// - Parameters:
    ///   - suffix: The benchmark's name after `indicators.evaluate.`.
    ///   - rules: The set's rules.
    ///   - type: The events' type.
    /// - Throws: The error making the events or writing the results.
    func run(_ suffix: String, _ rules: Rules, _ type: es_event_type_t) throws {
        try benchmarkEvaluation("indicators.evaluate." + suffix, rules, type)
    }

    /// Time the shipped indicators on connects that match none of them (``XCTestCase/connectEvents(_:count:)``).
    ///
    /// - Parameters:
    ///   - name: The events' type, as the benchmark's name has it.
    ///   - type: The events' type.
    /// - Throws: The error making the events or writing the results.
    func runConnects(_ name: String, _ type: es_event_type_t) throws {
        try benchmarkEvaluation("indicators.evaluate.\(name).\(Self.shipped)", CompiledIndicators(Indicator.defaults),
                                messages: connectEvents(type, count: Self.events), expecting: .decided)
    }

    /// Time a set on one type's events, then print its candidates and allocations per event.
    ///
    /// - Parameters:
    ///   - name: The benchmark's name.
    ///   - rules: The set's rules.
    ///   - type: The events' type.
    /// - Throws: The error making the events or writing the results.
    func benchmarkEvaluation(_ name: String, _ rules: Rules, _ type: es_event_type_t) throws {
        try benchmarkEvaluation(name, CompiledIndicators(try rules.indicators(for: type, in: self)),
                                messages: indicatorEvents(type, count: Self.events), expecting: .decided)
    }

    /// Time a hostile exec against its set (``AdversarialEvent``).
    ///
    /// - Parameter event: The exec.
    /// - Throws: The error making the event or writing the results.
    func benchmarkAdversarial(_ event: AdversarialEvent) throws {
        let message = try event.message(self)
        try benchmarkEvaluation("indicators.evaluate.exec.adversarial.\(event.rawValue)",
                                CompiledIndicators(event.indicators),
                                messages: Array(repeating: message, count: event.repetitions),
                                expecting: event.expectation, calibrating: true)
    }

    /// What a benchmark's events have to leave undecided.
    enum Expectation {
        /// Nothing: no read refused, the index's included, and no indicator undetermined.
        case decided
        /// Exactly these indicators, by name.
        case undetermined(Set<String>)
        /// Whatever they leave: reported only.
        case anything
    }

    /// Time a set on events, then print its rules of the events' type, the rules its index has each event evaluated
    /// against, its allocations per event and its scan units, and check what it left undecided.
    ///
    /// - Parameters:
    ///   - name: The benchmark's name.
    ///   - compiled: The set.
    ///   - messages: The events.
    ///   - expectation: What the events have to leave undecided.
    ///   - calibrating: Check that a unit took at most 3 ns, for an event that spent at least 10,000?
    /// - Throws: The error writing the results, or a failure when an event's hits aren't the same every time.
    func benchmarkEvaluation(_ name: String, _ compiled: CompiledIndicators, messages: [Message],
                             expecting expectation: Expectation, calibrating: Bool = false) throws {
        var values = MessageValueCache()
        var hits = 0
        try benchmark(name, operations: messages.count) {
            var found = 0
            for message in messages { found += compiled.hits(for: message, values: &values).count }
            guard hits == 0 || found == hits else { throw BenchmarkFailure("\(found) hits, then \(hits)") }
            hits = found
        }
        let type = CompiledIndicators.eventType(of: messages[0])
        let quiet = messages.filter { compiled.hits(for: $0, values: &values).isEmpty }
        let all = AllocationCounter.counting {
            for message in messages { _ = compiled.hits(for: message, values: &values) }
        }
        let none = AllocationCounter.counting {
            for message in quiet { _ = compiled.hits(for: message, values: &values) }
        }
        let evaluated = messages.reduce(0) { $0 + compiled.candidates(for: $1, values: &values).count }
        let scan = try scanReport(compiled, messages, expecting: expectation, calibrating: calibrating)
        print(String(format: "[performance] %@: %d rules of its type, %.2f evaluated/event, %.2f hits/event, "
                     + "%.3f allocations/event, %.3f allocations/event matching nothing (%d events), %d truncated, "
                     + "%@", name, compiled.candidates(forType: type), Double(evaluated) / Double(messages.count),
                     Double(hits) / Double(messages.count),
                     Double(all) / Double(messages.count), quiet.isEmpty ? 0 : Double(none) / Double(quiet.count),
                     quiet.count, values.truncatedEvaluations, scan))
    }

    /// Evaluate events once more for their scan units, the pools they were refused and what they left undecided,
    /// check those against what's expected, and time them for the nanoseconds a unit took.
    ///
    /// - Parameters:
    ///   - compiled: The set.
    ///   - messages: The events.
    ///   - expectation: What the events have to leave undecided.
    ///   - calibrating: Check the nanoseconds a unit took?
    /// - Returns: The report, as the benchmark's line ends.
    /// - Throws: A failure when an event leaves undecided what it shouldn't, spends past the event's limit, or a unit
    ///   took more than 3 ns.
    func scanReport(_ compiled: CompiledIndicators, _ messages: [Message], expecting expectation: Expectation,
                    calibrating: Bool) throws -> String {
        var values = MessageValueCache()
        var units = 0, refused: UInt8 = 0, refusedEvents = 0, undetermined = 0
        for message in messages {
            let evaluation = compiled.evaluate(message, values: &values)
            units += values.lastEventUnits
            refused |= values.lastEventRefused
            refusedEvents += values.lastEventRefused == 0 ? 0 : 1
            undetermined += evaluation.undeterminedCount
            guard values.lastEventUnits <= ScanBudget.eventLimit else {
                throw BenchmarkFailure("\(values.lastEventUnits) units is past the event's limit")
            }
            let names = Set(evaluation.undetermined.map(\.hit.name))
            switch expectation {
            case .decided where names.isEmpty && values.lastEventRefused == 0, .anything: break
            case .undetermined(let expected) where names == expected: break
            default:
                let pools = ScanPool.names(values.lastEventRefused)
                throw BenchmarkFailure("Undetermined \(names.sorted()), refused \(pools)")
            }
        }
        let clock = ContinuousClock()
        let elapsed = (0..<3).map { _ in
            clock.measure { for message in messages { _ = compiled.evaluate(message, values: &values) } }
        }.min() ?? .zero
        let perEvent = Double(elapsed.components.attoseconds) / 1e9 / Double(messages.count)
            + Double(elapsed.components.seconds) * 1e9 / Double(messages.count)
        let meanUnits = Double(units) / Double(messages.count)
        let perUnit = meanUnits > 0 ? perEvent / meanUnits : 0
        if calibrating, meanUnits >= 10_000, perUnit > 3 {
            throw BenchmarkFailure(String(format: "%.2f ns a unit, past 3", perUnit))
        }
        return String(format: "%.0f units/event, refused %@ (%d events), %.2f undetermined/event, %.2f ns/unit",
                      meanUnits, ScanPool.names(refused), refusedEvents,
                      Double(undetermined) / Double(messages.count), perUnit)
    }
}
