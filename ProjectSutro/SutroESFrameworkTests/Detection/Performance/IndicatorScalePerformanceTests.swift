//
//  IndicatorScalePerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/9/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Indicator scale
/// How the Security Extension's indicator cost grows with how many indicators there are and what shape they have, to
/// find where adding one starts to cost. Each sweep is the shipped indicators plus `N - <shipped>` generated ones of
/// one shape (``RuleShape``), for N in ``counts``, evaluated (``CompiledIndicators/hits(for:values:)``) on a
/// recording's ordinary events of one type (``XCTestCase/indicatorEvents(_:count:)``). None of the generated rules
/// matches them, so each sweep times what the set costs the events that match nothing, as nearly every one does.
/// The recording's processes are all platform binaries, so a rule guarded by `process.is_platform_binary == NO` stops
/// at its guard: the numbers sweeps time that, not a third-party process's events.
///
/// XCTest allows one `measure` per test, so a sweep times each N itself, as ``PerformanceTestCase`` does: one run to
/// warm up and size a sample to about ``sampleTarget``, then ``PerformanceRun/sampleCount`` samples, each written to
/// the results file under its own name. After each N it prints its rules of the events' type, the rules the index
/// had each event evaluated against, the scan units an event spent (``ScanBudget``), the events refused a read and
/// the indicators left undetermined, which an ordinary event should never have.
///
/// The compile sweeps time compiling each shape's set, print the heap it holds, and say whether the Security
/// Extension would take it (``IndicatorLimits``): past 256 rules on one type, or 2,048 indicators, it refuses the
/// whole set, so the larger counts here measure what those limits protect against, not a set a Mac can run.
///
/// | Benchmark | Budget |
/// |---|---|
/// | `indicators.scale.<shape>.<type>.<shipped>` | ≤ 3 µs, as `indicators.evaluate.<type>.<shipped>` |
/// | `indicators.scale.<shape>.<type>.<N>` | reported: where each shape's cost turns |
/// | `indicators.scale.path.nonascii.open.<N>` | reported: a path that isn't ASCII has every path rule's anchor |
/// | `indicators.scale.like.shared.home.close.<N>` | reported: a home folder's path has every rule's anchor |
/// | `indicators.scale.record.args.argv64.exec.<N>` | reported: every rule visits each of 64 arguments |
/// | `indicators.scale.compile.<shape>.<N>` | reported, with the heap the set holds |
final class IndicatorScalePerformanceTests: PerformanceTestCase {
    /// How many indicators Mac Monitor ships.
    private static let shipped = Indicator.defaults.count
    /// The set sizes each sweep measures: the shipped indicators, then larger sets that include them.
    static let counts = [shipped, 100, 500, 1_000, 2_048, 5_000, 10_000]
    /// The events a sweep evaluates, cycled through a recording's kinds of the type.
    private static let eventCount = 512
    /// About how long one sample takes.
    private static let sampleTarget = Duration.milliseconds(25)
    /// Samples per compile, which takes up to a second at the largest counts.
    private static let compileSamples = max(1, min(PerformanceRun.sampleCount, 5))

    // MARK: a. Path literals: BEGINSWITH and ENDSWITH[c], which the index's tries find in one walk of the path
    /// Execs, path prefixes and suffixes.
    func testPathExec() throws { try sweep(.path, ES_EVENT_TYPE_NOTIFY_EXEC) }
    /// Opens, path prefixes and suffixes.
    func testPathOpen() throws { try sweep(.path, ES_EVENT_TYPE_NOTIFY_OPEN) }
    /// Closes, path prefixes and suffixes.
    func testPathClose() throws { try sweep(.path, ES_EVENT_TYPE_NOTIFY_CLOSE) }
    /// Opens of a path that isn't ASCII, path prefixes and suffixes: the index marks every rule with an anchor on it.
    func testPathNonASCIIOpen() throws {
        let event = try nonASCIIPathEvent(ES_EVENT_TYPE_NOTIFY_OPEN)
        try sweep(.path, ES_EVENT_TYPE_NOTIFY_OPEN, label: "path.nonascii",
                  messages: Array(repeating: event, count: 64))
    }

    // MARK: a. Path literals searched for anywhere: CONTAINS, one search of the path per distinct literal
    /// Execs, path searches.
    func testPathContainsExec() throws { try sweep(.pathContains, ES_EVENT_TYPE_NOTIFY_EXEC) }
    /// Opens, path searches.
    func testPathContainsOpen() throws { try sweep(.pathContains, ES_EVENT_TYPE_NOTIFY_OPEN) }
    /// Closes, path searches.
    func testPathContainsClose() throws { try sweep(.pathContains, ES_EVENT_TYPE_NOTIFY_CLOSE) }

    // MARK: b. An exec's command line CONTAINS a distinct literal
    /// Execs, command line searches.
    func testCommandLine() throws { try sweep(.commandLine, ES_EVENT_TYPE_NOTIFY_EXEC) }
    /// Execs, command line searches with `[c]`.
    func testCommandLineFolded() throws { try sweep(.commandLineFolded, ES_EVENT_TYPE_NOTIFY_EXEC) }

    // MARK: c. Exact matches on direct fields: == and IN
    /// Execs, signing identifiers and executable names.
    func testExactExec() throws { try sweep(.exact, ES_EVENT_TYPE_NOTIFY_EXEC) }
    /// Opens, signing identifiers and executable names.
    func testExactOpen() throws { try sweep(.exact, ES_EVENT_TYPE_NOTIFY_OPEN) }
    /// Closes, signing identifiers and executable names.
    func testExactClose() throws { try sweep(.exact, ES_EVENT_TYPE_NOTIFY_CLOSE) }

    // MARK: d. LIKE patterns with stars
    /// Execs, patterns that start or end with a distinct literal.
    func testLikeAnchoredExec() throws { try sweep(.likeAnchored, ES_EVENT_TYPE_NOTIFY_EXEC) }
    /// Opens, patterns that start or end with a distinct literal.
    func testLikeAnchoredOpen() throws { try sweep(.likeAnchored, ES_EVENT_TYPE_NOTIFY_OPEN) }
    /// Closes, patterns that start or end with a distinct literal.
    func testLikeAnchoredClose() throws { try sweep(.likeAnchored, ES_EVENT_TYPE_NOTIFY_CLOSE) }
    /// Execs, patterns that all start with `/Users/`.
    func testLikeSharedExec() throws { try sweep(.likeShared, ES_EVENT_TYPE_NOTIFY_EXEC) }
    /// Opens, patterns that all start with `/Users/`.
    func testLikeSharedOpen() throws { try sweep(.likeShared, ES_EVENT_TYPE_NOTIFY_OPEN) }
    /// Closes, patterns that all start with `/Users/`.
    func testLikeSharedClose() throws { try sweep(.likeShared, ES_EVENT_TYPE_NOTIFY_CLOSE) }
    /// Closes of a file in a home folder, patterns that all start with `/Users/`: every one has the event's anchor.
    func testLikeSharedHomeClose() throws {
        let close = try nativeCopy(of: derivedClose(at: "/Users/marcus/Library/Caches/com.example.app/Cache.db",
                                                    type: nil))
        try sweep(.likeShared, ES_EVENT_TYPE_NOTIFY_CLOSE, label: "like.shared.home",
                  messages: Array(repeating: close, count: 64))
    }
    /// Execs, patterns that start and end with `*`.
    func testLikeFloatingExec() throws { try sweep(.likeFloating, ES_EVENT_TYPE_NOTIFY_EXEC) }
    /// Opens, patterns that start and end with `*`.
    func testLikeFloatingOpen() throws { try sweep(.likeFloating, ES_EVENT_TYPE_NOTIFY_OPEN) }
    /// Closes, patterns that start and end with `*`.
    func testLikeFloatingClose() throws { try sweep(.likeFloating, ES_EVENT_TYPE_NOTIFY_CLOSE) }

    // MARK: e. Literal-free: numbers and Booleans alone, which nothing prunes
    /// Execs, a platform binary check and an effective user.
    func testNumbersExec() throws { try sweep(.numbers, ES_EVENT_TYPE_NOTIFY_EXEC) }
    /// Opens, a platform binary check and a comparison of the ad hoc flag with a number it never is.
    func testNumbersOpen() throws { try sweep(.numbers, ES_EVENT_TYPE_NOTIFY_OPEN) }
    /// Closes, a platform binary check and a comparison of the ad hoc flag with a number it never is.
    func testNumbersClose() throws { try sweep(.numbers, ES_EVENT_TYPE_NOTIFY_CLOSE) }

    // MARK: f. Record fields: read from the event's encoding, in one walk
    /// Execs, a prefix of the working directory.
    func testRecordStringExec() throws { try sweep(.recordString, ES_EVENT_TYPE_NOTIFY_EXEC) }
    /// Opens, a prefix of the opened file's path.
    func testRecordStringOpen() throws { try sweep(.recordString, ES_EVENT_TYPE_NOTIFY_OPEN) }
    /// Closes, a prefix of the closed file's path.
    func testRecordStringClose() throws { try sweep(.recordString, ES_EVENT_TYPE_NOTIFY_CLOSE) }
    /// Execs, the process's parent.
    func testRecordNumberExec() throws { try sweep(.recordNumber, ES_EVENT_TYPE_NOTIFY_EXEC) }
    /// Opens, the process's parent.
    func testRecordNumberOpen() throws { try sweep(.recordNumber, ES_EVENT_TYPE_NOTIFY_OPEN) }
    /// Closes, the process's parent.
    func testRecordNumberClose() throws { try sweep(.recordNumber, ES_EVENT_TYPE_NOTIFY_CLOSE) }
    /// Execs, an argument.
    func testRecordArgsExec() throws { try sweep(.recordArgs, ES_EVENT_TYPE_NOTIFY_EXEC) }
    /// A compiler's exec with 64 include folders, an argument each: every rule visits all 64.
    func testRecordArgsLongExec() throws {
        let args = ["/usr/bin/clang"] + (1..<64).map { "-I/Users/user/Developer/Project/include/module\($0)" }
        let exec = try nativeCopy(of: importRecord(esloggerExec(parent: (401, 4010), args: args)))
        try sweep(.recordArgs, ES_EVENT_TYPE_NOTIFY_EXEC, label: "record.args.argv64",
                  messages: Array(repeating: exec, count: 64))
    }

    // MARK: g. A mix a detection engineer writes, over execs, opens and closes
    /// Execs, the mix.
    func testMixExec() throws { try sweep(.mix, ES_EVENT_TYPE_NOTIFY_EXEC) }
    /// Opens, the mix.
    func testMixOpen() throws { try sweep(.mix, ES_EVENT_TYPE_NOTIFY_OPEN) }
    /// Closes, the mix.
    func testMixClose() throws { try sweep(.mix, ES_EVENT_TYPE_NOTIFY_CLOSE) }

    // MARK: Compiling each shape's set, and the heap it holds
    /// Path prefixes and suffixes on execs.
    func testCompilePath() throws { try compileSweep(.path) }
    /// Command line searches.
    func testCompileCommandLine() throws { try compileSweep(.commandLine) }
    /// Exact matches on execs.
    func testCompileExact() throws { try compileSweep(.exact) }
    /// Anchored patterns on execs.
    func testCompileLike() throws { try compileSweep(.likeAnchored) }
    /// Numbers and Booleans on execs.
    func testCompileNumbers() throws { try compileSweep(.numbers) }
    /// Arguments.
    func testCompileRecordArgs() throws { try compileSweep(.recordArgs) }
    /// The mix.
    func testCompileMix() throws { try compileSweep(.mix) }
}


// MARK: - Rule shapes
extension IndicatorScalePerformanceTests {
    /// A shape of rule someone writes, generated as many times as a sweep needs, each with a literal or number of its
    /// own that no recorded event has.
    enum RuleShape: String {
        /// `target_path BEGINSWITH` a folder, or `ENDSWITH[c]` a file name, in turn.
        case path
        /// `target_path CONTAINS` a folder.
        case pathContains = "path.contains"
        /// `event.exec.command_line CONTAINS` an option.
        case commandLine = "command_line"
        /// The same with `[c]`.
        case commandLineFolded = "command_line.c"
        /// `process.signing_id ==` an identifier, or an executable's name `IN` two, in turn.
        case exact
        /// `target_path LIKE` a pattern that starts with a distinct folder, or ends with a distinct file, in turn.
        case likeAnchored = "like.anchored"
        /// `target_path LIKE[c] "/Users/*/Library/<distinct>/*"`, whose anchor every rule shares.
        case likeShared = "like.shared"
        /// `target_path LIKE[c] "*/<distinct>/*"`, which has no anchor.
        case likeFloating = "like.floating"
        /// Not a platform binary, and a number: an exec's effective user, or anything else's ad hoc signing.
        case numbers
        /// A record field's prefix: an exec's working directory, an open's or a close's file.
        case recordString = "record.string"
        /// `process.ppid ==` a number, a record field.
        case recordNumber = "record.number"
        /// `ANY event.exec.args ==` an argument, a record field.
        case recordArgs = "record.args"
        /// Ten rules a detection engineer writes, in turn (``mixRule(_:)``).
        case mix

        /// The shipped indicators and generated ones of the shape, `count` in all.
        ///
        /// - Parameters:
        ///   - count: How many, at least the shipped indicators.
        ///   - type: The events' type, which every generated rule runs on but the mix's.
        /// - Returns: The indicators, the shipped ones first.
        /// - Throws: A failure when a generated rule doesn't compile.
        func indicators(_ count: Int, for type: es_event_type_t) throws -> [Indicator] {
            let generated = (0..<max(0, count - Indicator.defaults.count)).map { index in
                let (ruleType, comparison) = rule(index, for: type)
                let check = "es_event_type == \"\(eventTypeToString(from: ruleType))\""
                return Indicator(name: "\(rawValue) \(index)", description: "", symbol: "star", color: .blue,
                                 predicate: check + " AND (" + comparison + ")")
            }
            let problems = CompiledIndicators(Array(generated.prefix(10))).problems
            guard problems.isEmpty else { throw BenchmarkFailure("\(self): \(problems.map(\.reason))") }
            return Indicator.defaults + generated
        }

        /// One generated rule.
        ///
        /// - Parameters:
        ///   - index: Its place among the generated rules, which makes its literal or number its own.
        ///   - type: The events' type.
        /// - Returns: The type it runs on, and its predicate after its type check.
        func rule(_ index: Int, for type: es_event_type_t) -> (es_event_type_t, String) {
            let exec = type == ES_EVENT_TYPE_NOTIFY_EXEC
            let comparison: String
            switch self {
            case .path:
                comparison = index.isMultiple(of: 2) ? #"target_path BEGINSWITH "/Library/Vendor\#(index)/""#
                    : #"target_path ENDSWITH[c] "/vendor\#(index).plist""#
            case .pathContains: comparison = #"target_path CONTAINS "/Vendor\#(index)/""#
            case .commandLine: comparison = #"event.exec.command_line CONTAINS " --vendor-\#(index) ""#
            case .commandLineFolded: comparison = #"event.exec.command_line CONTAINS[c] " --vendor-\#(index) ""#
            case .exact:
                let name = exec ? "event.exec.target.executable.name" : "process.executable.name"
                comparison = index.isMultiple(of: 2) ? #"process.signing_id == "com.vendor\#(index).agent""#
                    : #"\#(name) IN {"tool\#(index)", "tool\#(index)-helper"}"#
            case .likeAnchored:
                comparison = index.isMultiple(of: 2) ? #"target_path LIKE "/Library/Vendor\#(index)/*.plist""#
                    : #"target_path LIKE[c] "*/vendor\#(index).dylib""#
            case .likeShared: comparison = #"target_path LIKE[c] "/Users/*/Library/Vendor\#(index)/*""#
            case .likeFloating: comparison = #"target_path LIKE[c] "*/Vendor\#(index)/*""#
            case .numbers:
                comparison = exec ? "process.is_platform_binary == NO AND event.exec.target.euid == \(100_000 + index)"
                    : "process.is_platform_binary == NO AND process.is_adhoc_signed == \(2 + index)"
            case .recordString:
                let field = exec ? "event.exec.cwd.path"
                    : type == ES_EVENT_TYPE_NOTIFY_OPEN ? "event.open.file.path" : "event.close.target.path"
                comparison = #"\#(field) BEGINSWITH "/Library/Vendor\#(index)/""#
            case .recordNumber: comparison = "process.ppid == \(1_000_000 + index)"
            case .recordArgs: comparison = #"ANY event.exec.args == "--vendor-\#(index)""#
            case .mix: return Self.mixRule(index)
            }
            return (type, comparison)
        }

        /// One of the mix's rules: in each ten, two on closes, two on opens and six on execs.
        ///
        /// 0. A modified close of a launch daemon's property list, by its prefix.
        /// 1. A close of a launch agent in any home folder, by a pattern every such rule starts the same.
        /// 2. An open of a credentials file, searched for anywhere in the path, `[c]`.
        /// 3. A process that isn't a platform binary passing an option, searched for in the command line, `[c]`.
        /// 4. An exec of either of two signing identifiers.
        /// 5. An exec of a tool by name whose command line runs a script.
        /// 6. An exec of a payload from a temporary folder, by a pattern that ends with its name.
        /// 7. An exec from a working directory, a record field.
        /// 8. A root exec by a process that isn't a platform binary, for a real user: numbers alone.
        /// 9. An open of a socket by a process launchd started, a record field guarded by the path's end.
        ///
        /// - Parameter index: The rule's place among the generated rules.
        /// - Returns: Its type, and its predicate after its type check.
        static func mixRule(_ index: Int) -> (es_event_type_t, String) {
            let unique = 100_000 + index
            switch index % 10 {
            case 0:
                return (ES_EVENT_TYPE_NOTIFY_CLOSE, "event.close.modified == YES AND "
                        + #"target_path BEGINSWITH "/Library/LaunchDaemons/com.vendor\#(index).""#)
            case 1:
                return (ES_EVENT_TYPE_NOTIFY_CLOSE,
                        #"target_path LIKE[c] "/Users/*/Library/LaunchAgents/com.vendor\#(index).*""#)
            case 2: return (ES_EVENT_TYPE_NOTIFY_OPEN, #"target_path CONTAINS[c] "/vendor\#(index)/credentials""#)
            case 3:
                return (ES_EVENT_TYPE_NOTIFY_EXEC, "process.is_platform_binary == NO AND "
                        + #"event.exec.command_line CONTAINS[c] "--payload-\#(index)""#)
            case 4:
                return (ES_EVENT_TYPE_NOTIFY_EXEC, #"event.exec.target.signing_id IN "#
                        + #"{"com.vendor\#(index).updater", "com.vendor\#(index).helper"}"#)
            case 5:
                return (ES_EVENT_TYPE_NOTIFY_EXEC, #"event.exec.target.executable.name == "tool\#(index)" AND "#
                        + #"event.exec.command_line CONTAINS " -e ""#)
            case 6: return (ES_EVENT_TYPE_NOTIFY_EXEC, #"target_path LIKE[c] "*/tmp/*/payload\#(index)""#)
            case 7:
                return (ES_EVENT_TYPE_NOTIFY_EXEC, #"event.exec.cwd.path BEGINSWITH "/private/tmp/vendor\#(index)""#)
            case 8:
                return (ES_EVENT_TYPE_NOTIFY_EXEC, "event.exec.target.euid == 0 AND process.is_platform_binary == NO "
                        + "AND event.exec.target.ruid == \(unique)")
            default:
                return (ES_EVENT_TYPE_NOTIFY_OPEN,
                        #"process.ppid == 1 AND target_path ENDSWITH "/vendor\#(index).sock""#)
            }
        }
    }
}


// MARK: - Measuring
extension IndicatorScalePerformanceTests {
    /// Time a shape's sets at every count on one type's events, and print what each costs an event.
    ///
    /// - Parameters:
    ///   - shape: The rules' shape.
    ///   - type: The events' type.
    ///   - label: The shape as the benchmarks' names have it, its own by default.
    ///   - messages: The events, a recording's ordinary ones of the type by default.
    /// - Throws: The error making the events or writing the results, or a failure when a rule doesn't compile.
    func sweep(_ shape: RuleShape, _ type: es_event_type_t, label: String? = nil, messages: [Message]? = nil) throws {
        let messages = try messages ?? indicatorEvents(type, count: Self.eventCount)
        let typeName = Self.indicatorBenchmarkTypes.first { $0.type == type }?.name ?? "\(type.rawValue)"
        for count in Self.counts {
            let compiled = CompiledIndicators(try shape.indicators(count, for: type))
            guard compiled.problems.isEmpty else {
                throw BenchmarkFailure("\(shape) \(count): \(compiled.problems.map(\.reason))")
            }
            try benchmarkScale("indicators.scale.\(label ?? shape.rawValue).\(typeName).\(count)", compiled, messages)
        }
    }

    /// Time a set on events, per event, then print its rules of their type, those the index had each evaluated
    /// against, the scan units each spent, and what each left undecided.
    ///
    /// - Parameters:
    ///   - name: The benchmark's name.
    ///   - compiled: The set.
    ///   - messages: The events, all of one type.
    /// - Throws: The error writing the results, or a failure when an event's hits change from one run to the next.
    func benchmarkScale(_ name: String, _ compiled: CompiledIndicators, _ messages: [Message]) throws {
        var values = MessageValueCache()
        let clock = ContinuousClock()
        var hits = -1
        let warm = clock.measure { hits = Self.evaluate(compiled, messages, &values) }
        let events = warm > Self.sampleTarget
            ? Array(messages.prefix(max(16, Int(Double(messages.count) * (Self.sampleTarget / warm)))))
            : messages
        let passes = warm > Self.sampleTarget ? 1 : max(1, Int(Self.sampleTarget / max(warm, .nanoseconds(1))))
        let expected = events.count == messages.count ? hits * passes : -1
        var samples: [PerformanceSample] = []
        for _ in 0..<PerformanceRun.sampleCount {
            var found = 0
            samples.append(PerformanceSample.taking {
                for _ in 0..<passes { found += Self.evaluate(compiled, events, &values) }
            })
            guard expected < 0 || found == expected else { throw BenchmarkFailure("\(found) hits, not \(expected)") }
        }
        let result = PerformanceResult(name: name, test: self.name, unit: "event", operations: passes * events.count,
                                       samples: samples)
        try PerformanceReport.shared.add(result)
        print("[performance] \(result.summary)")
        print("[performance] \(name): " + Self.detail(compiled, events, &values))
    }

    /// Evaluate a set on events, as a capture lane does.
    ///
    /// - Parameters:
    ///   - compiled: The set.
    ///   - messages: The events.
    ///   - values: The lane's values.
    /// - Returns: How many hits they had in all.
    @inline(never)
    static func evaluate(_ compiled: CompiledIndicators, _ messages: [Message],
                         _ values: inout MessageValueCache) -> Int {
        var found = 0
        for message in messages { found += compiled.hits(for: message, values: &values).count }
        return found
    }

    /// What a set does to events, per event: its rules of their type, those the index has each evaluated against
    /// within the event's budget, its hits, the scan units spent, the events refused a read, and the indicators left
    /// undetermined.
    ///
    /// - Parameters:
    ///   - compiled: The set.
    ///   - messages: The events, all of one type.
    ///   - values: The lane's values.
    /// - Returns: The line, after the benchmark's name.
    static func detail(_ compiled: CompiledIndicators, _ messages: [Message],
                       _ values: inout MessageValueCache) -> String {
        var evaluated = 0, hits = 0, units = 0, refused: UInt8 = 0, refusedEvents = 0, undetermined = 0
        for message in messages {
            evaluated += compiled.candidates(for: message, values: &values, budget: ScanBudget.eventLimit).count
            let evaluation = compiled.evaluate(message, values: &values)
            hits += evaluation.hits.count
            units += values.lastEventUnits
            refused |= values.lastEventRefused
            refusedEvents += values.lastEventRefused == 0 ? 0 : 1
            undetermined += evaluation.undeterminedCount
        }
        let events = Double(messages.count)
        return String(format: "%d rules, %d of its type, %.2f evaluated/event, %.2f hits/event, %.0f units/event, "
                      + "refused %@ (%d of %d events), %.2f undetermined/event", compiled.count,
                      compiled.candidates(forType: CompiledIndicators.eventType(of: messages[0])),
                      Double(evaluated) / events, Double(hits) / events, Double(units) / events,
                      ScanPool.names(refused), refusedEvents, messages.count, Double(undetermined) / events)
    }

    /// Time compiling a shape's sets at every count, as the Security Extension compiles a saved set it loads, then
    /// print the heap each holds and whether the Security Extension takes it (``IndicatorFile/validate(_:)``).
    ///
    /// - Parameter shape: The rules' shape, on execs.
    /// - Throws: The error writing the results, or a failure when a rule doesn't compile.
    func compileSweep(_ shape: RuleShape) throws {
        for count in Self.counts {
            let indicators = try shape.indicators(count, for: ES_EVENT_TYPE_NOTIFY_EXEC)
            let name = "indicators.scale.compile.\(shape.rawValue).\(count)"
            _ = autoreleasepool { CompiledIndicators(indicators) }
            let samples = (0..<Self.compileSamples).map { _ in
                PerformanceSample.taking { _ = autoreleasepool { CompiledIndicators(indicators) } }
            }
            let result = PerformanceResult(name: name, test: self.name, unit: "set", operations: 1, samples: samples)
            try PerformanceReport.shared.add(result)
            print("[performance] \(result.summary)")
            let before = IndicatorSetPerformanceTests.heapInUse
            let set = autoreleasepool { CompiledIndicators(indicators) }
            let held = IndicatorSetPerformanceTests.heapInUse - before
            let busiest = set.busiestType().map { busiest in
                "\(busiest.rules) on \(eventTypeToString(from: es_event_type_t(rawValue: UInt32(busiest.type))))"
            }
            print(String(format: "[performance] %@: %.2f MB of heap, %d rules, %d nodes, busiest type %@, %@", name,
                         Double(held) / 1e6, set.count, set.nodeCount, busiest ?? "none",
                         Self.verdict(indicators, set)))
        }
    }

    /// Whether the Security Extension takes a set, as it checks one a request or its saved file brings.
    ///
    /// - Parameters:
    ///   - indicators: The set.
    ///   - compiled: The set, compiled.
    /// - Returns: "taken", or why it's refused.
    static func verdict(_ indicators: [Indicator], _ compiled: CompiledIndicators) -> String {
        do {
            try IndicatorFile.validate(indicators)
            try IndicatorFile.validate(compiled)
            return "taken"
        } catch {
            return "refused: \(error)"
        }
    }
}
