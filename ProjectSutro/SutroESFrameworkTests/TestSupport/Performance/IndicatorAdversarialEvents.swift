//
//  IndicatorAdversarialEvents.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Hostile events
/// The hostile events the indicator benchmarks and the scan budget's tests evaluate, each one Endpoint Security can
/// deliver: an exec's arguments and environment fit `ARG_MAX` as `execve` counts them (each string's bytes and NUL,
/// and an 8-byte pointer for each), and its script is 1 MiB at most.
///
/// - `ascii` and `nonascii`: `zsh -c` of a long run of options, with an "é" first for `nonascii`, so every comparison
///   of the line goes to Foundation.
/// - `ascii.crafted` and `nonascii.crafted`: a copy of launchctl whose one long argument is made of the first bytes of
///   the shipped rules' constants, with their whole constants only at its end, so every search runs the whole line.
/// - `nonascii.env`: a short non-ASCII command line and an environment of short non-ASCII variables filling the rest
///   of `ARG_MAX`, which Dylib inserted's `ANY` reads one at a time on every exec.
/// - `nonascii.env.xcode` and `ascii.env.xcode`: the same environment, of `éN` or `AN`, with one ASCII
///   `DYLD_INSERT_LIBRARIES` last and a target under `/Build/Products/`, so Dylib inserted's Xcode branch runs.
/// - `max`: a crafted 512 KiB argument, 43,690 `éN` variables, a 1 MiB script, and launchctl under `/Build/Products/`.
/// - `nonascii.16k`: a benign 16 KiB non-ASCII command line, which every rule should decide.
/// - `ascii.crafted.500`: the crafted line, its tail 500 distinct literals that 500 rules each search for.
/// - `marks`: a command line and a variable each a run of 8 KiB of combining marks, against rules that compare them
///   with `[c]`, `[d]` and `[cd]` (``diacriticRules``).
enum AdversarialEvent: String, CaseIterable {
    case ascii, nonascii
    case asciiCrafted = "ascii.crafted", nonasciiCrafted = "nonascii.crafted"
    case nonasciiEnv = "nonascii.env", nonasciiEnvXcode = "nonascii.env.xcode", asciiEnvXcode = "ascii.env.xcode"
    case max
    case nonascii16k = "nonascii.16k"
    case asciiCrafted500 = "ascii.crafted.500"
    case marks

    /// `ARG_MAX` on macOS: the most an exec's arguments and environment take, as `execve` counts them.
    static let argMax = 1 << 20
    /// The crafted line's repeated part: the shipped rules' constants' first bytes.
    static let craftedUnit = "c/ - . D L C -c l b s "
    /// The crafted line's end: the shipped rules' whole constants.
    static let craftedTail = " com.apple.atrun com.apple.Terminal CommandString com.apple.loginwindow LoginHook setenv "
        + "DYLD_INSERT_LIBRARIES -load-extension= bootstrap /Users/a/Library/LaunchAgents/x.plist"
    /// The library the Xcode cases insert, which isn't Xcode's.
    static let insertion = "DYLD_INSERT_LIBRARIES=/tmp/x.dylib"

    /// The literals `ascii.crafted.500`'s tail holds and its rules search for: each starts as the crafted line's
    /// repeated part does, so a search matches most of every repetition before it fails.
    static let distinctLiterals = (0..<500).map { craftedUnit + "#\($0)#" }

    /// The run of combining marks `marks` has in its command line and its variable.
    static let markRun = "D" + String(repeating: "\u{301}", count: 4_096) + " cur"

    /// Every comparison that reads characters, with `[c]`, `[d]` and `[cd]`, of the command line and of an `ANY` over
    /// the environment: what `marks` is evaluated against.
    static let diacriticRules: [Indicator] = {
        let comparisons = [#"CONTAINS%@ "curlx""#, #"ENDSWITH%@ "x.plist""#, #"BEGINSWITH%@ "DYLD""#, #"==%@ "D x""#,
                           #"LIKE%@ "*curl*x""#]
        let fields = ["event.exec.command_line ", "ANY event.exec.env "]
        return fields.flatMap { field in
            comparisons.flatMap { comparison in
                ["[c]", "[d]", "[cd]"].map { option in
                    Indicator(name: field + String(format: comparison, option), description: "", symbol: "star",
                              color: .red, predicate: #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" AND "# + field
                                + String(format: comparison, option))
                }
            }
        }
    }()

    /// The set the event is evaluated against: the shipped indicators, for `ascii.crafted.500` a rule per literal, and
    /// for `marks` ``diacriticRules``.
    var indicators: [Indicator] {
        if self == .marks { return Self.diacriticRules }
        guard self == .asciiCrafted500 else { return Indicator.defaults }
        return Self.distinctLiterals.enumerated().map { index, literal in
            Indicator(name: "Literal \(index)", description: "", symbol: "star", color: .red,
                      predicate: #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" AND event.exec.command_line CONTAINS "#
                        + IndicatorValue.literal(literal[...]))
        }
    }

    /// What it has to leave undecided against its set: nothing for the benign ones, Terminal startup and Login hook
    /// for `nonascii`, whose 1 MiB command line is past Foundation's window, and anything for the rest.
    var expectation: IndicatorPerformanceTests.Expectation {
        switch self {
        case .ascii, .nonascii16k: .decided
        case .nonascii: .undetermined(["Terminal startup command", "Login hook set"])
        default: .anything
        }
    }

    /// How many copies of it a benchmark's sample evaluates: fewer for those that cost the current engine most.
    var repetitions: Int {
        switch self {
        case .asciiCrafted500, .max, .nonasciiEnvXcode: 3
        case .nonascii16k: 2_000
        default: 50
        }
    }

    /// The event.
    ///
    /// - Parameter test: Makes the benchmark exec it starts from.
    /// - Returns: The exec, with native strings.
    /// - Throws: A failure when it wouldn't fit `ARG_MAX`, or the error making it.
    func message(_ test: XCTestCase) throws -> Message {
        let plan = self.plan
        let used = Self.execveBytes(plan.argv) + Self.execveBytes(plan.env)
        guard used <= Self.argMax else { throw BenchmarkFailure("\(rawValue): \(used) bytes is past ARG_MAX") }
        var message = try test.benchmarkExec()
        guard case .exec(var exec) = message.event else { throw BenchmarkFailure("Not an exec") }
        exec.args = plan.argv
        exec.argc = plan.argv.count
        exec.command_line = plan.argv.joined(separator: " ")
        if let env = plan.env { exec.env = env }
        exec.script_content = plan.script
        if let path = plan.target { exec.target.executable?.path = path }
        message.event = .exec(exec)
        return try test.nativeCopy(of: message)
    }

    /// An exec's arguments, environment (`nil` for the benchmark exec's own), script and target path.
    private typealias Plan = (argv: [String], env: [String]?, script: String?, target: String?)

    /// - Returns: What the event is made of.
    private var plan: Plan {
        let script = String(repeating: "echo hello world; ", count: Self.argMax / 18)
        let accent = "\u{E9}"
        let short = [accent, "/bin/zsh", "-c", "x"]
        switch self {
        case .ascii, .nonascii:
            let head = (self == .nonascii ? [accent] : []) + ["/bin/zsh", "-c"]
            return (head + [Self.filling(Self.argMax, after: head, with: "--option=value ")], [], script, nil)
        case .asciiCrafted, .nonasciiCrafted, .asciiCrafted500:
            let head = (self == .nonasciiCrafted ? [accent] : []) + ["/tmp/launchctl", "load"]
            let tail = self == .asciiCrafted500 ? Self.distinctLiterals.joined(separator: " ") : Self.craftedTail
            return (head + [Self.crafted(Self.argMax, after: head, tail: tail)], [], script, "/tmp/launchctl")
        case .nonasciiEnv:
            return (short, Self.environment("\u{E9}N", after: short), script, nil)
        case .nonasciiEnvXcode, .asciiEnvXcode:
            let argv = self == .asciiEnvXcode ? Array(short.dropFirst()) : short
            let element = self == .asciiEnvXcode ? "AN" : "\u{E9}N"
            let env = Self.environment(element, after: argv, reserving: [Self.insertion]) + [Self.insertion]
            return (argv, env, script, "/tmp/Build/Products/a")
        case .max:
            let head = ["/tmp/Build/Products/launchctl", "load"]
            let argv = head + [Self.crafted(Self.argMax / 2, after: head, tail: Self.craftedTail)]
            return (argv, Self.environment("\u{E9}N", after: argv), script, "/tmp/Build/Products/launchctl")
        case .nonascii16k:
            let head = [accent, "/bin/zsh", "-c"]
            return (head + [Self.filling(16 << 10, after: head, with: "--option=value ")], nil, nil, nil)
        case .marks:
            return (["/tmp/x", Self.markRun], [Self.markRun], nil, nil)
        }
    }

    /// - Parameter strings: An exec's arguments or environment.
    /// - Returns: What `execve` counts them as against `ARG_MAX`: their bytes, a NUL and a pointer each.
    static func execveBytes(_ strings: [String]?) -> Int {
        (strings ?? []).reduce(0) { $0 + $1.utf8.count + 1 + 8 }
    }

    /// - Parameters:
    ///   - size: The most the arguments may take.
    ///   - head: The arguments before the last.
    ///   - unit: What the last repeats.
    /// - Returns: The last argument: `unit` repeated as often as fits.
    private static func filling(_ size: Int, after head: [String], with unit: String) -> String {
        String(repeating: unit, count: (size - execveBytes(head) - 9) / unit.utf8.count)
    }

    /// - Parameters:
    ///   - size: The most the arguments may take.
    ///   - head: The arguments before the last.
    ///   - tail: What the last ends with.
    /// - Returns: The crafted last argument: ``craftedUnit`` repeated as often as fits before `tail`.
    private static func crafted(_ size: Int, after head: [String], tail: String) -> String {
        filling(size - tail.utf8.count, after: head, with: craftedUnit) + tail
    }

    /// - Parameters:
    ///   - element: Each variable.
    ///   - argv: The exec's arguments.
    ///   - reserved: Variables to leave room for.
    /// - Returns: As many copies of `element` as fit in what the arguments and `reserved` leave of `ARG_MAX`.
    private static func environment(_ element: String, after argv: [String],
                                    reserving reserved: [String] = []) -> [String] {
        let room = argMax - execveBytes(argv) - execveBytes(reserved)
        return Array(repeating: element, count: room / (element.utf8.count + 9))
    }
}


// MARK: - Benign events with non-ASCII paths
extension XCTestCase {
    /// A 256-byte path in a home folder whose name isn't ASCII, as a Mac whose user is named so has every day.
    static let nonASCIIHomePath: String = {
        let folder = "/Users/jos\u{E9}/Documents/Projects/"
        return folder + String(repeating: "a", count: 256 - folder.utf8.count - 4) + ".txt"
    }()

    /// A recording's event of one type with ``nonASCIIHomePath`` as its target, a close modified.
    ///
    /// - Parameter type: The type.
    /// - Returns: The event, with native strings.
    /// - Throws: A failure when the recording has none, or the error making it.
    func nonASCIIPathEvent(_ type: es_event_type_t) throws -> Message {
        let name = eventTypeToString(from: type)
        guard var message = try recordingEvents(400).first(where: { $0.es_event_type == name }) else {
            throw BenchmarkFailure("No \(name) events")
        }
        message.target_path = Self.nonASCIIHomePath
        if case .close(var close) = message.event {
            close.modified = true
            message.event = .close(close)
        }
        return try nativeCopy(of: message)
    }
}
