//
//  IndicatorCompiler.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
import EndpointSecurity


// MARK: - Indicator compiler
/// Makes an indicator's predicate into the ``IndicatorProgram`` the Security Extension runs, or says why it can't
/// (``SensorProblem``).
///
/// The predicate is read as Settings > Indicators reads it (``StreamFilter/Predicate/parse(_:for:maxLength:)`` for
/// ``PredicateAudience/indicator``), so its length cap, its booleans standing alone and ``PredicateGuard`` are the
/// same. The parsed tree is walked once and never evaluated. Parentheses and braces are counted first, and more than
/// ``maxDepth`` deep is refused before anything parses it.
///
/// Every indicator the Security Extension runs names its event types (``PredicateEventTypes``), and is run only on
/// events of those types. So a top-level `AND`'s `es_event_type` check that every one of them passes is dropped. A
/// type check anywhere else stays, as a comparison of the event's type number: Plist modified's `CLOSE` and `RENAME`
/// checks inside its `OR` still tell a close from a rename.
///
/// However a predicate orders its comparisons, each `AND`'s and `OR`'s children run cheapest to read first
/// (``IndicatorDraft/readingCheapestFirst``), so how a rule is written can't make an event's large fields be read
/// before a cheap field rules it out.
///
/// What it refuses, each with its own ``SensorProblem``:
/// - `MATCHES`, `SUBQUERY`, `ALL`, `BETWEEN`, functions, aggregates and variables.
/// - A key path it doesn't read (``IndicatorField``) or one filled after capture.
/// - A string compared with a number, ordered, or an array compared without `ANY`.
/// - `?`, `\` or other than ASCII in a `LIKE` pattern.
/// - A number that isn't whole within ±2^53 or finite.
/// - More than ``maxNodes`` nodes, or a constant over ``maxConstantBytes``.
/// - A rule that names no event type, and one whose type checks can never all pass.
public enum IndicatorCompiler {
    /// The deepest parentheses and braces may nest.
    public static let maxDepth = 32
    /// The most nodes a rule's program may have.
    public static let maxNodes = 256
    /// The longest a string constant may be, in UTF-8 bytes.
    public static let maxConstantBytes = 1_024
    /// The largest whole number compared exactly as a `Double`.
    static let maxInteger = Double(1 << 53)

    /// A compiled rule.
    public struct Rule: Equatable, Sendable {
        /// The event types it runs on, by number, in order.
        public let types: [Int]
        /// What it checks of each.
        public let program: IndicatorProgram
    }

    /// Compile a predicate.
    ///
    /// - Parameter source: The predicate's text, as an indicator has it.
    /// - Returns: The rule, or why the Security Extension can't run it.
    public static func compile(_ source: String) -> Result<Rule, SensorProblem> {
        let depth = nestingDepth(of: source)
        guard depth <= maxDepth else { return .failure(.tooDeep(depth)) }
        let parsed: NSPredicate
        do {
            parsed = try StreamFilter.Predicate.parse(source, for: .indicator)
        } catch {
            return .failure(.unreadable((error as? CommandLineUsageError)?.message ?? error.localizedDescription))
        }
        guard let names = PredicateEventTypes.eventTypes(of: parsed) else { return .failure(.untyped) }
        guard !names.isEmpty else { return .failure(.contradictoryTypes) }
        let types = names.map { eventStringToType(from: $0) }.filter { $0 != ES_EVENT_TYPE_LAST }
            .map { Int($0.rawValue) }
        guard !types.isEmpty else { return .failure(.unknownEventTypes(names.sorted())) }
        do {
            var drafting = IndicatorDraft.Builder()
            let draft = try drafting.draft(parsed).flattened.removingTypeChecks(passedBy: Set(types))
                .readingCheapestFirst
            return .success(Rule(types: types.sorted(), program: IndicatorProgram(draft)))
        } catch let problem as SensorProblem {
            return .failure(problem)
        } catch {
            return .failure(.unreadable(error.localizedDescription))
        }
    }

    /// Why a predicate can't run in the Security Extension, or `nil` when it can.
    ///
    /// - Parameter source: The predicate.
    /// - Returns: The problem, or `nil`.
    public static func problem(with source: String) -> SensorProblem? {
        if case .failure(let problem) = compile(source) { return problem }
        return nil
    }

    /// How deep a predicate's parentheses and braces nest, outside its quoted strings.
    ///
    /// - Parameter source: The predicate.
    /// - Returns: The deepest nesting.
    static func nestingDepth(of source: String) -> Int {
        var depth = 0, deepest = 0
        PredicateText.forEachUnquotedByte(in: source) { byte in
            switch byte {
            case UInt8(ascii: "("), UInt8(ascii: "{"):
                depth += 1
                deepest = max(deepest, depth)
            case UInt8(ascii: ")"), UInt8(ascii: "}"):
                depth = max(0, depth - 1)
            default:
                break
            }
        }
        return deepest
    }
}


// MARK: - Sensor problems
/// Why the Security Extension can't run an indicator's predicate. Settings shows it beside the card, as "Not run by
/// the Security Extension: <reason>" (``Indicator/sensorProblem``).
public enum SensorProblem: Error, Equatable, Sendable, CustomStringConvertible {
    /// The predicate can't be used at all: too long, unreadable, or more than a comparison of the record's values.
    case unreadable(String)
    /// Its parentheses or braces nest deeper than ``IndicatorCompiler/maxDepth``.
    case tooDeep(Int)
    /// It names no event type.
    case untyped
    /// Its event type checks can never all pass, as with two types joined by `AND`, or `IN {}`.
    case contradictoryTypes
    /// The event types it names aren't ones this build knows.
    case unknownEventTypes([String])
    /// It uses an operator, a modifier or an expression the Security Extension doesn't evaluate.
    case unsupported(String)
    /// It reads a key path an event's record doesn't have (``IndicatorField/record(_:)``).
    case unservedField(String)
    /// It reads a key path whose value can't be compared on its own, and why: an object, or a value inside an array
    /// of objects.
    case unservedKind(String, String)
    /// It compares a string with a number, or an array without `ANY`.
    case mismatchedTypes(String)
    /// Its `LIKE` pattern has `?`, `\` or other than ASCII.
    case unsupportedPattern(String)
    /// A number isn't whole within ±2^53, or isn't finite.
    case unrepresentableNumber(String)
    /// It has more than ``IndicatorCompiler/maxNodes`` nodes.
    case tooManyNodes
    /// A string constant is longer than ``IndicatorCompiler/maxConstantBytes``.
    case constantTooLong(Int)

    /// The reason, as Settings and `macmonitor indicators` show it.
    public var description: String {
        switch self {
        case .unreadable(let reason): reason
        case .tooDeep(let depth):
            "Its parentheses nest \(depth) deep: the Security Extension reads \(IndicatorCompiler.maxDepth) at most."
        case .untyped:
            "It doesn't name its event types: the Security Extension runs an indicator only on the types it tests "
                + "for, as in event.exec != nil."
        case .contradictoryTypes: "Its event type checks can never all pass, so it matches no event."
        case .unknownEventTypes(let names):
            "It names no event type this build knows: \(names.joined(separator: ", "))."
        case .unsupported(let part): "The Security Extension doesn't evaluate \(part)."
        case .unservedField(let path): "'\(path)' isn't a key path of an event's record."
        case .unservedKind(let path, let reason): "'\(path)' can't be compared on its own: \(reason)."
        case .mismatchedTypes(let part): "It compares values of different kinds: \(part)."
        case .unsupportedPattern(let pattern):
            "The Security Extension matches a LIKE pattern of ASCII and * alone, not \(pattern)."
        case .unrepresentableNumber(let number):
            "\(number) isn't a whole number within ±2^53 or a finite one."
        case .tooManyNodes:
            "It has more than \(IndicatorCompiler.maxNodes) parts: the Security Extension runs that many at most."
        case .constantTooLong(let bytes):
            "A constant is \(bytes) bytes: the Security Extension compares "
                + "\(IndicatorCompiler.maxConstantBytes) at most."
        }
    }
}
