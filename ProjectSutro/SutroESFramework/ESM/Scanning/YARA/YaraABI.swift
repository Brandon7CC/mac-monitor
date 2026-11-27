//
//  YaraABI.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/24/26.
//

import Foundation


// MARK: - The libyara layout
/// Which libyara the running macOS ships inside XprotectFramework, and where a rule's identifier sits in it.
///
/// Apple doesn't publish this library or its version. macOS 13 ships YARA 3.11 and macOS 27 ships YARA 4.1, and the
/// two differ in their callbacks and in the layout of a rule (`YR_RULE`). The layout is read from what the
/// Objective-C runtime records for Apple's own rule class: the argument of `-[YARARule initFromYARA:]` (`YaraRule` on
/// macOS 13) encodes `YR_RULE` field by field. The identifier is its first string, after a few integer fields, and its
/// offset follows from the fields before it. YARA 4.5 adds two integers before it, so a macOS that moves to 4.5 is
/// still read right.
///
/// Any layout that isn't one of the two known shapes makes scanning unavailable, with the reason. Nothing guesses.
struct YaraABI: Equatable, Sendable {
    /// The libyara generation, which decides the callbacks' signatures.
    enum Generation: String, Equatable, Sendable {
        /// YARA 3: callbacks take no scan context, and a rule starts with per-thread flags.
        case yara3
        /// YARA 4: callbacks take a scan context first, and a rule starts with 32-bit fields.
        case yara4
    }

    /// The generation.
    let generation: Generation
    /// The byte offset of `YR_RULE`'s identifier, a C string.
    let identifierOffset: Int

    /// The rule class Apple names each generation's rules with.
    static let ruleClassNames: [Generation: String] = [.yara3: "YaraRule", .yara4: "YARARule"]

    /// Reads the layout from the runtime's encodings.
    ///
    /// - Parameters:
    ///   - ruleEncoding: The type encoding of `initFromYARA:`'s argument, a pointer to `YR_RULE`.
    ///   - ruleClassName: The rule class the encoding was read from.
    ///   - rulesEncoding: The type encoding of `XPMalwareEvaluation`'s `_rules`, when the class has it. It only
    ///     confirms the generation.
    /// - Returns: The layout.
    /// - Throws: ``YaraUnavailable/unknownLayout(_:)`` when the encodings aren't a known shape or disagree.
    static func read(ruleEncoding: String, ruleClassName: String, rulesEncoding: String?) throws -> YaraABI {
        let unknown = YaraUnavailable.unknownLayout("The rule layout isn't one Mac Monitor knows (\(ruleEncoding)).")
        guard let fields = ruleFields(of: ruleEncoding),
              let identifier = fields.firstIndex(where: { $0.type.hasPrefix("(?=*") }) else { throw unknown }
        let leading = fields[..<identifier].map(\.type)
        let generation: Generation
        if leading.count == 2, leading[0] == "i", leading[1].hasPrefix("[") {
            generation = .yara3
        } else if leading.count >= 2, leading.allSatisfy({ $0 == "i" || $0 == "I" }) {
            generation = .yara4
        } else {
            throw unknown
        }
        guard ruleClassNames[generation] == ruleClassName else {
            throw YaraUnavailable.unknownLayout("\(ruleClassName) doesn't name \(generation.rawValue) rules.")
        }
        if let rulesEncoding, let named = Self.generation(ofRules: rulesEncoding), named != generation {
            throw YaraUnavailable.unknownLayout("The rule and rule set layouts disagree.")
        }
        return YaraABI(generation: generation, identifierOffset: fields[identifier].offset)
    }

    /// Which generation a `YR_RULES` encoding is: YARA 3's starts with a byte array of thread flags, YARA 4's with a
    /// pointer to its arena.
    ///
    /// - Parameter encoding: The type encoding of a pointer to `YR_RULES`.
    /// - Returns: The generation, or `nil` for a shape that's neither.
    static func generation(ofRules encoding: String) -> Generation? {
        if encoding.contains("YR_RULES=[") { return .yara3 }
        if encoding.contains("YR_RULES=^{YR_ARENA}") { return .yara4 }
        return nil
    }

    /// One field of an encoded struct.
    struct Field: Equatable {
        /// The field's own type encoding.
        let type: String
        /// Its byte offset in the struct.
        let offset: Int
    }

    /// The fields of the `YR_RULE` an encoding describes, with their offsets, laid out as the C compiler lays them.
    ///
    /// - Parameter encoding: A type encoding that contains `{YR_RULE=...}`.
    /// - Returns: The fields in order, or `nil` when there's no `YR_RULE` or a field can't be sized.
    static func ruleFields(of encoding: String) -> [Field]? {
        guard let start = encoding.range(of: "{YR_RULE=") else { return nil }
        let body = String(encoding[start.upperBound...])
        return body.withCString { base -> [Field]? in
            var fields: [Field] = []
            var cursor = base
            var offset = 0
            while cursor.pointee != 0, cursor.pointee != CChar(UInt8(ascii: "}")) {
                var size = 0, alignment = 0
                let next = NSGetSizeAndAlignment(cursor, &size, &alignment)
                guard next > cursor, size > 0 else { return nil }
                if alignment > 1 { offset = (offset + alignment - 1) / alignment * alignment }
                let length = next - cursor
                let type = String(decoding: UnsafeRawBufferPointer(start: UnsafeRawPointer(cursor), count: length),
                                  as: UTF8.self)
                fields.append(Field(type: type, offset: offset))
                offset += size
                cursor = next
            }
            return fields
        }
    }
}


// MARK: - Why scanning is unavailable
/// Why Apple's YARA rules can't be used on this Mac.
enum YaraUnavailable: Error, Equatable, CustomStringConvertible {
    /// XprotectFramework or one of its libyara functions isn't there.
    case missing(String)
    /// The libyara layout isn't one Mac Monitor knows.
    case unknownLayout(String)
    /// libyara failed to start.
    case failed(String)

    /// Why, as a sentence.
    var description: String {
        switch self {
        case .missing(let reason), .unknownLayout(let reason), .failed(let reason): return reason
        }
    }
}
