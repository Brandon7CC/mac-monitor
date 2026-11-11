//
//  CompiledIndicators+Source.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Predicates as a set keeps them
extension CompiledIndicators {
    /// A predicate compiled: the event types it runs on and its program, by its index in the set's store, or why it
    /// can't run.
    enum Compiled: Sendable {
        /// It compiled: its types, and its program's index.
        case rule(types: [Int], program: Int32)
        /// It didn't, and why.
        case problem(SensorProblem)
    }

    /// A predicate's text as the set keys it, by its UTF-8 bytes: hashed once, as a long predicate costs to hash, and
    /// compared whole. Swift's `String` equality takes canonically equivalent spellings as one (an NFC "\u{E9}" and
    /// an NFD "e\u{301}"), but `==`, `!=` and `IN` compare a constant's bytes, so two spellings are two programs.
    /// ``IndicatorMatcher`` keys its shared verdicts by it too.
    struct Source: Hashable, Sendable {
        /// The text.
        let text: String
        /// Its bytes' hash.
        private let hash: Int

        /// - Parameter text: A predicate's text.
        init(_ text: String) {
            var hasher = Hasher(), text = text
            text.withUTF8 { hasher.combine(bytes: UnsafeRawBufferPointer($0)) }
            self.text = text
            hash = hasher.finalize()
        }

        /// - Parameter hasher: Takes the bytes' hash.
        func hash(into hasher: inout Hasher) {
            hasher.combine(hash)
        }

        /// - Parameters:
        ///   - lhs: A predicate's text.
        ///   - rhs: Another's.
        /// - Returns: Whether they're the same bytes, compared at once.
        static func == (lhs: Source, rhs: Source) -> Bool {
            guard lhs.hash == rhs.hash else { return false }
            var left = lhs.text, right = rhs.text
            return left.withUTF8 { left in
                right.withUTF8 { right in
                    left.count == right.count
                        && (left.isEmpty || memcmp(left.baseAddress!, right.baseAddress!, left.count) == 0)
                }
            }
        }
    }
}
