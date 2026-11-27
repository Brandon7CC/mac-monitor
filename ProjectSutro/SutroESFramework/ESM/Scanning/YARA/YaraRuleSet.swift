//
//  YaraRuleSet.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/24/26.
//

import Foundation


// MARK: - A compiled rule set
/// A compiled set of YARA rules loaded in this process (`YR_RULES`), which scans bytes in memory.
///
/// It scans memory only, never a path or a descriptor: libyara maps a file to scan it, and a mapping updates the
/// file's access time even with Mac Monitor's no-access-time read policy set (``ReadingThreadPolicy``). The caller
/// reads the file with `pread` under that policy and hands over the bytes.
///
/// **Threading:** one scan at a time. YARA 3 refuses more than 32 at once, and the scans share the CPU budget anyway.
final class YaraRuleSet {
    /// What a scan found.
    enum Outcome: Equatable {
        /// The rules that matched, in the order libyara reported them. Empty when none did.
        case matched([YaraMatch])
        /// The scan stopped, and why.
        case failed(Failure)
    }

    /// Why a scan stopped.
    enum Failure: Equatable {
        /// It ran past its timeout (`ERROR_SCAN_TIMEOUT`).
        case timedOut
        /// Too many strings matched (`ERROR_TOO_MANY_MATCHES`). macOS 13 stops the scan where 27 finishes it.
        case tooManyMatches
        /// libyara ran out of memory, or another error, by its code.
        case error(Int32)
    }

    /// The library the rules belong to.
    let library: YaraLibrary
    /// The rules, destroyed with the set.
    private let rules: OpaquePointer

    /// - Parameters:
    ///   - rules: Rules libyara compiled or loaded. The set owns them from now on.
    ///   - library: Their library.
    init(taking rules: OpaquePointer, from library: YaraLibrary) {
        self.rules = rules
        self.library = library
    }

    deinit {
        _ = library.rulesDestroy(rules)
    }

    /// Loads rules a set saved (``save(to:)``) with the same library.
    ///
    /// - Parameters:
    ///   - descriptor: The open file, read from its current offset. The caller closes it.
    ///   - library: The library that saved them.
    /// - Returns: The set.
    /// - Throws: ``YaraUnavailable/failed(_:)`` with libyara's code when the file isn't rules it can load.
    static func load(from descriptor: Int32, library: YaraLibrary) throws -> YaraRuleSet {
        let stream = YaraStream(descriptor: descriptor)
        var rules: OpaquePointer?
        let code = library.rulesLoadStream(stream.pointer, &rules)
        guard code == 0, let rules else { throw YaraUnavailable.failed("Compiled rules didn't load (\(code)).") }
        return YaraRuleSet(taking: rules, from: library)
    }

    /// Saves the rules so ``load(from:library:)`` can load them again.
    ///
    /// - Parameter descriptor: The open file, written at its current offset. The caller closes it.
    /// - Throws: ``YaraUnavailable/failed(_:)`` with libyara's code when they can't be written.
    func save(to descriptor: Int32) throws {
        let stream = YaraStream(descriptor: descriptor)
        let code = library.rulesSaveStream(rules, stream.pointer)
        guard code == 0, stream.flush() else {
            throw YaraUnavailable.failed("Compiled rules couldn't be saved (\(code)).")
        }
    }

    /// Scans bytes with every rule.
    ///
    /// - Parameters:
    ///   - bytes: What to scan, such as a file's contents.
    ///   - timeout: The most seconds the scan may take. libyara counts whole seconds.
    /// - Returns: The rules that matched, or why the scan stopped.
    func scan(_ bytes: UnsafeRawBufferPointer, timeout: Int32) -> Outcome {
        let found = Found()
        let user = Unmanaged.passUnretained(found).toOpaque()
        let code = withExtendedLifetime(found) {
            library.rulesScanMemory(rules, bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), bytes.count,
                                    Self.flags(for: library.abi.generation), Self.callback(for: library.abi.generation),
                                    user, timeout)
        }
        switch code {
        case 0: return .matched(found.rules.map(library.match(of:)))
        case Self.timeoutError: return .failed(.timedOut)
        case Self.tooManyMatchesError: return .failed(.tooManyMatches)
        default: return .failed(.error(code))
        }
    }

    /// libyara's `ERROR_SCAN_TIMEOUT`.
    static let timeoutError: Int32 = 26
    /// libyara's `ERROR_TOO_MANY_MATCHES`.
    static let tooManyMatchesError: Int32 = 30

    /// The scan flags: never install a signal handler (`SCAN_FLAGS_NO_TRYCATCH`), since memory is never mapped from
    /// a file, and on YARA 4 call back only for rules that matched (`SCAN_FLAGS_REPORT_RULES_MATCHING`).
    ///
    /// - Parameter generation: The library's generation.
    /// - Returns: The flags.
    static func flags(for generation: YaraABI.Generation) -> Int32 {
        generation == .yara4 ? 4 | 8 : 4
    }
}


// MARK: - Callbacks
extension YaraRuleSet {
    /// The rules a scan's callback was told matched.
    private final class Found {
        var rules: [UnsafeRawPointer] = []
    }

    typealias ScanCallback3 = @convention(c) (Int32, UnsafeMutableRawPointer?, UnsafeMutableRawPointer?) -> Int32
    typealias ScanCallback4 = @convention(c) (UnsafeMutableRawPointer?, Int32, UnsafeMutableRawPointer?,
                                              UnsafeMutableRawPointer?) -> Int32

    /// YARA 3's callback: message, message data, user data.
    private static let callback3: ScanCallback3 = { message, data, user in
        note(message, data, user)
    }

    /// YARA 4's callback: the scan context first.
    private static let callback4: ScanCallback4 = { _, message, data, user in
        note(message, data, user)
    }

    /// The callback for a generation, as the untyped pointer libyara takes.
    ///
    /// - Parameter generation: The library's generation.
    /// - Returns: The callback.
    private static func callback(for generation: YaraABI.Generation) -> UnsafeRawPointer {
        switch generation {
        case .yara3: return unsafeBitCast(callback3, to: UnsafeRawPointer.self)
        case .yara4: return unsafeBitCast(callback4, to: UnsafeRawPointer.self)
        }
    }

    /// Keeps a matching rule (`CALLBACK_MSG_RULE_MATCHING`) and lets the scan go on (`CALLBACK_CONTINUE`).
    ///
    /// - Parameters:
    ///   - message: What the callback is told.
    ///   - data: The rule, for a match.
    ///   - user: The scan's ``Found``.
    /// - Returns: `CALLBACK_CONTINUE`.
    private static func note(_ message: Int32, _ data: UnsafeMutableRawPointer?,
                             _ user: UnsafeMutableRawPointer?) -> Int32 {
        if message == 1, let data, let user {
            Unmanaged<Found>.fromOpaque(user).takeUnretainedValue().rules.append(UnsafeRawPointer(data))
        }
        return 0
    }
}
