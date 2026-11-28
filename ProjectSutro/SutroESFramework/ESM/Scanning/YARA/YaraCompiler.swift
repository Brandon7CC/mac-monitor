//
//  YaraCompiler.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/24/26.
//

import Foundation


// MARK: - Compiling rules
/// Compiles YARA rule text into a ``YaraRuleSet`` with the library's own compiler.
///
/// A rule can't `include` another file: the include callback is turned off, so rule text never makes the compiler
/// read a file. Every error and warning comes back with its line (``YaraDiagnostic``). Rule text with an error makes
/// no rule set and never crashes, unlike `XPMalwareEvaluation`'s rule string initializer.
///
/// The Security Extension compiles Apple's rules in a child process (``XProtectRuleCompiler``), never in its own: on
/// macOS 13 compiling them peaks at about 96 MB, and on 27 the memory isn't given back.
enum YaraCompiler {
    /// What compiling gave.
    struct Compilation {
        /// The rules, or `nil` when there was an error.
        let rules: YaraRuleSet?
        /// Every error and warning, in the order the compiler reported them.
        let diagnostics: [YaraDiagnostic]
    }

    /// Compiles one rule text.
    ///
    /// - Parameters:
    ///   - text: The rules.
    ///   - library: The library to compile them with.
    /// - Returns: The rules and the diagnostics.
    static func compile(_ text: String, with library: YaraLibrary) -> Compilation {
        var compiler: OpaquePointer?
        guard library.compilerCreate(&compiler) == 0, let compiler else {
            return Compilation(rules: nil, diagnostics: [YaraDiagnostic(isError: true, line: 0,
                                                                   message: "The compiler didn't start.")])
        }
        defer { library.compilerDestroy(compiler) }
        library.compilerSetIncludeCallback(compiler, nil, nil, nil)
        let found = Found()
        let user = Unmanaged.passUnretained(found).toOpaque()
        library.compilerSetCallback(compiler, callback(for: library.abi.generation), user)
        let errors = withExtendedLifetime(found) {
            text.withCString { library.compilerAddString(compiler, $0, nil) }
        }
        guard errors == 0 else { return Compilation(rules: nil, diagnostics: found.diagnostics) }
        var rules: OpaquePointer?
        guard library.compilerGetRules(compiler, &rules) == 0, let rules else {
            return Compilation(rules: nil, diagnostics: found.diagnostics + [
                YaraDiagnostic(isError: true, line: 0, message: "The compiler couldn't make the rules.")])
        }
        return Compilation(rules: YaraRuleSet(taking: rules, from: library), diagnostics: found.diagnostics)
    }
}


// MARK: - Diagnostics
/// An error or warning from compiling rules.
struct YaraDiagnostic: Equatable, Sendable, Codable {
    /// Is it an error, which stops the rules compiling? Otherwise a warning.
    let isError: Bool
    /// The line of the rule text it's about, from 1. 0 when it's about none.
    let line: Int
    /// The compiler's message.
    let message: String
}


// MARK: - Callbacks
extension YaraCompiler {
    /// The diagnostics a compile's callback was given.
    private final class Found {
        var diagnostics: [YaraDiagnostic] = []
    }

    typealias Callback3 = @convention(c) (Int32, UnsafePointer<CChar>?, Int32, UnsafePointer<CChar>?,
                                          UnsafeMutableRawPointer?) -> Void
    typealias Callback4 = @convention(c) (Int32, UnsafePointer<CChar>?, Int32, UnsafeRawPointer?,
                                          UnsafePointer<CChar>?, UnsafeMutableRawPointer?) -> Void

    /// YARA 3's callback: level, file, line, message, user data.
    private static let callback3: Callback3 = { level, _, line, message, user in
        note(level, line, message, user)
    }

    /// YARA 4's callback: the rule comes before the message.
    private static let callback4: Callback4 = { level, _, line, _, message, user in
        note(level, line, message, user)
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

    /// Keeps one diagnostic. Level 0 is `YARA_ERROR_LEVEL_ERROR`, and 1 is a warning.
    ///
    /// - Parameters:
    ///   - level: The level.
    ///   - line: The line.
    ///   - message: The message.
    ///   - user: The compile's ``Found``.
    private static func note(_ level: Int32, _ line: Int32, _ message: UnsafePointer<CChar>?,
                             _ user: UnsafeMutableRawPointer?) {
        guard let user else { return }
        let text = message.map { String(cString: $0) } ?? ""
        Unmanaged<Found>.fromOpaque(user).takeUnretainedValue().diagnostics
            .append(YaraDiagnostic(isError: level == 0, line: Int(line), message: text))
    }
}
