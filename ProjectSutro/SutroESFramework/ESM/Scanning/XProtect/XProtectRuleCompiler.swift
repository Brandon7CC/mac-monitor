//
//  XProtectRuleCompiler.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/24/26.
//

import Foundation


// MARK: - Compiling Apple's rules in a child process
/// Compiles a rule file in a short-lived child process, so the Security Extension never runs a YARA compiler itself.
///
/// The child is the Security Extension's own executable, started with ``argument``. On macOS 13 compiling
/// XProtect.yara peaks at about 96 MB, and on 27 the memory a compile takes is never given back, so it's paid by a
/// process that then exits. A rule file that crashed the compiler would crash only the child, not the root
/// extension, and not again at every start.
///
/// **The child** (``runIfAsked(_:)``) drops to `nobody` before reading anything, reads the rule text on standard
/// input, writes the compiled rules to standard output, and writes its diagnostics to standard error, one JSON
/// ``YaraDiagnostic`` per line. It reads no file and writes none.
///
/// **The parent** (``compile(_:into:executable:timeout:)``) gives the child a new file in the root-only directory as
/// its standard output, so the compiled rules, 8 to 36 MB, never pass through the extension's memory.
public enum XProtectRuleCompiler {
    /// The argument that makes the Security Extension's executable compile rules and exit.
    public static let argument = "--compile-xprotect-rules"

    /// How the child ends.
    enum Status: Int32 {
        /// The rules compiled and were written.
        case compiled = 0
        /// The rule text has an error (`EX_DATAERR`).
        case invalid = 65
        /// libyara isn't usable on this Mac (`EX_UNAVAILABLE`).
        case unavailable = 69
        /// The rule text couldn't be read or the rules written (`EX_IOERR`).
        case inputOutput = 74
        /// The child couldn't drop to `nobody` (`EX_NOPERM`).
        case privileges = 77
    }

    /// The most rule text the child reads.
    static let maxInputBytes = XProtectRuleSources.maxBytes

    /// The user and group the child runs as: `nobody`.
    static let nobody = UInt32(bitPattern: -2)

    // MARK: The child

    /// Compiles rules and returns the exit status when the process was started to, before anything else runs.
    ///
    /// The Security Extension calls this first, with its arguments.
    ///
    /// - Parameter arguments: The process's arguments, its path first.
    /// - Returns: The status to exit with, or `nil` when the process wasn't started to compile.
    public static func runIfAsked(_ arguments: [String]) -> Int32? {
        guard arguments.dropFirst().first == argument else { return nil }
        guard dropPrivileges() else { return Status.privileges.rawValue }
        return runChild(input: STDIN_FILENO, output: STDOUT_FILENO, diagnostics: STDERR_FILENO).rawValue
    }

    /// Becomes `nobody` for good, when running as root: no groups, then the group, then the user.
    ///
    /// - Returns: Whether the process now runs as `nobody` and can't become root again, or wasn't root.
    static func dropPrivileges() -> Bool {
        guard getuid() == 0 || geteuid() == 0 else { return true }
        guard setgroups(0, nil) == 0, setgid(nobody) == 0, setuid(nobody) == 0 else { return false }
        return getuid() == nobody && geteuid() == nobody && getgid() == nobody && setuid(0) != 0
    }

    /// The child's work: read the rule text, compile it, write the rules and the diagnostics.
    ///
    /// - Parameters:
    ///   - input: Where the rule text comes from, read to its end.
    ///   - output: Where the compiled rules go.
    ///   - diagnostics: Where the diagnostics go, one JSON object per line.
    /// - Returns: How the child ends.
    static func runChild(input: Int32, output: Int32, diagnostics: Int32) -> Status {
        guard let text = FileHandle(fileDescriptor: input, closeOnDealloc: false).readAll(upTo: maxInputBytes),
              let rules = String(data: text, encoding: .utf8) else { return .inputOutput }
        let library: YaraLibrary
        switch YaraLibrary.shared {
        case .success(let loaded): library = loaded
        case .failure(let reason):
            report([YaraDiagnostic(isError: true, line: 0, message: reason.description)], to: diagnostics)
            return .unavailable
        }
        let compiled = YaraCompiler.compile(rules, with: library)
        report(compiled.diagnostics, to: diagnostics)
        guard let set = compiled.rules else { return .invalid }
        return (try? set.save(to: output)) == nil ? .inputOutput : .compiled
    }

    /// Writes diagnostics, one JSON object per line.
    ///
    /// - Parameters:
    ///   - diagnostics: The diagnostics.
    ///   - descriptor: Where they go.
    private static func report(_ diagnostics: [YaraDiagnostic], to descriptor: Int32) {
        let encoder = JSONEncoder()
        var lines = Data()
        for diagnostic in diagnostics {
            guard let line = try? encoder.encode(diagnostic) else { continue }
            lines.append(line)
            lines.append(UInt8(ascii: "\n"))
        }
        _ = lines.writeAll(to: descriptor)
    }
}


// MARK: - Reading to an end
extension FileHandle {
    /// Everything left to read, up to a limit.
    ///
    /// - Parameter limit: The most bytes to read.
    /// - Returns: The bytes, or `nil` when the read fails or there's more than `limit`.
    func readAll(upTo limit: Int) -> Data? {
        guard let data = try? read(upToCount: limit + 1) ?? Data() else { return nil }
        return data.count > limit ? nil : data
    }
}
