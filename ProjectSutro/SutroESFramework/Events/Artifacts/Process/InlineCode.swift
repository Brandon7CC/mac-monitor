//
//  InlineCode.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/26/26.
//

import Foundation


// MARK: - Inline code
/// Code an interpreter got on its command line rather than in a file: `osascript -e`'s, `bash -c`'s or
/// `python3 -c`'s. Event Facts shows it as the exec's script when there's no script file.
///
/// It's read from the exec's arguments as the interpreter reads them
/// (``ScriptInterpreter/inlineCode(in:executableName:)``), so it works on records from other Macs too.
public struct InlineCode: Equatable {
    /// The code's language.
    public enum Language {
        case shell, python, perl, ruby, javascript, applescript
    }

    /// The interpreter's executable name, such as `osascript` or `python3`.
    public let interpreter: String
    /// The code. Several pieces are joined a line each, as the interpreter joins them.
    public let text: String
    /// The option that gave each piece, in order, as written: `-e`, `-c`, `--eval`.
    public let options: [String]
    /// The code's language: the interpreter's, or the one `osascript -l` names.
    public let language: Language

    /// Where the code came from, for Event Facts' tooltip, such as "From sh's -c argument."
    public var source: String {
        let named = options.reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }
            .joined(separator: " and ")
        guard options.count > 1 else { return "From \(interpreter)'s \(named) argument." }
        return "From \(interpreter)'s \(options.count) \(named) arguments, joined a line each, as \(interpreter) does."
    }
}


// MARK: - Reading it from an exec
extension InlineCode {
    /// The code an exec's interpreter got on its command line.
    ///
    /// - Parameters:
    ///   - args: The exec's arguments, `argv[0]` first. They're read only when the executable is an interpreter, since
    ///     a stored exec decodes them each time.
    ///   - executableName: The file name of the exec's executable, such as `osascript` or `python3.12`.
    /// - Returns: `nil` when the executable isn't an interpreter whose inline code Mac Monitor reads, or its arguments
    ///   give no code, such as a script file's (`python3 tool.py`).
    public init?(args: @autoclosure () -> [String], executableName: String) {
        guard let interpreter = ScriptInterpreter.takingCode(named: executableName),
              let code = interpreter.inlineCode(in: args().dropFirst(), executableName: executableName)
        else { return nil }
        self = code
    }
}
