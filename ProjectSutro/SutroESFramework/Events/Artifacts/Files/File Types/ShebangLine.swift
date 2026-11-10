//
//  ShebangLine.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation


// MARK: - A script's interpreter
/// The interpreter a script's `#!` line names, and the script's type by it.
///
/// The interpreter is the line's first word, by its last path component, or through `env` the first word after `env`'s
/// options and `NAME=value` assignments: `#!/usr/bin/env -S python3 -u` is `python3`. A version after the name doesn't
/// count (`python3.12`, `perl5.34`).
struct ShebangLine {
    /// The `#!` a script starts with.
    static let magic = Array("#!".utf8)

    /// The script types of the interpreters that have one, by name without a version.
    static let identifiers: [String: String] = [
        "sh": "public.shell-script", "bash": "public.bash-script", "zsh": "public.zsh-script",
        "csh": "public.csh-script", "tcsh": "public.tcsh-script", "ksh": "public.ksh-script",
        "python": "public.python-script", "perl": "public.perl-script", "ruby": "public.ruby-script",
        "node": "com.netscape.javascript-source", "bun": "com.netscape.javascript-source",
        "osascript": FileType.appleScriptText.identifier,
    ]
    /// `env`'s options that take the next word as their value.
    private static let envValueOptions: Set<Substring> = ["-u", "-P", "-L", "-U", "-C"]

    /// The interpreter's name, such as `python3.12`, or "" when the line names none.
    let interpreter: String
    /// The words after the interpreter.
    let arguments: [Substring]

    /// The interpreter a script's first line names.
    ///
    /// - Parameter header: The file's first bytes, `#!` first.
    init<Bytes: ByteSample>(_ header: Bytes) {
        let line = header.dropFirst(Self.magic.count).prefix { $0 != 0x0A && $0 != 0x0D && $0 != 0 }
        var words = String(decoding: line, as: UTF8.self).split(whereSeparator: { $0 == " " || $0 == "\t" })[...]
        var name = words.popFirst().map { String($0).lastPathComponent } ?? ""
        if name == "env" {
            while let word = words.first, word.hasPrefix("-") || word.contains("=") {
                words.removeFirst()
                if Self.envValueOptions.contains(word) { words = words.dropFirst() }
            }
            name = words.popFirst().map { String($0).lastPathComponent } ?? ""
        }
        (interpreter, arguments) = (name, Array(words))
    }

    /// The interpreter's name without a version after it: `python` for `python3.12`, `pythonw` and `python3`.
    var baseName: String {
        if interpreter.hasPrefix("python") { return "python" }
        return String(interpreter.reversed().drop { $0.isNumber || $0 == "." }.reversed())
    }

    /// The script's type: its interpreter's script type, JavaScript for `osascript -l JavaScript`, or any script.
    var fileType: FileType {
        if baseName == "osascript", let language = arguments.firstIndex(of: "-l").map({ $0 + 1 }),
           language < arguments.count, arguments[language] == "JavaScript" {
            return FileType("com.netscape.javascript-source")
        }
        return Self.identifiers[baseName].map { FileType($0) } ?? .script
    }
}
