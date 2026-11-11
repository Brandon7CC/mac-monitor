//
//  ProcessHelpers+Scripts.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation
import MachO


// MARK: - The script an exec runs
extension ProcessHelpers {
    /// How many bytes of a file ``isScriptProbe(_:)`` looks at to tell a script from a binary.
    static let scriptProbeLength = 512

    /// The script an interpreter runs, from the exec's arguments, when ES doesn't name it (`bash tool.sh`), and its
    /// text.
    ///
    /// The script is opened once: the checks ``openRegularFile(at:for:expecting:)`` makes, the probe, and the text are
    /// all of that one open file, so a file swapped in under the path after the open is never the one read.
    ///
    /// - Parameters:
    ///   - args: The exec's arguments, `argv[0]` first.
    ///   - interpreter: The interpreter the exec runs, whose options decide which argument is the script.
    ///   - workingDirectory: The exec's working directory, for a relative path.
    ///   - reader: Who the script is read for: the user the exec's target runs as. `nil` reads it as Mac Monitor.
    /// - Returns: The script's path and text, or `nil` when the arguments don't name one (inline code, standard input),
    ///   the reader couldn't read it, or it isn't a script (``scriptText(readingFrom:)``).
    static func scriptFromArgs(args: [String], interpreter: ScriptInterpreter, workingDirectory: String,
                               reader: FileReader? = nil) -> (path: String, content: String)? {
        guard let argument = interpreter.scriptArgument(in: args.dropFirst()), !argument.isEmpty else { return nil }
        let path = argument.hasPrefix("/") ? argument : workingDirectory.appendingPathComponent(argument)
        guard let file = openRegularFile(at: path, for: reader), let content = scriptText(readingFrom: file) else {
            return nil
        }
        return (path, content)
    }

    /// The text of an open file, when its first ``scriptProbeLength`` bytes pass ``isScriptProbe(_:)``. The rest is
    /// read from the same descriptor, and only when the probe hasn't already reached the text's end.
    ///
    /// - Parameter file: The open file, at its start.
    /// - Returns: The text (``scriptText(of:)``), or `nil` for a binary, an empty file, or one that can't be read.
    static func scriptText(readingFrom file: FileHandle) -> String? {
        guard let probe = try? file.read(upToCount: scriptProbeLength), isScriptProbe(probe) else { return nil }
        guard probe.count == scriptProbeLength, !probe.contains(0) else { return scriptText(of: probe) }
        guard let rest = try? file.read(upToCount: fileContentsLimit + 1 - probe.count) ?? Data() else { return nil }
        return scriptText(of: probe + rest)
    }

    /// The magic numbers a Mach-O or universal binary starts with, in either byte order.
    private static let machOMagics: Set<UInt32> = [MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64,
                                                   FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64]

    /// Could a file's first bytes be a script's? Only the bytes before the first NUL count, as they do for its text,
    /// so a payload appended to a shell header (a self-extracting installer's) doesn't make it a binary. Nor does a
    /// byte that isn't UTF-8, such as one `0xFF` in a comment: refusing those would let a script hide by holding one.
    ///
    /// - Parameter data: The file's first bytes, up to ``scriptProbeLength``.
    /// - Returns: `false` for a Mach-O or universal binary, or when nothing before the first NUL is printable text.
    static func isScriptProbe(_ data: Data) -> Bool {
        let magic = data.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        guard data.count < 4 || !machOMagics.contains(magic) else { return false }
        let text = data.prefix(upTo: data.firstIndex(of: 0) ?? data.endIndex)
        return String(decoding: text, as: UTF8.self).unicodeScalars.contains { scalar in
            scalar.properties.isWhitespace
                || (scalar != "\u{FFFD}" && scalar.properties.generalCategory != .control)
        }
    }

    /// The text of the script an exec runs, up to ``fileContentsLimit``.
    ///
    /// A script is read more leniently than a property list (``getFileContents(at:)``): the text stops at its first
    /// NUL, so a script with a payload appended (a self-extracting installer's archive) keeps its shell header, and a
    /// byte that isn't UTF-8 reads as U+FFFD rather than losing the whole script.
    ///
    /// - Parameters:
    ///   - path: The script's path.
    ///   - reader: Who the script is read for: the user the exec's target runs as.
    ///   - identity: The file ES reported, which the path must still name, or `nil` for any.
    /// - Returns: The text, or `nil` if ``openRegularFile(at:for:expecting:)`` doesn't open the script or it can't be
    ///   read.
    static func getScriptContents(at path: String, for reader: FileReader?,
                                  expecting identity: FileIdentity? = nil) -> String? {
        readRegularFile(at: path, for: reader, expecting: identity).map(scriptText(of:))
    }

    /// Bytes as a script's text: up to the first NUL and ``fileContentsLimit``, with any byte that isn't UTF-8 as
    /// U+FFFD.
    ///
    /// - Parameter data: The script's bytes, up to one more than ``fileContentsLimit``.
    /// - Returns: The text, cut at the limit back to the end of a whole character.
    static func scriptText(of data: Data) -> String {
        var end = data.firstIndex(of: 0) ?? data.endIndex
        if end - data.startIndex > fileContentsLimit {
            let cut = data.startIndex + fileContentsLimit
            end = cut
            /// The byte after the cut continuing a character means the cut splits it: a character is at most 4 bytes.
            while end > cut - 3, data[end] & 0xC0 == 0x80 { end -= 1 }
        }
        return String(decoding: data[data.startIndex..<end], as: UTF8.self)
    }
}
