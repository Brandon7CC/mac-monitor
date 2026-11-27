//
//  ProcessHelpers+Scripts.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation
import MachO


// MARK: - A script as read
/// A script as the capture lane read it for an exec's `script_content`, before its text is decoded and cut at a NUL.
/// It's kept for the script's scan (``Message/requestYaraScan(of:from:volumes:)``) and never encoded.
struct ScriptRead {
    /// The path the scanner reads it at, when ``isWhole`` is false: the open file's `F_GETPATH`, which has no symbolic
    /// link, as the scanner opens a file. Otherwise the path it was opened at.
    let path: String
    /// The open file's `fstat`.
    let info: stat
    /// Its bytes from the start, as read: up to one more than ``ProcessHelpers/fileContentsLimit``, or only the
    /// probe's when a NUL ends the text within it (``ProcessHelpers/scriptBytes(readingFrom:)``).
    let bytes: Data
    /// Where it was downloaded from (``ProcessHelpers/whereFroms(of:)``), read from the open file.
    let whereFroms: [String]?

    /// - Parameters:
    ///   - opened: The open file and its `fstat`.
    ///   - bytes: What was read from its start.
    ///   - path: The path it was opened at.
    init(_ opened: (file: FileHandle, info: stat), bytes: Data, at path: String) {
        info = opened.info
        self.bytes = bytes
        whereFroms = ProcessHelpers.whereFroms(of: opened.file.fileDescriptor)
        self.path = bytes.count < Int(opened.info.st_size)
            ? Self.pathWithoutLinks(of: opened.file.fileDescriptor) ?? path : path
    }

    /// Were all of its bytes read?
    var isWhole: Bool { bytes.count == Int(info.st_size) }

    /// An open file's path, with no symbolic link.
    ///
    /// - Parameter descriptor: The open file.
    /// - Returns: Its `F_GETPATH`, or `nil` when it has none.
    private static func pathWithoutLinks(of descriptor: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(descriptor, F_GETPATH, &buffer) != -1 else { return nil }
        return String(cString: buffer)
    }
}


// MARK: - The script an exec runs
extension ProcessHelpers {
    /// How many bytes of a file ``isScriptProbe(_:)`` looks at to tell a script from a binary.
    static let scriptProbeLength = 512

    /// The script an interpreter runs, from the exec's arguments, when ES doesn't name it (`bash tool.sh`), its text,
    /// and what was read of it.
    ///
    /// The script is opened once: the checks ``openRegularFile(at:for:expecting:)`` makes, the probe, and the text are
    /// all of that one open file, so a file swapped in under the path after the open is never the one read.
    ///
    /// - Parameters:
    ///   - args: The exec's arguments, `argv[0]` first.
    ///   - interpreter: The interpreter the exec runs, whose options decide which argument is the script.
    ///   - workingDirectory: The exec's working directory, for a relative path.
    ///   - reader: Who the script is read for: the user the exec's target runs as. `nil` reads it as Mac Monitor.
    /// - Returns: The script's path, text and read, or `nil` when the arguments don't name one (inline code, standard
    ///   input), the reader couldn't read it, or it isn't a script (``scriptBytes(readingFrom:)``).
    static func scriptFromArgs(args: [String], interpreter: ScriptInterpreter, workingDirectory: String,
                               reader: FileReader? = nil) -> (path: String, content: String, read: ScriptRead)? {
        guard let argument = interpreter.scriptArgument(in: args.dropFirst()), !argument.isEmpty else { return nil }
        let path = argument.hasPrefix("/") ? argument : workingDirectory.appendingPathComponent(argument)
        guard let opened = openRegularFile(at: path, for: reader),
              let bytes = scriptBytes(readingFrom: opened.file) else { return nil }
        return (path, scriptText(of: bytes), ScriptRead(opened, bytes: bytes, at: path))
    }

    /// The bytes of an open file a script's text is made from, when its first ``scriptProbeLength`` bytes pass
    /// ``isScriptProbe(_:)``. The rest is read from the same descriptor, and only when the probe hasn't already reached
    /// the text's end.
    ///
    /// - Parameter file: The open file, at its start.
    /// - Returns: The bytes, or `nil` for a binary, an empty file, or one that can't be read.
    static func scriptBytes(readingFrom file: FileHandle) -> Data? {
        guard let probe = try? file.read(upToCount: scriptProbeLength), isScriptProbe(probe) else { return nil }
        guard probe.count == scriptProbeLength, !probe.contains(0) else { return probe }
        guard let rest = try? file.read(upToCount: fileContentsLimit + 1 - probe.count) ?? Data() else { return nil }
        return probe + rest
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

    /// The script an exec runs, as read for its text: up to one more than ``fileContentsLimit`` bytes.
    ///
    /// A script is read more leniently than a property list (``getFileContents(at:)``): the text stops at its first
    /// NUL, so a script with a payload appended (a self-extracting installer's archive) keeps its shell header, and a
    /// byte that isn't UTF-8 reads as U+FFFD rather than losing the whole script (``scriptText(of:)``).
    ///
    /// - Parameters:
    ///   - path: The script's path.
    ///   - reader: Who the script is read for: the user the exec's target runs as.
    ///   - identity: The file ES reported, which the path must still name, or `nil` for any.
    /// - Returns: The read, or `nil` if ``openRegularFile(at:for:expecting:)`` doesn't open the script or it can't be
    ///   read.
    static func readScript(at path: String, for reader: FileReader?, expecting identity: FileIdentity?) -> ScriptRead? {
        guard let opened = openRegularFile(at: path, for: reader, expecting: identity),
              let bytes = try? opened.file.read(upToCount: fileContentsLimit + 1) ?? Data() else { return nil }
        return ScriptRead(opened, bytes: bytes, at: path)
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
