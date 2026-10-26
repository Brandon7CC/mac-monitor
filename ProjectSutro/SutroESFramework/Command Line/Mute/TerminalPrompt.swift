//
//  TerminalPrompt.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Terminal prompt
/// Asks the person at the terminal a yes-or-no question (command line context), as `macmonitor mute import` and
/// `mute reset` do before they change the saved mute set.
///
/// The question and the answer go through the controlling terminal (`/dev/tty`), never standard input or output, so
/// `mute import -` can read its file from a pipe and still ask. Only when standard error is a terminal: a command
/// with its diagnostics redirected is a script, which has no one to ask and must say `--yes`.
public enum TerminalPrompt {
    /// The controlling terminal.
    static let terminalPath = "/dev/tty"
    /// The longest answer read, in bytes. The rest of a longer line is left unread.
    static let maximumAnswer = 256
    
    /// Ask at the controlling terminal.
    ///
    /// - Parameter question: The question, on one or more lines.
    /// - Returns: `true` for yes, `false` for anything else, or `nil` if standard error isn't a terminal or there's
    ///   no controlling terminal.
    public static func ask(_ question: String) -> Bool? {
        guard isatty(STDERR_FILENO) == 1 else { return nil }
        let terminal = open(terminalPath, O_RDWR | O_NOCTTY | O_CLOEXEC)
        guard terminal >= 0 else { return nil }
        defer { close(terminal) }
        return ask(question, input: terminal, output: terminal)
    }
    
    /// Ask on two descriptors: write the question with " [y/N] ", then read one line.
    ///
    /// - Parameters:
    ///   - question: The question.
    ///   - input: Where the answer is read.
    ///   - output: Where the question is written.
    /// - Returns: `true` for `y` or `yes` in any case, `false` for anything else, an empty line, or no answer.
    static func ask(_ question: String, input: Int32, output: Int32) -> Bool {
        try? FileOutput(descriptor: output).write(Data("\(question) [y/N] ".utf8))
        return isYes(readLine(from: input))
    }
    
    /// Read one line, without its newline: up to a newline, the end of the input, or ``maximumAnswer`` bytes.
    ///
    /// - Parameter descriptor: Where to read.
    /// - Returns: The line.
    static func readLine(from descriptor: Int32) -> String {
        var line: [UInt8] = []
        var byte: UInt8 = 0
        while line.count < maximumAnswer {
            let count = read(descriptor, &byte, 1)
            if count < 0, errno == EINTR { continue }
            guard count == 1, byte != UInt8(ascii: "\n") else { break }
            line.append(byte)
        }
        return String(decoding: line, as: UTF8.self)
    }
    
    /// Is an answer yes?
    ///
    /// - Parameter answer: The line typed.
    /// - Returns: `true` for `y` or `yes`, in any case, with any spaces around it.
    static func isYes(_ answer: String) -> Bool {
        ["y", "yes"].contains(answer.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
    }
}
