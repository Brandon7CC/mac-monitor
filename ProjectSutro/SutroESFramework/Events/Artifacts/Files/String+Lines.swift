//
//  String+Lines.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation


// MARK: - Line count
public extension String {
    /// How many lines the text has, as Mac Monitor shows a script or property list: "" is one line, and a final newline
    /// doesn't start another. Newline bytes are counted, so `\r\n` ends a line, and a megabyte of text is counted
    /// without walking its characters.
    var lineCount: Int {
        utf8.reduce(into: 1) { if $1 == 0x0A { $0 += 1 } } - (utf8.last == 0x0A ? 1 : 0)
    }
}
