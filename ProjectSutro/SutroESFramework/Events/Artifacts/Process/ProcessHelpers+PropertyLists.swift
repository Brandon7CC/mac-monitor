//
//  ProcessHelpers+PropertyLists.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation


// MARK: - Reading property lists
extension ProcessHelpers {
    /// The magic bytes a binary property list starts with.
    private static let binaryPropertyListMagic = Data("bplist".utf8)

    /// The text of a property list file inside a directory, such as a launch item's launchd plist, up to
    /// ``fileContentsLimit``.
    ///
    /// - Parameters:
    ///   - relativePath: The file's path inside the directory, such as an `SMAppService` agent's
    ///     `Contents/Library/LaunchAgents/com.example.agent.plist`, or a legacy plist's name.
    ///   - directory: The directory: the agent's app, or the folder a legacy plist is in.
    /// - Returns: The text (``propertyListText(of:)``), or `nil` if the file isn't one
    ///   ``openContainedRegularFile(_:in:)`` opens (a symbolic link below the directory, a FIFO) or isn't a property
    ///   list in text or binary form.
    public static func getPropertyListContents(_ relativePath: String, in directory: String) -> String? {
        readContainedRegularFile(relativePath, in: directory).flatMap(propertyListText(of:))
    }

    /// A property list's bytes as text: XML or other text as it is, and a binary property list converted to XML with
    /// `PropertyListSerialization`, so a plist stored in binary reads like any other.
    ///
    /// - Parameter data: The bytes, up to one more than ``fileContentsLimit``.
    /// - Returns: The text, cut at ``fileContentsLimit`` (``limitedText(of:)``), or `nil` for a binary property list
    ///   that's longer than the limit or doesn't parse, or for bytes that are neither one nor UTF-8 text.
    static func propertyListText(of data: Data) -> String? {
        guard data.starts(with: binaryPropertyListMagic) else { return limitedText(of: data) }
        guard data.count <= fileContentsLimit,
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let xml = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0) else {
            return nil
        }
        return limitedText(of: xml)
    }

    /// A property list's top-level dictionary, in any of its formats.
    ///
    /// - Parameter data: The bytes.
    /// - Returns: The dictionary, or `nil` if the bytes aren't a property list whose top level is one.
    static func propertyListDictionary(of data: Data) -> [String: Any]? {
        (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
    }
}
