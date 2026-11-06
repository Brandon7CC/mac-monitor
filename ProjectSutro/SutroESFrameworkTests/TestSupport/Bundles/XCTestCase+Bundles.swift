//
//  XCTestCase+Bundles.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Bundles on disk
extension XCTestCase {
    /// A small Info.plist with the essentials Mac Monitor reads.
    static let exampleInfo: [String: Any] = [
        "CFBundleIdentifier": "com.example.helper", "CFBundleName": "Helper", "CFBundleDisplayName": "Example Helper",
        "CFBundleVersion": "42", "CFBundleShortVersionString": "1.2.3", "CFBundleExecutable": "Helper",
        "LSUIElement": true,
    ]

    /// An unsigned bundle in a directory, with a shell script for its executable.
    ///
    /// - Parameters:
    ///   - name: The bundle's name, such as `Helper.app`, or a relative path to it.
    ///   - directory: Where it goes: a new temporary directory by default.
    ///   - info: The Info.plist's dictionary, or `nil` for no Info.plist.
    ///   - format: How the Info.plist is stored: XML or binary.
    ///   - shallow: Put the Info.plist and the executable at the top, as a shallow bundle does.
    /// - Returns: The bundle's path.
    /// - Throws: The error creating the directories or writing the files.
    @discardableResult
    func makeBundle(_ name: String = "Helper.app", in directory: URL? = nil, info: [String: Any]? = exampleInfo,
                    format: PropertyListSerialization.PropertyListFormat = .xml,
                    shallow: Bool = false) throws -> String {
        let bundle = try (directory ?? makeTemporaryDirectory()).appendingPathComponent(name, isDirectory: true)
        let contents = shallow ? bundle : bundle.appendingPathComponent("Contents", isDirectory: true)
        let executables = shallow ? bundle : contents.appendingPathComponent("MacOS", isDirectory: true)
        try FileManager.default.createDirectory(at: executables, withIntermediateDirectories: true)
        if let info {
            try PropertyListSerialization.data(fromPropertyList: info, format: format, options: 0)
                .write(to: contents.appendingPathComponent("Info.plist"))
            if let executable = info["CFBundleExecutable"] as? String {
                let script = executables.appendingPathComponent(executable)
                try Data("#!/bin/sh\nexit 0\n".utf8).write(to: script)
                chmod(script.path, 0o755)
            }
        }
        return bundle.path
    }

    /// Give a file a `com.apple.metadata:kMDItemWhereFroms` attribute, as a browser does: a binary property list
    /// array.
    ///
    /// - Parameters:
    ///   - origins: The URLs.
    ///   - path: The file.
    /// - Throws: The error encoding the list, or an `XCTest` failure if the attribute can't be set.
    func setWhereFroms(_ origins: [String], on path: String) throws {
        let data = try PropertyListSerialization.data(fromPropertyList: origins, format: .binary, options: 0)
        let result = data.withUnsafeBytes {
            setxattr(path, ProcessHelpers.whereFromsAttribute, $0.baseAddress, data.count, 0, 0)
        }
        XCTAssertEqual(result, 0, errnoText())
    }

    /// Quarantine a file, as a browser's download is.
    ///
    /// - Parameter path: The file.
    func quarantine(_ path: String) {
        let value = "0083;6900a000;Safari;"
        XCTAssertEqual(setxattr(path, "com.apple.quarantine", value, value.utf8.count, 0, 0), 0, errnoText())
    }

    /// A launch item as Endpoint Security hands one to the Security Extension.
    ///
    /// - Parameters:
    ///   - type: The item's type.
    ///   - url: `item_url`.
    ///   - appURL: `app_url`, or `nil` for none.
    ///   - legacy: Is it a legacy plist?
    /// - Returns: The item, which lives as long as the test.
    func rawLaunchItem(_ type: es_btm_item_type_t, url: String, appURL: String? = nil,
                       legacy: Bool = false) -> es_btm_launch_item_t {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD)
        var item = es_btm_launch_item_t()
        item.item_type = type
        item.item_url = fixture.token(url)
        item.app_url = fixture.token(appURL)
        item.legacy = legacy
        item.uid = 501
        return item
    }

    /// A `file://` URL as Background Task Management writes one: a directory's ends in "/".
    ///
    /// - Parameter path: The path.
    /// - Returns: The URL's text.
    func fileURL(_ path: String) -> String {
        URL(fileURLWithPath: path).absoluteString
    }
}
