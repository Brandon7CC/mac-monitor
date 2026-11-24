//
//  SecurityExtensionNameTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import XCTest


// MARK: - Security Extension name
/// Pins how the Security Extension gets its name in System Settings' dialogs.
///
/// macOS 27.3's Full Disk Access dialogs name a bundle as the Finder would. A system extension's file name is its
/// bundle identifier, so the dialogs read `com.swiftlydetecting.agent.securityextension.systemextension`. The
/// Finder shows a localized name only when the Info.plist's `CFBundleDisplayName` is the file name without its
/// extension, and then takes the name from `InfoPlist.strings`.
final class SecurityExtensionNameTests: XCTestCase {
    /// The folder that holds the Xcode project.
    private var project: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
    }

    /// Every build configuration of the Security Extension names it by its bundle identifier in its Info.plist.
    func testTheInfoPlistNameIsTheFileName() throws {
        let settings = try String(contentsOf: project.appendingPathComponent("ProjectSutro.xcodeproj/project.pbxproj"),
                                  encoding: .utf8)
        let blocks = settings.components(separatedBy: "INFOPLIST_FILE = SecurityExtension/Info.plist;").dropFirst()
        XCTAssertEqual(blocks.count, 3, "Debug, Release and Community")
        for block in blocks {
            let name = block.components(separatedBy: "\n").first { $0.contains("INFOPLIST_KEY_CFBundleDisplayName") }
            XCTAssertEqual(name?.trimmingCharacters(in: .whitespaces),
                           "INFOPLIST_KEY_CFBundleDisplayName = \"$(PRODUCT_BUNDLE_IDENTIFIER)\";")
        }
    }

    /// The name people read is in the localized strings, and built into the Security Extension.
    func testTheLocalizedNameIsMacMonitorSecurityExtension() throws {
        let strings = project.appendingPathComponent("SecurityExtension/en.lproj/InfoPlist.strings")
        let names = try XCTUnwrap(NSDictionary(contentsOf: strings) as? [String: String])
        XCTAssertEqual(names, ["CFBundleDisplayName": "Mac Monitor Security Extension",
                               "CFBundleName": "Mac Monitor Security Extension"])
        let settings = try String(contentsOf: project.appendingPathComponent("ProjectSutro.xcodeproj/project.pbxproj"),
                                  encoding: .utf8)
        XCTAssertTrue(settings.contains("/* InfoPlist.strings in Resources */,"))
    }
}
