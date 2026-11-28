//
//  AppletScriptTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/26/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Where an applet's script is
/// Pins where an applet's main.scpt is, from its executable's path alone (``AppletScript``), as the scan and Event
/// Facts' Script fact read it: for any executable in a bundle's Contents/MacOS, whatever its name.
final class AppletScriptTests: XCTestCase {
    /// A bundle's executable, `applet` or renamed, names its bundle's main.scpt. A path outside Contents/MacOS, or in a
    /// folder below it, names none.
    func testABundlesExecutableNamesItsScript() {
        let paths: [String?: String?] = [
            "/Users/a/Login.app/Contents/MacOS/applet": "/Users/a/Login.app/Contents/Resources/Scripts/main.scpt",
            "/Users/a/Invoice.app/Contents/MacOS/Invoice": "/Users/a/Invoice.app/Contents/Resources/Scripts/main.scpt",
            "/Users/a/Invoice.app/Contents/MacOS/Helpers/tool": nil,
            "/Users/a/Invoice.app/Contents/Resources/applet": nil,
            "/usr/bin/osascript": nil,
            "applet": nil,
            nil: nil,
        ]
        for (executable, script) in paths {
            XCTAssertEqual(AppletScript.path(ofBundleExecutable: executable), script, "\(executable ?? "nil")")
        }
    }
}
