//
//  FileScanKindTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - What's scanned
/// Pins which written files are scanned, and with which rule files, from the type their close was read as.
final class FileScanKindTests: XCTestCase {
    /// The rule files for a type.
    private func files(_ type: String?, _ machO: String? = nil, path: String = "/tmp/f") -> Set<XProtectRuleFile>? {
        FileScanKind.ruleFiles(fileType: type, machOType: machO, path: path)
    }

    /// Mach-O code is scanned with XProtect.yara, and objects, dSYMs and cores aren't scanned at all.
    func testMachOCode() {
        for type in ["MH_EXECUTE", "MH_DYLIB", "MH_BUNDLE", "MH_KEXT_BUNDLE", "MH_DYLINKER"] {
            XCTAssertEqual(files("com.apple.mach-o-binary", type), [.xprotect], type)
        }
        for type in ["MH_OBJECT", "MH_DSYM", "MH_CORE", "MH_FILESET", "0x1f"] {
            XCTAssertNil(files("com.apple.mach-o-binary", type), type)
        }
    }

    /// AppleScript, compiled or as text, and compiled JXA also get XPScripts.yr, as XProtect evaluates what osascript
    /// runs. A compiled script's type is the same for both.
    func testAppleScript() {
        XCTAssertEqual(files("com.apple.applescript.script"), [.xprotect, .scripts])
        XCTAssertEqual(files("com.apple.applescript.text"), [.xprotect, .scripts])
        XCTAssertEqual(files("public.plain-text", path: "/tmp/Run.APPLESCRIPT"), [.xprotect, .scripts])
    }

    /// Plain text named .scpt is AppleScript too: osascript and Script Editor run it as one. Compiled .scpt is
    /// typed by its header, so only text needs the extension.
    func testAppleScriptTextNamedScpt() {
        XCTAssertEqual(files("public.plain-text", path: "/tmp/Invoice.scpt"), [.xprotect, .scripts])
        XCTAssertEqual(files("public.plain-text", path: "/tmp/Invoice.SCPT"), [.xprotect, .scripts])
    }

    /// JXA as text is a #! script that osascript runs. Its type is the same as any JavaScript's, so its first line
    /// adds XPScripts.yr once it's read. A node script's, a line that isn't first, and a type that has it don't.
    func testJavaScriptForAutomationByItsFirstLine() {
        let javaScript = files("com.netscape.javascript-source")
        XCTAssertEqual(javaScript, [.xprotect], "The type alone could be node's.")
        for line in ["#!/usr/bin/osascript -l JavaScript", "#!/usr/bin/env osascript -l JavaScript",
                     "#!/usr/bin/osascript"] {
            XCTAssertEqual(FileScanKind.ruleFiles([.xprotect], reading: Array((line + "\nrun()").utf8)),
                           [.xprotect, .scripts], line)
        }
        for text in ["#!/usr/bin/env node\nrun()", "#!/bin/zsh\nosascript -l JavaScript x.js",
                     "run()\n#!/usr/bin/osascript -l JavaScript", ""] {
            XCTAssertEqual(FileScanKind.ruleFiles([.xprotect], reading: Array(text.utf8)), [.xprotect], text)
        }
        XCTAssertEqual(FileScanKind.ruleFiles([.xprotect, .scripts], reading: Array("#!/usr/bin/osascript".utf8)),
                       [.xprotect, .scripts])
    }

    /// A #! script of any interpreter is scanned with XProtect.yara, and so is plain text with a shell script's
    /// extension.
    func testScripts() {
        for type in ["public.shell-script", "public.zsh-script", "public.python-script", "public.script",
                     "com.netscape.javascript-source"] {
            XCTAssertEqual(files(type), [.xprotect], type)
        }
        for name in ["install.sh", "run.command", "x.zsh", "y.bash"] {
            XCTAssertEqual(files("public.plain-text", path: "/tmp/" + name), [.xprotect], name)
        }
    }

    /// Everything else isn't scanned: other text, data, archives, an empty or replaced file, or one never read.
    func testEverythingElse() {
        XCTAssertNil(files("public.plain-text", path: "/tmp/notes.txt"))
        for type in ["public.data", "public.zip-archive", "com.apple.disk-image-udif", "empty", "replaced"] {
            XCTAssertNil(files(type), type)
        }
        XCTAssertNil(files(nil))
    }
}
