//
//  FileScanKind.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - What's scanned
/// Which written files are scanned, and with which of Apple's rule files, from the type a close's file was read as
/// (``FileTypeReader``).
///
/// - Mach-O code: an executable, library, bundle, kernel extension or dynamic linker, thin or universal. Not an object
///   file, a dSYM or a core file: a build writes thousands of objects, and no XProtect rule is for one.
/// - Scripts: a `#!` script of any interpreter, and shell scripts and AppleScript by their extension when they have no
///   `#!` line.
/// - AppleScript, compiled or as text, and JavaScript for Automation, compiled or as a `#!` script, which also get
///   `XPScripts.yr`, as XProtect evaluates what `osascript` runs. A JXA script's type is the same as any other
///   JavaScript's, so its first line tells, once the scanner has read it (``ruleFiles(_:reading:)``). Text named
///   `.scpt` is AppleScript too: compiled `.scpt` is typed by its header, so only text needs the extension.
///
/// Everything gets `XProtect.yara`.
enum FileScanKind {
    /// The Mach-O file types scanned.
    static let machOTypes: Set<String> = ["MH_EXECUTE", "MH_DYLIB", "MH_BUNDLE", "MH_KEXT_BUNDLE", "MH_DYLINKER"]

    /// The script types `osascript` runs.
    static let osascriptTypes: Set<String> = [FileType.compiledAppleScript.identifier,
                                              FileType.appleScriptText.identifier]

    /// The extensions of plain text scanned as a script, and those `osascript` runs.
    static let scriptExtensions: Set<String> = ["sh", "zsh", "bash", "command"]
    static let osascriptExtensions: Set<String> = ["applescript", "scpt"]

    /// The rule files that apply to a file, or `nil` when it isn't scanned.
    ///
    /// - Parameters:
    ///   - fileType: The `file_type` it was read as.
    ///   - machOType: Its `mach_o_type`, for a Mach-O.
    ///   - path: Its path, for a script's extension.
    /// - Returns: The rule files.
    static func ruleFiles(fileType: String?, machOType: String?, path: String) -> Set<XProtectRuleFile>? {
        guard let fileType else { return nil }
        if let machOType { return machOTypes.contains(machOType) ? [.xprotect] : nil }
        if osascriptTypes.contains(fileType) { return [.xprotect, .scripts] }
        if isScript(fileType) { return [.xprotect] }
        guard fileType == FileType.plainText.identifier else { return nil }
        let pathExtension = (path as NSString).pathExtension.lowercased()
        if osascriptExtensions.contains(pathExtension) { return [.xprotect, .scripts] }
        return scriptExtensions.contains(pathExtension) ? [.xprotect] : nil
    }

    /// The rule files for the script an exec runs, by its interpreter: `osascript`'s gets `XPScripts.yr` too, as
    /// XProtect evaluates what `osascript` runs. Once the script is read, its `#!` line adds `XPScripts.yr` for
    /// another interpreter, such as `env`, that runs `osascript` (``ruleFiles(_:reading:)``).
    ///
    /// - Parameter interpreter: The name of the exec's target, such as `bash`.
    /// - Returns: The rule files.
    static func ruleFiles(forInterpreter interpreter: String?) -> Set<XProtectRuleFile> {
        interpreter == "osascript" ? [.xprotect, .scripts] : [.xprotect]
    }

    /// The rule files for a file once its bytes are read: its type's, and `XPScripts.yr` for a `#!` script that
    /// `osascript` runs. `osascript -l JavaScript` names any JavaScript's type (``ShebangLine/fileType``), a node
    /// script's too, so only the line tells them apart.
    ///
    /// - Parameters:
    ///   - files: The rule files its type gets (``ruleFiles(fileType:machOType:path:)``).
    ///   - bytes: The file's bytes.
    /// - Returns: The rule files.
    static func ruleFiles(_ files: Set<XProtectRuleFile>,
                          reading bytes: some Collection<UInt8>) -> Set<XProtectRuleFile> {
        guard !files.contains(.scripts), bytes.starts(with: ShebangLine.magic),
              ShebangLine(Array(bytes.prefix(FileTypeClassifier.headerLength))).baseName == "osascript" else {
            return files
        }
        return files.union([.scripts])
    }

    /// Is a type one a `#!` line names: an interpreter's script type, or any script?
    ///
    /// - Parameter fileType: The type.
    /// - Returns: Whether it's a script.
    private static func isScript(_ fileType: String) -> Bool {
        fileType == FileType.script.identifier || ShebangLine.identifiers.values.contains(fileType)
    }
}
