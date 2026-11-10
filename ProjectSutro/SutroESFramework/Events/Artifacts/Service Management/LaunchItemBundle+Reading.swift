//
//  LaunchItemBundle+Reading.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation


// MARK: - Bundle layout
extension LaunchItemBundle {
    /// Where a bundle keeps its Info.plist and executable.
    enum Layout: Equatable {
        /// An app's: `Contents/Info.plist` and `Contents/MacOS/<CFBundleExecutable>`.
        case deep
        /// A shallow bundle's: `Info.plist` and `<CFBundleExecutable>` at the bundle's top.
        case shallow

        /// The layout of a bundle directory.
        ///
        /// Only `stat(2)`: a FIFO or other special file where the Info.plist should be is found, but never opened here.
        ///
        /// - Parameter path: The directory. A symbolic link is followed.
        /// - Returns: The layout, or `nil` when the path isn't a directory or has neither Info.plist.
        init?(bundle path: String) {
            func exists(_ path: String, directory: Bool = false) -> Bool {
                var info = stat()
                return stat(path, &info) == 0 && (!directory || info.st_mode & S_IFMT == S_IFDIR)
            }
            guard exists(path, directory: true) else { return nil }
            if exists(Self.deep.infoPlistPath(in: path)) {
                self = .deep
            } else if exists(Self.shallow.infoPlistPath(in: path)) {
                self = .shallow
            } else {
                return nil
            }
        }

        /// The bundle's Info.plist, relative to the bundle.
        var infoPlistName: String { self == .deep ? "Contents/Info.plist" : "Info.plist" }

        /// The bundle's Info.plist.
        ///
        /// - Parameter bundle: The bundle directory.
        /// - Returns: The plist's path.
        func infoPlistPath(in bundle: String) -> String {
            bundle.appendingPathComponent(infoPlistName)
        }

        /// The bundle's executable.
        ///
        /// - Parameters:
        ///   - name: The executable's name, such as `CFBundleExecutable`.
        ///   - bundle: The bundle directory.
        /// - Returns: The executable's path, whether or not it exists.
        func executablePath(named name: String, in bundle: String) -> String {
            bundle.appendingPathComponent(self == .deep ? "Contents/MacOS/\(name)" : name)
        }
    }
}


// MARK: - Reading a bundle
extension LaunchItemBundle {
    /// Read the bundle at a path from disk: its Info.plist essentials, its signature, and where it came from.
    ///
    /// The Info.plist is read as a regular file inside the bundle only
    /// (``ProcessHelpers/readContainedRegularFile(_:in:)``: not through a symbolic link below the bundle, nor a FIFO),
    /// never through `Bundle`, which keeps every instance it makes for the life of the process. The signature is read
    /// statically (``StaticCodeSigning``), and quarantine, where-froms and the birth time from the bundle directory.
    ///
    /// Security reads the Info.plist, the executable and the signature's files itself, without the same guards, so the
    /// signature is only read when the Info.plist was, when none of those is a FIFO or other special file
    /// (``isSafeToReadSignature(at:)``, ``isRegularOrMissing(_:)``), and then off the capture lane with a deadline
    /// (``StaticCodeSigning/read(path:)``).
    ///
    /// - Parameter path: The bundle directory.
    /// - Returns: The bundle, and its Info.plist as text (XML for a binary plist,
    ///   ``ProcessHelpers/propertyListText(of:)``), or `nil` when the path isn't a bundle directory (``Layout``), as
    ///   when it's gone by the time a remove is recorded.
    static func read(at path: String) -> (bundle: LaunchItemBundle, infoPlist: String?)? {
        guard let layout = Layout(bundle: path) else { return nil }
        var bundle = LaunchItemBundle(path: path)
        bundle.info_plist_path = layout.infoPlistPath(in: path)
        let data = ProcessHelpers.readContainedRegularFile(layout.infoPlistName, in: path)
        bundle.readInfo(data.flatMap(ProcessHelpers.propertyListDictionary(of:)) ?? [:], layout: layout)
        if data != nil, isSafeToReadSignature(at: path), bundle.executable_path.map(isRegularOrMissing) ?? true,
           let signing = StaticCodeSigning.read(path: path) {
            bundle.signing_id = signing.signingID
            bundle.team_id = signing.teamID
            bundle.codesigning_type = signing.type
        }
        bundle.is_quarantined = Int16(ProcessHelpers.isFileQuarantined(filePath: path))
        bundle.where_froms = ProcessHelpers.whereFroms(at: path)
        bundle.birth_time = ProcessHelpers.birthTime(at: path)
        return (bundle, data.flatMap(ProcessHelpers.propertyListText(of:)))
    }

    /// Fill in the Info.plist's essentials.
    ///
    /// - Parameters:
    ///   - plist: The Info.plist's dictionary: empty when it couldn't be read.
    ///   - layout: The bundle's layout, which places its executable.
    mutating func readInfo(_ plist: [String: Any], layout: Layout) {
        func text(_ key: String) -> String? { (plist[key] as? String).nonEmpty }
        identifier = text("CFBundleIdentifier")
        name = text("CFBundleDisplayName") ?? text("CFBundleName")
        version = text("CFBundleVersion")
        short_version = text("CFBundleShortVersionString")
        executable_path = executablePath(plist, layout: layout)
        is_ui_element = Self.flag(plist["LSUIElement"])
        is_background_only = Self.flag(plist["LSBackgroundOnly"])
    }

    /// The bundle's executable, found as CFBundle finds it, and so as Security and launchd do.
    ///
    /// - Parameters:
    ///   - plist: The Info.plist's dictionary.
    ///   - layout: The bundle's layout.
    /// - Returns: `CFBundleExecutable` or, without that key, `NSExecutable`, when it's a non-empty string, whether or
    ///   not the file exists, else the bundle's name without its extension, when that file exists, else `nil`.
    func executablePath(_ plist: [String: Any], layout: Layout) -> String? {
        if let named = ((plist["CFBundleExecutable"] ?? plist["NSExecutable"]) as? String).nonEmpty {
            return layout.executablePath(named: named, in: path)
        }
        let unnamed = (path.lastPathComponent as NSString).deletingPathExtension
        guard !unnamed.isEmpty else { return nil }
        let fallback = layout.executablePath(named: unnamed, in: path)
        var info = stat()
        return stat(fallback, &info) == 0 ? fallback : nil
    }

    /// An Info.plist flag such as `LSUIElement`, which apps write as a Boolean, a number or a string.
    ///
    /// - Parameter value: The key's value.
    /// - Returns: The Boolean, 1 or 0, or "1", "YES" or "true" (any case) and "0", "NO" or "false". `nil` for anything
    ///   else, or no value.
    static func flag(_ value: Any?) -> Bool? {
        switch value {
        case let number as NSNumber:
            return number.boolValue
        case let text as String:
            switch text.lowercased() {
            case "1", "yes", "true": return true
            case "0", "no", "false": return false
            default: return nil
            }
        default:
            return nil
        }
    }
}
