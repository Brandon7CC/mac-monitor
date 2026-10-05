//
//  ToolVersion.swift
//  macmonitor
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import MachO
import SutroESFramework


// MARK: - Version
/// `macmonitor`'s own version, from the `Info.plist` linked into its `__TEXT,__info_plist` section.
///
/// Never from `Bundle.main`: `macmonitor` lives in `Mac Monitor.app/Contents/MacOS`, so `Bundle.main` is the app, and
/// the framework's own version is 1.
enum ToolVersion {
    /// Such as "2.2.0 (1)", in the format the Security Extension reports its own, or "unknown (unknown)" if the
    /// section can't be read.
    static let current: String = StreamService.version(from: embeddedInfo())
    
    /// The `Info.plist` in this image's `__TEXT,__info_plist` section.
    ///
    /// - Returns: Its keys, or none if it's missing.
    private static func embeddedInfo() -> [String: Any] {
        var size: UInt = 0
        let header = #dsohandle.assumingMemoryBound(to: mach_header_64.self)
        guard let section = getsectiondata(header, "__TEXT", "__info_plist", &size), size > 0 else { return [:] }
        let data = Data(bytes: section, count: Int(size))
        return (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any] ?? [:]
    }
}
