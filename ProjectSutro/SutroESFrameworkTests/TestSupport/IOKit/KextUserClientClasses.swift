//
//  KextUserClientClasses.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation


// MARK: - User client classes the installed kexts name
/// The user client classes the kexts under `/System/Library/Extensions` name in their Info.plists, as a personality's
/// `IOUserClientClass`, whether or not the kext is loaded. On Apple silicon the kexts' binaries are in the kernel
/// collection, not their bundles, so a class only a binary defines isn't here.
enum KextUserClientClasses {
    /// The folder of the system's kexts.
    static let extensions = URL(fileURLWithPath: "/System/Library/Extensions", isDirectory: true)
    /// The personality key naming the class of the user client a service makes.
    static let key = "IOUserClientClass"

    /// Every class a kext's Info.plist names, its plug-in kexts' included.
    ///
    /// - Parameter folder: The folder to search.
    /// - Returns: The classes, empty when the folder can't be read.
    static func named(under folder: URL = extensions) -> Set<String> {
        guard let files = FileManager.default.enumerator(at: folder, includingPropertiesForKeys: nil) else { return [] }
        var classes: Set<String> = []
        for case let url as URL in files where url.lastPathComponent == "Info.plist"
            && url.deletingLastPathComponent().deletingLastPathComponent().pathExtension == "kext" {
            guard let data = try? Data(contentsOf: url),
                  let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) else { continue }
            collect(plist, into: &classes)
        }
        return classes
    }

    /// - Parameters:
    ///   - value: A property list value.
    ///   - classes: The classes found so far, which gets every `IOUserClientClass` string below `value`.
    private static func collect(_ value: Any, into classes: inout Set<String>) {
        if let dictionary = value as? [String: Any] {
            for (name, child) in dictionary {
                if name == key, let className = child as? String { classes.insert(className) }
                collect(child, into: &classes)
            }
        } else if let array = value as? [Any] {
            array.forEach { collect($0, into: &classes) }
        }
    }
}
