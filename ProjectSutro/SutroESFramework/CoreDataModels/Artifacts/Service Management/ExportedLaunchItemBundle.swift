//
//  ExportedLaunchItemBundle.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation


// MARK: - A launch item bundle in the export
/// A ``LaunchItemBundle`` as the export writes it, under `item.bundle` and `item.app_bundle`: every key, `null` when
/// the bundle has no value, and the birth time in eslogger's `timespec` format (``TimeSpec/humanFormat()``), without
/// Mac Monitor's identifiers. File > Open Trace... reads it back into a ``LaunchItemBundle``.
struct ExportedLaunchItemBundle: Encodable {
    /// The bundle.
    let bundle: LaunchItemBundle

    /// The export's keys, in the order it writes them.
    enum CodingKeys: String, CodingKey {
        case path, info_plist_path, identifier, name, version, short_version, executable_path, is_ui_element
        case is_background_only, signing_id, team_id, codesigning_type, is_quarantined, where_froms, birth_time, age_ms
    }

    /// - Parameter bundle: The bundle.
    init(_ bundle: LaunchItemBundle) {
        self.bundle = bundle
    }

    /// Write every key, `nil` values as `null`.
    ///
    /// - Parameter encoder: The export's encoder.
    /// - Throws: The encoder's error.
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(bundle.path, forKey: .path)
        try container.encode(bundle.info_plist_path, forKey: .info_plist_path)
        try container.encode(bundle.identifier, forKey: .identifier)
        try container.encode(bundle.name, forKey: .name)
        try container.encode(bundle.version, forKey: .version)
        try container.encode(bundle.short_version, forKey: .short_version)
        try container.encode(bundle.executable_path, forKey: .executable_path)
        try container.encode(bundle.is_ui_element, forKey: .is_ui_element)
        try container.encode(bundle.is_background_only, forKey: .is_background_only)
        try container.encode(bundle.signing_id, forKey: .signing_id)
        try container.encode(bundle.team_id, forKey: .team_id)
        try container.encode(bundle.codesigning_type, forKey: .codesigning_type)
        try container.encode(bundle.is_quarantined, forKey: .is_quarantined)
        try container.encode(bundle.where_froms, forKey: .where_froms)
        try container.encode(bundle.birth_time?.humanFormat(), forKey: .birth_time)
        try container.encode(bundle.age_ms, forKey: .age_ms)
    }
}
