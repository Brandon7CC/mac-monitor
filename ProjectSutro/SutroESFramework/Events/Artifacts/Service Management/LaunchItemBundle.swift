//
//  LaunchItemBundle.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation


// MARK: - Launch item bundle
/// The app or helper bundle a launch item names, as the Security Extension read it from disk when it recorded a
/// `btm_launch_item_add` or `btm_launch_item_remove` event: the bundle's counterpart of a launchd plist
/// (``LaunchItem/plist_contents``).
///
/// It's read once, at capture (``read(at:)``), and never derived again: a trace opened on another Mac keeps the bundle
/// as it was recorded, and one without it has none. Every field but ``path`` and ``is_quarantined`` can be `nil`,
/// which the export writes as `null`: a key the bundle's Info.plist doesn't have, or one that couldn't be read.
public struct LaunchItemBundle: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()

    /// The bundle directory read.
    public var path: String

    // MARK: Info.plist
    /// The Info.plist read: `Contents/Info.plist`, or a shallow bundle's `Info.plist` at its top. `nil` only in a
    /// record that doesn't name it.
    public var info_plist_path: String?
    /// `CFBundleIdentifier`.
    public var identifier: String?
    /// `CFBundleDisplayName`, else `CFBundleName`.
    public var name: String?
    /// `CFBundleVersion`.
    public var version: String?
    /// `CFBundleShortVersionString`.
    public var short_version: String?
    /// The executable, as CFBundle finds it: `Contents/MacOS/<CFBundleExecutable>`, or `<CFBundleExecutable>` beside a
    /// shallow bundle's Info.plist. `NSExecutable` without `CFBundleExecutable`, and without either, a file named as
    /// the bundle without its extension, when there's one (``executablePath(_:layout:)``).
    public var executable_path: String?
    /// `LSUIElement`: the app runs as an agent, without a Dock icon or menu bar.
    public var is_ui_element: Bool?
    /// `LSBackgroundOnly`: the app runs with no user interface at all.
    public var is_background_only: Bool?

    // MARK: Code signing
    /// The bundle's signing identifier, from a static read of its signature.
    public var signing_id: String?
    /// The bundle's team identifier: `nil` for an Apple platform, adhoc or unsigned bundle.
    public var team_id: String?
    /// How the bundle as a whole is signed.
    public var codesigning_type: CodeSigningType?

    // MARK: Provenance
    /// 1 if the bundle directory has a `com.apple.quarantine` attribute, 0 if not, and 2 if it couldn't be found
    /// (``ProcessHelpers/isFileQuarantined(filePath:)``).
    public var is_quarantined: Int16 = 2
    /// Where the bundle was downloaded from (`com.apple.metadata:kMDItemWhereFroms`): the download URL, then the page
    /// it was found on. `nil` without the attribute.
    public var where_froms: [String]?
    /// When the bundle directory was created (`st_birthtimespec`).
    public var birth_time: TimeSpec?
    /// How old the bundle was at the event: milliseconds from ``birth_time`` to the message's time, rounded. Negative
    /// when the clock stepped back. Derived with the message's time (``Message/deriveBundleAges()``), never read.
    public var age_ms: Int?

    /// A bundle with only its path, whose details are filled in as they're read.
    ///
    /// - Parameter path: The bundle directory.
    public init(path: String) {
        self.path = path
    }
}


// MARK: - Age at the event
extension LaunchItemBundle {
    /// Derive ``age_ms`` from the message's time, unless the bundle has one or its birth time is unknown.
    ///
    /// - Parameter time: The message's time.
    mutating func deriveAge(at time: Date) {
        guard age_ms == nil, let birth = birth_time, birth.tv_sec > 0 else { return }
        let born = Date(timeIntervalSince1970: TimeInterval(birth.tv_sec) + TimeInterval(birth.tv_nsec) / 1e9)
        age_ms = Message.milliseconds(from: born, to: time)
    }

    /// Seconds from the bundle's birth to the event (``age_ms``), or `nil` when it's unknown or negative.
    public var age: TimeInterval? {
        EventAge.seconds(fromMilliseconds: age_ms.map { NSNumber(value: $0) })
    }

    /// ``age`` as text (``EventAge/text(seconds:)``), such as "4min" or "12 days", or `nil`.
    public var ageText: String? { EventAge.text(seconds: age) }

    /// Does the app run without a Dock icon (`LSUIElement` or `LSBackgroundOnly`)? Hidden apps are a persistence tell.
    public var isHidden: Bool { is_ui_element == true || is_background_only == true }
}
