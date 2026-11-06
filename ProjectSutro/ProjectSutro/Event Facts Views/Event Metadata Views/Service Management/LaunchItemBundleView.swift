//
//  LaunchItemBundleView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/5/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Launch item bundles
/// The bundle a launch item names in Event Facts, in a section of its own, as the Security Extension read it when it
/// recorded the event. Nothing when the item has none.
struct LaunchItemBundleSection: View {
    /// The launch item.
    let item: ESLaunchItem

    var body: some View {
        if let bundle = item.bundle {
            Divider()
            LaunchItemBundleView(title: "Bundle", systemImage: "shippingbox", bundle: bundle)
        }
    }
}

/// A launch item's app's bundle in Event Facts, under its Registering application section. Nothing when the item has
/// none, or when it's the item's own bundle, as an app item's is, which ``LaunchItemBundleSection`` shows already.
struct LaunchItemAppBundleSection: View {
    /// The launch item.
    let item: ESLaunchItem

    var body: some View {
        if let app = item.app_bundle, app.path != item.bundle?.path {
            LaunchItemBundleView(title: "App bundle", systemImage: "app.badge", bundle: app)
        }
    }
}


// MARK: - One bundle
/// One bundle's facts: its Info.plist essentials, whether it hides from the Dock, its signing, and where it came from.
struct LaunchItemBundleView: View {
    /// The section's title.
    let title: LocalizedStringKey
    /// The section's symbol.
    let systemImage: String
    /// The bundle.
    let bundle: LaunchItemBundle

    /// The version as "short (build)", either alone, or `nil`.
    private var versionText: String? {
        switch (bundle.short_version, bundle.version) {
        case let (short?, build?) where short != build: return "\(short) (\(build))"
        case let (short, build): return short ?? build
        }
    }

    /// The Info.plist keys that hide the app, or `nil` when it isn't hidden (``LaunchItemBundle/isHidden``).
    private var hiddenText: String? {
        guard bundle.isHidden else { return nil }
        let keys = [bundle.is_ui_element == true ? "LSUIElement" : nil,
                    bundle.is_background_only == true ? "LSBackgroundOnly" : nil].compactMap { $0 }
        return "No Dock icon (\(keys.joined(separator: ", ")))"
    }

    var body: some View {
        VStack(alignment: .leading) {
            Label(title, systemImage: systemImage)
                .bold()
                .font(.title3)
                .padding([.top, .leading], 5.0)

            FactRow(name: "Bundle path", value: bundle.path, stacked: true)
            FactRow(name: "Identifier", value: bundle.identifier)
            FactRow(name: "Version", value: versionText)
            if let executable = bundle.executable_path {
                FactRow(name: "Executable", value: executable, stacked: true)
            }
            if let hiddenText {
                FactRow(name: "Hidden", value: hiddenText)
            }
            if let ageText = bundle.ageText {
                FactRow(name: "Bundle age", value: ageText)
            }
            if let origins = bundle.where_froms, !origins.isEmpty {
                FactRow(name: "Download origin", value: origins.joined(separator: "\n"), stacked: true)
            }

            LaunchItemBundleSigningView(bundle: bundle)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}


// MARK: - Signing
/// A bundle's signing, boxed the way the process views box a process's code signing details: an unsigned bundle says
/// so in place of a signing ID, as an exec's target does, and a bundle whose signature wasn't read says that instead.
struct LaunchItemBundleSigningView: View {
    /// The bundle.
    let bundle: LaunchItemBundle

    var body: some View {
        GroupBox {
            VStack(alignment: .leading) {
                Label("**Code signing details**", systemImage: "signature")
                    .font(.title3)
                    .padding([.top, .leading], 5.0)
                switch bundle.codesigning_type {
                case nil:
                    note("The signature wasn't read")
                case .unsigned?:
                    FactRow(name: "Code signing type", value: CodeSigningType.unsigned.rawValue)
                    note("Code object is not signed at all")
                case let type?:
                    FactRow(name: "Code signing type", value: type.rawValue)
                    FactRow(name: "Signing ID", value: bundle.signing_id)
                    if let teamID = bundle.team_id {
                        FactRow(name: "Team ID", value: teamID)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    /// A line in place of the signing's facts.
    ///
    /// - Parameter text: What to say.
    /// - Returns: The text, boxed as the exec views box theirs.
    private func note(_ text: LocalizedStringKey) -> some View {
        GroupBox {
            Text(text)
                .frame(alignment: .leading)
        }
    }
}


// MARK: - Instigator
/// How old the process that registered or removed the launch item was at the event, or nothing when that's unknown.
/// The instigator's row is the event's own, so it keeps its age (``ESProcess/processAgeText``).
struct LaunchItemInstigatorAgeRow: View {
    /// The instigator, or `nil`.
    let instigator: ESProcess?

    var body: some View {
        if let age = instigator?.processAgeText {
            HStack {
                Text("\u{2022} **Instigator age:**")
                GroupBox {
                    Text("`\(age)`")
                }
            }
        }
    }
}
