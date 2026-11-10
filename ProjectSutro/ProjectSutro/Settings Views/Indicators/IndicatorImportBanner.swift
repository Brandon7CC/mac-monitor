//
//  IndicatorImportBanner.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/8/26.
//

import SwiftUI
import SutroESFramework


// MARK: - 3.0 import offer
/// Settings > Indicators' one offer of this user's Mac Monitor 3.0 indicators (``IndicatorImportOffer``): it lists
/// their own indicators, and, as its own choice, the shipped ones they edited, which would replace this Mac's
/// versions. It says that every user of this Mac sees and is watched by them. While this Mac Monitor can't change the
/// Mac's indicators, it says so and stays until the import runs.
struct IndicatorImportBanner: View {
    let offer: IndicatorImportOffer
    /// May the Mac's indicators be changed?
    let canChange: Bool
    /// Imports them, replacing this Mac's versions of the edited ones when `true`.
    let take: (Bool) -> Void
    /// Doesn't offer them again.
    let decline: () -> Void
    /// Do the edited shipped indicators replace this Mac's versions?
    @State private var replacesEdited = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Import your 3.0 indicators to this Mac", systemImage: "square.and.arrow.down.on.square")
                .font(.headline)
            Text("This Mac now has one set of indicators, which the Security Extension runs on every event. Imported "
                 + "indicators are visible to, and run for, every user of this Mac. Mac Monitor's own indicators "
                 + "you turned off or deleted aren't carried over; your own come over on or off as you left them.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if !offer.added.isEmpty {
                Text(names(offer.added)).font(.callout)
            }
            if !offer.edited.isEmpty {
                Toggle(isOn: $replacesEdited) {
                    let noun = offer.edited.count == 1 ? "indicator" : "indicators"
                    Text("Also import the Mac Monitor \(noun) you edited: \(names(offer.edited)). Each replaces "
                         + "this Mac's version.")
                        .font(.callout)
                }
                .toggleStyle(.checkbox)
            }
            HStack {
                if !canChange {
                    Text("Only the Mac Monitor that owns the event stream, with a Security Extension from 3.1 or "
                         + "later, can import them.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Don't Import", action: decline)
                Button("Import") { take(replacesEdited) }
                    .disabled(!canChange || (offer.added.isEmpty && !replacesEdited))
            }
        }
        .padding(12)
        .background(.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(.blue.opacity(0.3)))
    }

    /// - Parameter indicators: Indicators.
    /// - Returns: Their names, in order, joined.
    private func names(_ indicators: [Indicator]) -> String {
        indicators.map(\.name).formatted(.list(type: .and))
    }
}
