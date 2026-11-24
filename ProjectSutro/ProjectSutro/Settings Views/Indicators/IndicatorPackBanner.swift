//
//  IndicatorPackBanner.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/17/26.
//

import SwiftUI
import SutroESFramework


// MARK: - A newer pack is out
/// Settings > Indicators' line for a newer indicator pack the Security Extension found: which it is, what installing
/// it would do once that's known, and Install, which opens ``IndicatorPackSheet``. It shows only while a newer pack
/// is out. Which pack this Mac has, and how newer ones are taken, are in Settings > General.
struct IndicatorPackBanner: View {
    /// The newer pack's release.
    let sequence: Int
    /// What installing it would do, once a look has said.
    let offer: IndicatorPackOffer?
    /// Is a look for what it would do under way?
    let isLooking: Bool
    /// Opens the offer.
    let install: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Label(text, systemImage: "arrow.down.circle.fill")
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            if isLooking { ProgressView().controlSize(.small) }
            Button("Install…", action: install)
                .disabled(isLooking)
        }
        .padding(12)
        .background(.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(.blue.opacity(0.3)))
    }

    /// Such as "Indicator pack 2 is out: it adds 3 indicators and changes 5."
    private var text: String {
        guard let offer, offer.sequence == sequence else { return "Indicator pack \(sequence) is out." }
        return "Indicator pack \(sequence) is out: it \(offer.effect)."
    }
}
