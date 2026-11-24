//
//  IndicatorPackSettings.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/17/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Settings > General > Updates: indicator packs
/// Settings > General's two rows for indicator packs, under Mac Monitor's own updates: which pack this Mac has, what
/// the last look for a newer one found, and Check Now. Then how newer packs are taken: never looked for, looked for
/// once a day and told of, or looked for and installed. The mode is the Mac's, for every user, so it's off-limits
/// while this Mac Monitor may not change the indicators. A newer pack Check Now finds is offered in
/// ``IndicatorPackSheet``.
struct IndicatorPackSettings: View {
    @ObservedObject private var store = IndicatorStore.shared
    /// The pack Check Now found, while its sheet is open.
    @State private var offer: IndicatorPackOffer?
    /// Why the last Check Now couldn't look, until the next.
    @State private var problem: String?

    var body: some View {
        let engine = store.engine
        LabeledContent {
            Button("Check Now", action: checkNow)
                .disabled(engine.isLookingForPack || engine.connection != .connected)
        } label: {
            SettingsIconLabel(IndicatorPackText.title(engine.pack),
                              detail: problem ?? IndicatorPackText.detail(engine.pack,
                                                                         isLooking: engine.isLookingForPack),
                              symbol: "shield.lefthalf.filled", tint: .orange)
        }
        .indicatorPackOffer($offer)
        Picker(selection: mode) {
            ForEach(IndicatorPackMode.allCases, id: \.self) { mode in
                Text(IndicatorPackText.name(of: mode)).tag(mode)
            }
        } label: {
            SettingsIconLabel("Indicator updates", detail: IndicatorPackText.detail(of: engine.pack?.mode),
                              symbol: "arrow.triangle.2.circlepath", tint: .teal)
        }
        .disabled(!store.canChangeIndicators || engine.pack?.mode == nil)
        .help(store.canChangeIndicators ? "" : "Only the Mac Monitor that owns the event stream may change this.")
    }

    /// The Mac's mode, which the Security Extension keeps: notify until it says.
    private var mode: Binding<IndicatorPackMode> {
        Binding { store.engine.pack?.mode ?? .notify } set: { store.engine.setPackMode($0) }
    }

    /// Have the Security Extension look for a newer pack, and offer one it finds. What else it found shows in the
    /// row, as the Security Extension says it.
    private func checkNow() {
        problem = nil
        store.engine.lookForPack { look in
            switch look {
            case .newer(let found): offer = found
            case .upToDate: break
            case .failed(let reason): problem = store.engine.pack?.problem == nil ? reason : nil
            }
        }
    }
}
