//
//  IndicatorPackSheet.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/17/26.
//

import SwiftUI
import SutroESFramework


// MARK: - A newer indicator pack
/// Offers a newer indicator pack as ``UpdateAvailableSheet`` offers a release: which pack is out over which, when it
/// was released and where, then what the pack says of itself, and Skip This Pack, Remind Me Later or Install. What's
/// New, the release's notes, and Indicators that change, each one by name, open on a click, one at a time so the
/// sheet fits a small screen. The Security Extension installs it, and only the pack that's offered here. Why it
/// wasn't installed, if it wasn't, shows in the sheet. A checkbox has later packs installed automatically, which
/// Install applies along with the pack.
struct IndicatorPackSheet: View {
    let offer: IndicatorPackOffer
    @ObservedObject private var store = IndicatorStore.shared
    @Environment(\.dismiss) private var dismiss
    /// The pack Skip This Pack skipped. Mac Monitor doesn't offer it again when it opens.
    @AppStorage(Self.skippedPackKey) private var skippedPack = 0
    @State private var isInstalling = false
    /// Why the pack wasn't installed.
    @State private var problem: String?
    /// The section that's open, if one is.
    @State private var open: Part?
    /// Is the checkbox for installing later packs automatically ticked? `nil` until it's touched, when it shows the
    /// Mac's mode.
    @State private var installsLater: Bool?

    /// A section that opens on a click.
    private enum Part {
        /// The release's notes.
        case notes
        /// The indicators that change.
        case changes
    }

    /// Where the skipped pack is kept.
    static let skippedPackKey = "indicatorPackSkipped"

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top, spacing: 16) {
                Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 64, height: 64)
                VStack(alignment: .leading, spacing: 6) {
                    Text("A newer indicator pack is available").font(.headline)
                    Text(IndicatorPackText.availability(of: offer, over: store.engine.pack))
                        .fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 4) {
                        if let day = IndicatorPackText.day(offer.published) {
                            Text("Released \(day) ·").foregroundStyle(.secondary)
                        }
                        Link("View on GitHub", destination: offer.page)
                    }
                }
            }
            details
            VStack(alignment: .leading, spacing: 10) {
                section("What's New", .notes) { notes }
                if !groups.isEmpty {
                    section("Indicators that change", .changes) { changes }
                }
            }
            if let problem {
                Label(problem, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange).textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            } else if !store.canChangeIndicators {
                Label("Another Mac Monitor owns the event stream, so it alone may install the pack.",
                      systemImage: "lock.fill")
                    .foregroundStyle(.secondary)
            }
            Toggle("Install future indicator packs automatically", isOn: Binding {
                installsLater ?? (store.engine.pack?.mode == .automatic)
            } set: { installsLater = $0 })
                .toggleStyle(.checkbox)
                .disabled(isInstalling || !store.canChangeIndicators)
            HStack {
                Button("Skip This Pack") {
                    skippedPack = offer.sequence
                    dismiss()
                }
                .disabled(isInstalling)
                Spacer()
                if isInstalling { ProgressView().controlSize(.small) }
                Button("Remind Me Later") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(isInstalling)
                Button("Install", action: install)
                    .keyboardShortcut(.defaultAction)
                    .disabled(isInstalling || !store.canChangeIndicators)
            }
        }
        .padding(24)
        .frame(width: 560)
        .interactiveDismissDisabled(isInstalling)
    }

    // MARK: - Details
    /// The indicators the pack adds, removes and changes on this Mac, leaving out a kind it has none of.
    private var groups: [(title: String, symbol: String, tint: Color, names: [String])] {
        [("New", "plus.circle.fill", Color.green, offer.added),
         ("Removed", "minus.circle.fill", Color.red, offer.removed),
         ("Changed", "pencil.circle.fill", Color.orange, offer.changed)].filter { !$0.3.isEmpty }
    }

    /// This Mac's version and the pack's, how many indicators it leaves this Mac with, how many of each kind change,
    /// who signed it, and what happens to this Mac's own changes, as labelled rows.
    private var details: some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 16, verticalSpacing: 6) {
            row("Version") { Text(IndicatorPackText.versions(of: offer, over: store.engine.pack)) }
            row("Indicators") { Text("\(offer.total) total") }
            row("Changes") {
                if groups.isEmpty {
                    Text("None for this Mac")
                } else {
                    HStack(spacing: 14) {
                        ForEach(groups, id: \.title) { group in
                            Label {
                                Text("\(group.names.count) \(group.title.lowercased())")
                            } icon: {
                                Image(systemName: group.symbol).foregroundStyle(group.tint)
                            }
                        }
                    }
                }
            }
            row("Signed by") { Text("Swiftly Detecting, team ID \(SensorXPC.teamID)") }
            row("Your changes") { Text("Indicators changed or deleted on this Mac stay as they are") }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
    }

    /// One labelled row of ``details``.
    ///
    /// - Parameters:
    ///   - label: What the row is.
    ///   - value: What it says.
    /// - Returns: The row.
    private func row(_ label: String, @ViewBuilder value: () -> some View) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
            value().frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: - Sections that open
    /// A titled section that's closed until its title is clicked. Opening one closes the other.
    ///
    /// - Parameters:
    ///   - title: The title.
    ///   - part: Which section it is.
    ///   - content: What it shows once open.
    /// - Returns: The section.
    private func section(_ title: String, _ part: Part, @ViewBuilder content: () -> some View) -> some View {
        let isOpen = open == part
        return VStack(alignment: .leading, spacing: 8) {
            Button {
                withAnimation(.easeInOut(duration: 0.15)) { open = isOpen ? nil : part }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "chevron.right")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .rotationEffect(.degrees(isOpen ? 90 : 0))
                    Text(title).font(.headline)
                    Spacer()
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityValue(isOpen ? "Expanded" : "Collapsed")
            if isOpen { content() }
        }
    }

    /// The release's notes, in the box ``UpdateAvailableSheet`` shows a release's in.
    private var notes: some View {
        box(height: 180) {
            Text(ReleaseNotesText.attributed(offer.notes ?? "This release has no notes."))
                .textSelection(.enabled)
        }
    }

    /// The indicators the pack adds, removes and changes on this Mac, by name.
    private var changes: some View {
        box(height: 180) {
            VStack(alignment: .leading, spacing: 10) {
                ForEach(groups, id: \.title) { group in
                    VStack(alignment: .leading, spacing: 4) {
                        Text("\(group.title) (\(group.names.count))").font(.subheadline.weight(.semibold))
                            .foregroundStyle(.secondary)
                        ForEach(Array(group.names.enumerated()), id: \.offset) { _, name in
                            Label { Text(name) } icon: { Image(systemName: group.symbol).foregroundStyle(group.tint) }
                        }
                    }
                }
            }
        }
    }

    /// A scrolling box of a fixed height.
    ///
    /// - Parameters:
    ///   - height: Its height.
    ///   - content: What scrolls in it.
    /// - Returns: The box.
    private func box(height: CGFloat, @ViewBuilder content: () -> some View) -> some View {
        ScrollView {
            content()
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
        }
        .frame(height: height)
        .background(Color(NSColor.textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.gray.opacity(0.3), lineWidth: 1))
    }

    // MARK: - Actions
    /// Have the Security Extension install the offered pack, then close, or say why it wasn't installed. Once it's
    /// installed, the checkbox decides whether later packs install automatically, if it was touched: ticked is the
    /// automatic mode, and cleared is the notify mode.
    private func install() {
        (isInstalling, problem) = (true, nil)
        store.engine.installPack(offer) { failure in
            isInstalling = false
            if let failure { return problem = failure }
            if let installsLater, installsLater != (store.engine.pack?.mode == .automatic) {
                store.engine.setPackMode(installsLater ? .automatic : .notify)
            }
            dismiss()
        }
    }
}


// MARK: - Presenting
extension View {
    /// Shows ``IndicatorPackSheet`` for a newer indicator pack, the same when Mac Monitor opens and from Settings.
    ///
    /// - Parameter offer: The pack to offer. Closing the sheet sets it back to `nil`.
    /// - Returns: The view, presenting the offer.
    func indicatorPackOffer(_ offer: Binding<IndicatorPackOffer?>) -> some View {
        sheet(item: offer) { IndicatorPackSheet(offer: $0) }
    }
}
