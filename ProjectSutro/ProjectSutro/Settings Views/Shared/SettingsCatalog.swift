//
//  SettingsCatalog.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/8/26.
//

import SwiftUI


// MARK: - Catalog panes
/// A pane that lists things by class, as Subscriptions lists events and Indicators lists indicators: the search field
/// over a list of the classes in a rounded box, 250 points wide, beside a grouped `Form` of the classes' sections,
/// which scrolls on its own. The list picks a class as System Settings > Notifications picks an app.
struct SettingsCatalog<Classes: View, Sections: View>: View {
    @Binding var query: String
    /// The search field's placeholder.
    let prompt: String
    /// What the sections say when there are none, or `nil` while there are.
    let empty: String?
    /// An item to scroll the sections to, by its row's `id`, which is cleared once they have.
    var reveal: Binding<AnyHashable?> = .constant(nil)
    /// The list's rows (``SettingsClassRow``), with ``SettingsClassDivider`` between groups.
    @ViewBuilder let classes: Classes
    /// The form's sections (``SettingsClassSection``, or any `Section`).
    @ViewBuilder let sections: Sections

    var body: some View {
        HStack(alignment: .top, spacing: 0) {
            VStack(spacing: 10) {
                SettingsSearchField(text: $query, prompt: prompt)
                ScrollView {
                    VStack(spacing: 1) { classes }
                        .padding(4)
                }
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(.separator))
            }
            .frame(width: 250)
            ScrollViewReader { proxy in
                Form {
                    if let empty {
                        Section {
                            Text(empty).foregroundStyle(.secondary)
                                .frame(maxWidth: .infinity).padding(.vertical, 24)
                        }
                    }
                    sections
                }
                .formStyle(.grouped)
                /// A grouped form keeps a margin around its sections, which the pane around it already has: its
                /// trailing one and most of its top one are taken back, so the sections line up with the pane's
                /// header and start beside the search field. Its leading one is the gap after the list.
                .padding(.trailing, -Self.formMargin)
                .padding(.top, -Self.paneSpacing)
                .onAppear { scroll(proxy) }
                .onChange(of: reveal.wrappedValue) { _ in scroll(proxy) }
            }
        }
    }

    /// The margin a grouped form keeps around its sections, in points.
    private static var formMargin: CGFloat { 20 }
    /// The space ``SettingsPage`` keeps above the catalog, in points.
    private static var paneSpacing: CGFloat { 14 }

    /// Scroll the sections to the item asked for, if any, once they're laid out for it, and forget it.
    ///
    /// - Parameter proxy: The sections' scroll proxy.
    private func scroll(_ proxy: ScrollViewProxy) {
        guard let id = reveal.wrappedValue else { return }
        DispatchQueue.main.async {
            withAnimation { proxy.scrollTo(id, anchor: .center) }
            reveal.wrappedValue = nil
        }
    }
}


// MARK: - Classes
/// A class in a catalog's list: its tile, its name, and its count, filled with the accent color while it's picked.
struct SettingsClassRow: View {
    let title: String
    let symbol: String
    let tint: Color
    /// Is it the row for every class, whose name is bold?
    let isBold: Bool
    /// Its count, such as `3/5`, or how many a search finds.
    let count: String
    /// What its count's first number counts, as VoiceOver says it, such as "subscribed" in "3 of 5 subscribed".
    let unit: String
    let isSelected: Bool
    let pick: () -> Void

    var body: some View {
        Button(action: pick) {
            HStack(spacing: 10) {
                SettingsRowIcon(symbol, tint)
                Text(title).fontWeight(isBold ? .semibold : .regular).lineLimit(1)
                Spacer(minLength: 4)
                Text(count).monospacedDigit().font(.callout)
                    .foregroundStyle(isSelected ? Color.white.opacity(0.85) : .secondary)
            }
            .foregroundStyle(isSelected ? Color.white : .primary)
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(isSelected ? Color.accentColor : .clear, in: RoundedRectangle(cornerRadius: 7))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(title)
        .accessibilityValue(spokenCount)
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }

    /// Its count as VoiceOver says it: `3/5` as "3 of 5 on", rather than as a fraction or a date.
    private var spokenCount: String {
        let parts = count.split(separator: "/")
        return parts.count == 2 ? "\(parts[0]) of \(parts[1]) \(unit)" : count
    }
}


/// The line between groups of a catalog's list, such as under its row for every class.
struct SettingsClassDivider: View {
    var body: some View {
        Divider().padding(.horizontal, 8).padding(.vertical, 3)
    }
}


/// A class's section of a catalog's form: its header, then a row for each of its items, and any footer.
struct SettingsClassSection<Item: Identifiable, Row: View>: View {
    let header: SettingsClassHeader
    let items: [Item]
    /// What the section says under its items, or `nil`.
    var footer: String?
    /// An item's row, usually a ``SettingsItemRow``.
    @ViewBuilder let row: (Item) -> Row

    var body: some View {
        Section {
            ForEach(items) { row($0) }
        } header: {
            header
        } footer: {
            if let footer { Text(footer) }
        }
    }
}


/// A class's header: a row-sized tile, its name and any identity beside it, how many are on, and Turn All On or Off.
struct SettingsClassHeader: View {
    let title: String
    /// An identity beside the name, such as an ATT&CK tactic's `TA0003`, or `nil`.
    var identifier: String?
    let symbol: String
    let tint: Color
    /// How many are on, such as "3 of 5 subscribed".
    let detail: String
    /// Is every one on, so the button turns them all off?
    let allOn: Bool
    /// May they be turned on or off?
    var canTurnAll = true
    /// Turns every one on, or off.
    let turnAll: (Bool) -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 8) {
            SettingsRowIcon(symbol, tint, size: 20)
            Text(title).font(.headline).foregroundStyle(.primary)
            if let identifier {
                Text(identifier).font(.caption.monospaced()).foregroundStyle(.secondary)
            }
            Spacer()
            Text(detail).font(.caption).foregroundStyle(.secondary).monospacedDigit()
            Button(allOn ? "Turn All Off" : "Turn All On") { turnAll(!allOn) }
                .controlSize(.small)
                .accessibilityLabel("\(allOn ? "Turn All Off" : "Turn All On"), \(title)")
                .disabled(!canTurnAll)
        }
    }
}


// MARK: - Items
/// An item in a class's section: its symbol, in its class's color while it's on, its name and any badges, what more
/// there is to say under them, its accessories, then its switch.
struct SettingsItemRow<Badges: View, Details: View, Accessory: View>: View {
    let title: String
    let symbol: String
    let tint: Color
    /// The switch's VoiceOver label, such as "Subscribe to Exec".
    let switchLabel: String
    @Binding var isOn: Bool
    /// May the switch be used?
    var canSwitch = true
    /// What clicking the row's symbol, name or details does, or `nil` for nothing.
    var open: (() -> Void)?
    /// Beside the name, such as a severity.
    @ViewBuilder let badges: Badges
    /// Under the name.
    @ViewBuilder let details: Details
    /// Before the switch, such as a link to documentation.
    @ViewBuilder let accessory: Accessory

    var body: some View {
        HStack(spacing: 12) {
            HStack(spacing: 12) {
                SettingsRowIcon(symbol, isOn ? tint : Color(nsColor: .tertiaryLabelColor))
                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 6) {
                        Text(title).foregroundStyle(isOn ? .primary : .secondary)
                        badges
                    }
                    details
                }
                Spacer(minLength: 8)
            }
            .modifier(OpensOnClick(open: open))
            accessory
            Toggle(switchLabel, isOn: $isOn).labelsHidden().toggleStyle(.switch)
                .disabled(!canSwitch)
        }
    }
}


/// Clicking anywhere in the view opens its item, when there's something to open.
private struct OpensOnClick: ViewModifier {
    let open: (() -> Void)?

    /// The view, opening its item on a click when there's one to open.
    /// - Parameter content: The view this modifies.
    /// - Returns: The view, clickable as a whole when ``open`` is set, else as it is.
    func body(content: Content) -> some View {
        if let open {
            content.contentShape(Rectangle()).onTapGesture(perform: open)
        } else {
            content
        }
    }
}
