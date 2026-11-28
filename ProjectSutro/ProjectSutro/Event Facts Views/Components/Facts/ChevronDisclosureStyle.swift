//
//  ChevronDisclosureStyle.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/25/26.
//

import SwiftUI


// MARK: - Chevron disclosure
/// A disclosure group for Event Facts: a chevron button before the label opens and closes it, and the content shows
/// below the label while it's open, lined up with the label.
///
/// SwiftUI's own style draws no control in Event Facts on macOS 13, and leaves the content showing. This one draws
/// the same on every macOS. The label stays selectable text, so only the chevron toggles.
struct ChevronDisclosureStyle: DisclosureGroupStyle {
    /// The chevron's width, in points.
    private static let chevronWidth: CGFloat = 12
    /// The space between the chevron and the label, in points.
    private static let spacing: CGFloat = 6

    /// - Parameter configuration: The group's label, content and whether it's open.
    /// - Returns: The group.
    func makeBody(configuration: Configuration) -> some View {
        VStack(alignment: .leading) {
            HStack(alignment: .firstTextBaseline, spacing: Self.spacing) {
                Button {
                    withAnimation(.easeInOut(duration: 0.15)) { configuration.isExpanded.toggle() }
                } label: {
                    Image(systemName: "chevron.right")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .rotationEffect(.degrees(configuration.isExpanded ? 90 : 0))
                        .frame(width: Self.chevronWidth, height: Self.chevronWidth)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help(configuration.isExpanded ? "Hide the details" : "Show the details")
                .accessibilityLabel(configuration.isExpanded ? "Hide the details" : "Show the details")
                configuration.label
            }
            if configuration.isExpanded {
                configuration.content
                    .padding(.leading, Self.chevronWidth + Self.spacing)
            }
        }
    }
}
