//
//  CalloutBadge.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/6/26.
//

import SwiftUI


// MARK: - Callout badge
/// A small tinted badge beside a fact, pointing out something about it worth a look, such as "Executable", with
/// what it means on hover.
struct CalloutBadge: View {
    /// The badge's text.
    let text: String
    /// The text's color, and its background's at a lighter tint.
    let color: Color
    /// What the callout means, shown on hover.
    let help: String

    var body: some View {
        Text(text)
            .font(.caption.bold())
            .foregroundStyle(color)
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .background(color.opacity(0.18), in: RoundedRectangle(cornerRadius: 5))
            .help(help)
    }
}


extension CalloutBadge {
    /// The mark on a rule XProtect only reports, in Event Facts and Settings > XProtect Rules.
    static let reportOnly = CalloutBadge(text: "Report only", color: .purple,
                                         help: "XProtect only reports this rule and never acts on it (match_type = 4), "
                                            + "as for Apple's hunting rules.")
    /// The mark on a Settings pane this release adds, in the sidebar until the pane is opened.
    static let new = CalloutBadge(text: "NEW", color: .blue, help: "New in this release")
}


// MARK: - Info tip
/// A small "info.circle" beside a fact, with more about it on hover: where a script came from, or what an IOKit user
/// client gives the process that opens it.
struct InfoTip: View {
    /// What the tip says, on hover and to VoiceOver.
    let text: String

    var body: some View {
        Image(systemName: "info.circle")
            .foregroundStyle(.secondary)
            .help(text)
            .accessibilityLabel(text)
    }
}
