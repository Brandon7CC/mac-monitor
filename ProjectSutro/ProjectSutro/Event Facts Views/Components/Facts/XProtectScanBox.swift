//
//  XProtectScanBox.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/25/26.
//

import SwiftUI
import SutroESFramework


// MARK: - XProtect scan
/// What scanning a written file, or the script an exec runs, with Apple's XProtect rules found, as a section of its
/// own below the event's facts, titled as Details is and drawn with the same facts: how many rules matched and how
/// many of them XProtect only reports, a list of them (``XProtectMatchList``), and the XProtect version. A file that
/// wasn't scanned says why.
struct XProtectScanBox: View {
    /// The scan.
    let scan: YaraScan
    /// Is it the scan of the script an exec runs, not of a written file?
    var isScript = false

    var body: some View {
        Divider()
        Label("**XProtect scan**", systemImage: "xmark.shield").font(.title2).padding([.leading], 5.0)
        FactsBox {
            if scan.status != YaraScan.scanned {
                FactRow {
                    Fact("Not scanned", scan.status)
                    InfoTip(text: Self.reason(scan.status, isScript: isScript))
                }
            } else if scan.rules.isEmpty {
                FactRow(name: "Rules matched", value: "None")
            } else {
                FactRow {
                    Fact("Rules matched", String(scan.rules.count))
                    if !scan.report_only.isEmpty {
                        Text("\(scan.report_only.count) report only").foregroundStyle(.secondary)
                    }
                }
                XProtectMatchList(scan: scan)
            }
            if let version = scan.xprotect_version {
                FactRow(name: "XProtect version", value: version)
            }
        }
    }

    /// Why a file wasn't scanned, in words.
    ///
    /// - Parameters:
    ///   - status: The scan's status.
    ///   - isScript: Is it the script an exec runs?
    /// - Returns: The reason.
    static func reason(_ status: String, isScript: Bool = false) -> String {
        switch status {
        case YaraScan.tooLarge: return "The file is larger than the 32 MB the scanner reads."
        case YaraScan.overBudget: return "The scanner had spent its share of the CPU."
        case YaraScan.busy: return "The scan couldn't finish within half a second, behind the files before it."
        case YaraScan.unreadable where isScript:
            return "The script was gone, not downloaded, or one its process couldn't read."
        case YaraScan.unreadable: return "The file was gone, not downloaded, or one its writer couldn't read."
        case YaraScan.changed where isScript: return "The script was written again before it was read."
        case YaraScan.changed: return "The file was written again before it was read. The close of that write is "
            + "scanned."
        case YaraScan.unavailable: return "Apple's XProtect rules couldn't be loaded on this Mac."
        case YaraScan.timedOut: return "The scan ran past its time."
        case YaraScan.tooManyMatches: return "So many strings matched that the scan stopped."
        default: return "The scan says \(status)."
        }
    }
}


// MARK: - Matched rules
/// The rules a scan matched, a row each, as Settings > XProtect Rules lists them: XProtect's name over the rule's
/// identifier when the two differ, binoculars and a badge on a rule XProtect only reports, and an arrow that shows
/// the rule in Settings. The rules XProtect acts on come first, each group in the scan's order.
struct XProtectMatchList: View {
    /// The scan.
    let scan: YaraScan

    /// A rule that matched.
    private struct Match {
        let identifier: String
        let name: String
        let isReportOnly: Bool
    }

    /// The matches, in the list's order.
    private var matches: [Match] {
        let all = zip(scan.rules, scan.names).map {
            Match(identifier: $0, name: $1, isReportOnly: scan.report_only.contains($0))
        }
        return all.filter { !$0.isReportOnly } + all.filter(\.isReportOnly)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(matches.enumerated()), id: \.offset) { index, match in
                if index > 0 { Divider() }
                row(match)
            }
        }
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(.separator))
    }

    /// One rule's row.
    ///
    /// - Parameter match: The rule.
    /// - Returns: The row.
    private func row(_ match: Match) -> some View {
        HStack(spacing: 10) {
            Image(systemName: match.isReportOnly ? "binoculars.fill" : "xmark.shield.fill")
                .foregroundStyle(match.isReportOnly ? CalloutBadge.reportOnly.color : Color.red)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(match.name).font(.body.monospaced().weight(.semibold))
                if match.name != match.identifier {
                    Text(match.identifier).font(.callout.monospaced()).foregroundStyle(.secondary)
                }
            }
            .textSelection(.enabled)
            Spacer(minLength: 8)
            if match.isReportOnly {
                CalloutBadge.reportOnly
            }
            ShowRuleButton(identifier: match.identifier, name: match.name)
        }
        .padding(.vertical, 7)
        .padding(.horizontal, 10)
    }
}


// MARK: - Show a rule
/// The arrow after a rule that matched: it asks Settings > XProtect Rules to show the rule
/// (``XProtectRuleReveal``), then opens the Settings window, or brings it to the front when it's open.
struct ShowRuleButton: View {
    /// The rule's identifier.
    let identifier: String
    /// XProtect's name for it.
    let name: String
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button {
            XProtectRuleReveal.shared.identifier = identifier
            openWindow(id: ProjectSutroApp.settingsWindow)
        } label: {
            Image(systemName: "arrow.up.right.circle.fill")
                .imageScale(.large)
                .foregroundStyle(Color.accentColor)
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .help("Show in Settings")
        .accessibilityLabel("Show \(name) in Settings")
    }
}
