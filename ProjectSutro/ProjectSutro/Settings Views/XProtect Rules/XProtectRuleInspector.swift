//
//  XProtectRuleInspector.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/26/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Inspector
/// The selected rule beside the table: its name, marked when XProtect only reports it, its identifier, UUID and rule
/// file, then its source in the read-only editor Event Facts uses, colored as YARA.
struct XProtectRuleInspector: View {
    /// The rule, or `nil` while none is selected.
    let rule: XProtectRule?
    @StateObject private var editor = ReadOnlyTextController()

    var body: some View {
        if let rule {
            VStack(alignment: .leading, spacing: 0) {
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 6) {
                        Text(rule.name).font(.headline)
                        if rule.isReportOnly { CalloutBadge.reportOnly }
                    }
                    fact("Identifier", rule.identifier)
                    if let uuid = rule.uuid { fact("UUID", uuid) }
                    fact("File", "\(rule.file.rawValue) · \(rule.file.gloss)")
                }
                .textSelection(.enabled)
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                Divider()
                ReadOnlyTextEditor(text: rule.source, language: .yara, controller: editor)
            }
        } else {
            Text("Select a rule to see its source.")
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    /// One fact about the rule: its name small, and its value monospaced under it.
    ///
    /// - Parameters:
    ///   - name: What it is, such as "UUID".
    ///   - value: Its value.
    /// - Returns: The fact.
    private func fact(_ name: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(name).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.callout.monospaced()).fixedSize(horizontal: false, vertical: true)
        }
    }
}
