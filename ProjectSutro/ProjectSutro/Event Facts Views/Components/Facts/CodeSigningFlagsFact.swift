//
//  CodeSigningFlagsFact.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/27/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Code signing flags
/// A process's code signing flags: the value, then the names of the flags set in a box as wide as the facts. Hovering
/// over the names lists what each flag means. Without a flag set, "none set" follows the value.
struct CodeSigningFlagsFact: View {
    /// `es_process_t`'s `codesigning_flags`.
    let flags: Int64

    var body: some View {
        let set = ProcessHelpers.codeSigningFlags(flags)
        let value = String(format: "0x%08X", UInt32(truncatingIfNeeded: flags))
        if set.isEmpty {
            FactRow {
                Fact("Code signing flags", value)
                Text("none set").foregroundStyle(.secondary)
            }
        } else {
            FactRow(stacked: true) {
                FactRow(name: "Code signing flags", value: value)
                FactValue(set.map(\.name).joined(separator: ", "), fillsWidth: true)
                    .help(set.map { "\($0.name): \($0.summary)" }.joined(separator: "\n"))
            }
        }
    }
}
