//
//  ProcessView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 7/13/25.
//

import SwiftUI
import SutroESFramework

/// A process in Event Facts: when it started, its user, its name, IDs and path, and how it's signed.
struct ProcessView: View {
    var message: ESMessage
    var process: ESProcess
    /// How old the process was at the event, as text, or `nil`. Passed in because ``process`` may be a shared row,
    /// which has no age: the event keeps it (``ESMessage/processAgeText``, ``ESProcessForkEvent/childAgeText``).
    let ageText: String?

    var body: some View {
        GroupBox {
            VStack(alignment: .leading) {
                ProcessStartFacts(process: process, ageText: ageText)
                HStack {
                    Label("**User:**", systemImage: "person.fill")
                    UserFact(process: process)
                }
                ProcessIDFacts(process: process, name: process.executable?.name ?? "")
                FactRow(name: "Process path", value: process.executable?.path ?? "")
                if let ttyPath = process.tty?.path {
                    FactRow(name: "TTY", value: ttyPath)
                }
            }.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)

            Divider()

            FactsBox {
                Label("**Code signing details**", systemImage: "signature")
                    .font(.title3)
                    .padding([.top, .leading], 5.0)
                FactRow(name: "Code signing type", value: process.codeSigningTypeLabel(version: message.version))
                FactRow(name: "Process signing ID", value: process.signing_id.nonEmpty)
                CDHashFact(process: process)
            }
        }
    }
}


// MARK: - Code signing type
extension ESProcess {
    /// How the process is signed, as Event Facts names it: its code signing validation category and number from
    /// message version 10 on (`PLATFORM (1)`), else its code signing type. Category 10 (`NONE`) says nothing the
    /// code signing type doesn't, so it shows the type.
    ///
    /// - Parameter version: The message version of the event the process is in.
    /// - Returns: The label.
    func codeSigningTypeLabel(version: Int32) -> String {
        if version >= 10, cs_validation_category != 10, let category = cs_validation_category_string {
            return "\(category.droppingPrefix("ES_CS_VALIDATION_CATEGORY_")) (\(cs_validation_category))"
        }
        return codesigning_type
    }
}


// MARK: - Start time
/// When a process started, how old it was at its event, and its File Quarantine badge when it has one.
struct ProcessStartFacts: View {
    /// The process.
    let process: ESProcess
    /// How old the process was at the event, as text, or `nil`.
    let ageText: String?

    var body: some View {
        HStack {
            Label("**Start time:**", systemImage: "clock")
            GroupBox {
                Text("`\(process.start_time)`")
            }
            ProcessAgeFact(ageText: ageText)
            if process.file_quarantine_type != "DISABLED" {
                FileQuarantineLabelView(type: process.file_quarantine_type)
            }
        }
    }
}


// MARK: - Name and IDs
/// A process's name, PID and group ID in one row, then anything the event adds to it.
struct ProcessIDFacts<Trailing: View>: View {
    /// The process.
    let process: ESProcess
    /// The process's name, as the event names it.
    let name: String
    /// Shown after the group ID.
    @ViewBuilder let trailing: () -> Trailing

    /// - Parameters:
    ///   - process: The process.
    ///   - name: The process's name, as the event names it.
    ///   - trailing: Shown after the group ID.
    init(process: ESProcess, name: String, @ViewBuilder trailing: @escaping () -> Trailing = { EmptyView() }) {
        self.process = process
        self.name = name
        self.trailing = trailing
    }

    var body: some View {
        HStack {
            fact("Process name", name)
            fact("PID", String(process.pid))
            fact("GID", String(process.group_id))
            trailing()
        }.frame(maxWidth: .infinity, alignment: .leading)
    }

    /// - Parameters:
    ///   - name: The fact's name, without a colon.
    ///   - value: Its value.
    /// - Returns: The bulleted name and its value as code, in a row with the others.
    @ViewBuilder
    private func fact(_ name: String, _ value: String) -> some View {
        Text("\u{2022} **\(name):**")
        GroupBox {
            Text("`\(value)`")
        }
    }
}


// MARK: - Signing ID
/// A process's signing ID, or that its code isn't signed at all.
struct SigningIDFact: View {
    /// The process.
    let process: ESProcess

    var body: some View {
        if let signingID = process.signing_id.nonEmpty, signingID != "Unknown" {
            FactRow(name: "Process signing ID", value: signingID)
        } else {
            GroupBox {
                Text("Code object is not signed at all")
                    .frame(alignment: .leading)
            }
        }
    }
}


// MARK: - Code directory hash
/// A process's SHA-256 code directory hash, or "Unknown" without one.
struct CDHashFact: View {
    /// The process.
    let process: ESProcess

    var body: some View {
        HStack {
            Text("\u{2022} **`SHA256` Code directory hash:**")
            GroupBox {
                Text("`\(process.cdhash ?? "Unknown")`")
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}


// MARK: - Target process
/// The process an event acted on: its name, its path below it, and its signing ID when it has one. Its name and
/// path read "Unknown" when the event doesn't say which process it was.
struct TargetProcessFacts: View {
    /// The process, or `nil` when the event doesn't say.
    let process: ESProcess?
    /// The path's name, without a colon.
    var pathName = "Target process path"
    /// How the values are drawn.
    var style = FactRow.Style.code

    var body: some View {
        FactRow(name: "Target process name", value: process?.executable?.name, style: style)
        FactRow(name: pathName, value: process?.executable?.path, stacked: true, style: style)
        if let signingID = process?.signing_id, !signingID.isEmpty {
            FactRow(name: "Signing ID", value: signingID, style: style)
        }
    }
}


// MARK: - Process age
/// How old a process was at its event (``EventAge``), or nothing when that's unknown. The Groups inspector names the
/// same fact "Process age".
struct ProcessAgeFact: View {
    /// The age as text, or `nil`.
    let ageText: String?

    var body: some View {
        if let ageText {
            Label("**Process age:**", systemImage: "hourglass")
            GroupBox {
                Text("`\(ageText)`")
            }
        }
    }
}
