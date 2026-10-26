//
//  MuteFileMenu.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI
import SutroESFramework
import OSLog


/// Import and Export for the saved mute set, as Path Muting's action menu offers them.
///
/// - **Import…** reads a mute file (version 1, or the list Mac Monitor exported before 3.0), shows what it holds and
///   what was left out, then replaces the saved set or adds to it.
/// - **Export Saved Mute Set…** writes the saved set as a version 1 mute file, exactly as the Security Extension
///   keeps it.
/// - **Export Apple Mute Set…** writes Endpoint Security's own default mutes as before, one `ESMutedPath` per line.
@MainActor
final class MuteFileActions: ObservableObject {
    /// A file read and waiting for the user to choose Replace or Add.
    struct PendingImport: Identifiable {
        let id = UUID()
        /// The file's name, for the alert.
        let fileName: String
        /// What it holds.
        let imported: MuteImport
    }

    @Published var pending: PendingImport?
    /// Why a file couldn't be read or written.
    @Published var fileError: String?

    /// The most warnings an alert lists before summarizing the rest.
    private nonisolated static let warningsShown = 10

    /// Ask for a file and read it, at most one byte past ``MuteLimits/maxFileBytes``.
    func chooseImport() {
        guard let url = showMuteOpenPanel() else { return }
        do {
            let file = try FileHandle(forReadingFrom: url)
            defer { try? file.close() }
            let data = try file.read(upToCount: MuteLimits.maxFileBytes + 1) ?? Data()
            pending = PendingImport(fileName: url.lastPathComponent, imported: try MuteFileReader.read(data))
        } catch let error as MuteFileError {
            fileError = "“\(url.lastPathComponent)” couldn't be imported. \(error)"
        } catch {
            fileError = "“\(url.lastPathComponent)” couldn't be imported. \(error.localizedDescription)"
        }
    }

    /// Send the file's mutes to the Security Extension.
    ///
    /// - Parameters:
    ///   - pending: The file read.
    ///   - replacing: Replace the saved set, or add to it.
    ///   - manager: The Security Extension's manager.
    func apply(_ pending: PendingImport, replacing: Bool, through manager: EndpointSecurityManager) {
        manager.requestMutes(MuteRequest(replacing ? .replace : .add, MuteFile(pending.imported.list).mutes)) { reply in
            os_log("Imported %{public}@: %{public}@", pending.fileName, reply?.status.rawValue ?? "no reply")
        }
    }

    /// Ask for a place, then write the saved set as the Security Extension has it right now.
    ///
    /// - Parameter manager: The Security Extension's manager.
    func exportSavedSet(from manager: EndpointSecurityManager) {
        guard let url = showMuteSavePanel(title: "Export saved mute set", name: "mutes.json") else { return }
        manager.requestMutes(MuteRequest(.list)) { [weak self] reply in
            guard let reply else {
                self?.fileError = "The Security Extension didn't send the saved mute set."
                return
            }
            self?.write(MuteFile(mutes: reply.mutes).encoded(), to: url)
        }
    }

    /// Ask the Security Extension for Endpoint Security's default mutes, then for a place to write them.
    ///
    /// - Parameter manager: The Security Extension's manager.
    func exportAppleSet(from manager: EndpointSecurityManager) {
        manager.requestAppleMuteSet { [weak self] snapshot in
            guard let url = showMuteSavePanel(title: "Export Apple mute set", name: "apple-mutes.json") else { return }
            self?.write(Data(snapshot.sorted().joined(separator: "\n").utf8), to: url)
        }
    }

    /// The confirmation's title.
    var pendingTitle: String {
        guard let pending else { return "" }
        let count = pending.imported.list.count
        guard count > 0 else { return "“\(pending.fileName)” has no mutes Mac Monitor can use" }
        return "Import \(TraceSession.counted(count, "mute")) from “\(pending.fileName)”?"
    }

    /// What the file is, and what was left out of it.
    ///
    /// - Parameter pending: The file read.
    /// - Returns: The confirmation's message.
    func message(for pending: PendingImport) -> String {
        let format = pending.imported.format == .current ? "A Mac Monitor mute file."
            : "A mute list exported before Mac Monitor 3.0."
        let choice = pending.imported.list.isEmpty ? ""
            : " Replace makes it the saved mute set. Add merges it into the saved set."
        guard !pending.imported.warnings.isEmpty else { return format + choice }
        return format + choice + "\n\n" + Self.summary(of: pending.imported.warnings)
    }

    /// Up to ``warningsShown`` sentences, then how many more there are.
    ///
    /// - Parameter lines: The sentences.
    /// - Returns: One per line.
    nonisolated static func summary(of lines: [String]) -> String {
        let shown = lines.prefix(warningsShown).map { "• \($0)" }
        let more = lines.count > warningsShown ? ["…and \(lines.count - warningsShown) more."] : []
        return (shown + more).joined(separator: "\n")
    }

    /// Write some bytes, reporting a failure.
    ///
    /// - Parameters:
    ///   - data: The bytes.
    ///   - url: Where.
    private func write(_ data: Data, to url: URL) {
        do {
            try data.write(to: url, options: .atomic)
        } catch {
            fileError = "“\(url.lastPathComponent)” couldn't be written. \(error.localizedDescription)"
        }
    }
}


/// The alerts Import and Export raise: Replace or Add for a file read, and a file that couldn't be read or written.
struct MuteFileAlerts: ViewModifier {
    @ObservedObject var actions: MuteFileActions
    let manager: EndpointSecurityManager

    func body(content: Content) -> some View {
        content
            .alert(actions.pendingTitle, isPresented: Binding { actions.pending != nil } set: {
                if !$0 { actions.pending = nil }
            }, presenting: actions.pending) { pending in
                if pending.imported.list.isEmpty {
                    Button("OK", role: .cancel, action: {})
                } else {
                    Button("Replace Saved Set", role: .destructive) {
                        actions.apply(pending, replacing: true, through: manager)
                    }
                    Button("Add to Saved Set") { actions.apply(pending, replacing: false, through: manager) }
                    Button("Cancel", role: .cancel, action: {})
                }
            } message: { pending in
                Text(actions.message(for: pending))
            }
            .alert("Mute file", isPresented: Binding { actions.fileError != nil } set: {
                if !$0 { actions.fileError = nil }
            }, actions: { Button("OK", role: .cancel, action: {}) }, message: { Text(actions.fileError ?? "") })
    }
}
