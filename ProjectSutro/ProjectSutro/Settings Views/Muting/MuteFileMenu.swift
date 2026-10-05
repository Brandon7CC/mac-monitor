//
//  MuteFileMenu.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI
import SutroESFramework
import OSLog


/// Import… and Export for the saved mute set.
///
/// - **Import…** reads a mute file (version 1, or the list Mac Monitor exported before 2.2), shows what it holds and
///   what was left out, then replaces the saved set or adds to it.
/// - **Export ▸ Saved mute set…** writes the saved set as a version 1 mute file, exactly as the Security Extension
///   keeps it.
/// - **Export ▸ Apple mute set…** writes Endpoint Security's own default mutes as before, one `ESMutedPath` per line.
struct MuteFileMenu: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    
    /// A file read and waiting for the user to choose Replace or Add.
    struct PendingImport: Identifiable {
        let id = UUID()
        /// The file's name, for the alert.
        let fileName: String
        /// What it holds.
        let imported: MuteImport
    }
    
    @State private var pending: PendingImport?
    /// Why a file couldn't be read or written.
    @State private var fileError: String?
    
    /// The most warnings an alert lists before summarizing the rest.
    private static let warningsShown = 10
    
    var body: some View {
        HStack {
            Button("Import…") { chooseImport() }
                .disabled(!systemExtensionManager.canChangeSavedMutes)
                .help("Replace the saved mute set with a mute file's mutes, or add them to it.")
            
            Menu("Export") {
                Button("Saved mute set…") { exportSavedSet() }
                    .help("The saved mute set, as a mute file Import reads back.")
                Button("Apple mute set…") {
                    systemExtensionManager.requestAppleMuteSet { snapshot in
                        write(Data(snapshot.sorted().joined(separator: "\n").utf8), title: "Export Apple mute set")
                    }
                }
                .help("Endpoint Security's own default mutes, which aren't part of the saved set.")
            }
            .frame(maxWidth: 100)
        }
        .alert(pendingTitle, isPresented: Binding(get: { pending != nil }, set: { if !$0 { pending = nil } }),
               presenting: pending) { pending in
            if pending.imported.list.isEmpty {
                Button("OK", role: .cancel, action: {})
            } else {
                Button("Replace Saved Set", role: .destructive) { apply(pending, replacing: true) }
                Button("Add to Saved Set") { apply(pending, replacing: false) }
                Button("Cancel", role: .cancel, action: {})
            }
        } message: { pending in
            Text(message(for: pending))
        }
        .alert("Mute file", isPresented: Binding(get: { fileError != nil }, set: { if !$0 { fileError = nil } }),
               actions: { Button("OK", role: .cancel, action: {}) },
               message: { Text(fileError ?? "") })
    }
    
    /// The confirmation's title.
    private var pendingTitle: String {
        guard let pending else { return "" }
        let count = pending.imported.list.count
        guard count > 0 else { return "“\(pending.fileName)” has no mutes Mac Monitor can use" }
        return "Import \(TraceSession.counted(count, "mute")) from “\(pending.fileName)”?"
    }
    
    /// What the file is, and what was left out of it.
    ///
    /// - Parameter pending: The file read.
    /// - Returns: The confirmation's message.
    private func message(for pending: PendingImport) -> String {
        let format = pending.imported.format == .current ? "A Mac Monitor mute file."
            : "A mute list exported before Mac Monitor 2.2."
        let choice = pending.imported.list.isEmpty ? ""
            : " Replace makes it the saved mute set; Add merges it into the saved set."
        guard !pending.imported.warnings.isEmpty else { return format + choice }
        return format + choice + "\n\n" + Self.summary(of: pending.imported.warnings)
    }
    
    /// Up to ``warningsShown`` sentences, then how many more there are.
    ///
    /// - Parameter lines: The sentences.
    /// - Returns: One per line.
    static func summary(of lines: [String]) -> String {
        let shown = lines.prefix(warningsShown).map { "• \($0)" }
        let more = lines.count > warningsShown ? ["…and \(lines.count - warningsShown) more."] : []
        return (shown + more).joined(separator: "\n")
    }
    
    /// Ask for a file and read it, at most one byte past ``MuteLimits/maxFileBytes``.
    private func chooseImport() {
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
    private func apply(_ pending: PendingImport, replacing: Bool) {
        systemExtensionManager.importMutes(pending.imported, replacing: replacing) { reply in
            os_log("Imported %{public}@: %{public}@", pending.fileName, reply?.status.rawValue ?? "no reply")
        }
    }
    
    /// Ask for a place, then write the saved set as the Security Extension has it right now.
    private func exportSavedSet() {
        guard let url = showMuteSavePanel(title: "Export saved mute set", name: "mutes.json") else { return }
        systemExtensionManager.requestMutes(MuteRequest(.list)) { reply in
            guard let reply else {
                fileError = "The Security Extension didn't send the saved mute set."
                return
            }
            write(MuteFile(mutes: reply.mutes).encoded(), to: url)
        }
    }
    
    /// Ask for a place, then write some bytes there.
    ///
    /// - Parameters:
    ///   - data: The bytes.
    ///   - title: The save panel's title.
    private func write(_ data: Data, title: String) {
        guard let url = showMuteSavePanel(title: title, name: "apple-mutes.json") else { return }
        write(data, to: url)
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
