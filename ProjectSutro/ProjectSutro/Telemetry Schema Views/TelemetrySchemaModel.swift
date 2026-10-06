//
//  TelemetrySchemaModel.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI
import AppKit
import UniformTypeIdentifiers
import os
import SutroESFramework


// MARK: - Telemetry schema window
/// What Help > Telemetry Schema… shows and does: the telemetry schema the framework bundles, to copy or save, and
/// traces checked against it in the background.
///
/// One trace is checked at a time: checking another, Cancel, Done, or closing the window stops the one that's running,
/// and its report is dropped. Main thread only.
final class TelemetrySchemaModel: ObservableObject {
    /// Checking one trace, from choosing it until its report is dismissed.
    struct TraceCheck {
        /// Where checking has got.
        enum State {
            /// Reading the trace: bytes read, of the file's size.
            case running(read: Int64, total: Int64)
            /// Checked to the end, or stopped: the report.
            case finished(TelemetryValidation)
            /// The trace couldn't be read: why.
            case failed(Error)
        }
        
        /// The trace.
        let url: URL
        /// Which of its keys are checked.
        let mode: TelemetryValidator.Mode
        /// Where checking has got.
        var state: State
    }
    
    /// The most issues a report keeps; every issue is still counted.
    static let issueLimit = 100
    /// How the window checks only eslogger's keys, which a report's hint for eslogger's own JSON ends with.
    static let esloggerAdvice = "Check eslogger's Fields checks only the keys eslogger writes."
    
    /// The schema as the framework bundles it, or why it couldn't be read.
    let schema: Swift.Result<Data, Error>
    /// The schema's text, empty if it couldn't be read.
    let schemaText: String
    /// The trace being checked, or whose report is showing; `nil` when neither is.
    @Published private(set) var check: TraceCheck?
    
    /// Stops the check that's running: read by the validator before each record.
    private var cancelled: OSAllocatedUnfairLock<Bool>?
    /// Checks started: progress and reports from a check that's since been stopped are dropped.
    private var runs = 0
    
    /// - Parameter schema: The schema, or why it couldn't be read: by default, the framework's.
    init(schema: Swift.Result<Data, Error> = Swift.Result { try TelemetrySchema.data() }) {
        self.schema = schema
        schemaText = (try? schema.get()).map { String(decoding: $0, as: UTF8.self) } ?? ""
    }
    
    /// Stop a check that's still running when the window closes.
    deinit { cancelled?.withLock { $0 = true } }
    
    // MARK: Schema
    
    /// Copy: put the schema's text on the pasteboard.
    func copySchema() {
        guard !schemaText.isEmpty else { return }
        Self.copy(schemaText)
    }
    
    /// Save Schema…: write the schema, byte for byte, where the user chooses.
    func saveSchema() {
        guard case .success(let data) = schema else { return }
        Self.save(data, title: "Save Telemetry Schema", name: TelemetrySchema.fileName, type: .json)
    }
    
    // MARK: Checking traces
    
    /// Validate Trace…: choose a trace and check it.
    func chooseTrace() {
        let panel = NSOpenPanel()
        panel.title = "Validate Trace"
        panel.message = "Choose a Mac Monitor export to check against the telemetry schema."
        panel.prompt = "Validate"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        validate(url)
    }
    
    /// Check a trace against the schema in the background, stopping any check that's running. Progress and the report
    /// arrive in ``check``.
    ///
    /// - Parameters:
    ///   - url: The trace.
    ///   - mode: Which of its keys are checked: every key, or only eslogger's.
    func validate(_ url: URL, mode: TelemetryValidator.Mode = .macMonitor) {
        stop()
        guard case .success(let data) = schema else { return }
        let cancelled = OSAllocatedUnfairLock(initialState: false)
        let run = runs
        self.cancelled = cancelled
        check = TraceCheck(url: url, mode: mode, state: .running(read: 0, total: 0))
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            /// How far reading has got, after each batch of records.
            let progress = { (read: Int64, total: Int64) in
                DispatchQueue.main.async { self?.update(run, .running(read: read, total: total)) }
            }
            let state: TraceCheck.State
            do {
                let validator = try TelemetryValidator(schema: data, mode: mode)
                state = .finished(try validator.validate(traceAt: url, keepingIssues: Self.issueLimit,
                                                         isCancelled: { cancelled.withLock { $0 } },
                                                         progress: progress))
            } catch {
                state = .failed(error)
            }
            DispatchQueue.main.async { self?.update(run, state) }
        }
    }
    
    /// Check the trace whose report is showing again, checking only its eslogger keys: for eslogger's own JSON.
    func validateESLoggerFields() {
        guard let check else { return }
        validate(check.url, mode: .eslogger)
    }
    
    /// Cancel or Done: stop the check that's running, if one is, and close its sheet.
    func close() {
        stop()
        check = nil
    }
    
    /// Record where the current check has got; a stopped check's are dropped.
    ///
    /// - Parameters:
    ///   - run: The check's number.
    ///   - state: Where it has got.
    private func update(_ run: Int, _ state: TraceCheck.State) {
        guard run == runs, check != nil else { return }
        check?.state = state
        if case .running = state { return }
        cancelled = nil
    }
    
    /// Stop the check that's running, so nothing more arrives from it.
    private func stop() {
        cancelled?.withLock { $0 = true }
        cancelled = nil
        runs += 1
    }
    
    // MARK: Reports
    
    /// The text of the report showing: its summary, hint, kinds of issue and issues, with the hint the sheet shows.
    private var reportText: String? {
        guard let check, case .finished(let report) = check.state else { return nil }
        return report.report(fileName: check.url.lastPathComponent, esloggerAdvice: Self.esloggerAdvice)
    }
    
    /// Copy Report: put the report's text on the pasteboard.
    func copyReport() {
        guard let reportText else { return }
        Self.copy(reportText)
    }
    
    /// Save Report…: write the report's text where the user chooses, named after the trace.
    func saveReport() {
        guard let reportText, let url = check?.url else { return }
        let name = url.deletingPathExtension().lastPathComponent + " validation.txt"
        Self.save(Data(reportText.utf8), title: "Save Validation Report", name: name, type: .plainText)
    }
    
    // MARK: Pasteboard and files
    
    /// Put text on the general pasteboard.
    ///
    /// - Parameter text: The text.
    private static func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
    
    /// Ask where to save a file, and write it there. A failure is shown in an alert.
    ///
    /// - Parameters:
    ///   - data: The file's contents.
    ///   - title: The save panel's title.
    ///   - name: The file's suggested name.
    ///   - type: The file's type.
    private static func save(_ data: Data, title: String, name: String, type: UTType) {
        let panel = NSSavePanel()
        panel.title = title
        panel.nameFieldStringValue = name
        panel.allowedContentTypes = [type]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try data.write(to: url, options: .atomic)
        } catch {
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Mac Monitor can't save “\(url.lastPathComponent)”."
            alert.informativeText = error.localizedDescription
            alert.runModal()
        }
    }
}
