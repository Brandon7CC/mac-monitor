//
//  TraceValidationSheet.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Checking a trace
/// The Telemetry Schema window's sheet for a trace being checked: its progress and Cancel while it runs, then its
/// report (the summary, a hint, and the issues found) to copy or save.
struct TraceValidationSheet: View {
    /// The trace's check.
    @ObservedObject var model: TelemetrySchemaModel
    
    /// The check's progress, report, or failure.
    var body: some View {
        if let check = model.check {
            switch check.state {
            case .running(let read, let total):
                running(check.url, read: read, total: total)
            case .finished(let report):
                finished(check.url, report)
            case .failed(let error):
                failed(check.url, error)
            }
        }
    }
    
    /// The trace being read: how far by bytes, and Cancel.
    ///
    /// - Parameters:
    ///   - url: The trace.
    ///   - read: The bytes read so far.
    ///   - total: The file's size.
    /// - Returns: The progress.
    private func running(_ url: URL, read: Int64, total: Int64) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Checking “\(url.lastPathComponent)”…")
                .font(.headline)
            ProgressView(value: total > 0 ? min(Double(read) / Double(total), 1) : 0)
            HStack {
                Text(total > 0 ? "\(Self.bytes(read)) of \(Self.bytes(total))" : "Reading…")
                    .monospacedDigit()
                    .foregroundColor(.secondary)
                Spacer()
                Button("Cancel") { model.close() }
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(20)
        .frame(width: 460)
    }
    
    /// The report: what was found, a hint, and the issues kept.
    ///
    /// - Parameters:
    ///   - url: The trace.
    ///   - report: The report.
    /// - Returns: The report's view.
    private func finished(_ url: URL, _ report: TelemetryValidation) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Self.heading(url, report)
            if !report.details.isEmpty {
                ReadOnlyTextView(text: report.details)
                    .frame(minHeight: 260)
                    .border(Color(nsColor: .separatorColor))
            }
            HStack {
                if report.looksLikeESLogger {
                    Button("Check eslogger's Fields") { model.validateESLoggerFields() }
                        .help("Check only the keys eslogger writes, as eslogger's own JSON")
                }
                Spacer()
                Button("Copy Report") { model.copyReport() }
                Button("Save Report…") { model.saveReport() }
                Button("Done") { model.close() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 680)
    }
    
    /// The trace couldn't be read.
    ///
    /// - Parameters:
    ///   - url: The trace.
    ///   - error: Why.
    /// - Returns: The explanation, and Done.
    private func failed(_ url: URL, _ error: Error) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Label {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Mac Monitor can't check “\(url.lastPathComponent)”.")
                        .font(.headline)
                    Text(error.localizedDescription)
                        .foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.yellow)
                    .font(.title)
            }
            HStack {
                Spacer()
                Button("Done") { model.close() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 460)
    }
    
    /// The verdict (on eslogger's fields alone, for eslogger's JSON), the report's summary line, and its hint.
    ///
    /// - Parameters:
    ///   - url: The trace.
    ///   - report: The report.
    /// - Returns: The heading.
    private static func heading(_ url: URL, _ report: TelemetryValidation) -> some View {
        let name = url.lastPathComponent
        let verdict = switch (report.mode, report.isValid) {
        case (.macMonitor, true): "“\(name)” follows the telemetry schema."
        case (.macMonitor, false): "“\(name)” doesn't follow the telemetry schema."
        case (.eslogger, true): "eslogger's fields in “\(name)” follow the telemetry schema."
        case (.eslogger, false): "eslogger's fields in “\(name)” don't follow the telemetry schema."
        }
        /// eslogger's own JSON gets the Check eslogger's Fields button, which its hint names.
        let hint = report.hint(esloggerAdvice: TelemetrySchemaModel.esloggerAdvice)
        return Label {
            VStack(alignment: .leading, spacing: 4) {
                Text(verdict)
                    .font(.headline)
                Text(report.summary(fileName: name))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                if let hint {
                    Text(hint)
                        .foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        } icon: {
            Image(systemName: report.isValid ? "checkmark.seal.fill" : "xmark.octagon.fill")
                .foregroundColor(report.isValid ? .green : .red)
                .font(.title)
        }
    }
    
    /// A number of bytes as a file size.
    ///
    /// - Parameter count: A number of bytes.
    /// - Returns: The size, e.g. "12.3 MB".
    private static func bytes(_ count: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: count, countStyle: .file)
    }
}
