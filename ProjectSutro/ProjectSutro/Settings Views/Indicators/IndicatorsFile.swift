//
//  IndicatorsFile.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/8/26.
//

import SwiftUI
import UniformTypeIdentifiers
import SutroESFramework


// MARK: - Indicators file
/// Indicators as a JSON file to share, for Settings > Indicators' Export and Import (``IndicatorExchange``).
struct IndicatorsFile: FileDocument {
    static let readableContentTypes: [UTType] = [.json]

    /// The indicators it holds, in order.
    let indicators: [Indicator]

    /// - Parameter indicators: The indicators to export.
    init(_ indicators: [Indicator]) {
        self.indicators = indicators
    }

    /// - Parameter configuration: The file to read.
    /// - Throws: ``IndicatorExchange/ImportError`` when it isn't a file of indicators.
    init(configuration: ReadConfiguration) throws {
        guard let data = configuration.file.regularFileContents else { throw CocoaError(.fileReadCorruptFile) }
        indicators = try IndicatorExchange.indicators(from: data)
    }

    /// - Parameter configuration: Where it's written.
    /// - Returns: The file.
    /// - Throws: The encoder's error.
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: try IndicatorExchange.data(of: indicators))
    }

    /// The file's name: the one indicator's, or "Indicators".
    var defaultName: String {
        indicators.count == 1 ? indicators[0].name : "Indicators"
    }
}


extension IndicatorStore {
    /// Add a file's indicators to the Mac's set: one with an identity already there replaces it, in its place, and
    /// the rest go at the end, in one request.
    ///
    /// - Parameters:
    ///   - imported: The file's indicators.
    ///   - completion: How many were added and how many replaced, or why the Security Extension refused them.
    func importIndicators(_ imported: [Indicator], completion: @escaping (Result<(added: Int, replaced: Int), Error>)
                            -> Void) {
        let merged = IndicatorExchange.merge(imported, into: engine.indicators)
        engine.add(imported) { reply in
            guard let reply, reply.status == .ok else {
                let reason = reply?.failure ?? IndicatorEngine.updateNotice
                return completion(.failure(IndicatorExchange.ImportError(message: reason)))
            }
            completion(.success((merged.added, merged.replaced)))
        }
    }
}


// MARK: - Import
extension IndicatorsSettingsView {
    /// Add the indicators of a file Import chose: a regular file of at most 4 MiB.
    ///
    /// - Parameters:
    ///   - result: The file, or why there's none.
    ///   - store: Where they're added.
    ///   - done: What the import did, or why it couldn't, for its alert.
    static func importFile(_ result: Result<URL, Error>, into store: IndicatorStore,
                           done: @escaping (_ title: String, _ message: String) -> Void) {
        let failed = { (error: Error) in done("Couldn't import the file", error.localizedDescription) }
        let indicators: [Indicator]
        do {
            let url = try result.get()
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            indicators = try IndicatorExchange.indicators(contentsOf: url)
        } catch {
            return failed(error)
        }
        store.importIndicators(indicators) { result in
            switch result {
            case .success(let (added, replaced)):
                let count = added + replaced
                done("Imported \(count) \(count == 1 ? "indicator" : "indicators")",
                     "\(added) added, \(replaced) replaced, for every user of this Mac. One the Security Extension "
                     + "can't run is marked, and never found until it's fixed.")
            case .failure(let error):
                failed(error)
            }
        }
    }
}
