//
//  TraceImport+Extensions.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - New paths
extension Message {
    /// Repair what older exports wrote wrong in a create or rename event's new path.
    ///
    /// - Exports from 2.0.0 to 2.1.0 wrote ``ESNewPath``'s `dir` only when it was already loaded, which it rarely was,
    ///   so an imported event's directory would be empty: it's restored from the event's full destination path (its
    ///   path and name are what the create event's Event Facts show; its `stat` is lost).
    /// - Exports from 2.0.0 to 2.1.0 wrote a rename's new path with `mode` 0, which a rename doesn't have (only a
    ///   create's new path does): it's dropped, as eslogger has none.
    mutating func repairNewPath() {
        /// `full` less `file`, and the "/" (or "\/", as `target_path` writes it) before it.
        func directory(of full: String?, file: String) -> String? {
            guard let full, !file.isEmpty, full.hasSuffix(file) else { return nil }
            var directory = full.dropLast(file.count)
            guard directory.popLast() == "/" else { return nil }
            if directory.last == "\\" { directory.removeLast() }
            return String(directory)
        }
        switch event {
        case .create(var create):
            guard case .new_path(var path) = create.destination, path.dir.path.isEmpty,
                  let directory = directory(of: target_path, file: path.filename) else { return }
            path.dir.path = directory
            create.destination = .new_path(path)
            event = .create(create)
        case .rename(var rename):
            guard case .new_path(var path) = rename.destination else { return }
            path.mode = nil
            if path.dir.path.isEmpty, let directory = directory(of: rename.destination_path, file: path.filename) {
                path.dir.path = directory
            }
            rename.destination = .new_path(path)
            event = .rename(rename)
        default:
            return
        }
    }
}


// MARK: - Decoding and range helpers
extension DecodingError {
    /// Where and why decoding failed.
    var context: Context? {
        switch self {
        case .typeMismatch(_, let context), .valueNotFound(_, let context), .keyNotFound(_, let context), .dataCorrupted(let context): context
        @unknown default: nil
        }
    }
}


extension ClosedRange {
    /// The smallest range holding this one and `other`.
    ///
    /// - Parameter other: Another range.
    /// - Returns: The union of the two, with any gap between them.
    func including(_ other: ClosedRange) -> ClosedRange {
        Swift.min(lowerBound, other.lowerBound)...Swift.max(upperBound, other.upperBound)
    }
}
