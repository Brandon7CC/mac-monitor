//
//  FileScanTicket.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - A scan's answer, to come
/// Where a queued scan's answer comes, for the lane's hold to wait on. The scanner can answer before the hold asks,
/// or after, so whichever comes second runs the handler.
///
/// **Threading:** thread-safe. The handler runs on whichever thread comes second, never under the ticket's lock.
final class FileScanTicket: @unchecked Sendable {
    private let lock = NSLock()
    private var answer: YaraScan?
    private var handler: ((YaraScan) -> Void)?

    /// The scanner's answer. Only the first counts.
    ///
    /// - Parameter scan: The result.
    func deliver(_ scan: YaraScan) {
        lock.lock()
        guard answer == nil else { return lock.unlock() }
        answer = scan
        let waiting = handler
        handler = nil
        lock.unlock()
        waiting?(scan)
    }

    /// Run a handler with the answer, now if it's here, else when it comes.
    ///
    /// - Parameter handler: Receives the answer once.
    func whenAnswered(_ handler: @escaping (YaraScan) -> Void) {
        lock.lock()
        guard let answer else {
            self.handler = handler
            return lock.unlock()
        }
        lock.unlock()
        handler(answer)
    }
}
