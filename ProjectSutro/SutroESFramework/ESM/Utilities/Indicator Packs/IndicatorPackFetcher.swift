//
//  IndicatorPackFetcher.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/16/26.
//

import Foundation
import os


// MARK: - Fetching
/// Gets what the Security Extension reads from GitHub to find and download an indicator pack (Security Extension
/// context): the real thing over HTTPS (``IndicatorPackFetcher``), or a test's.
public protocol IndicatorPackFetching: AnyObject {
    /// Get a URL's contents.
    ///
    /// - Parameters:
    ///   - url: The URL, which is HTTPS.
    ///   - limit: The most bytes to read. A longer answer fails with ``IndicatorPackFetchError/tooLarge``.
    ///   - completion: Called once, on any queue, with the bytes and the HTTP status, or why there are none.
    func fetch(_ url: URL, limit: Int,
               completion: @escaping (Result<(data: Data, status: Int?), IndicatorPackFetchError>) -> Void)
}


// MARK: - Fetching over HTTPS
/// Gets a URL's contents over HTTPS, never reading more than it's allowed, with no cookies, cache or credentials
/// kept. A redirect is followed only to another HTTPS URL, as a release's download redirects to GitHub's storage.
public final class IndicatorPackFetcher: NSObject, IndicatorPackFetching, URLSessionDataDelegate {
    /// One fetch under way.
    private struct Fetch {
        /// The most bytes to read.
        let limit: Int
        /// What's been read.
        var data = Data()
        /// Called once with the outcome.
        let completion: (Result<(data: Data, status: Int?), IndicatorPackFetchError>) -> Void
    }

    /// The fetches under way, by their task's identifier.
    private let fetches = OSAllocatedUnfairLock(initialState: [Int: Fetch]())
    /// URL loading protocols tried before the system's: none, unless a test passes its own.
    private let protocols: [AnyClass]
    /// Made on first use, with this object as its delegate.
    private lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = protocols + (configuration.protocolClasses ?? [])
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 120
        configuration.httpShouldSetCookies = false
        return URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    }()

    /// - Parameter protocols: URL loading protocols to try before the system's. A test passes one that answers in
    ///   GitHub's place.
    public init(protocols: [AnyClass] = []) {
        self.protocols = protocols
    }

    /// Get a URL's contents.
    ///
    /// - Parameters:
    ///   - url: The URL. Anything but HTTPS fails without a request.
    ///   - limit: The most bytes to read.
    ///   - completion: Called once, on any queue, with the bytes and the HTTP status, or why there are none.
    public func fetch(_ url: URL, limit: Int,
                      completion: @escaping (Result<(data: Data, status: Int?), IndicatorPackFetchError>) -> Void) {
        guard url.scheme == "https" else {
            return completion(.failure(.unreachable("Only HTTPS is used, not \(url.scheme ?? "no scheme").")))
        }
        var request = URLRequest(url: url)
        request.setValue("application/vnd.github+json, application/octet-stream", forHTTPHeaderField: "Accept")
        let task = session.dataTask(with: request)
        fetches.withLock { $0[task.taskIdentifier] = Fetch(limit: limit, completion: completion) }
        task.resume()
    }

    /// End a fetch with its outcome, once.
    ///
    /// - Parameters:
    ///   - task: The fetch's task.
    ///   - outcome: Makes the outcome from what was read.
    private func finish(_ task: URLSessionTask,
                        _ outcome: (Data) -> Result<(data: Data, status: Int?), IndicatorPackFetchError>) {
        guard let fetch = fetches.withLock({ $0.removeValue(forKey: task.taskIdentifier) }) else { return }
        fetch.completion(outcome(fetch.data))
    }

    /// Keep what arrived, and stop a fetch that's past its limit.
    public func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        let isPastLimit = fetches.withLock { fetches -> Bool in
            guard var fetch = fetches[dataTask.taskIdentifier] else { return false }
            fetch.data.append(data)
            fetches[dataTask.taskIdentifier] = fetch
            return fetch.data.count > fetch.limit
        }
        guard isPastLimit else { return }
        finish(dataTask) { _ in .failure(.tooLarge) }
        dataTask.cancel()
    }

    /// Follow a redirect only to HTTPS.
    public func urlSession(_ session: URLSession, task: URLSessionTask,
                           willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                           completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(request.url?.scheme == "https" ? request : nil)
    }

    /// Hand over what was read, or why nothing was.
    public func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        finish(task) { data in
            if let error { return .failure(.unreachable(error.localizedDescription)) }
            return .success((data, (task.response as? HTTPURLResponse)?.statusCode))
        }
    }
}
