//
//  FakePackFetcher.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/16/26.
//

import XCTest
import os
@testable import SutroESFramework


// MARK: - GitHub in a test
/// Stands in for GitHub when a ``SavedIndicatorSet`` looks for a newer pack: it answers the releases' listing and
/// each release's download from what a test offers, counts what it's asked, and can hold its answers until told.
final class FakePackFetcher: IndicatorPackFetching {
    /// What a URL answers.
    typealias Answer = Result<(data: Data, status: Int?), IndicatorPackFetchError>

    private struct State {
        var answers: [URL: Answer] = [:]
        var asked: [URL] = []
        var holds = false
        var held: [() -> Void] = []
    }

    private let state = OSAllocatedUnfairLock(initialState: State())

    /// Every URL asked for, in order.
    var asked: [URL] {
        state.withLock { $0.asked }
    }

    /// How many times the releases' listing was asked for.
    var listings: Int {
        asked.filter { $0 == IndicatorPackRelease.releasesURL }.count
    }

    /// Where a release's pack is downloaded from.
    ///
    /// - Parameter tag: The release's tag.
    /// - Returns: The URL.
    static func download(of tag: String) -> URL {
        URL(string: "https://example.com/download/\(tag)/\(IndicatorPackRelease.assetName)")!
    }

    /// Offer releases, newest first as GitHub lists them, each with its pack to download.
    ///
    /// - Parameters:
    ///   - releases: Each release's tag and its pack's file.
    ///   - notes: What every release says of its pack, or `nil` for nothing.
    func offer(_ releases: [(tag: String, file: Data)], notes: String? = nil) {
        let listing = releases.map { release -> [String: Any] in
            ["tag_name": release.tag, "draft": false, "prerelease": false, "body": notes ?? "",
             "assets": [["name": IndicatorPackRelease.assetName,
                         "browser_download_url": Self.download(of: release.tag).absoluteString,
                         "size": release.file.count]]]
        }
        let data = (try? JSONSerialization.data(withJSONObject: listing)) ?? Data()
        state.withLock { state in
            state.answers[IndicatorPackRelease.releasesURL] = .success((data, 200))
            for release in releases { state.answers[Self.download(of: release.tag)] = .success((release.file, 200)) }
        }
    }

    /// Answer a URL some other way: a failure, another status, or other bytes.
    ///
    /// - Parameters:
    ///   - url: The URL.
    ///   - answer: What it answers.
    func answer(_ url: URL, with answer: Answer) {
        state.withLock { $0.answers[url] = answer }
    }

    /// Keep every answer until ``release()``, as a slow network does.
    func hold() {
        state.withLock { $0.holds = true }
    }

    /// Give every answer that was kept, and answer at once from now on.
    func release() {
        let held = state.withLock { state -> [() -> Void] in
            state.holds = false
            defer { state.held = [] }
            return state.held
        }
        for answer in held { answer() }
    }

    func fetch(_ url: URL, limit: Int, completion: @escaping (Answer) -> Void) {
        let answer = state.withLock { state -> (() -> Void)? in
            state.asked.append(url)
            var answer = state.answers[url] ?? .failure(.unreachable("No answer."))
            if case .success(let got) = answer, got.data.count > limit { answer = .failure(.tooLarge) }
            let give = { completion(answer) }
            guard state.holds else { return give }
            state.held.append(give)
            return nil
        }
        answer?()
    }
}


// MARK: - A clock a test sets
/// The time a ``SavedIndicatorSet`` thinks it is, which a test moves.
final class TestClock {
    private let time: OSAllocatedUnfairLock<Date>

    /// - Parameter now: The time it starts at.
    init(_ now: Date = XCTestCase.packClock) {
        time = OSAllocatedUnfairLock(initialState: now)
    }

    /// The time now.
    var now: Date {
        time.withLock { $0 }
    }

    /// Move the time on.
    ///
    /// - Parameter seconds: By how much.
    func advance(by seconds: TimeInterval) {
        time.withLock { $0 += seconds }
    }
}
