//
//  ReleaseNotesSheet.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/23/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Release notes
/// The notes GitHub has for this version of Mac Monitor, or for the latest release when this version has none.
@MainActor
final class ReleaseNotes: ObservableObject {
    /// One release, as GitHub's API describes it.
    struct Release: Decodable {
        let name: String?
        let tag: String
        let body: String?
        let page: URL
        let published: Date?

        enum CodingKeys: String, CodingKey {
            case name, body
            case tag = "tag_name"
            case page = "html_url"
            case published = "published_at"
        }
    }

    /// Where the releases are.
    static let releasesPage = URL(string: "https://github.com/Brandon7CC/mac-monitor/releases")!
    /// GitHub's API for them.
    private static let api = "https://api.github.com/repos/Brandon7CC/mac-monitor/releases/"

    /// This copy's version, such as "3.0.0".
    static var version: String { Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "" }
    /// This copy's build, such as "1".
    static var build: String { Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "" }

    @Published private(set) var release: Release?
    @Published private(set) var failure: String?
    @Published private(set) var isLoading = false

    /// Fetch this version's release, then the latest if this version wasn't released on GitHub.
    func load() {
        guard release == nil, !isLoading else { return }
        isLoading = true
        failure = nil
        Task {
            defer { isLoading = false }
            do {
                if let tagged = try await Self.fetch("tags/v\(Self.version)") {
                    release = tagged
                } else {
                    release = try await Self.fetch("latest")
                }
                if release == nil { failure = "GitHub has no release notes for Mac Monitor yet." }
            } catch {
                failure = "Release notes couldn't be loaded. \(error.localizedDescription)"
            }
        }
    }

    /// One release from GitHub's API.
    ///
    /// - Parameter path: The API path under the repository's releases, such as `latest`.
    /// - Returns: The release, or `nil` when GitHub has none there.
    private static func fetch(_ path: String) async throws -> Release? {
        var request = URLRequest(url: URL(string: api + path)!, timeoutInterval: 15)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(Release.self, from: data)
    }
}


/// Settings ▸ General ▸ Release Notes…: a release's notes as GitHub shows them, with a link to its page.
struct ReleaseNotesSheet: View {
    @ObservedObject var notes: ReleaseNotes
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.title3.bold())
                if let release = notes.release {
                    Text("From GitHub" + (release.published.map { " · " + $0.formatted(date: .long, time: .omitted) }
                                          ?? ""))
                        .foregroundStyle(.secondary)
                }
            }
            Group {
                if let release = notes.release {
                    ScrollView {
                        Text(Self.markdown(release.body ?? "No notes."))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                } else if let failure = notes.failure {
                    VStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle").font(.largeTitle).foregroundStyle(.secondary)
                        Text(failure).foregroundStyle(.secondary).multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .frame(minHeight: 260, maxHeight: 420)
            HStack {
                Link("View on GitHub", destination: notes.release?.page ?? ReleaseNotes.releasesPage)
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 540)
        .onAppear { notes.load() }
    }

    /// The release's name, or what's being loaded.
    private var title: String {
        guard let release = notes.release else { return "What's New in Mac Monitor \(ReleaseNotes.version)" }
        return release.name.nonEmpty ?? "Mac Monitor \(release.tag)"
    }

    /// GitHub's Markdown, with its line breaks kept.
    ///
    /// - Parameter text: The release's body.
    /// - Returns: The text to show.
    private static func markdown(_ text: String) -> AttributedString {
        let options = AttributedString.MarkdownParsingOptions(interpretedSyntax: .inlineOnlyPreservingWhitespace)
        return (try? AttributedString(markdown: text, options: options)) ?? AttributedString(text)
    }
}
