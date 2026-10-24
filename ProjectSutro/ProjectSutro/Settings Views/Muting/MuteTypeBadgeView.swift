//
//  MuteTypeBadgeView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 9/10/25.
//

import SwiftUI
import SutroESFramework


// MARK: - Mute kinds
/// How a mute matches its path: Endpoint Security's four `es_mute_path_type_t` values, in the order their names sort,
/// which is the order Path Muting lists them in.
enum MuteKind: String, CaseIterable, Identifiable {
    case literal = "ES_MUTE_PATH_TYPE_LITERAL"
    case prefix = "ES_MUTE_PATH_TYPE_PREFIX"
    case targetLiteral = "ES_MUTE_PATH_TYPE_TARGET_LITERAL"
    case targetPrefix = "ES_MUTE_PATH_TYPE_TARGET_PREFIX"

    var id: String { rawValue }

    /// The kind a saved mute's type name names, if any.
    ///
    /// - Parameter type: The `ES_MUTE_PATH_TYPE_*` name.
    init?(type: String) {
        self.init(rawValue: type)
    }

    /// The kind for what a mute matches, and how.
    ///
    /// - Parameters:
    ///   - target: The target path, or the process's.
    ///   - prefix: Anything under the path, or the path exactly.
    init(target: Bool, prefix: Bool) {
        switch (target, prefix) {
        case (false, false): self = .literal
        case (false, true): self = .prefix
        case (true, false): self = .targetLiteral
        case (true, true): self = .targetPrefix
        }
    }

    /// Its name in Path Muting.
    var title: String {
        switch self {
        case .literal: return "Initiating literal"
        case .prefix: return "Initiating prefix"
        case .targetLiteral: return "Target literal"
        case .targetPrefix: return "Target prefix"
        }
    }

    /// What it matches, in Endpoint Security's words.
    var detail: String {
        switch self {
        case .literal: return "Initiating executable path literal"
        case .prefix: return "Initiating executable path prefix"
        case .targetLiteral: return "Target path literal"
        case .targetPrefix: return "Target path prefix"
        }
    }

    /// The order the Add sheet offers them in: the initiating process's, then the target's, prefix first.
    static let offered: [MuteKind] = [.prefix, .literal, .targetPrefix, .targetLiteral]

    /// Does it match the event's target, rather than the process that caused it?
    var isTarget: Bool { self == .targetLiteral || self == .targetPrefix }

    /// Does it match anything under its path, rather than the path exactly?
    var isPrefix: Bool { self == .prefix || self == .targetPrefix }

    /// Its color: orange, red, blue, or green.
    var color: Color {
        switch self {
        case .literal: return .orange
        case .prefix: return .red
        case .targetLiteral: return .blue
        case .targetPrefix: return .green
        }
    }

    /// Endpoint Security's value for it.
    var esType: es_mute_path_type_t {
        switch self {
        case .literal: return ES_MUTE_PATH_TYPE_LITERAL
        case .prefix: return ES_MUTE_PATH_TYPE_PREFIX
        case .targetLiteral: return ES_MUTE_PATH_TYPE_TARGET_LITERAL
        case .targetPrefix: return ES_MUTE_PATH_TYPE_TARGET_PREFIX
        }
    }
}


// MARK: - Badge
/// A mute kind's badge: its name on a soft tint of its color, as Finder draws tags, so it reads in light and dark.
struct MuteTypeBadgeView: View {
    let kind: MuteKind?

    /// - Parameter path: A saved mute.
    init(path: ESMutedPath) {
        kind = MuteKind(type: path.type)
    }

    /// - Parameter kind: The kind.
    init(kind: MuteKind) {
        self.kind = kind
    }

    var body: some View {
        Text(kind?.title ?? "Unknown")
            .font(.caption.weight(.semibold))
            .foregroundStyle(kind?.color ?? .secondary)
            .padding(.horizontal, 7)
            .padding(.vertical, 1)
            .background((kind?.color ?? .gray).opacity(0.15), in: RoundedRectangle(cornerRadius: 5, style: .continuous))
    }
}
