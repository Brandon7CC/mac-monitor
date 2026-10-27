//
//  SymbolPicker.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/26/26.
//

import SwiftUI
import AppKit
import SutroESFramework


// MARK: - Symbol picker
/// A finding's symbol, as a button that opens a grid of SF Symbols to choose from. Its search field filters them by
/// name. Other… takes any symbol's name.
struct SymbolPicker: View {
    @Binding var finding: Finding
    @State private var isShowing = false
    @State private var query = ""
    /// The name typed under Other….
    @State private var other = ""

    var body: some View {
        Button { isShowing = true } label: {
            HStack(spacing: 6) {
                FindingSymbol(finding: finding).frame(width: 20)
                Text(finding.symbol).font(.body.monospaced()).lineLimit(1).truncationMode(.middle)
                Image(systemName: "chevron.down").font(.caption2).foregroundStyle(.secondary)
            }
        }
        .accessibilityLabel("Symbol, \(finding.symbol)")
        .popover(isPresented: $isShowing, arrowEdge: .bottom) { picker }
    }

    private var picker: some View {
        let words = query.lowercased().split(whereSeparator: \.isWhitespace)
        let shown = Self.names.filter { name in words.allSatisfy { name.contains($0) } }
        return VStack(alignment: .leading, spacing: 10) {
            TextField("Search", text: $query, prompt: Text("Search symbols")).textFieldStyle(.roundedBorder)
            ScrollView {
                LazyVGrid(columns: Array(repeating: GridItem(.fixed(32), spacing: 4), count: 9), spacing: 4) {
                    ForEach(shown, id: \.self) { name in
                        Button { choose(name) } label: {
                            Image(systemName: name).font(.title3).frame(width: 32, height: 32)
                                .background(name == finding.symbol ? Color.accentColor.opacity(0.25) : .clear,
                                            in: RoundedRectangle(cornerRadius: 6))
                        }
                        .buttonStyle(.plain).help(name).accessibilityLabel(name)
                    }
                }
            }
            .frame(height: 220)
            if shown.isEmpty { Text("No symbol matches.").foregroundStyle(.secondary) }
            Divider()
            HStack(spacing: 8) {
                TextField("Other…", text: $other, prompt: Text("Other symbol name")).textFieldStyle(.roundedBorder)
                    .font(.body.monospaced()).onSubmit { if Self.exists(other) { choose(other) } }
                Image(systemName: Self.exists(other) ? other : "questionmark.square.dashed").frame(width: 20)
                    .foregroundStyle(Self.exists(other) ? .primary : .secondary)
                Button("Use") { choose(other) }.disabled(!Self.exists(other))
            }
            if !other.isEmpty && !Self.exists(other) {
                Text("No SF Symbol has that name.").font(.caption).foregroundStyle(.red)
            }
        }
        .padding(12)
        .frame(width: 340)
    }

    /// - Parameter name: The symbol chosen, which closes the popover.
    private func choose(_ name: String) {
        finding.symbol = name.trimmingCharacters(in: .whitespaces)
        isShowing = false
    }

    /// - Parameter name: A symbol's name.
    /// - Returns: Is there an SF Symbol by that name on this Mac?
    static func exists(_ name: String) -> Bool {
        let name = name.trimmingCharacters(in: .whitespaces)
        return !name.isEmpty && NSImage(systemSymbolName: name, accessibilityDescription: nil) != nil
    }

    /// The symbols the grid offers: every SF Symbol on this Mac, in the SF Symbols app's order. There's no public way
    /// to list them, so this reads the list macOS keeps in CoreGlyphs. If it can't be read, the grid is empty and
    /// Other… still takes any name.
    static let names: [String] = {
        guard let url = Bundle(path: "/System/Library/CoreServices/CoreGlyphs.bundle")?
                .url(forResource: "symbol_order", withExtension: "plist"),
              let data = try? Data(contentsOf: url),
              let all = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String] else {
            return []
        }
        return all.filter { !localizedVariants.contains(String($0.split(separator: ".").last ?? "")) }
    }()

    /// The last component of a symbol's localized variants, such as `character.ar`. The grid offers the plain symbol.
    private static let localizedVariants: Set = ["ar", "bn", "el", "gu", "he", "hi", "ja", "kn", "ko", "ml", "mni",
                                                 "mr", "or", "pa", "ru", "sat", "si", "ta", "te", "th", "zh"]
}
