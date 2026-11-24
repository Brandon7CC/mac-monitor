//
//  FactRow.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/4/26.
//

import SwiftUI


// MARK: - Fact
/// One fact in Event Facts: its name, bulleted or beside a symbol, and its value monospaced in a box. Several in a
/// ``FactRow`` share a line.
struct Fact: View {
    /// The fact's name, without a colon.
    let name: String
    /// The value, or `nil` for "Unknown".
    let value: String?
    /// The SF Symbol before the name, or `nil` for a bullet.
    let systemImage: String?
    /// Is the value's box as wide as the facts, rather than as the value?
    let fillsWidth: Bool

    /// - Parameters:
    ///   - name: The fact's name, without a colon.
    ///   - value: The value, or `nil` for "Unknown".
    ///   - systemImage: The SF Symbol before the name, or `nil` for a bullet.
    ///   - fillsWidth: Is the value's box as wide as the facts, rather than as the value?
    init(_ name: String, _ value: String?, systemImage: String? = nil, fillsWidth: Bool = false) {
        self.name = name
        self.value = value
        self.systemImage = systemImage
        self.fillsWidth = fillsWidth
    }

    var body: some View {
        if let systemImage {
            Label("**\(name):**", systemImage: systemImage)
        } else {
            Text("\u{2022} **\(name):**")
        }
        FactValue(value, fillsWidth: fillsWidth)
    }
}


// MARK: - Fact value
/// A fact's value alone, for a line that draws its own name: monospaced, in a box as wide as the value. A long value,
/// such as a command line, can take a box as wide as the facts instead.
struct FactValue: View {
    /// The value, or `nil` for "Unknown".
    let value: String?
    /// Is the box as wide as the facts, rather than as the value?
    let fillsWidth: Bool

    /// - Parameters:
    ///   - value: The value, or `nil` for "Unknown".
    ///   - fillsWidth: Is the box as wide as the facts, rather than as the value?
    init(_ value: String?, fillsWidth: Bool = false) {
        self.value = value
        self.fillsWidth = fillsWidth
    }

    var body: some View {
        GroupBox {
            Text(value ?? "Unknown")
                .monospaced()
                .lineLimit(nil)
                .frame(maxWidth: fillsWidth ? .infinity : nil, alignment: .leading)
        }
    }
}


// MARK: - Fact row
/// A line of Event Facts: its facts side by side from the leading edge, or, stacked, one below another, as a long
/// value such as a command line sits below its name in a box as wide as the facts.
struct FactRow<Facts: View>: View {
    /// Show the facts below one another rather than side by side.
    var stacked = false
    /// The facts: ``Fact``s, mostly.
    @ViewBuilder let facts: () -> Facts

    var body: some View {
        let layout = stacked ? AnyLayout(VStackLayout(alignment: .leading)) : AnyLayout(HStackLayout())
        layout(facts).frame(maxWidth: .infinity, alignment: .leading)
    }
}

extension FactRow where Facts == Fact {
    /// A line with one fact.
    ///
    /// - Parameters:
    ///   - name: The fact's name, without a colon.
    ///   - value: The value, or `nil` for "Unknown".
    ///   - stacked: Show the value below the name, in a box as wide as the facts: for a long value.
    init(name: String, value: String?, stacked: Bool = false) {
        self.init(stacked: stacked) { Fact(name, value, fillsWidth: stacked) }
    }
}


// MARK: - Facts grid
/// Rows of facts under column headers, for a table in Event Facts. The facts already scroll as a whole, and a SwiftUI
/// `Table` scrolls on its own, a second scroll inside them: a grid instead takes the height its rows need.
struct FactsGrid<Row, ID: Hashable>: View {
    /// A column: its header, and each row's value in it.
    struct Column {
        /// The header.
        let title: String
        /// Show the values monospaced, as code is?
        var monospaced = true
        /// A row's value.
        let value: (Row) -> String

        /// - Parameters:
        ///   - title: The header.
        ///   - monospaced: Show the values monospaced, as code is?
        ///   - value: A row's value.
        init(_ title: String, monospaced: Bool = true, value: @escaping (Row) -> String) {
            self.title = title
            self.monospaced = monospaced
            self.value = value
        }
    }

    /// The rows.
    let rows: [Row]
    /// A row's identity.
    let id: KeyPath<Row, ID>
    /// The columns, in order.
    let columns: [Column]

    /// - Parameters:
    ///   - rows: The rows.
    ///   - id: A row's identity.
    ///   - columns: The columns, in order.
    init(_ rows: [Row], id: KeyPath<Row, ID>, columns: Column...) {
        self.rows = rows
        self.id = id
        self.columns = columns
    }

    var body: some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 18, verticalSpacing: 6) {
            GridRow {
                ForEach(columns.indices, id: \.self) { index in
                    Text(columns[index].title).bold()
                }
            }
            ForEach(rows, id: id) { row in
                Divider()
                GridRow {
                    ForEach(columns.indices, id: \.self) { index in
                        cell(columns[index], row)
                    }
                }
            }
        }
        .padding(4)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// A row's value in a column, or a dash when it has none: an empty cell has no baseline to align its row by.
    ///
    /// - Parameters:
    ///   - column: The column.
    ///   - row: The row.
    /// - Returns: The cell.
    @ViewBuilder
    private func cell(_ column: Column, _ row: Row) -> some View {
        let value = column.value(row)
        if value.isEmpty {
            Text("\u{2014}").foregroundStyle(.secondary)
        } else {
            Text(value)
                .monospaced(column.monospaced)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

extension FactsGrid where Row: Identifiable, ID == Row.ID {
    /// - Parameters:
    ///   - rows: The rows, each its own identity.
    ///   - columns: The columns, in order.
    init(_ rows: [Row], columns: Column...) {
        self.rows = rows
        self.id = \.id
        self.columns = columns
    }
}
