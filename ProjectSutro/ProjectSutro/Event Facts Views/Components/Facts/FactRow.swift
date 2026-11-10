//
//  FactRow.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/4/26.
//

import SwiftUI


// MARK: - Fact row
/// One fact in Event Facts: a bulleted name, and its value as code in a box, beside it or, for a long value such as a
/// path, below it.
struct FactRow: View {
    /// How a fact's value is drawn.
    enum Style {
        /// A Markdown code span, in a box as wide as the facts.
        case code
        /// Monospaced text, in a box as wide as the value (or as the facts, when stacked), with the name indented: the
        /// look of most Event Facts views.
        case monospaced
    }
    
    /// The fact's name, without a colon.
    let name: String
    /// The value, or `nil` for "Unknown".
    let value: String?
    /// Show the value below the name rather than beside it.
    var stacked = false
    /// How the value is drawn.
    var style = Style.code
    
    var body: some View {
        let layout = stacked ? AnyLayout(VStackLayout(alignment: .leading)) : AnyLayout(HStackLayout())
        layout {
            switch style {
            case .code:
                Text("\u{2022} **\(name):**")
                GroupBox {
                    Text("`\(value ?? "Unknown")`")
                        .lineLimit(nil)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            case .monospaced:
                Text("\u{2022} \(name):")
                    .bold()
                    .padding([.leading], 5.0)
                GroupBox {
                    Text(value ?? "Unknown")
                        .monospaced()
                        .frame(maxWidth: stacked ? .infinity : nil, alignment: .leading)
                }
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
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
