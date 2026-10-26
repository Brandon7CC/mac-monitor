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
