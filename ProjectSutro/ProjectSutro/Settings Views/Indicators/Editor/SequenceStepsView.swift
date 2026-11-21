//
//  SequenceStepsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/15/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Sequence steps
/// A sequence indicator's rule in the editor, to read but not change: its order, window and keys, then each step's
/// name, predicate and joins. Sequences are written in the indicators repository and ship in a pack.
struct SequenceStepsView: View {
    let sequence: IndicatorSequence

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(summary).font(.callout).foregroundStyle(.secondary)
            ForEach(Array(sequence.steps.enumerated()), id: \.offset) { index, step in
                VStack(alignment: .leading, spacing: 3) {
                    Text("\(index + 1). \(step.name)").font(.callout.weight(.semibold))
                    Text(step.predicate).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                    ForEach(step.join, id: \.self) { join in
                        Text("\(join.field) == \(join.step).\(join.stepField)")
                            .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }

    /// Its order, window and keys in a sentence, such as "In order, within 5 seconds."
    private var summary: String {
        let order = sequence.order == .ordered ? "In order" : "In any order"
        let count = sequence.atLeast < sequence.steps.count
            ? ", at least \(sequence.atLeast) of \(sequence.steps.count) steps" : ""
        let keys = sequence.by.isEmpty ? "" : ", sharing \(sequence.by.joined(separator: ", "))"
        return "\(order)\(count), within \(Duration.seconds(sequence.within).formatted(.units(width: .wide)))\(keys)."
    }
}
