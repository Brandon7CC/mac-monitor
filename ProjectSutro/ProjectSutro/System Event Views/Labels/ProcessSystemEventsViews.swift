//
//  ProcessSystemEventsViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import SutroESFramework


/// An exec's process name in the Process Execution table. Its built-in marks come first (``Indicator/nameMarks``), then
/// the indicators that mark it (Settings > Indicators), then how it's signed (``ESProcess/seal``). A name that isn't
/// signed is bold. An indicator that colors its label (``Indicator/TableMarks/label``) colors the name and its seal,
/// as Adhoc signed and Unsigned do.
struct ProcessExecEventNameView: View {
    var message: ESMessage
    /// The name follows the indicators as Settings changes them.
    @ObservedObject private var store = IndicatorStore.shared

    /// Nothing for an exec that's gone, as a Clear's events are while the tables let go of them.
    var body: some View {
        if let exec = message.event.exec {
            let name = (exec.target.executable?.path ?? "").lastPathComponent
            HStack {
                BuiltInMarks(message: message, marks: Indicator.nameMarks)
                let seal = exec.target.seal
                IndicatorMarks(message: message, besides: Indicator.nameMarks, labelSymbol: seal.symbol)
                let look = EventLabelLook(signatureOf: exec.target)
                    .colored(by: store.marks(for: message).labelIndicator)
                if seal == .signed {
                    Label(name, systemImage: seal.symbol).eventLabelLook(look)
                } else {
                    Label("**\(name)**", systemImage: seal.symbol).eventLabelLook(look)
                }
            }
            .frame(alignment: .leading)
        }
    }
}
