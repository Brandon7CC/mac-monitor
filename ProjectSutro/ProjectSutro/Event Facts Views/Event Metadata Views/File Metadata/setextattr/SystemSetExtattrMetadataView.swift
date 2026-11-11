//
//  SystemSetExtattrMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/17/25.
//

import SwiftUI
import SutroESFramework


/// What a `setextattr` event says: the extended attribute set, and the file it's on.
struct SystemSetXattrMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.setextattr {
            EventFactsCard(message: esSystemEvent) {
                ExtendedAttributeFacts(attribute: event.extattr, file: event.target)
            }
        }
    }
}


// MARK: - Extended attribute facts
/// The facts the extended attribute events share: the attribute, when the event names one, and the file it's on.
struct ExtendedAttributeFacts: View {
    /// The extended attribute, or `nil` for an event that names none, as `listextattr` does.
    var attribute: String? = nil
    /// The file.
    let file: ESFile

    var body: some View {
        FactsBox {
            if let attribute {
                FactRow(name: "Extended attribute", value: attribute, style: .monospaced)
            }
            FactRow(name: "File name", value: file.name, style: .monospaced)
            if let path = file.path {
                FactRow(name: "File path", value: path, stacked: true, style: .monospaced)
            }
        }
    }
}
