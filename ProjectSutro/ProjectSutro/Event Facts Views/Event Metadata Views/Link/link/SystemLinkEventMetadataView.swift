//
//  SystemLinkEventMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/3/23.
//

import SwiftUI
import SutroESFramework

/// What a `link` event says: the file linked, and the new link to it.
struct SystemLinkEventMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.link {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    if let srcPath = event.source.path {
                        FactRow(name: "Source file path", value: srcPath, stacked: true, style: .monospaced)
                    }
                    if let tgtPath = esSystemEvent.target_path {
                        FactRow(name: "Destination file path", value: tgtPath, stacked: true, style: .monospaced)
                    }

                    Divider()

                    HStack {
                        VStack(alignment: .leading) {
                            Text("\u{2022} Source file name:")
                                .bold()
                                .padding([.leading], 5.0)
                            GroupBox {
                                Text(event.source.name)
                                    .monospaced()
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                        Image(systemName: "arrow.right")
                        VStack(alignment: .leading) {
                            Text("\u{2022} Destination file name:")
                                .bold()
                                .padding([.leading], 5.0)
                            GroupBox {
                                Text(event.target_filename)
                                    .monospaced()
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
    }
}
