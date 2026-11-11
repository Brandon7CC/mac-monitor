//
//  SystemBTMRemoveMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework


/// What a `btm_launch_item_remove` event says: the launch item removed, its bundle, the app that registered it, and
/// the process that instigated it.
struct SystemBTMRemoveMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.btm_launch_item_remove {
            EventFactsCard(message: esSystemEvent) {
                LaunchItemFacts(event: event)
            }
        }
    }
}

extension ESLaunchItemRemoveEvent: LaunchItemEventFacts {
    /// Always `nil`: a removal doesn't give the item's executable.
    var executablePath: String? { nil }
}
