//
//  SystemBTMAddMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

/// What a `btm_launch_item_add` event says: the launch item registered, its bundle, the app that registered it, and
/// the process that instigated it.
struct SystemBTMAddMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.btm_launch_item_add {
            EventFactsCard(message: esSystemEvent) {
                LaunchItemFacts(event: event)
            }
        }
    }
}


// MARK: - Launch item events
/// What a launch item event (`btm_launch_item_add` or `btm_launch_item_remove`) says, for ``LaunchItemFacts``.
protocol LaunchItemEventFacts {
    /// The launch item.
    var item: ESLaunchItem { get }
    /// The app that registered the item, or `nil`.
    var app: ESProcess? { get }
    /// The process that instigated the event, or `nil`.
    var instigator: ESProcess? { get }
    /// The item's name: the last component of its URL, or `nil`.
    var itemName: String? { get }
    /// The path of the item's executable, or `nil` for an event that doesn't give one.
    var executablePath: String? { get }
}

extension ESLaunchItemAddEvent: LaunchItemEventFacts {
    /// The path of the item's executable, as the event gives it.
    var executablePath: String? { executable_path }
}


// MARK: - Launch item facts
/// A launch item event's facts: the item's type, flags, name and path, its bundle, the app that registered it, and
/// the process that instigated the event.
struct LaunchItemFacts<Event: LaunchItemEventFacts>: View {
    /// The event.
    let event: Event

    var body: some View {
        FactsBox {
            FactRow(name: "Type", value: event.item.item_type_string, style: .monospaced)

            if let executablePath = event.executablePath {
                FactRow(name: "Executable path", value: executablePath, style: .monospaced)
            }

            HStack {
                Text("\u{2022} **Is legacy:**")
                GroupBox {
                    Text("`\(String(event.item.legacy))`")
                }

                Text("\u{2022} **Is managed:**")
                GroupBox {
                    Text(String(event.item.managed))
                        .monospaced()
                }
            }

            if let itemName = event.itemName {
                FactRow(name: "Item name", value: itemName, style: .monospaced)
            }

            FactRow(name: "Item path", value: event.item.item_path)

            // MARK: Bundle
            LaunchItemBundleSection(item: event.item)

            if let appPath = event.item.app_path, !appPath.isEmpty {
                registeringApplication(appPath)
            }

            if let instigator = event.instigator,
               let instigatingPath = instigator.executable?.path,
               !instigatingPath.isEmpty {
                instigatorFacts(instigator, path: instigatingPath)
            }
        }
    }

    /// The app that registered the item: its path, team and signing IDs, and its bundle.
    ///
    /// - Parameter appPath: The app's path.
    /// - Returns: The Registering application section.
    @ViewBuilder
    private func registeringApplication(_ appPath: String) -> some View {
        Divider()

        Label("Registering application", systemImage: "plus.app")
            .bold()
            .font(.title3)
            .padding([.top, .leading], 5.0)

        FactRow(name: "App path", value: appPath)

        if let teamID = event.app?.team_id.nonEmpty {
            FactRow(name: "App Team ID", value: teamID, style: .monospaced)
        }

        if let signingID = event.app?.signing_id.nonEmpty {
            FactRow(name: "App Signing ID", value: signingID, style: .monospaced)
        }

        // MARK: App bundle
        LaunchItemAppBundleSection(item: event.item)
    }

    /// The process that instigated the event: its path, age, and team and signing IDs.
    ///
    /// - Parameters:
    ///   - instigator: The instigator.
    ///   - path: The instigator's path.
    /// - Returns: The Instigator section.
    @ViewBuilder
    private func instigatorFacts(_ instigator: ESProcess, path: String) -> some View {
        Divider()

        Label("Instigator", systemImage: "app.connected.to.app.below.fill")
            .bold()
            .font(.title3)
            .padding([.top, .leading], 5.0)

        FactRow(name: "Instigator path", value: path)

        LaunchItemInstigatorAgeRow(instigator: instigator)

        if let teamID = instigator.team_id.nonEmpty {
            FactRow(name: "Instigator Team ID", value: teamID, style: .monospaced)
        }

        if let signingID = instigator.signing_id.nonEmpty {
            FactRow(name: "Instigator Signing ID", value: signingID, style: .monospaced)
        }
    }
}
