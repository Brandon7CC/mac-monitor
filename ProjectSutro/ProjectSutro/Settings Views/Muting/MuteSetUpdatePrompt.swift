//
//  MuteSetUpdatePrompt.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/8/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Offering a newer default mute set
/// Offers a newer default mute set once the Security Extension connects, when the user has changed their saved set
/// so it wasn't updated by itself (``MuteSetUpdate``).
///
/// - **Update** merges it in, keeping the user's changes.
/// - **Later** asks again at the next launch.
/// - **Don't Update** stops asking about this default set, for every user: the Security Extension keeps the answer
///   (``MuteRequest/Operation/decline``) and never applies it by itself. Settings > Path Muting still offers it.
///
/// It asks once a launch, and not when this Mac Monitor may only read the saved set.
struct MuteSetUpdatePrompt: ViewModifier {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @State private var offered: MuteSetUpdate?
    /// Asked already this launch, from any window.
    @MainActor private static var hasAsked = false

    /// - Parameter content: The main window.
    /// - Returns: It, offering the update when there's one.
    func body(content: Content) -> some View {
        content
            .onAppear(perform: offerIfNeeded)
            .onChange(of: systemExtensionManager.connectionResult) { _ in offerIfNeeded() }
            .alert("Update your mute set?", isPresented: Binding { offered != nil } set: { if !$0 { offered = nil } },
                   presenting: offered) { update in
                Button("Update") {
                    systemExtensionManager.requestMutes(MuteRequest(.update), from: .eventMenu)
                }
                .keyboardShortcut(.defaultAction)
                Button("Later", role: .cancel) {}
                Button("Don't Update") {
                    systemExtensionManager.requestMutes(MuteRequest(.decline), from: .eventMenu)
                }
            } message: { update in
                Text(Self.message(for: update))
            }
    }

    /// Ask the Security Extension for the saved set once it's connected, and offer its update unless the user
    /// declined this one.
    private func offerIfNeeded() {
        guard systemExtensionManager.connectionResult == .success, systemExtensionManager.canChangeSavedMutes,
              !Self.hasAsked else { return }
        Self.hasAsked = true
        systemExtensionManager.requestMutes(MuteRequest(.list), from: .eventMenu) { reply in
            guard let update = reply?.update, !update.declined else { return }
            offered = update
        }
    }
    
    /// The question's explanation.
    ///
    /// - Parameters:
    ///   - update: The update.
    ///   - inSettings: Asked from Settings > Path Muting, so neither why it's asked nor where else to update is said.
    /// - Returns: The explanation, naming the release and what the update changes.
    static func message(for update: MuteSetUpdate, inSettings: Bool = false) -> String {
        let change = "Mac Monitor \(update.release)'s default mute set \(update.summary) in your saved mute set."
        let keeps = "Updating merges the new defaults in and keeps your changes."
        guard !inSettings else { return "\(change) \(keeps)" }
        return """
            \(change) You've changed your saved set, so it wasn't updated by itself. \(keeps) You can also update \
            later in Settings > Path Muting.
            """
    }
}
