//
//  IndicatorAlertCenter+Responses.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/8/26.
//

import SwiftUI
import CoreData
import UserNotifications
import SutroESFramework


// MARK: - Clicks and actions
extension IndicatorAlertCenter: UNUserNotificationCenterDelegate {
    /// Show notifications while Mac Monitor is in front, too: as a banner and in the list, with sound for a High.
    ///
    /// - Parameters:
    ///   - center: The notification center.
    ///   - notification: The notification about to show.
    ///   - completionHandler: Takes how to show it.
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            willPresent notification: UNNotification,
                                            withCompletionHandler completionHandler:
                                            @escaping (UNNotificationPresentationOptions) -> Void) {
        let sound = notification.request.content.sound != nil
        completionHandler(sound ? [.banner, .list, .sound] : [.banner, .list])
    }

    /// Answer a click or an action, on the main queue.
    ///
    /// - Parameters:
    ///   - center: The notification center.
    ///   - response: The click or action.
    ///   - completionHandler: Called once it's handled.
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            didReceive response: UNNotificationResponse,
                                            withCompletionHandler completionHandler: @escaping () -> Void) {
        let action = response.actionIdentifier
        guard let info = IndicatorAlertInfo(userInfo: response.notification.request.content.userInfo) else {
            return completionHandler()
        }
        DispatchQueue.main.async {
            MainActor.assumeIsolated { IndicatorAlertCenter.shared.respond(to: info, action: action) }
            completionHandler()
        }
    }

    /// Act on a click or an action, or hold it until a main window attaches, as for a click that launched Mac
    /// Monitor.
    ///
    /// - Parameters:
    ///   - info: What the notification carries.
    ///   - action: The action's identifier.
    func respond(to info: IndicatorAlertInfo, action: String) {
        guard openWindow != nil else { return heldResponse = (info, action) }
        switch action {
        case IndicatorAlertInfo.dontNotifyAction:
            setSilenced(info.indicatorID, true)
        case IndicatorAlertInfo.showAllAction:
            showMatches(info.search)
        case UNNotificationDefaultActionIdentifier:
            if info.kind == .overflow { showMatches(info.search) } else { showEvent(info.eventID) }
        default:
            break
        }
    }

    /// Open an event in Event Facts, or say it's gone: Event Facts would close itself at once without it.
    ///
    /// - Parameter id: The event's identity.
    private func showEvent(_ id: UUID) {
        let request = NSFetchRequest<ESMessage>(entityName: "ESMessage")
        request.predicate = NSPredicate(format: "id == %@", id as CVarArg)
        let context = manager?.coreDataContainer.container.viewContext
        guard let context, (try? context.count(for: request)) ?? 0 > 0 else {
            showMainWindow()
            let alert = NSAlert()
            alert.messageText = "This event is no longer in Mac Monitor."
            alert.informativeText = "It was cleared, an opened trace replaced it, or Mac Monitor quit since."
            alert.runModal()
            return
        }
        openWindow?(value: id)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// Show the main window, filtered by a search.
    ///
    /// - Parameter source: The predicate.
    private func showMatches(_ source: String) {
        showMainWindow()
        search?.draft = source
        search?.apply(source)
    }

    /// Bring a main window forward, opening one if none is open.
    private func showMainWindow() {
        let main = NSApp.windows.first {
            $0.isVisible && $0.identifier?.rawValue.hasPrefix(ProjectSutroApp.mainWindow) == true
        }
        if let main { main.makeKeyAndOrderFront(nil) } else { openWindow?(id: ProjectSutroApp.mainWindow) }
        NSApp.activate(ignoringOtherApps: true)
    }
}
