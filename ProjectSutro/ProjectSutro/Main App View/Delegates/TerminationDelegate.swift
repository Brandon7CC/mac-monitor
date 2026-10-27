//
//  TerminationDelegate.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/7/23.
//


import Cocoa
import SutroESFramework

class AppDelegate: NSObject, NSApplicationDelegate {
    override init() {
        super.init()
        let userDefaults = UserDefaults.standard
        let defaultValues = [
            "lifecycleWarnBeforeQuit" : true,
            "lifecycleWarnBeforeClear" : true,
            /// Open a new main window at launch rather than restoring the last session's windows: their events were
            /// cleared at quit, and a main window saved by an older version restores to no window at all.
            "ApplePersistenceIgnoreState" : true
        ]
        userDefaults.register(defaults: defaultValues)
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        /// Quitting stops a save, which the warning before quitting can't be turned off for.
        if let saving = CoreDataController.shared.exportDestinations.first,
           !UserDefaults.standard.bool(forKey: "lifecycleQuitInternal") {
            let alert = NSAlert()
            alert.messageText = "Quit Mac Monitor while saving “\(saving.lastPathComponent)”?"
            alert.informativeText = "Quitting stops the save before it finishes and clears any system trace."
            alert.addButton(withTitle: "Keep Saving")
            alert.addButton(withTitle: "Quit")
            /// Esc keeps saving, as it cancels the usual quit warning.
            /// NSAlert gives Esc only to a button titled Cancel.
            let escape = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
                guard event.keyCode == 53, event.window === alert.window else { return event }
                alert.buttons[0].performClick(nil)
                return nil
            }
            defer { escape.map(NSEvent.removeMonitor) }
            return alert.runModal() == .alertSecondButtonReturn ? .terminateNow : .terminateCancel
        }
        if UserDefaults.standard.bool(forKey: "lifecycleWarnBeforeQuit") && !UserDefaults.standard.bool(forKey: "lifecycleQuitInternal") {
            let alert = NSAlert()
            alert.messageText = "Quit Mac Monitor?"
            alert.informativeText = "Please save your work. Quitting will clear any system trace."
            alert.addButton(withTitle: "Confirm App Quit")
            alert.addButton(withTitle: "Cancel")
            alert.showsSuppressionButton = true
            let response = alert.runModal()

            if let suppressionButton = alert.suppressionButton,
               suppressionButton.state == .on {
                UserDefaults.standard.set(false, forKey: "lifecycleWarnBeforeQuit")
            }

            return response == .alertFirstButtonReturn ? .terminateNow : .terminateCancel
        } else {
            return .terminateNow
        }
    }
    
    /// Files opened from Finder's Open With or `open -a` after the first, which SwiftUI hands to a main window's
    /// `onOpenURL` (see `EventView`). Mac Monitor shows one trace at a time, so the rest are ignored.
    ///
    /// - Parameters:
    ///   - application: Mac Monitor.
    ///   - urls: The files no window took.
    func application(_ application: NSApplication, open urls: [URL]) {}
}
