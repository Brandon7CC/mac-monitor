//
//  QuitReason.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/1/26.
//

import Foundation
import CoreServices


// MARK: - Quit reason
/// Who asked Mac Monitor to quit, from the quit Apple Event's reason (`kAEQuitReason`).
///
/// macOS asks every app to quit when it logs out, restarts or shuts down, with a reason that says which. A warning
/// before quitting then holds the logout, restart or shutdown until someone answers it, so Mac Monitor only warns
/// when a person quits it.
public enum QuitReason: Equatable {
    /// ⌘Q, the Quit menu item, or another app asking.
    case user
    /// macOS logging out, restarting or shutting down.
    case system

    /// The reasons macOS gives when it logs out, restarts or shuts down.
    static let systemReasons: Set<UInt32> = [
        kAELogOut, kAEReallyLogOut, kAEShowRestartDialog, kAERestart, kAEShowShutdownDialog, kAEShutDown
    ]

    /// - Parameter code: The quit Apple Event's `kAEQuitReason`, or `nil` when it has none.
    public init(appleEventReason code: UInt32?) {
        self = code.map(Self.systemReasons.contains) == true ? .system : .user
    }

    /// The reason for the quit being handled now. Call it from `applicationShouldTerminate(_:)`, while AppKit is
    /// handling the quit Apple Event. A quit with no Apple Event, such as `NSApp.terminate(_:)`, is ``user``.
    public static var current: QuitReason {
        let event = NSAppleEventManager.shared().currentAppleEvent
        return QuitReason(appleEventReason: event?.attributeDescriptor(forKeyword: kAEQuitReason)?.enumCodeValue)
    }
}
