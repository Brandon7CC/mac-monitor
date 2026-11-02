//
//  EventLabelViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import SutroESFramework


// MARK: - Event type
/// An event's type in the Unified table and Event Facts. Its built-in marks come first (``Finding/labelMarks``). Then
/// comes the type's name in bold code, with the symbol and color its event calls for (``EventLabelLook``).
struct SystemEventTypeLabel: View {
    var message: ESMessage
    /// The color of a type the label doesn't color. Event Facts' Open Directory labels are orange.
    var tint: Color?

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let eventType = message.es_event_type {
            let look = EventLabelLook(message, tint: tint)
            HStack {
                BuiltInMarks(message: message, marks: Finding.labelMarks)
                Label("**`\(eventType)`**", systemImage: look.symbol ?? eventStringToImage(from: eventType))
                    .eventLabelLook(look)
            }
            .frame(alignment: .leading)
        }
    }
}


// MARK: - Look
/// How an event type's label draws its name, as the hard-coded labels did.
struct EventLabelLook {
    /// Its symbol, or `nil` for the type's own.
    var symbol: String?
    /// The color of its name and symbol, or `nil` for the text's own.
    var tint: Color?
    /// Is its symbol drawn as a palette?
    var palette = false
    /// Its help, or `nil` for none.
    var help: String?
}


extension EventLabelLook {
    /// The look of a type no event colors. Its symbol is drawn as a palette.
    ///
    /// - Parameter tint: Its color, if any.
    /// - Returns: The look.
    static func plain(_ tint: Color? = nil) -> Self { Self(tint: tint, palette: true) }

    /// - Parameters:
    ///   - message: The event.
    ///   - tint: The color of a type the label doesn't color.
    init(_ message: ESMessage, tint: Color? = nil) {
        let event = message.event
        switch message.es_event_type?.droppingPrefix("ES_EVENT_TYPE_NOTIFY_") ?? "" {
        case "EXEC":
            self = event.exec.map { Self(signatureOf: $0.target) } ?? .plain(tint)
        case "FORK":
            self.init(symbol: "point.topleft.down.curvedto.point.bottomright.up")
        case "CREATE":
            self = event.create.map { Self(create: $0, by: message.process) } ?? .plain(tint)
        case "MMAP":
            self = event.mmap?.source.path.map(Self.init(mappedPath:)) ?? .plain(tint)
        case "RENAME":
            self = event.rename.map(Self.init(rename:)) ?? .plain(tint)
        case "EXIT":
            self.init(symbol: "eject.fill")
        case "DELETEEXTATTR" where event.deleteextattr?.extattr.hasSuffix("apple.quarantine") == true:
            self.init(symbol: "lock.slash", tint: .red, palette: true)
        case "DELETEEXTATTR":
            self.init(tint: .orange)
        case "SETEXTATTR":
            self = event.setextattr?.extattr == "com.apple.quarantine" ? Self(tint: .green, palette: true) : Self()
        case "WRITE":
            self.init(tint: event.write?.target.path?.contains("backgroundtaskmanagementd") == true ? .orange : nil)
        case "IOKIT_OPEN":
            self.init(tint: event.iokit_open?.user_client_class.contains("IOHIDLibUserClient") == true ? .orange : nil)
        case "BTM_LAUNCH_ITEM_ADD", "BTM_LAUNCH_ITEM_REMOVE":
            self.init(symbol: "lock.doc", tint: .orange, palette: true)
        case "OPENSSH_LOGIN", "OPENSSH_LOGOUT":
            self.init(symbol: "network", tint: .blue, palette: true)
        case "XP_MALWARE_DETECTED":
            self.init(symbol: "bolt.shield", tint: .purple, palette: true)
        case "XP_MALWARE_REMEDIATED":
            self.init(symbol: "checkmark.shield", tint: .purple, palette: true)
        case "LOGIN_LOGIN":
            self.init(symbol: "person.fill.checkmark", tint: .blue)
        case "LW_SESSION_LOGIN", "LW_SESSION_UNLOCK":
            self.init(symbol: "macwindow.badge.plus", tint: .blue)
        case "MOUNT":
            self.init(symbol: "mount")
        case "DUP":
            self.init(symbol: "folder.badge.plus")
        case "UNLINK", "OPEN", "LINK", "CLOSE", "SIGNAL", "PROC_CHECK", "PROFILE_ADD", "PROC_SUSPEND_RESUME":
            self.init()
        case "REMOTE_THREAD_CREATE", "CS_INVALIDATED":
            self = .plain(.red)
        case "TRACE", "GET_TASK", "OD_GROUP_ADD", "OD_GROUP_REMOVE", "OD_CREATE_GROUP", "OD_ATTRIBUTE_VALUE_ADD",
            "AUTHORIZATION_PETITION", "AUTHORIZATION_JUDGEMENT", "TCC_MODIFY", "GATEKEEPER_USER_OVERRIDE":
            self = .plain(.orange)
        case "OD_CREATE_USER":
            self.init(tint: .orange, palette: true, help: "A user was added to an Open Directory node.")
        case "OD_MODIFY_PASSWORD":
            self.init(tint: .orange, palette: true, help: "A user's password was modified in an Open Directory node.")
        default:
            self = .plain(tint)
        }
    }

    /// An exec's label or process name, as its new process is signed. Adhoc is a seal crossed out in orange, whose help
    /// says whether the linker signed it. A signing ID is a checked seal. Neither is a seal crossed out in red.
    ///
    /// - Parameter process: The exec's new process.
    init(signatureOf process: ESProcess) {
        if process.is_adhoc_signed {
            let help = process.isLinkerSignedAdhoc
                ? "Adhoc signed by the linker, as a freshly compiled binary is." : "Adhoc signed."
            self.init(symbol: "xmark.seal", tint: .orange, palette: true, help: help)
        } else if process.hasSigningID {
            self.init(symbol: "checkmark.seal")
        } else {
            self.init(symbol: "xmark.seal", tint: .red, palette: true)
        }
    }

    /// A created file. An image for reflective loading is red. A file left unquarantined is red, as a palette.
    ///
    /// - Parameters:
    ///   - create: The create.
    ///   - process: The process that created the file.
    private init(create: ESFileCreateEvent, by process: ESProcess) {
        let path = create.targetPath
        let quarantines = process.file_quarantine_type != "DISABLED"
            || (process.executable?.name == "ArchiveService" && !path.hasPrefix("/private/var/folders/"))
        if path.lastPathComponent.hasPrefix("NSCreateObjectFileImageFromMemory-") {
            self.init(symbol: "doc.plaintext", tint: .red)
        } else if quarantines && create.is_quarantined == 0 {
            self.init(symbol: "doc.plaintext", tint: .red, palette: true)
        } else {
            self.init(symbol: "doc.plaintext")
        }
    }

    /// A mapped file. An image for reflective loading is red. An OSA component is orange.
    ///
    /// - Parameter mappedPath: The mapped file's path.
    private init(mappedPath: String) {
        if mappedPath.lastPathComponent.hasPrefix("NSCreateObjectFileImageFromMemory-") {
            self.init(symbol: "memorychip", tint: .red)
        } else if ["AppleScript.component", "JavaScript.component", ".osax"].contains(where: mappedPath.contains) {
            self.init(symbol: "memorychip", tint: .orange)
        } else {
            self.init(symbol: "memorychip")
        }
    }

    /// A rename. An unquarantined app bundle is red. The service management database is orange.
    ///
    /// - Parameter rename: The rename.
    private init(rename: ESFileRenameEvent) {
        let path = rename.destination_path
        if rename.is_quarantined == 0 && path.hasSuffix(".app") {
            self.init(symbol: "filemenu.and.cursorarrow", tint: .red)
        } else if rename.is_quarantined != 1 && path.contains("com.apple.backgroundtaskmanagement") {
            self.init(symbol: "lock.doc", tint: .orange)
        } else {
            self.init(symbol: "filemenu.and.cursorarrow")
        }
    }
}


extension View {
    /// - Parameter look: How a label draws its name.
    /// - Returns: The label, drawn so.
    @ViewBuilder
    func eventLabelLook(_ look: EventLabelLook) -> some View {
        let drawn = symbolRenderingMode(look.palette ? .palette : nil).help(ifAny: look.help ?? "")
        if let tint = look.tint {
            drawn.foregroundStyle(tint)
        } else {
            drawn
        }
    }
}


extension ESProcess {
    /// Is it signed with a signing ID, and not adhoc?
    var hasSigningID: Bool {
        !is_adhoc_signed && (signing_id.nonEmpty ?? "Unknown") != "Unknown"
    }
}


// MARK: - Executable age
extension ESProcessExecEvent {
    /// How long before the exec its executable was created, such as "3.25 s", "4 min" or "12 days", or `nil`.
    var executableAgeText: String? {
        guard let age = executableAge else { return nil }
        switch age {
        case ..<60: return String(format: "%.2fs", age)
        case ..<3600: return "\(Int(age) / 60)min"
        case ..<86_400: return "\(Int(age) / 3600)h"
        default: return "\(Int(age) / 86_400) days"
        }
    }
}
