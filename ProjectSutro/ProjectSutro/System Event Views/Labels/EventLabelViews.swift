//
//  EventLabelViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import SutroESFramework


// MARK: - Event type
/// An event's type in the Unified table and Event Facts. Its built-in marks come first (``Indicator/labelMarks``). Then
/// comes the type's name in bold code, with the symbol and color its event calls for (``EventLabelLook``), or the
/// color of an indicator it matched that colors its label (``Indicator/TableMarks/label``).
struct SystemEventTypeLabel: View {
    var message: ESMessage
    /// The color of a type the label doesn't color. Event Facts' Open Directory labels are orange.
    var tint: Color?
    /// The label follows the indicators as Settings changes them.
    @ObservedObject private var store = IndicatorStore.shared

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let eventType = message.es_event_type {
            let look = EventLabelLook(message, tint: tint).colored(by: store.marks(for: message).labelIndicator)
            HStack {
                BuiltInMarks(message: message, marks: Indicator.labelMarks)
                Label("**`\(eventType)`**", systemImage: look.symbol ?? eventStringToImage(from: eventType))
                    .eventLabelLook(look)
            }
            .frame(alignment: .leading)
        }
    }

    /// - Parameter message: An event.
    /// - Returns: The symbol its label draws, or `nil` for an event that's gone. An indicator that colors the label
    ///   and has the same symbol isn't drawn again before it (``IndicatorMarks``).
    static func symbol(of message: ESMessage) -> String? {
        message.es_event_type.map { EventLabelLook(message).symbol ?? eventStringToImage(from: $0) }
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
            /// The Reflective loading and Unquarantined file from a File Quarantine-aware app indicators color a create
            /// (``Indicator/TableMarks/label``).
            self.init(symbol: "doc.plaintext")
        case "MMAP":
            self = event.mmap?.source.path.map(Self.init(mappedPath:)) ?? .plain(tint)
        case "RENAME":
            self = event.rename.map(Self.init(rename:)) ?? .plain(tint)
        case "EXIT":
            self.init(symbol: "eject.fill")
        case "DELETEEXTATTR" where event.deleteextattr?.extattr.hasSuffix("apple.quarantine") == true:
            self.init(symbol: "lock.slash", palette: true)
        case "DELETEEXTATTR":
            self.init(tint: .orange)
        case "SETEXTATTR":
            self = event.setextattr?.extattr == "com.apple.quarantine" ? Self(tint: .green, palette: true) : Self()
        case "WRITE":
            self.init(tint: event.write?.target.path?.contains("backgroundtaskmanagementd") == true ? .orange : nil)
        case "BTM_LAUNCH_ITEM_ADD", "BTM_LAUNCH_ITEM_REMOVE":
            self.init(symbol: "lock.doc", palette: true)
        case "OPENSSH_LOGIN", "OPENSSH_LOGOUT":
            self.init(symbol: "network", tint: .blue, palette: true)
        case "XP_MALWARE_DETECTED":
            self.init(symbol: "bolt.shield", palette: true)
        case "XP_MALWARE_REMEDIATED":
            self.init(symbol: "checkmark.shield", palette: true)
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
        case "OD_GROUP_ADD", "OD_GROUP_REMOVE", "OD_CREATE_GROUP", "OD_ATTRIBUTE_VALUE_ADD",
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

    /// - Parameter indicator: The indicator that colors the label, if one does.
    /// - Returns: The look in the indicator's color, whatever color the event called for, or the look as it is.
    func colored(by indicator: Indicator?) -> Self {
        guard let indicator else { return self }
        var look = self
        look.tint = indicator.tint
        return look
    }

    /// An exec's label or process name, as its new process is signed (``ESProcess/seal``). Adhoc is a seal crossed
    /// out, whose help says whether the linker signed it. So is unsigned. Signed is a checked seal. The seal has no
    /// color of its own: the Adhoc signed and Unsigned indicators color the label orange and red
    /// (``Indicator/TableMarks/label``), for as long as Settings > Indicators has them do so.
    ///
    /// - Parameter process: The exec's new process.
    init(signatureOf process: ESProcess) {
        switch process.seal {
        case .adhoc:
            let help = process.isLinkerSignedAdhoc
                ? "Adhoc signed by the linker, as a freshly compiled binary is." : "Adhoc signed."
            self.init(symbol: process.seal.symbol, palette: true, help: help)
        case .unsigned:
            self.init(symbol: process.seal.symbol, palette: true)
        case .signed:
            self.init(symbol: process.seal.symbol)
        }
    }

    /// A mapped file. The Reflective loading and AppleScript / JXA indicators color an image for reflective loading
    /// and a scripting component (``Indicator/TableMarks/label``).
    ///
    /// - Parameter mappedPath: The mapped file's path.
    private init(mappedPath: String) {
        self.init(symbol: "memorychip")
    }

    /// A rename. An unquarantined app bundle is red. The BTM database modified indicator colors a rename onto
    /// Background Task Management's database (``Indicator/TableMarks/label``).
    ///
    /// - Parameter rename: The rename.
    private init(rename: ESFileRenameEvent) {
        let isUnquarantinedApp = rename.is_quarantined == 0 && rename.destination_path.hasSuffix(".app")
        self.init(symbol: "filemenu.and.cursorarrow", tint: isUnquarantinedApp ? .red : nil)
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


// MARK: - Seal
extension ESProcess {
    /// How a process's code is signed, as an exec's label shows it.
    enum Seal {
        /// Signed, with a signing ID.
        case signed
        /// Adhoc signed.
        case adhoc
        /// Not signed, or its signature is no longer valid.
        case unsigned

        /// Its symbol: a checked seal, or one crossed out.
        var symbol: String { self == .signed ? "checkmark.seal" : "xmark.seal" }
    }

    /// How its code is signed, read as the Adhoc signed and Unsigned indicators read an exec's record, so the seal
    /// and the indicator that colors it agree: adhoc by its flag or its type, else unsigned by its type or for want
    /// of a signing ID.
    var seal: Seal {
        if is_adhoc_signed || codesigning_type == "ADHOC" { return .adhoc }
        if codesigning_type == "UNSIGNED" || (signing_id.nonEmpty ?? "Unknown") == "Unknown" { return .unsigned }
        return .signed
    }
}
