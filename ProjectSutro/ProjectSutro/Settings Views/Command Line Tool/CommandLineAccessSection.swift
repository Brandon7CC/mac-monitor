//
//  CommandLineAccessSection.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/5/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Settings > Command Line > Without sudo
/// Two switches for using `macmonitor` without `sudo` (``CommandLineAccess``): streaming, and changing the saved mute
/// set and the indicators too, which needs the first. Both are off by default, and any Mac Monitor that controls the
/// event stream may flip them, with no password.
///
/// The copy says plainly what turning it on exposes, since any user on the Mac, and any process they run, could then
/// read every process's events.
struct CommandLineAccessSection: View {
    @ObservedObject var model: CommandLineAccessModel
    /// Sends changes to the Security Extension.
    let manager: EndpointSecurityManager

    var body: some View {
        SettingsSection(title: "Without sudo") {
            VStack(alignment: .leading, spacing: 0) {
                row("Stream without sudo",
                    detail: "Any user can run macmonitor stream, and list and export mutes and indicators.",
                    isOn: binding(on: .streaming, off: .rootOnly))
                Divider()
                row("Change mutes and indicators without sudo",
                    detail: "Saved mutes and indicators apply to Mac Monitor and every stream.",
                    isOn: binding(on: .streamingAndChanges, off: .streaming))
                    .disabled((model.access ?? .rootOnly) < .streaming)
                if (model.access ?? .rootOnly) > .rootOnly {
                    Callout(title: "Any user can read every process's events", text: Self.exposure)
                }
                Text(Self.enforcement)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(EdgeInsets(top: 8, leading: 14, bottom: 12, trailing: 14))
            }
            .disabled(model.access == nil || model.isChanging)
        }
        .onAppear { model.refresh(through: manager) }
        .alert("Command line tool", isPresented: Binding(get: { model.failure != nil },
                                                          set: { if !$0 { model.failure = nil } }),
               actions: { Button("OK", role: .cancel, action: {}) },
               message: { Text(model.failure ?? "") })
    }

    /// What turning it on exposes.
    static let exposure = "And any program they run, malware included, with no password."

    /// When turning it off applies.
    static let enforcement = "Turning it off applies to new streams."

    /// A switch with what it means. The label takes the row's width, so every switch lines up at the trailing edge
    /// whatever its text's length.
    ///
    /// - Parameters:
    ///   - title: What it does.
    ///   - detail: What that means.
    ///   - isOn: The switch's state.
    /// - Returns: The row.
    private func row(_ title: String, detail: String, isOn: Binding<Bool>) -> some View {
        Toggle(isOn: isOn) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                Text(detail).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .toggleStyle(.switch)
        .padding(.vertical, 10)
        .padding(.horizontal, 14)
    }

    /// A switch that's on at `on` or wider, and asks for `on` or `off` when flipped.
    ///
    /// - Parameters:
    ///   - on: The level the switch turns on.
    ///   - off: The level it falls back to.
    /// - Returns: The binding.
    private func binding(on: CommandLineAccess, off: CommandLineAccess) -> Binding<Bool> {
        Binding(get: { (model.access ?? .rootOnly) >= on },
                set: { model.change(to: $0 ? on : off, through: manager) })
    }
}
