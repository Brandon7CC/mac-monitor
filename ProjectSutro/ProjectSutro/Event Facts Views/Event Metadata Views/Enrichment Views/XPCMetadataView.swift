//
//  XPCMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

// MARK: - XPC details view
/// The XPC service an exec'd process was started as (``ESProcessExecEvent/xpcServiceName``).
struct XPCMetadataView: View {
    /// The service's name.
    var serviceName: String
    
    var body: some View {
        VStack(alignment: .leading) {
            Text("\u{2022} **XPC service name**").font(.title3)
            GroupBox {
                Text("`\(serviceName)`").font(.title3)
            }
        }
    }
}
