//
//  InitiatingUserView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework


// MARK: Initiating user
struct InitiatingUserView: View {
    var selectedMessage: ESMessage
    
    var body: some View {
        if selectedMessage.process.ruid != selectedMessage.process.euid {
            GroupBox {
                HStack {
                    Text("**Effective:**")
                    GroupBox {
                        Text(
                            "`\(selectedMessage.process.euid_human!) (\(selectedMessage.process.euid))`"
                        )
                    }
                    Image(systemName: "arrow.right")
                    Text("\u{2022} **Real:**")
                    GroupBox {
                        Text(
                            "`\(selectedMessage.process.ruid_human!) (\(selectedMessage.process.ruid))`"
                        )
                    }
                }.frame(alignment: .leading)
            }.frame(alignment: .leading)
            
        } else {
            HStack {
                GroupBox {
                    Text(
                        "`\(selectedMessage.process.euid_human!) (\(selectedMessage.process.euid))`"
                    )
                }
            }.frame(alignment: .leading)
        }
    }
}
