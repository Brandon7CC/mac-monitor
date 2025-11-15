//
//  FileContentView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

struct FileContentView: View {
    var path, content: String
    
    var body: some View {
        Section("**`\(path)`**") {
            ScrollView {
                Text(content)
                    .monospaced()
                    .foregroundColor(.white)
                    .multilineTextAlignment(.leading)
                    .frame(
                        maxWidth: .infinity,
                        alignment: .leading
                    )
                    .textSelection(.enabled)
                    .padding()
            }
            .background(.black)
        }
    }
}
