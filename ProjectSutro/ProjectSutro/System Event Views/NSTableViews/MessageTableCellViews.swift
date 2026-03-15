//
//  MessageTableCellViews.swift
//  ProjectSutro
//
//  NSTableCellView implementations for Message table columns.
//

import AppKit
import SutroESFramework
import SwiftUI

class MonospacedTextCellView: NSTableCellView {
    private let valueTextField: NSTextField
    
    override init(frame frameRect: NSRect) {
        valueTextField = NSTextField(labelWithString: "")
        valueTextField.font = NSFont.monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        valueTextField.lineBreakMode = .byTruncatingTail
        valueTextField.allowsDefaultTighteningForTruncation = true
        valueTextField.isSelectable = false
        valueTextField.alignment = .left
        
        super.init(frame: frameRect)
        addSubview(valueTextField)
        valueTextField.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            valueTextField.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4),
            valueTextField.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -4),
            valueTextField.centerYAnchor.constraint(equalTo: centerYAnchor)
        ])
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    func setText(_ text: String, lineBreakMode: NSLineBreakMode = .byTruncatingTail) {
        valueTextField.stringValue = text
        valueTextField.lineBreakMode = lineBreakMode
    }
}

class SelectableTextCellView: NSTableCellView {
    private let valueTextField: NSTextField
    
    override init(frame frameRect: NSRect) {
        valueTextField = NSTextField(labelWithString: "")
        valueTextField.font = NSFont.monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        valueTextField.lineBreakMode = .byTruncatingMiddle
        valueTextField.isSelectable = false
        valueTextField.alignment = .left
        
        super.init(frame: frameRect)
        addSubview(valueTextField)
        valueTextField.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            valueTextField.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4),
            valueTextField.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -4),
            valueTextField.centerYAnchor.constraint(equalTo: centerYAnchor)
        ])
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    func setText(_ text: String, lineBreakMode: NSLineBreakMode = .byTruncatingMiddle) {
        valueTextField.stringValue = text
        valueTextField.lineBreakMode = lineBreakMode
    }
}

class MultilineTextCellView: NSTableCellView {
    private let valueTextField: NSTextField
    
    override init(frame frameRect: NSRect) {
        valueTextField = NSTextField(labelWithString: "")
        valueTextField.font = NSFont.monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        valueTextField.lineBreakMode = .byWordWrapping
        valueTextField.allowsDefaultTighteningForTruncation = true
        valueTextField.isSelectable = false
        valueTextField.alignment = .left
        valueTextField.maximumNumberOfLines = 8
        valueTextField.cell?.wraps = true
        valueTextField.cell?.usesSingleLineMode = false
        
        super.init(frame: frameRect)
        addSubview(valueTextField)
        valueTextField.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            valueTextField.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4),
            valueTextField.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -4),
            valueTextField.topAnchor.constraint(equalTo: topAnchor, constant: 4),
            valueTextField.bottomAnchor.constraint(lessThanOrEqualTo: bottomAnchor, constant: -4)
        ])
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    func setText(_ text: String, maxLines: Int = 8) {
        valueTextField.stringValue = text
        valueTextField.maximumNumberOfLines = maxLines
        valueTextField.lineBreakMode = .byWordWrapping
    }
}

class SwiftUIHostingCellView<Content: View>: NSTableCellView {
    private let hostingView: NSHostingView<Content>
    
    init(content: Content) {
        hostingView = NSHostingView(rootView: content)
        super.init(frame: .zero)
        addSubview(hostingView)
        hostingView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            hostingView.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4),
            hostingView.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -4),
            hostingView.topAnchor.constraint(equalTo: topAnchor),
            hostingView.bottomAnchor.constraint(equalTo: bottomAnchor)
        ])
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    func updateContent(_ content: Content) {
        hostingView.rootView = content
    }
}
