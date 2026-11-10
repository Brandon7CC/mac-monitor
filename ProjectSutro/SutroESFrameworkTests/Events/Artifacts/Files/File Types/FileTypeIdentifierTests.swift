//
//  FileTypeIdentifierTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import XCTest
import UniformTypeIdentifiers
@testable import SutroESFramework


// MARK: - Declared type identifiers
/// Pins that every type identifier a ``FileTypeClassifier`` can answer with is one Launch Services declares on this
/// Mac, so Event Facts can describe it (`UTType(identifier)?.localizedDescription`). Only `empty`,
/// `dyld_shared_cache` and `replaced` aren't identifiers.
final class FileTypeIdentifierTests: XCTestCase {
    /// Every identifier the classifier answers with: its own types (``FileType/classified``), Mach-O's by file type,
    /// and scripts' by interpreter.
    static var identifiers: Set<String> {
        Set(FileType.classified.map(\.identifier)).union(MachOHeader.identifiers.values)
            .union(ShebangLine.identifiers.values).union(["com.netscape.javascript-source"])
    }

    /// Each identifier is declared, not dynamic, and has a description.
    func testEveryIdentifierIsDeclared() {
        XCTAssertEqual(Self.identifiers.count, 44)
        for identifier in Self.identifiers.sorted() {
            let type = UTType(identifier)
            XCTAssertNotNil(type, "\(identifier) isn't declared on this Mac")
            XCTAssertEqual(type?.isDynamic, false, identifier)
            XCTAssertNotNil(type?.localizedDescription, identifier)
        }
    }

    /// The classifier's own list holds every type identifier its signatures and a zip's first entry name, once each.
    func testClassifiedHoldsEverySignaturesType() {
        let named = FileTypeClassifier.signatureTypes.filter { !FileType.isSpecial($0.identifier) }
        XCTAssertTrue(named.isSubset(of: Set(FileType.classified)), "\(named.subtracting(FileType.classified))")
        XCTAssertEqual(FileTypeClassifier.signatureTypes.subtracting(named), [.dyldCache])
        XCTAssertEqual(Set(FileType.classified).count, FileType.classified.count)
    }

    /// The three values that aren't identifiers aren't declared as any.
    func testSpecialValuesAreNotIdentifiers() {
        for value in [FileType.empty, FileType.dyldSharedCache, FileType.replaced] {
            XCTAssertTrue(FileType.isSpecial(value))
            XCTAssertNil(UTType(value), value)
        }
        XCTAssertFalse(Self.identifiers.contains(where: FileType.isSpecial))
    }

    /// Descriptions as Event Facts shows them.
    func testDescriptions() {
        XCTAssertEqual(UTType("com.apple.mach-o-dylib")?.localizedDescription, "Mach-O dynamic library")
        XCTAssertEqual(UTType("com.apple.mach-o-executable")?.localizedDescription, "Mach-O executable")
        XCTAssertEqual(UTType("public.zsh-script")?.localizedDescription, "Z Shell script")
    }
}
