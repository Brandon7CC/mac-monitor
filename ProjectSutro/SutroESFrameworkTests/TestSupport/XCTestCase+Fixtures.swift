//
//  XCTestCase+Fixtures.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest


// MARK: - Fixtures and scratch files
extension XCTestCase {
    /// The folder in the test bundle's resources that holds the fixtures.
    private static let fixturesFolder = "Fixtures"
    
    /// The URL of a fixture in the test bundle's `Fixtures` folder.
    ///
    /// - Parameter name: The fixture's file name, with its extension.
    /// - Returns: The fixture's URL.
    /// - Throws: An `XCTest` failure if the bundle has no such fixture.
    func fixtureURL(_ name: String) throws -> URL {
        let bundle = Bundle(for: type(of: self))
        return try XCTUnwrap(bundle.url(forResource: name, withExtension: nil, subdirectory: Self.fixturesFolder),
                             "No fixture named \(name) in the test bundle")
    }
    
    /// The bytes of a fixture in the test bundle's `Fixtures` folder.
    ///
    /// - Parameter name: The fixture's file name, with its extension.
    /// - Returns: The fixture's contents.
    /// - Throws: An `XCTest` failure if the bundle has no such fixture, or the error reading it.
    func fixture(_ name: String) throws -> Data {
        try Data(contentsOf: try fixtureURL(name))
    }
    
    /// A fixture that holds one JSON object, parsed so a test can change it.
    ///
    /// - Parameter name: The fixture's file name, with its extension.
    /// - Returns: The fixture's object.
    /// - Throws: An `XCTest` failure if the fixture is missing or isn't a JSON object, or the error parsing it.
    func fixtureObject(_ name: String) throws -> [String: Any] {
        try XCTUnwrap(try JSONSerialization.jsonObject(with: try fixture(name)) as? [String: Any],
                      "Fixture \(name) isn't a JSON object")
    }
    
    /// A new, empty directory in the temporary folder, deleted when the test ends.
    ///
    /// - Returns: The directory's URL.
    /// - Throws: The error creating it.
    func makeTemporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("SutroESFrameworkTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        return directory
    }
    
    /// Write UTF-8 text to a new file in a temporary directory that's deleted when the test ends.
    ///
    /// - Parameters:
    ///   - text: The file's contents.
    ///   - name: The file's name.
    /// - Returns: The file's URL.
    /// - Throws: The error creating the directory or writing the file.
    func temporaryFile(containing text: String, named name: String = "trace.json") throws -> URL {
        let url = try makeTemporaryDirectory().appendingPathComponent(name)
        try Data(text.utf8).write(to: url)
        return url
    }
}
