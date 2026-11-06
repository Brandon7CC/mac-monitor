//
//  LaunchItemBundleTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Reading a launch item's bundle
/// Pins ``LaunchItemBundle/read(at:)`` on bundles built in a temporary directory: the Info.plist's essentials in XML
/// and binary, missing keys, the forms of `LSUIElement`, shallow bundles, paths that aren't bundles, a FIFO wherever
/// Mac Monitor or Security would open one, an oversized Info.plist, linked Info.plists, quarantine and where-froms, and
/// unsigned and adhoc signing.
final class LaunchItemBundleTests: XCTestCase {
    /// Read a bundle, failing the test when it isn't one.
    ///
    /// - Parameter path: The bundle.
    /// - Returns: The bundle, and its Info.plist's text.
    /// - Throws: An `XCTest` failure if the path isn't read as a bundle.
    private func read(_ path: String) throws -> (bundle: LaunchItemBundle, infoPlist: String?) {
        try XCTUnwrap(LaunchItemBundle.read(at: path), "\(path) isn't read as a bundle")
    }

    // MARK: Info.plist

    /// An XML Info.plist's essentials, its display name over its name, and its text as it's stored.
    func testXMLInfoPlist() throws {
        let path = try makeBundle()
        let (bundle, infoPlist) = try read(path)
        XCTAssertEqual(bundle.path, path)
        XCTAssertEqual(bundle.info_plist_path, path + "/Contents/Info.plist")
        XCTAssertEqual(bundle.identifier, "com.example.helper")
        XCTAssertEqual(bundle.name, "Example Helper")
        XCTAssertEqual(bundle.version, "42")
        XCTAssertEqual(bundle.short_version, "1.2.3")
        XCTAssertEqual(bundle.executable_path, path + "/Contents/MacOS/Helper")
        XCTAssertEqual(bundle.is_ui_element, true)
        XCTAssertNil(bundle.is_background_only)
        XCTAssertTrue(bundle.isHidden)
        XCTAssertEqual(infoPlist, try String(contentsOfFile: path + "/Contents/Info.plist", encoding: .utf8))
    }

    /// A binary Info.plist reads the same, and its text is XML.
    func testBinaryInfoPlist() throws {
        let path = try makeBundle(format: .binary)
        let (bundle, infoPlist) = try read(path)
        XCTAssertEqual(bundle.identifier, "com.example.helper")
        XCTAssertEqual(bundle.executable_path, path + "/Contents/MacOS/Helper")
        let text = try XCTUnwrap(infoPlist)
        XCTAssertTrue(text.hasPrefix("<?xml"), text)
        XCTAssertTrue(text.contains("<string>com.example.helper</string>"), text)
    }

    /// Without CFBundleDisplayName, the name is CFBundleName. Empty values are none.
    func testNameFallsBackToBundleName() throws {
        var info = Self.exampleInfo
        info["CFBundleDisplayName"] = ""
        info["CFBundleVersion"] = ""
        let bundle = try read(try makeBundle(info: info)).bundle
        XCTAssertEqual(bundle.name, "Helper")
        XCTAssertNil(bundle.version)
    }

    /// An Info.plist without any of the keys leaves every value `nil`, and a dictionary that isn't one reads none.
    func testMissingKeys() throws {
        let empty = try read(try makeBundle(info: [:])).bundle
        for (key, value) in [("identifier", empty.identifier), ("name", empty.name), ("version", empty.version),
                             ("short_version", empty.short_version), ("executable_path", empty.executable_path)] {
            XCTAssertNil(value, key)
        }
        XCTAssertNil(empty.is_ui_element)
        XCTAssertNil(empty.is_background_only)
        XCTAssertFalse(empty.isHidden)

        let path = try makeBundle(info: nil)
        try Data("not a property list".utf8).write(to: URL(fileURLWithPath: path + "/Contents/Info.plist"))
        let (garbled, text) = try read(path)
        XCTAssertNil(garbled.identifier)
        XCTAssertEqual(text, "not a property list")
    }

    /// LSUIElement and LSBackgroundOnly as Booleans, numbers and strings.
    func testFlagForms() throws {
        let cases: [(Any, Bool?)] = [(true, true), (false, false), (1, true), (0, false), ("1", true), ("YES", true),
                                     ("true", true), ("0", false), ("NO", false), ("no", false), ("maybe", nil),
                                     ([1], nil)]
        for (value, expected) in cases {
            var info = Self.exampleInfo
            info["LSUIElement"] = value
            info["LSBackgroundOnly"] = value
            let bundle = try read(try makeBundle(info: info, format: .binary)).bundle
            XCTAssertEqual(bundle.is_ui_element, expected, "\(value)")
            XCTAssertEqual(bundle.is_background_only, expected, "\(value)")
        }
    }

    /// A shallow bundle's Info.plist and executable are at its top.
    func testShallowBundle() throws {
        let path = try makeBundle("Helper.bundle", shallow: true)
        let bundle = try read(path).bundle
        XCTAssertEqual(bundle.info_plist_path, path + "/Info.plist")
        XCTAssertEqual(bundle.identifier, "com.example.helper")
        XCTAssertEqual(bundle.executable_path, path + "/Helper")
    }

    // MARK: Not bundles

    /// A regular file, a directory without an Info.plist, and a path that's gone (a remove's) aren't bundles.
    func testPathsThatArentBundles() throws {
        let directory = try makeTemporaryDirectory()
        let file = directory.appendingPathComponent("tool")
        try Data("#!/bin/sh\n".utf8).write(to: file)
        XCTAssertNil(LaunchItemBundle.read(at: file.path))
        XCTAssertNil(LaunchItemBundle.read(at: directory.path))
        XCTAssertNil(LaunchItemBundle.read(at: directory.appendingPathComponent("Gone.app").path))
        XCTAssertNil(LaunchItemBundle.read(at: ""))
    }

    /// Read bundles on another thread, failing the test if that takes longer than 10 s, as a read that opened a FIFO
    /// would: it waits for good.
    ///
    /// - Parameter paths: The bundles.
    /// - Returns: Each one's read, or none at all when they didn't finish.
    private func readWithoutHanging(_ paths: [String]) -> [(bundle: LaunchItemBundle, infoPlist: String?)?] {
        let done = expectation(description: "read")
        var results: [(bundle: LaunchItemBundle, infoPlist: String?)?] = []
        DispatchQueue.global().async {
            results = paths.map(LaunchItemBundle.read(at:))
            done.fulfill()
        }
        wait(for: [done], timeout: 10)
        return results
    }

    /// Make a FIFO, replacing any file there.
    ///
    /// - Parameter path: Where.
    private func makeFIFO(_ path: String) {
        try? FileManager.default.removeItem(atPath: path)
        XCTAssertEqual(mkfifo(path, 0o644), 0, errnoText())
    }

    /// A FIFO where the Info.plist or the executable should be is never opened: reading the bundle returns at once,
    /// with what could be read safely and no signature.
    func testFIFOsDontHang() throws {
        let plistFIFO = try makeBundle(info: nil)
        makeFIFO(plistFIFO + "/Contents/Info.plist")
        let executableFIFO = try makeBundle()
        makeFIFO(executableFIFO + "/Contents/MacOS/Helper")

        let results = readWithoutHanging([plistFIFO, executableFIFO])
        guard results.count == 2 else { return }
        let plist = try XCTUnwrap(results[0])
        XCTAssertNil(plist.bundle.identifier)
        XCTAssertNil(plist.infoPlist)
        XCTAssertNil(plist.bundle.codesigning_type)
        XCTAssertEqual(plist.bundle.is_quarantined, 0)
        let executable = try XCTUnwrap(results[1])
        XCTAssertEqual(executable.bundle.identifier, "com.example.helper")
        XCTAssertNil(executable.bundle.codesigning_type)
    }

    /// Without CFBundleExecutable, Security finds the executable as CFBundle does: NSExecutable, else the bundle's name
    /// without its extension, also when the Info.plist doesn't parse. A FIFO there, at a shallow bundle's top, or among
    /// the signature's files of a bundle without an executable, is never opened by Security either.
    func testFIFOsSecurityWouldOpenDontHang() throws {
        var unnamed = Self.exampleInfo
        unnamed["CFBundleExecutable"] = nil
        let byBundleName = try makeBundle(info: unnamed)
        makeFIFO(byBundleName + "/Contents/MacOS/Helper")

        let garbled = try makeBundle(info: nil)
        try Data("not a property list".utf8).write(to: URL(fileURLWithPath: garbled + "/Contents/Info.plist"))
        makeFIFO(garbled + "/Contents/MacOS/Helper")

        var old = unnamed
        old["NSExecutable"] = "Payload"
        let byOldKey = try makeBundle(info: old)
        makeFIFO(byOldKey + "/Contents/MacOS/Payload")

        let shallow = try makeBundle("Helper.bundle", shallow: true)
        makeFIFO(shallow + "/Helper")

        let signature = try makeBundle(info: unnamed)
        let signatureFolder = signature + "/Contents/_CodeSignature"
        try FileManager.default.createDirectory(atPath: signatureFolder, withIntermediateDirectories: true)
        makeFIFO(signatureFolder + "/CodeSignature")

        let paths = [byBundleName, garbled, byOldKey, shallow, signature]
        let results = readWithoutHanging(paths)
        guard results.count == paths.count else { return }
        for (path, result) in zip(paths, results) {
            let bundle = try XCTUnwrap(result, path).bundle
            XCTAssertNil(bundle.codesigning_type, path)
            XCTAssertFalse(LaunchItemBundle.isSafeToReadSignature(at: path), "Security isn't asked to: \(path)")
        }
        XCTAssertTrue(LaunchItemBundle.isSafeToReadSignature(at: try makeBundle()))
        XCTAssertEqual(results[0]?.bundle.executable_path, byBundleName + "/Contents/MacOS/Helper")
        XCTAssertEqual(results[1]?.bundle.executable_path, garbled + "/Contents/MacOS/Helper")
        XCTAssertEqual(results[2]?.bundle.executable_path, byOldKey + "/Contents/MacOS/Payload")
        XCTAssertEqual(results[3]?.bundle.executable_path, shallow + "/Helper")
        XCTAssertNil(results[4]?.bundle.executable_path, "No file is named as the bundle")
    }

    /// An Info.plist longer than the limit is neither read nor handed to Security, which would read it whole.
    func testOversizedInfoPlistIsntSigned() throws {
        let path = try makeBundle()
        let file = try FileHandle(forWritingTo: URL(fileURLWithPath: path + "/Contents/Info.plist"))
        try file.truncate(atOffset: 64 << 20)
        try file.close()
        XCTAssertNil(try read(path).bundle.codesigning_type)
        XCTAssertFalse(LaunchItemBundle.isSafeToReadSignature(at: path))
    }

    /// An Info.plist reached through a symbolic link, whether the plist or `Contents` is the link, isn't read, so a
    /// local user can't have root read a file they can't. Nor is a hard link to a file someone else owns.
    func testLinkedInfoPlistsArentRead() throws {
        let outside = try temporaryFile(containing: "<plist><dict><key>CFBundleIdentifier</key>"
                                        + "<string>com.example.secret</string></dict></plist>", named: "secret.plist")
        let linkedPlist = try makeBundle(info: nil)
        try FileManager.default.createSymbolicLink(atPath: linkedPlist + "/Contents/Info.plist",
                                                   withDestinationPath: outside.path)
        let real = try makeBundle()
        let linkedContents = try makeTemporaryDirectory().appendingPathComponent("Linked.app").path
        try FileManager.default.createDirectory(atPath: linkedContents, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: linkedContents + "/Contents",
                                                   withDestinationPath: real + "/Contents")
        for path in [linkedPlist, linkedContents] {
            let (bundle, infoPlist) = try read(path)
            XCTAssertNil(infoPlist, path)
            XCTAssertNil(bundle.identifier, path)
            XCTAssertNil(bundle.codesigning_type, path)
        }

        let hardLinked = try makeBundle(info: nil)
        let rootOwned = "/private/etc/hosts"
        try XCTSkipUnless(link(rootOwned, hardLinked + "/Contents/Info.plist") == 0,
                          "Can't link \(rootOwned) here: \(errnoText())")
        XCTAssertNil(try read(hardLinked).infoPlist, "A hard link to root's file in a user's bundle")
        XCTAssertNotNil(ProcessHelpers.readContainedRegularFile("hosts", in: "/private/etc"),
                        "The file itself, in its own folder")
    }

    // MARK: Provenance

    /// Quarantine and where-froms are read from the bundle directory, and the birth time is the directory's.
    func testQuarantineWhereFromsAndBirthTime() throws {
        let plain = try read(try makeBundle()).bundle
        XCTAssertEqual(plain.is_quarantined, 0)
        XCTAssertNil(plain.where_froms)

        let path = try makeBundle()
        let origins = ["https://example.com/Helper.zip", "https://example.com/download"]
        quarantine(path)
        try setWhereFroms(origins, on: path)
        let downloaded = try read(path).bundle
        XCTAssertEqual(downloaded.is_quarantined, 1)
        XCTAssertEqual(downloaded.where_froms, origins)

        var info = stat()
        XCTAssertEqual(stat(path, &info), 0)
        XCTAssertEqual(downloaded.birth_time?.tv_sec, info.st_birthtimespec.tv_sec)
        XCTAssertEqual(downloaded.birth_time?.tv_nsec, info.st_birthtimespec.tv_nsec)
        XCTAssertNil(downloaded.age_ms, "An age is derived with the message's time, never read")
    }

    /// A where-froms attribute that isn't an array of strings reads as none, or as its strings.
    func testWhereFromsShapes() throws {
        let path = try makeBundle()
        let text = Data("https://example.com".utf8)
        _ = text.withUnsafeBytes {
            setxattr(path, ProcessHelpers.whereFromsAttribute, $0.baseAddress, text.count, 0, 0)
        }
        XCTAssertNil(ProcessHelpers.whereFroms(at: path))
        let mixed = try PropertyListSerialization.data(fromPropertyList: ["https://example.com", 7] as [Any],
                                                       format: .binary, options: 0)
        _ = mixed.withUnsafeBytes {
            setxattr(path, ProcessHelpers.whereFromsAttribute, $0.baseAddress, mixed.count, 0, 0)
        }
        XCTAssertEqual(ProcessHelpers.whereFroms(at: path), ["https://example.com"])
    }

    // MARK: Signing

    /// A bundle without a signature is UNSIGNED, with no signing or team ID.
    func testUnsignedBundle() throws {
        let bundle = try read(try makeBundle()).bundle
        XCTAssertEqual(bundle.codesigning_type, .unsigned)
        XCTAssertNil(bundle.signing_id)
        XCTAssertNil(bundle.team_id)
    }

    /// Calculator, on any Mac that has it: a platform bundle, signed as com.apple.calculator.
    func testCalculatorIsPlatform() throws {
        let path = "/System/Applications/Calculator.app"
        try XCTSkipUnless(FileManager.default.fileExists(atPath: path), "No Calculator on this Mac")
        let bundle = try read(path).bundle
        XCTAssertEqual(bundle.codesigning_type, .platform)
        XCTAssertEqual(bundle.signing_id, "com.apple.calculator")
        XCTAssertNil(bundle.team_id)
        XCTAssertEqual(bundle.identifier, "com.apple.calculator")
        XCTAssertEqual(bundle.executable_path, path + "/Contents/MacOS/Calculator")
        XCTAssertEqual(bundle.is_quarantined, 0)
        XCTAssertNotNil(bundle.birth_time)
    }

    /// What a signing information dictionary says: a platform identifier, the adhoc flag (with certificates or
    /// without), certificates alone, no identifier.
    func testSigningFromInformation() throws {
        let platform = StaticCodeSigning(information: [kSecCodeInfoIdentifier as String: "com.apple.example",
                                                       kSecCodeInfoPlatformIdentifier as String: 27])
        XCTAssertEqual(platform.type, .platform)
        XCTAssertEqual(platform.signingID, "com.apple.example")
        XCTAssertNil(platform.teamID)
        let adhoc = SecCodeSignatureFlags.adhoc.rawValue
        XCTAssertEqual(StaticCodeSigning(information: [kSecCodeInfoIdentifier as String: "a.out",
                                                       kSecCodeInfoFlags as String: adhoc]).type, .adhoc)
        XCTAssertEqual(StaticCodeSigning(information: [kSecCodeInfoIdentifier as String: "a.out"]).type, .adhoc,
                       "No certificates")
        XCTAssertEqual(StaticCodeSigning(information: [:]).type, .unsigned)
        XCTAssertNil(StaticCodeSigning(path: "/nonexistent/Gone.app"))

        var anchors: CFArray?
        XCTAssertEqual(SecTrustCopyAnchorCertificates(&anchors), errSecSuccess)
        let certificate = try XCTUnwrap((anchors as? [SecCertificate])?.first)
        let summary = try XCTUnwrap(SecCertificateCopySubjectSummary(certificate) as String?)
        let signed: [String: Any] = [kSecCodeInfoIdentifier as String: "com.example.helper",
                                     kSecCodeInfoCertificates as String: [certificate]]
        XCTAssertEqual(StaticCodeSigning(information: signed).type,
                       ProcessHelpers.certificateType(summaries: [summary]), "The certificates decide")
        XCTAssertEqual(StaticCodeSigning(information: signed.merging([kSecCodeInfoFlags as String: adhoc]) { $1 }).type,
                       .adhoc, "The adhoc flag decides before certificates do")
    }

    /// A bundle signed adhoc with `codesign -s -` reads as ADHOC, with its identifier and no team.
    func testAdhocSignedBundle() throws {
        let path = try makeBundle()
        let codesign = Foundation.Process()
        codesign.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        codesign.arguments = ["--sign", "-", "--force", path]
        codesign.standardOutput = FileHandle.nullDevice
        codesign.standardError = FileHandle.nullDevice
        try codesign.run()
        codesign.waitUntilExit()
        try XCTSkipUnless(codesign.terminationStatus == 0, "codesign couldn't sign the test bundle")
        let bundle = try read(path).bundle
        XCTAssertEqual(bundle.codesigning_type, .adhoc)
        XCTAssertEqual(bundle.signing_id, "com.example.helper")
        XCTAssertNil(bundle.team_id)
    }

    /// Certificates name the App Store and Developer ID, and nothing else.
    func testCertificateTypes() {
        XCTAssertEqual(ProcessHelpers.certificateType(summaries: ["Apple Mac OS Application Signing"]), .appStore)
        XCTAssertEqual(ProcessHelpers.certificateType(summaries: ["Developer ID Application: Example (ABCDE12345)",
                                                                   "Developer ID Certification Authority"]),
                       .developerId)
        XCTAssertEqual(ProcessHelpers.certificateType(summaries: ["Apple Development: someone"]), .unknown)
        XCTAssertEqual(ProcessHelpers.certificateType(summaries: []), .unknown)
    }

    // MARK: Cost

    /// What one read of a real bundle costs (Info.plist, signature, quarantine, where-froms and birth time): XCTest
    /// reports the time. Calculator's, which has certificates to evaluate, or a test bundle's without it.
    func testReadCost() throws {
        let calculator = "/System/Applications/Calculator.app"
        let path = FileManager.default.fileExists(atPath: calculator) ? calculator : try makeBundle()
        measure(metrics: [XCTClockMetric()]) {
            XCTAssertNotNil(LaunchItemBundle.read(at: path))
        }
    }
}
