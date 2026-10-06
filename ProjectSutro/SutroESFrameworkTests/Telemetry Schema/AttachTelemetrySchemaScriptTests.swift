//
//  AttachTelemetrySchemaScriptTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import SutroESFramework


// MARK: - Attaching the schema to a release
/// Runs `ProjectSutro/Scripts/attach-telemetry-schema.sh` against a stand-in for `gh` and a scratch repository with a
/// tag, to pin what it guards: Mac-Monitor.pkg stays the release's first asset (Mac Monitor's update check installs
/// the first) under GitHub's order by name, the schema attached is the one committed at the tag and is never replaced,
/// and the schema's version must be listed with its SHA-256 in `Schema/released-versions.txt`.
final class AttachTelemetrySchemaScriptTests: XCTestCase {
    /// The release's tag in the scratch repository.
    private static let tag = "v9.9.9"
    /// The installer, which must stay the release's first asset.
    private static let pkg = "Mac-Monitor.pkg"
    /// The schema's name on the release.
    private static let asset = TelemetrySchema.releaseAssetName
    /// The repository the script attaches to.
    private static let repository = "Brandon7CC/mac-monitor"
    
    /// A stand-in for `gh` that logs each call to `$STATE/calls` and keeps the release's assets in `$STATE/assets` as
    /// the REST API lists them, a line each: the name, a tab, and the digest. GitHub lists assets by name, ignoring
    /// case, so an upload is sorted in; with `FAKE_GH_UPLOADS_FIRST` set it's listed first instead. Like `gh release
    /// upload` without `--clobber`, it refuses a name that's taken.
    private static let fakeGH = """
        #!/bin/zsh
        print -r -- "$*" >> "$STATE/calls"
        case "$1 $2" in
            "release view") print 42 ;;
            "api repos/\(repository)/releases/42") /bin/cat "$STATE/assets" ;;
            "release upload")
                name="${4:t}"
                if /usr/bin/cut -f 1 "$STATE/assets" | /usr/bin/grep -qxF -- "$name"; then
                    print -r -- "an asset named $name already exists" >&2; exit 1
                fi
                line="$name"$'\t'"sha256:$(/usr/bin/shasum -a 256 "$4" | /usr/bin/cut -d ' ' -f 1)"
                if [[ -n "${FAKE_GH_UPLOADS_FIRST:-}" ]]; then
                    { print -r -- "$line"; /bin/cat "$STATE/assets" } > "$STATE/listed"
                else
                    { /bin/cat "$STATE/assets"; print -r -- "$line" } | LC_ALL=C /usr/bin/sort -f > "$STATE/listed"
                fi
                /bin/mv "$STATE/listed" "$STATE/assets"
                /bin/cp "$4" "$STATE/uploaded" ;;
            *) print -r -- "unexpected gh call: $*" >&2; exit 2 ;;
        esac
        """
    
    /// What one run of the script did.
    private struct Run {
        /// Its exit status.
        let status: Int32
        /// What it wrote to standard output.
        let output: String
        /// What it wrote to standard error.
        let errors: String
        /// The stand-in `gh`'s arguments, a call to a line.
        let calls: [String]
        /// The names of the release's assets afterwards, as GitHub lists them.
        let assets: [String]
        /// The bytes uploaded, if any were.
        let uploaded: Data?
        
        /// Did the script upload anything?
        var uploadedAnything: Bool { calls.contains { $0.hasPrefix("release upload") } }
    }
    
    /// The scratch folder: `repo` (the scratch repository), `bin` (the stand-in `gh`) and `state` (its state).
    private var root: URL!
    
    /// The committed schema, which the scratch repository commits at its tag.
    private var schema: Data { get throws { try Data(contentsOf: Self.schemaFileURL) } }
    
    /// The line `Schema/released-versions.txt` must have for the committed schema: its version and SHA-256.
    private var releasedLine: String { get throws { "\(TelemetrySchema.version) \(try Self.schemaSHA256)" } }
    
    /// Make the scratch folder, the stand-in `gh`, and the scratch repository with the script in it.
    ///
    /// - Throws: The error making them.
    override func setUpWithError() throws {
        root = try makeTemporaryDirectory()
        let bin = root.appendingPathComponent("bin"), state = root.appendingPathComponent("state")
        for folder in [bin, state, repo("Schema"), repo("ProjectSutro/Scripts")] {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        }
        try write(Self.fakeGH, to: bin.appendingPathComponent("gh"), executable: true)
        try FileManager.default.copyItem(at: Self.scriptURL, to: repo(Self.scriptPath))
        try schema.write(to: repo("Schema/\(TelemetrySchema.fileName)"))
    }
    
    // MARK: Attaching
    
    /// With the pkg first, the tag's schema (not the working tree's) is uploaded under its name on the release, which
    /// GitHub lists after the pkg.
    ///
    /// - Throws: The error setting up or running the script.
    func testAttachesTheTagsSchemaAfterThePackage() throws {
        try commitAndTag(released: [try releasedLine])
        try Data("{}".utf8).write(to: repo("Schema/\(TelemetrySchema.fileName)"))
        
        let run = try attach(assets: [Self.pkg, "notes.txt"])
        XCTAssertEqual(run.status, 0, run.errors)
        XCTAssertEqual(run.assets, [Self.pkg, Self.asset, "notes.txt"])
        XCTAssertEqual(run.uploaded, try schema, "The schema committed at the tag")
        let upload = try XCTUnwrap(run.calls.first { $0.hasPrefix("release upload") })
        XCTAssertTrue(upload.hasPrefix("release upload \(Self.tag) /"), upload)
        XCTAssertTrue(upload.hasSuffix("/\(Self.asset) --repo \(Self.repository)"), upload)
        XCTAssertEqual(run.output, "Attached telemetry \(TelemetrySchema.version) (\(try Self.schemaSHA256)) to "
                       + "\(Self.tag) as \(Self.asset). Assets: \(Self.pkg) \(Self.asset) notes.txt\n")
    }
    
    /// Attaching the same schema again changes nothing and uploads nothing.
    ///
    /// - Throws: The error setting up or running the script.
    func testAttachingAgainChangesNothing() throws {
        try commitAndTag(released: [try releasedLine])
        let assets = [Self.pkg, Self.asset]
        let run = try attach(assets: assets, digests: [Self.asset: "sha256:\(try Self.schemaSHA256)"])
        XCTAssertEqual(run.status, 0, run.errors)
        XCTAssertFalse(run.uploadedAnything)
        XCTAssertEqual(run.assets, assets)
        XCTAssertEqual(run.output, "Telemetry \(TelemetrySchema.version) (\(try Self.schemaSHA256)) is already "
                       + "attached to \(Self.tag). Assets: \(Self.pkg) \(Self.asset)\n")
    }
    
    // MARK: Refusing
    
    /// Another schema attached under the same name is refused, never replaced: replacing deletes the attached one
    /// first, and a failed upload would leave the release without a schema.
    ///
    /// - Throws: The error setting up or running the script.
    func testRefusesToReplaceAnotherSchema() throws {
        try commitAndTag(released: [try releasedLine])
        let other = "sha256:" + String(repeating: "0", count: 64)
        let run = try attach(assets: [Self.pkg, Self.asset], digests: [Self.asset: other])
        XCTAssertEqual(run.status, 1)
        XCTAssertEqual(run.errors, "Another \(Self.asset) is attached to \(Self.tag): delete it on the release page, "
                       + "then run this again.\n")
        XCTAssertFalse(run.uploadedAnything)
        XCTAssertEqual(run.assets, [Self.pkg, Self.asset])
    }
    
    /// Until Mac-Monitor.pkg is the first asset, nothing is uploaded.
    ///
    /// - Throws: The error setting up or running the script.
    func testRefusesUntilThePackageIsFirst() throws {
        try commitAndTag(released: [try releasedLine])
        for assets in [[], [Self.asset], ["Install-Notes.txt", Self.pkg], [TelemetrySchema.fileName, Self.pkg]] {
            let run = try attach(assets: assets)
            XCTAssertEqual(run.status, 1, "\(assets)")
            XCTAssertTrue(run.errors.hasPrefix("Upload \(Self.pkg) to \(Self.tag) first"), run.errors)
            XCTAssertFalse(run.uploadedAnything, "\(assets)")
            XCTAssertEqual(run.assets, assets)
        }
    }
    
    /// A name GitHub would list before the pkg is refused before uploading: the repository's own file name,
    /// `mac-monitor-telemetry.schema.json`, sorts first, since `-` comes before `.`.
    ///
    /// - Throws: The error setting up or running the script.
    func testRefusesANameThatSortsBeforeThePackage() throws {
        try commitAndTag(released: [try releasedLine])
        let script = try String(contentsOf: repo(Self.scriptPath), encoding: .utf8)
        let named = "ASSET=\"\(Self.asset)\""
        XCTAssertTrue(script.contains(named), "The script names the asset as TelemetrySchema does")
        try write(script.replacingOccurrences(of: named, with: "ASSET=\"\(TelemetrySchema.fileName)\""),
                  to: repo(Self.scriptPath), executable: true)
        
        let run = try attach(assets: [Self.pkg])
        XCTAssertEqual(run.status, 1)
        XCTAssertEqual(run.errors, "GitHub would list \(TelemetrySchema.fileName) before \(Self.pkg), which must stay "
                       + "the release's first asset: rename the asset.\n")
        XCTAssertFalse(run.uploadedAnything)
        XCTAssertEqual(run.assets, [Self.pkg])
    }
    
    /// A schema whose version isn't listed with its SHA-256 at the tag (listed with another file's, or not at all)
    /// is refused before asking GitHub anything: a released version's schema never changes.
    ///
    /// - Throws: The error setting up or running the script.
    func testRefusesAVersionThatIsNotListed() throws {
        let other = "\(TelemetrySchema.version) \(String(repeating: "0", count: 64))"
        try commitAndTag(released: ["# A comment", other])
        let run = try attach(assets: [Self.pkg])
        XCTAssertEqual(run.status, 1)
        XCTAssertEqual(run.errors, "Schema/released-versions.txt at \(Self.tag) must list the schema's version and "
                       + "SHA-256: \(try releasedLine)\n")
        XCTAssertEqual(run.calls, [])
        XCTAssertEqual(run.assets, [Self.pkg])
    }
    
    /// A tag that isn't in the repository is refused before asking GitHub anything.
    ///
    /// - Throws: The error setting up or running the script.
    func testRefusesATagThatIsNotHere() throws {
        try commitAndTag(released: [try releasedLine])
        let run = try attach(assets: [Self.pkg], tag: "v0.0.0")
        XCTAssertEqual(run.status, 1)
        XCTAssertTrue(run.errors.hasPrefix("There's no tag v0.0.0 in "), run.errors)
        XCTAssertEqual(run.calls, [])
    }
    
    /// If GitHub lists the schema first after all (its order changed), the script says so and fails.
    ///
    /// - Throws: The error setting up or running the script.
    func testChecksTheOrderAfterUploading() throws {
        try commitAndTag(released: [try releasedLine])
        let run = try attach(assets: [Self.pkg], environment: ["FAKE_GH_UPLOADS_FIRST": "1"])
        XCTAssertEqual(run.status, 1)
        XCTAssertEqual(run.errors, "Check \(Self.tag)'s assets: \(Self.pkg) must be first, beside \(Self.asset). "
                       + "Assets now: \(Self.asset) \(Self.pkg)\n")
    }
    
    /// The script in the repository can be run as it is.
    func testScriptIsExecutable() {
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: Self.scriptURL.path))
    }
    
    // MARK: Helpers
    
    /// The script's path in a repository.
    private static let scriptPath = "ProjectSutro/Scripts/attach-telemetry-schema.sh"
    /// The script in the repository.
    private static var scriptURL: URL { repositoryURL.appendingPathComponent(scriptPath) }
    
    /// A path in the scratch repository.
    ///
    /// - Parameter path: The path, relative to the repository.
    /// - Returns: Its URL.
    private func repo(_ path: String) -> URL { root.appendingPathComponent("repo").appendingPathComponent(path) }
    
    /// Write text to a file.
    ///
    /// - Parameters:
    ///   - text: The text.
    ///   - url: The file.
    ///   - executable: Make the file executable.
    /// - Throws: The error writing the file.
    private func write(_ text: String, to url: URL, executable: Bool = false) throws {
        try Data(text.utf8).write(to: url)
        guard executable else { return }
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
    }
    
    /// Commit the scratch repository, with these lines in `Schema/released-versions.txt`, and tag it.
    ///
    /// - Parameter released: The lines.
    /// - Throws: The error writing the file or running `git`.
    private func commitAndTag(released: [String]) throws {
        try write(released.joined(separator: "\n") + "\n", to: repo("Schema/released-versions.txt"))
        for arguments in [["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "Release"], ["tag", Self.tag]] {
            let status = try run("/usr/bin/git", ["-C", repo("").path, "-c", "user.name=Test",
                                                  "-c", "user.email=test@example.invalid"] + arguments).status
            XCTAssertEqual(status, 0, "git \(arguments.joined(separator: " "))")
        }
    }
    
    /// Run the script in the scratch repository against the stand-in `gh`.
    ///
    /// - Parameters:
    ///   - assets: The names of the release's assets beforehand, as GitHub lists them.
    ///   - digests: Their digests, by name: `null` for those not named.
    ///   - tag: The tag to attach to.
    ///   - environment: More environment variables for the stand-in `gh`.
    /// - Returns: What the run did.
    /// - Throws: The error setting up or running the script.
    private func attach(assets: [String], digests: [String: String] = [:],
                        tag: String = AttachTelemetrySchemaScriptTests.tag,
                        environment: [String: String] = [:]) throws -> Run {
        let state = root.appendingPathComponent("state")
        let listing = assets.map { "\($0)\t\(digests[$0] ?? "null")\n" }.joined()
        try write(listing, to: state.appendingPathComponent("assets"))
        for name in ["calls", "uploaded"] {
            try? FileManager.default.removeItem(at: state.appendingPathComponent(name))
        }
        let (status, output, errors) = try run(repo(Self.scriptPath).path, [tag], environment: environment)
        let calls = (try? String(contentsOf: state.appendingPathComponent("calls"), encoding: .utf8)) ?? ""
        let listed = try String(contentsOf: state.appendingPathComponent("assets"), encoding: .utf8)
        return Run(status: status, output: output, errors: errors,
                   calls: calls.split(separator: "\n").map(String.init),
                   assets: listed.split(separator: "\n").map { String($0.prefix { $0 != "\t" }) },
                   uploaded: try? Data(contentsOf: state.appendingPathComponent("uploaded")))
    }
    
    /// Run a program with only the stand-in `gh`, the system's tools, and no `git` configuration of the user's.
    ///
    /// - Parameters:
    ///   - path: The program.
    ///   - arguments: Its arguments.
    ///   - environment: More environment variables.
    /// - Returns: Its exit status, standard output and standard error.
    /// - Throws: The error starting it.
    private func run(_ path: String, _ arguments: [String],
                     environment: [String: String] = [:]) throws -> (status: Int32, output: String, errors: String) {
        let output = root.appendingPathComponent("stdout"), errors = root.appendingPathComponent("stderr")
        FileManager.default.createFile(atPath: output.path, contents: nil)
        FileManager.default.createFile(atPath: errors.path, contents: nil)
        let process = Foundation.Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        var variables = ["PATH": "\(root.appendingPathComponent("bin").path):/usr/bin:/bin",
                         "STATE": root.appendingPathComponent("state").path, "HOME": root.path,
                         "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"]
        variables["DEVELOPER_DIR"] = ProcessInfo.processInfo.environment["DEVELOPER_DIR"]
        process.environment = variables.merging(environment) { $1 }
        process.standardOutput = try FileHandle(forWritingTo: output)
        process.standardError = try FileHandle(forWritingTo: errors)
        try process.run()
        process.waitUntilExit()
        return (process.terminationStatus, try String(contentsOf: output, encoding: .utf8),
                try String(contentsOf: errors, encoding: .utf8))
    }
}
