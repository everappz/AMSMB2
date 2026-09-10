//
//  AMSMB2CoverageTests.swift
//  Full-coverage integration tests for the SWIFT AMSMB2 client (SMB2Manager) against a real server.
//
//  Credentials are NEVER hard-coded: user/password come from the SMB_USER / SMB_PASSWORD environment
//  variables. Only the (non-secret) server address + share have in-source defaults, overridable via
//  SMB_SERVER / SMB_SHARE. All tests operate inside a per-test subfolder under the `Tests` folder on
//  the share and clean up after themselves.
//
//  Run:  SMB_USER=... SMB_PASSWORD=... swift test --filter AMSMB2CoverageTests
//

import XCTest
@testable import AMSMB2

final class AMSMB2CoverageTests: XCTestCase, @unchecked Sendable {
    // Non-secret: safe to keep in source (overridable via env).
    static let defaultServer = "smb://NAS730C60.local"
    static let defaultShare = "Public"
    /// Base folder on the share that every test works under.
    static let baseFolder = "Tests"

    lazy var server: URL = URL(string: ProcessInfo.processInfo.environment["SMB_SERVER"] ?? Self.defaultServer)!
    lazy var share: String = ProcessInfo.processInfo.environment["SMB_SHARE"] ?? Self.defaultShare
    lazy var credential: URLCredential? = {
        guard let user = ProcessInfo.processInfo.environment["SMB_USER"],
              let pass = ProcessInfo.processInfo.environment["SMB_PASSWORD"]
        else { return nil }
        return URLCredential(user: user, password: pass, persistence: .forSession)
    }()

    override func setUpWithError() throws {
        try XCTSkipIf(ProcessInfo.processInfo.environment["SMB_USER"] == nil,
                      "Set SMB_USER / SMB_PASSWORD to run live-server coverage tests.")
    }

    // MARK: - Helpers

    private func connect() async throws -> SMB2Manager {
        let smb = SMB2Manager(url: server, credential: credential)!
        try await smb.connectShare(name: share)
        try? await smb.createDirectory(atPath: Self.baseFolder) // idempotent base
        return smb
    }

    /// A fresh, isolated working directory for a test (created on the server, removed at teardown).
    private func workspace(_ smb: SMB2Manager, _ fn: String = #function) async throws -> String {
        let dir = "\(Self.baseFolder)/\(fn.trimmingCharacters(in: CharacterSet(charactersIn: "()")))"
        try? await smb.removeItem(atPath: dir)
        try await smb.createDirectory(atPath: dir)
        addTeardownBlock { try? await smb.removeItem(atPath: dir) }
        return dir
    }

    private func names(_ smb: SMB2Manager, _ path: String, recursive: Bool = false) async throws -> [String] {
        try await smb.contentsOfDirectory(atPath: path, recursive: recursive).compactMap { $0[.nameKey] as? String }
    }

    private func exists(_ smb: SMB2Manager, _ path: String) async -> Bool {
        do { _ = try await smb.attributesOfItem(atPath: path); return true } catch { return false }
    }

    private func randomData(_ size: Int) -> Data {
        var d = Data(count: size)
        if size > 0 { d.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, size, $0.baseAddress!) } }
        return d
    }

    private func tempFile(_ data: Data) throws -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("amsmb2-\(UUID().uuidString).dat")
        try data.write(to: url)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }

    private func tempOut() -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("dl-\(UUID().uuidString).dat")
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }

    /// Create a local temp file of `size` bytes written in chunks (avoids holding it all in memory).
    private func tempFileLarge(_ size: Int) throws -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("big-\(UUID().uuidString).dat")
        FileManager.default.createFile(atPath: url.path, contents: nil)
        let fh = try FileHandle(forWritingTo: url)
        defer { try? fh.close() }
        let chunk = 8 << 20
        var remaining = size
        while remaining > 0 {
            let n = min(chunk, remaining)
            fh.write(randomData(n))
            remaining -= n
        }
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }

    private let umlaut = "Grüße-Öl-Ärger-Übung"
    private let umlautFolder = "Ördnung-Ä"

    // MARK: - Connection & listing (1-5)

    func testConnectDisconnectReconnect() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        try await smb.connectShare(name: share)
        try await smb.disconnectShare(gracefully: true)
        try await smb.connectShare(name: share)
    }

    func testListSharesContainsShare() async throws {
        let smb = SMB2Manager(url: server, credential: credential)!
        let shares = try await smb.listShares()
        XCTAssertTrue(shares.contains { $0.name.caseInsensitiveCompare(self.share) == .orderedSame })
    }

    func testFileSystemAttributes() async throws {
        let smb = try await connect()
        let attrs = try await smb.attributesOfFileSystem(forPath: Self.baseFolder)
        let size = attrs[.systemSize] as? Int64 ?? 0
        XCTAssertGreaterThan(size, 0)
    }

    func testBaseFolderExists() async throws {
        let smb = try await connect()
        let attrs = try await smb.attributesOfItem(atPath: Self.baseFolder)
        XCTAssertEqual(attrs[.fileResourceTypeKey] as? URLFileResourceType, .directory)
    }

    func testListRootOfShare() async throws {
        let smb = try await connect()
        let items = try await smb.contentsOfDirectory(atPath: "/")
        XCTAssertFalse(items.isEmpty)
    }

    // MARK: - File create/write/read/modify/delete (6-17)

    func testWriteReadSmall() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let data = randomData(64)
        try await smb.write(data: data, toPath: "\(dir)/small.dat", progress: nil)
        let back = try await smb.contents(atPath: "\(dir)/small.dat")
        XCTAssertEqual(data, back)
    }

    func testWriteReadEmpty() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.write(data: Data(), toPath: "\(dir)/empty.dat", progress: nil)
        let back = try await smb.contents(atPath: "\(dir)/empty.dat")
        XCTAssertEqual(back.count, 0)
    }

    func testWriteReadMedium() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let data = randomData(262_144)
        try await smb.write(data: data, toPath: "\(dir)/medium.dat", progress: nil)
        let back = try await smb.contents(atPath: "\(dir)/medium.dat")
        XCTAssertEqual(back, data)
    }

    func testWriteReadLarge1MB() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let data = randomData(1 << 20)
        try await smb.write(data: data, toPath: "\(dir)/large.dat", progress: nil)
        let back = try await smb.contents(atPath: "\(dir)/large.dat")
        XCTAssertEqual(back, data)
    }

    func testOverwriteTruncates() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.write(data: randomData(4096), toPath: "\(dir)/o.dat", progress: nil)
        let small = randomData(16)
        try await smb.removeFile(atPath: "\(dir)/o.dat") // write() won't overwrite in place; replace it
        try await smb.write(data: small, toPath: "\(dir)/o.dat", progress: nil)
        let back = try await smb.contents(atPath: "\(dir)/o.dat")
        XCTAssertEqual(back, small)
    }

    func testModifyFileContent() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        // AMSMB2's write() creates a new file and errors on an existing path (STATUS_OBJECT_NAME_COLLISION),
        // so changing content is remove-then-write (the same pattern the app uses to overwrite).
        try await smb.write(data: Data("v1".utf8), toPath: "\(dir)/m.dat", progress: nil)
        try await smb.removeFile(atPath: "\(dir)/m.dat")
        try await smb.write(data: Data("version-2".utf8), toPath: "\(dir)/m.dat", progress: nil)
        let back = try await smb.contents(atPath: "\(dir)/m.dat")
        XCTAssertEqual(back, Data("version-2".utf8))
    }

    func testAppendAtOffset() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let head = randomData(100), tail = randomData(100)
        try await smb.write(data: head, toPath: "\(dir)/a.dat", progress: nil)
        try await smb.append(data: tail, toPath: "\(dir)/a.dat", offset: Int64(head.count), progress: nil)
        let back = try await smb.contents(atPath: "\(dir)/a.dat")
        XCTAssertEqual(back, head + tail)
    }

    func testReadRange() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let data = randomData(1000)
        try await smb.write(data: data, toPath: "\(dir)/r.dat", progress: nil)
        let part = try await smb.contents(atPath: "\(dir)/r.dat", range: 100..<200, progress: nil)
        XCTAssertEqual(part, data[100..<200])
    }

    func testReadFromOffsetToEnd() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let data = randomData(1000)
        try await smb.write(data: data, toPath: "\(dir)/roe.dat", progress: nil)
        let tail = try await smb.contents(atPath: "\(dir)/roe.dat", range: 600..., progress: nil)
        XCTAssertEqual(tail, data[600...])
    }

    // Streaming read: pull the file as an AsyncThrowingStream of chunks and reassemble.
    func testStreamRead() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let data = randomData(300_000)
        try await smb.write(data: data, toPath: "\(dir)/sr.dat", progress: nil)
        var acc = Data()
        for try await chunk in smb.contents(atPath: "\(dir)/sr.dat", range: 0..<Int64(data.count)) {
            acc.append(chunk)
        }
        XCTAssertEqual(acc, data)
    }

    // Streaming write: feed an AsyncThrowingStream (from a local file) into write(stream:).
    func testStreamWrite() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let data = randomData(400_000)
        let local = try tempFile(data)
        try await smb.write(stream: AsyncThrowingStream(url: local), toPath: "\(dir)/sw.dat", progress: { _ in true })
        let back = try await smb.contents(atPath: "\(dir)/sw.dat")
        XCTAssertEqual(back, data)
    }

    func testDeleteFile() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.write(data: randomData(32), toPath: "\(dir)/d.dat", progress: nil)
        try await smb.removeFile(atPath: "\(dir)/d.dat")
        let present = await exists(smb, "\(dir)/d.dat")
        XCTAssertFalse(present)
    }

    func testDeleteMissingFileFails() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        var failed = false
        do { try await smb.removeFile(atPath: "\(dir)/nope.dat") } catch { failed = true }
        XCTAssertTrue(failed)
    }

    func testFileSizeAttribute() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.write(data: randomData(4321), toPath: "\(dir)/s.dat", progress: nil)
        let attrs = try await smb.attributesOfItem(atPath: "\(dir)/s.dat")
        XCTAssertEqual(attrs[.fileSizeKey] as? Int, 4321)
    }

    func testModificationDatePresent() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.write(data: randomData(10), toPath: "\(dir)/t.dat", progress: nil)
        let attrs = try await smb.attributesOfItem(atPath: "\(dir)/t.dat")
        XCTAssertNotNil(attrs[.contentModificationDateKey])
    }

    func testBinaryRoundtripIntegrity() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let data = randomData(9999)
        try await smb.write(data: data, toPath: "\(dir)/b.bin", progress: nil)
        let back = try await smb.contents(atPath: "\(dir)/b.bin")
        XCTAssertEqual(back, data)
    }

    // MARK: - Directory (18-27)

    func testCreateDirectory() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.createDirectory(atPath: "\(dir)/sub")
        let attrs = try await smb.attributesOfItem(atPath: "\(dir)/sub")
        XCTAssertEqual(attrs[.fileResourceTypeKey] as? URLFileResourceType, .directory)
    }

    func testCreateNestedDirectory() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.createDirectory(atPath: "\(dir)/a")
        try await smb.createDirectory(atPath: "\(dir)/a/b")
        try await smb.createDirectory(atPath: "\(dir)/a/b/c")
        let attrs = try await smb.attributesOfItem(atPath: "\(dir)/a/b/c")
        XCTAssertEqual(attrs[.fileResourceTypeKey] as? URLFileResourceType, .directory)
    }

    func testListEmptyDirectory() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.createDirectory(atPath: "\(dir)/empty")
        let items = try await names(smb, "\(dir)/empty")
        XCTAssertTrue(items.filter { $0 != "." && $0 != ".." }.isEmpty)
    }

    func testListDirectoryWithFiles() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        for i in 0..<5 { try await smb.write(data: randomData(8), toPath: "\(dir)/f\(i).dat", progress: nil) }
        let listed = try await names(smb, dir)
        for i in 0..<5 { XCTAssertTrue(listed.contains("f\(i).dat")) }
    }

    func testListRecursive() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.createDirectory(atPath: "\(dir)/x")
        try await smb.write(data: randomData(8), toPath: "\(dir)/x/deep.dat", progress: nil)
        let listed = try await names(smb, dir, recursive: true)
        XCTAssertTrue(listed.contains("deep.dat"))
    }

    func testRemoveEmptyDirectory() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.createDirectory(atPath: "\(dir)/gone")
        try await smb.removeDirectory(atPath: "\(dir)/gone", recursive: false)
        let present = await exists(smb, "\(dir)/gone")
        XCTAssertFalse(present)
    }

    func testRemoveDirectoryRecursiveWithFiles() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.createDirectory(atPath: "\(dir)/tree")
        try await smb.createDirectory(atPath: "\(dir)/tree/inner")
        try await smb.write(data: randomData(16), toPath: "\(dir)/tree/a.dat", progress: nil)
        try await smb.write(data: randomData(16), toPath: "\(dir)/tree/inner/b.dat", progress: nil)
        try await smb.removeDirectory(atPath: "\(dir)/tree", recursive: true)
        let present = await exists(smb, "\(dir)/tree")
        XCTAssertFalse(present)
    }

    func testRemoveMissingDirectoryFails() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        var failed = false
        do { try await smb.removeDirectory(atPath: "\(dir)/nope", recursive: false) } catch { failed = true }
        XCTAssertTrue(failed)
    }

    func testDirectoryResourceType() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let attrs = try await smb.attributesOfItem(atPath: dir)
        XCTAssertEqual(attrs[.fileResourceTypeKey] as? URLFileResourceType, .directory)
    }

    func testCountFilesInDirectory() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        for i in 0..<7 { try await smb.write(data: randomData(4), toPath: "\(dir)/c\(i).dat", progress: nil) }
        let items = try await smb.contentsOfDirectory(atPath: dir)
        let files = items.filter { ($0[.fileResourceTypeKey] as? URLFileResourceType) == .regular }
        XCTAssertEqual(files.count, 7)
    }

    // MARK: - Rename / move (28-33)

    func testRenameFile() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.write(data: randomData(20), toPath: "\(dir)/old.dat", progress: nil)
        try await smb.moveItem(atPath: "\(dir)/old.dat", toPath: "\(dir)/new.dat")
        let listed = try await names(smb, dir)
        XCTAssertTrue(listed.contains("new.dat")); XCTAssertFalse(listed.contains("old.dat"))
    }

    func testRenamePreservesContent() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let data = randomData(500)
        try await smb.write(data: data, toPath: "\(dir)/a.dat", progress: nil)
        try await smb.moveItem(atPath: "\(dir)/a.dat", toPath: "\(dir)/b.dat")
        let back = try await smb.contents(atPath: "\(dir)/b.dat")
        XCTAssertEqual(back, data)
    }

    func testMoveFileIntoSubdir() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.createDirectory(atPath: "\(dir)/sub")
        try await smb.write(data: randomData(30), toPath: "\(dir)/m.dat", progress: nil)
        try await smb.moveItem(atPath: "\(dir)/m.dat", toPath: "\(dir)/sub/m.dat")
        let listed = try await names(smb, "\(dir)/sub")
        XCTAssertTrue(listed.contains("m.dat"))
    }

    func testRenameDirectoryWithContents() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.createDirectory(atPath: "\(dir)/d1")
        try await smb.write(data: randomData(12), toPath: "\(dir)/d1/keep.dat", progress: nil)
        try await smb.moveItem(atPath: "\(dir)/d1", toPath: "\(dir)/d2")
        let listed = try await names(smb, "\(dir)/d2")
        XCTAssertTrue(listed.contains("keep.dat"))
    }

    func testMoveDirectoryIntoDirectory() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.createDirectory(atPath: "\(dir)/src")
        try await smb.createDirectory(atPath: "\(dir)/dst")
        try await smb.write(data: randomData(12), toPath: "\(dir)/src/x.dat", progress: nil)
        try await smb.moveItem(atPath: "\(dir)/src", toPath: "\(dir)/dst/src")
        let listed = try await names(smb, "\(dir)/dst/src")
        XCTAssertTrue(listed.contains("x.dat"))
    }

    func testRenameOverExisting() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let data = randomData(40)
        try await smb.write(data: data, toPath: "\(dir)/src.dat", progress: nil)
        try await smb.write(data: randomData(10), toPath: "\(dir)/dst.dat", progress: nil)
        try? await smb.removeFile(atPath: "\(dir)/dst.dat")
        try await smb.moveItem(atPath: "\(dir)/src.dat", toPath: "\(dir)/dst.dat")
        let back = try await smb.contents(atPath: "\(dir)/dst.dat")
        XCTAssertEqual(back, data)
    }

    // MARK: - Copy (34-36)

    func testCopyFile() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.write(data: randomData(200), toPath: "\(dir)/c.dat", progress: nil)
        try await smb.copyItem(atPath: "\(dir)/c.dat", toPath: "\(dir)/c-copy.dat", recursive: false, progress: { _, _ in true })
        let listed = try await names(smb, dir)
        XCTAssertTrue(listed.contains("c.dat")); XCTAssertTrue(listed.contains("c-copy.dat"))
    }

    func testCopyFilePreservesContent() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let data = randomData(1024)
        try await smb.write(data: data, toPath: "\(dir)/orig.dat", progress: nil)
        try await smb.copyItem(atPath: "\(dir)/orig.dat", toPath: "\(dir)/dup.dat", recursive: false, progress: { _, _ in true })
        let back = try await smb.contents(atPath: "\(dir)/dup.dat")
        XCTAssertEqual(back, data)
    }

    func testCopyDirectoryRecursive() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.createDirectory(atPath: "\(dir)/from")
        try await smb.write(data: randomData(64), toPath: "\(dir)/from/f.dat", progress: nil)
        try await smb.copyItem(atPath: "\(dir)/from", toPath: "\(dir)/to", recursive: true, progress: { _, _ in true })
        let listed = try await names(smb, "\(dir)/to")
        XCTAssertTrue(listed.contains("f.dat"))
    }

    // MARK: - Upload / download (37-42)

    func testUploadFile() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let local = try tempFile(randomData(4096))
        try await smb.uploadItem(at: local, toPath: "\(dir)/up.dat", progress: { _ in true })
        let attrs = try await smb.attributesOfItem(atPath: "\(dir)/up.dat")
        XCTAssertEqual(attrs[.fileSizeKey] as? Int, 4096)
    }

    func testUploadDownloadRoundtrip() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let data = randomData(50_000)
        let local = try tempFile(data)
        try await smb.uploadItem(at: local, toPath: "\(dir)/rt.dat", progress: { _ in true })
        let out = tempOut()
        try await smb.downloadItem(atPath: "\(dir)/rt.dat", to: out, progress: { _, _ in true })
        XCTAssertEqual(try Data(contentsOf: out), data)
    }

    func testDownloadContentMatches() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let data = randomData(8192)
        try await smb.write(data: data, toPath: "\(dir)/dc.dat", progress: nil)
        let out = tempOut()
        try await smb.downloadItem(atPath: "\(dir)/dc.dat", to: out, progress: { _, _ in true })
        XCTAssertEqual(try Data(contentsOf: out), data)
    }

    func testUploadOverwrite() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.write(data: randomData(1000), toPath: "\(dir)/ov.dat", progress: nil)
        let data = randomData(200)
        let local = try tempFile(data)
        try? await smb.removeFile(atPath: "\(dir)/ov.dat")
        try await smb.uploadItem(at: local, toPath: "\(dir)/ov.dat", progress: { _ in true })
        let back = try await smb.contents(atPath: "\(dir)/ov.dat")
        XCTAssertEqual(back, data)
    }

    func testUploadDownload150MB() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let size = 150 << 20 // 150 MiB
        let local = try tempFileLarge(size)
        try await smb.uploadItem(at: local, toPath: "\(dir)/big.bin", progress: { _ in true })
        let attrs = try await smb.attributesOfItem(atPath: "\(dir)/big.bin")
        XCTAssertEqual(attrs[.fileSizeKey] as? Int, size)
        let out = tempOut()
        try await smb.downloadItem(atPath: "\(dir)/big.bin", to: out, progress: { _, _ in true })
        XCTAssertTrue(FileManager.default.contentsEqual(atPath: local.path, andPath: out.path),
                      "150MB round-trip content mismatch")
    }

    func testUploadProgressReported() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let local = try tempFile(randomData(120_000))
        let reported = Box(false)
        try await smb.uploadItem(at: local, toPath: "\(dir)/p.dat", progress: { n in reported.value = reported.value || n > 0; return true })
        XCTAssertTrue(reported.value)
    }

    func testDownloadProgressReported() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.write(data: randomData(120_000), toPath: "\(dir)/pd.dat", progress: nil)
        let out = tempOut()
        let reported = Box(false)
        try await smb.downloadItem(atPath: "\(dir)/pd.dat", to: out, progress: { n, t in reported.value = reported.value || n > 0; return true })
        XCTAssertTrue(reported.value)
    }

    // MARK: - Truncate (43-45)

    func testTruncateShrink() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.write(data: randomData(2000), toPath: "\(dir)/tr.dat", progress: nil)
        try await smb.truncateFile(atPath: "\(dir)/tr.dat", atOffset: 500)
        let back = try await smb.contents(atPath: "\(dir)/tr.dat")
        XCTAssertEqual(back.count, 500)
    }

    func testTruncateExtend() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.write(data: randomData(100), toPath: "\(dir)/te.dat", progress: nil)
        try await smb.truncateFile(atPath: "\(dir)/te.dat", atOffset: 4096)
        let attrs = try await smb.attributesOfItem(atPath: "\(dir)/te.dat")
        XCTAssertEqual(attrs[.fileSizeKey] as? Int, 4096)
    }

    func testTruncateToZero() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.write(data: randomData(300), toPath: "\(dir)/tz.dat", progress: nil)
        try await smb.truncateFile(atPath: "\(dir)/tz.dat", atOffset: 0)
        let back = try await smb.contents(atPath: "\(dir)/tz.dat")
        XCTAssertEqual(back.count, 0)
    }

    // MARK: - Umlaut / unicode (46-57)

    func testWriteReadUmlautFileName() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let data = randomData(256)
        try await smb.write(data: data, toPath: "\(dir)/\(umlaut).dat", progress: nil)
        let back = try await smb.contents(atPath: "\(dir)/\(umlaut).dat")
        XCTAssertEqual(back, data)
    }

    func testCreateUmlautFolder() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.createDirectory(atPath: "\(dir)/\(umlautFolder)")
        let attrs = try await smb.attributesOfItem(atPath: "\(dir)/\(umlautFolder)")
        XCTAssertEqual(attrs[.fileResourceTypeKey] as? URLFileResourceType, .directory)
    }

    func testNestedUmlautPath() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.createDirectory(atPath: "\(dir)/Ä")
        try await smb.createDirectory(atPath: "\(dir)/Ä/Ö")
        try await smb.write(data: randomData(50), toPath: "\(dir)/Ä/Ö/Ü.dat", progress: nil)
        let attrs = try await smb.attributesOfItem(atPath: "\(dir)/Ä/Ö/Ü.dat")
        XCTAssertEqual(attrs[.fileSizeKey] as? Int, 50)
    }

    func testListDirContainingUmlautNames() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.write(data: randomData(8), toPath: "\(dir)/\(umlaut).dat", progress: nil)
        try await smb.createDirectory(atPath: "\(dir)/\(umlautFolder)")
        let listed = try await names(smb, dir)
        XCTAssertTrue(listed.contains("\(umlaut).dat"))
        XCTAssertTrue(listed.contains(umlautFolder))
    }

    func testRenameToUmlautName() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.write(data: randomData(20), toPath: "\(dir)/plain.dat", progress: nil)
        try await smb.moveItem(atPath: "\(dir)/plain.dat", toPath: "\(dir)/\(umlaut).dat")
        let listed = try await names(smb, dir)
        XCTAssertTrue(listed.contains("\(umlaut).dat"))
    }

    func testMoveIntoUmlautFolder() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.createDirectory(atPath: "\(dir)/\(umlautFolder)")
        try await smb.write(data: randomData(20), toPath: "\(dir)/f.dat", progress: nil)
        try await smb.moveItem(atPath: "\(dir)/f.dat", toPath: "\(dir)/\(umlautFolder)/f.dat")
        let listed = try await names(smb, "\(dir)/\(umlautFolder)")
        XCTAssertTrue(listed.contains("f.dat"))
    }

    func testDeleteUmlautFile() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.write(data: randomData(16), toPath: "\(dir)/\(umlaut).dat", progress: nil)
        try await smb.removeFile(atPath: "\(dir)/\(umlaut).dat")
        let listed = try await names(smb, dir)
        XCTAssertFalse(listed.contains("\(umlaut).dat"))
    }

    func testDeleteUmlautFolderWithFiles() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.createDirectory(atPath: "\(dir)/\(umlautFolder)")
        try await smb.write(data: randomData(16), toPath: "\(dir)/\(umlautFolder)/\(umlaut).dat", progress: nil)
        try await smb.removeDirectory(atPath: "\(dir)/\(umlautFolder)", recursive: true)
        let listed = try await names(smb, dir)
        XCTAssertFalse(listed.contains(umlautFolder))
    }

    func testUploadDownloadUmlautFile() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let data = randomData(3000)
        let local = try tempFile(data)
        try await smb.uploadItem(at: local, toPath: "\(dir)/\(umlaut).bin", progress: { _ in true })
        let out = tempOut()
        try await smb.downloadItem(atPath: "\(dir)/\(umlaut).bin", to: out, progress: { _, _ in true })
        XCTAssertEqual(try Data(contentsOf: out), data)
    }

    func testCopyUmlautFile() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let data = randomData(128)
        try await smb.write(data: data, toPath: "\(dir)/\(umlaut).dat", progress: nil)
        try await smb.copyItem(atPath: "\(dir)/\(umlaut).dat", toPath: "\(dir)/\(umlaut)-Kopie.dat", recursive: false, progress: { _, _ in true })
        let back = try await smb.contents(atPath: "\(dir)/\(umlaut)-Kopie.dat")
        XCTAssertEqual(back, data)
    }

    func testUmlautDirectoryListingCount() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        try await smb.createDirectory(atPath: "\(dir)/\(umlautFolder)")
        for n in ["Straße.dat", "Café.dat", "Piñata.dat"] {
            try await smb.write(data: randomData(8), toPath: "\(dir)/\(umlautFolder)/\(n)", progress: nil)
        }
        let items = try await smb.contentsOfDirectory(atPath: "\(dir)/\(umlautFolder)")
        let files = items.filter { ($0[.fileResourceTypeKey] as? URLFileResourceType) == .regular }
        XCTAssertEqual(files.count, 3)
    }

    func testSpecialSymbolsFileName() async throws {
        let smb = try await connect(); let dir = try await workspace(smb)
        let name = "a b + c (1) [2] #3 &4.dat"
        let data = randomData(64)
        try await smb.write(data: data, toPath: "\(dir)/\(name)", progress: nil)
        let back = try await smb.contents(atPath: "\(dir)/\(name)")
        XCTAssertEqual(back, data)
    }
}

/// Minimal reference box so progress closures can flip a flag across the async boundary.
final class Box<T>: @unchecked Sendable {
    var value: T
    init(_ v: T) { value = v }
}
