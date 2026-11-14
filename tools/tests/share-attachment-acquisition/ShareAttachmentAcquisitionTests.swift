import Foundation
import XCTest

__SOURCE__

final class ShareAttachmentAcquisitionTests: XCTestCase {
    private var rootURL: URL!
    private var providerURL: URL!
    private var protectedURL: URL!
    private var temporaryURL: URL!

    override func setUpWithError() throws {
        rootURL = FileManager.default.temporaryDirectory.appendingPathComponent("ShareAttachmentAcquisitionTests-\(UUID().uuidString)", isDirectory: true)
        providerURL = rootURL.appendingPathComponent("provider", isDirectory: true)
        protectedURL = rootURL.appendingPathComponent("group", isDirectory: true)
        temporaryURL = rootURL.appendingPathComponent("extension", isDirectory: true)
        try FileManager.default.createDirectory(at: providerURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: protectedURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: temporaryURL, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: rootURL)
    }

    func testProviderFileIsCopiedIntoExtensionStorage() throws {
        let sourceURL = providerURL.appendingPathComponent("report.pdf")
        let sourceData = Data("provider payload".utf8)
        try sourceData.write(to: sourceURL)

        let copiedURL = ShareAttachmentAcquisition.copyProviderFile(
            at: sourceURL,
            preferredName: "Quarterly Report.pdf",
            protectedRootURLs: [protectedURL],
            temporaryDirectoryURL: temporaryURL
        )

        XCTAssertNotNil(copiedURL)
        XCTAssertTrue(ShareAttachmentAcquisition.contains(copiedURL!, in: temporaryURL))
        XCTAssertEqual(copiedURL?.lastPathComponent, "Quarterly Report.pdf")
        XCTAssertEqual(try Data(contentsOf: copiedURL!), sourceData)
        XCTAssertNotEqual(copiedURL?.standardizedFileURL, sourceURL.standardizedFileURL)
    }

    func testApplicationGroupFilesAndAliasesAreRejected() throws {
        let secretURL = protectedURL.appendingPathComponent("account.db")
        try Data("secret".utf8).write(to: secretURL)
        let aliasURL = providerURL.appendingPathComponent("shared.db")
        try FileManager.default.createSymbolicLink(at: aliasURL, withDestinationURL: secretURL)

        XCTAssertNil(ShareAttachmentAcquisition.copyProviderFile(
            at: secretURL,
            preferredName: nil,
            protectedRootURLs: [protectedURL],
            temporaryDirectoryURL: temporaryURL
        ))
        XCTAssertNil(ShareAttachmentAcquisition.copyProviderFile(
            at: aliasURL,
            preferredName: nil,
            protectedRootURLs: [protectedURL],
            temporaryDirectoryURL: temporaryURL
        ))
    }

    func testFileURLDataCannotBecomeSharedText() {
        let fileURL = protectedURL.appendingPathComponent("account.db")

        XCTAssertNil(ShareAttachmentAcquisition.text(from: fileURL as NSURL))
        XCTAssertNil(ShareAttachmentAcquisition.text(from: Data(fileURL.absoluteString.utf8) as NSData))
        XCTAssertTrue(ShareAttachmentAcquisition.isFileURL(fileURL as NSURL))
        XCTAssertTrue(ShareAttachmentAcquisition.isFileURL(Data(fileURL.absoluteString.utf8) as NSData))
    }

    func testWebURLsRemainShareableText() {
        let url = URL(string: "https://telegram.org/example")!

        XCTAssertEqual(ShareAttachmentAcquisition.text(from: url as NSURL), url.absoluteString)
        XCTAssertEqual(ShareAttachmentAcquisition.text(from: Data(url.absoluteString.utf8) as NSData), url.absoluteString)
    }

    func testSuggestedNameCannotEscapeExtensionStorage() throws {
        let sourceURL = providerURL.appendingPathComponent("payload.bin")
        try Data("payload".utf8).write(to: sourceURL)

        let copiedURL = ShareAttachmentAcquisition.copyProviderFile(
            at: sourceURL,
            preferredName: "../../account.db",
            protectedRootURLs: [protectedURL],
            temporaryDirectoryURL: temporaryURL
        )

        XCTAssertEqual(copiedURL?.lastPathComponent, "account.db")
        XCTAssertTrue(ShareAttachmentAcquisition.contains(copiedURL!, in: temporaryURL))
    }
}

