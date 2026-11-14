import Foundation
import Security
import XCTest
import BuildConfig

final class AppEncryptionDeviceKeyTests: XCTestCase {
    private func makeRoot() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
    private func makeParameters(_ root: URL, _ service: String) -> AppEncryptionParameters {
        AppEncryptionParameters(path: root.path, keychainAccessGroup: nil, keychainService: service)
    }
    private func removeKeychainItems(_ service: String) {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        if #available(macOS 10.15, *) {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        SecItemDelete(query as CFDictionary)
    }
    func testKeychainEnvelopePreservesParametersAcrossRestartAndPasscodeChange() throws {
        let root = try makeRoot(), service = "BuildConfigDeviceTest." + UUID().uuidString
        defer { try? FileManager.default.removeItem(at: root); removeKeychainItems(service) }
        let original = makeParameters(root, service)
        let initial = try XCTUnwrap(original.decrypt())
        let path = root.appendingPathComponent(".tempkeyEncrypted")
        XCTAssertEqual(try Data(contentsOf: path).count, 128)
        let restarted = try XCTUnwrap(makeParameters(root, service).decrypt())
        XCTAssertEqual(restarted.key, initial.key)
        XCTAssertEqual(restarted.salt, initial.salt)
        original.change("1234")
        XCTAssertEqual(try Data(contentsOf: path).count, 144)
        let locked = makeParameters(root, service)
        XCTAssertNil(locked.decrypt())
        locked.applyPasscode("1234")
        let unlocked = try XCTUnwrap(locked.decrypt())
        XCTAssertEqual(unlocked.key, initial.key)
        locked.remove()
        let restored = try XCTUnwrap(makeParameters(root, service).decrypt())
        XCTAssertEqual(restored.key, initial.key)
        XCTAssertEqual(try Data(contentsOf: path).count, 128)
    }
    func testCopiedOrTamperedDeviceEnvelopeDoesNotDecrypt() throws {
        let root = try makeRoot(), copy = try makeRoot(), service = "BuildConfigDeviceTest." + UUID().uuidString
        defer { try? FileManager.default.removeItem(at: root); try? FileManager.default.removeItem(at: copy); removeKeychainItems(service) }
        let original = makeParameters(root, service)
        XCTAssertNotNil(original.decrypt())
        let path = root.appendingPathComponent(".tempkeyEncrypted")
        let data = try Data(contentsOf: path)
        try data.write(to: copy.appendingPathComponent(".tempkeyEncrypted"), options: .atomic)
        XCTAssertNil(makeParameters(copy, service).decrypt())
        var tampered = data
        tampered[tampered.count - 1] ^= 1
        try tampered.write(to: path, options: .atomic)
        XCTAssertNil(makeParameters(root, service).decrypt())
        try data.write(to: path, options: .atomic)
        XCTAssertNotNil(makeParameters(root, service).decrypt())
    }
}
