import XCTest
import GZIP

final class GZIPTests: XCTestCase {
    private func compressed(_ data: Data) throws -> Data {
        return try XCTUnwrap(TGGZipData(data, -1))
    }

    func testOutputAtLimitIsDecoded() throws {
        let input = Data(repeating: 0x61, count: 16 * 1024)
        let data = try self.compressed(input)
        XCTAssertEqual(TGGUnzipData(data, UInt32(input.count)), input)
    }

    func testOutputOverLimitIsRejected() throws {
        let input = Data([0x61, 0x62])
        let data = try self.compressed(input)
        XCTAssertNil(TGGUnzipData(data, 1))
    }

    func testTruncatedAndCorruptStreamsAreRejected() throws {
        let input = Data("valid gzip data".utf8)
        let data = try self.compressed(input)
        XCTAssertNil(TGGUnzipData(Data(data.dropLast()), 1024))

        var corrupt = data
        corrupt[corrupt.index(before: corrupt.endIndex)] ^= 0xff
        XCTAssertNil(TGGUnzipData(corrupt, 1024))
    }

    func testRepeatedFailuresRemainRejected() throws {
        let overLimit = try self.compressed(Data([0x61, 0x62]))
        let valid = try self.compressed(Data("valid gzip data".utf8))
        let truncated = Data(valid.dropLast())
        for _ in 0 ..< 256 {
            autoreleasepool {
                XCTAssertNil(TGGUnzipData(overLimit, 1))
                XCTAssertNil(TGGUnzipData(truncated, 1024))
            }
        }
    }

    func testValidStreamWithoutLimitIsDecoded() throws {
        let input = Data("valid gzip data".utf8)
        let data = try self.compressed(input)
        XCTAssertEqual(TGGUnzipData(data, 0), input)
    }
}

