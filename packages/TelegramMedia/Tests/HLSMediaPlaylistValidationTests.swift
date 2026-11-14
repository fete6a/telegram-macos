import Foundation
import XCTest
import HLSPlayback
@testable import TelegramMedia

final class HLSMediaPlaylistValidationTests: XCTestCase {
    private func playlistData(resourceURI: String = "mtproto:42", initRange: String = "100@0", segmentRanges: [String] = ["200@100", "200@300"]) -> Data {
        var lines = [
            "#EXTM3U",
            "#EXT-X-MAP:URI=\"\(resourceURI)\",BYTERANGE=\"\(initRange)\"",
        ]
        for range in segmentRanges {
            lines.append("#EXTINF:5.0,")
            lines.append("#EXT-X-BYTERANGE:\(range)")
            lines.append(resourceURI)
        }
        return Data((lines + ["#EXT-X-ENDLIST"]).joined(separator: "\n").utf8)
    }

    func testAcceptsValidResourceRanges() throws {
        let playlist = try XCTUnwrap(validatedHLSMediaPlaylist(data: self.playlistData(), expectedResourceId: 42, resourceSize: 500))
        XCTAssertEqual(playlist.initSegment, 0 ..< 100)
        XCTAssertEqual(playlist.prefixRange(seconds: 10.0), 0 ..< 500)
    }

    func testAcceptsImplicitAndDerivedRanges() throws {
        let implicitPlaylist = try XCTUnwrap(validatedHLSMediaPlaylist(data: self.playlistData(segmentRanges: ["200@100", "200"]), expectedResourceId: 42, resourceSize: 500))
        XCTAssertEqual(implicitPlaylist.segments[1].byteRange, 300 ..< 500)

        let mappedText = try XCTUnwrap(String(data: self.playlistData(), encoding: .utf8))
        let derivedText = mappedText.replacingOccurrences(of: "#EXT-X-MAP:URI=\"mtproto:42\",BYTERANGE=\"100@0\"\n", with: "")
        let derivedPlaylist = try XCTUnwrap(validatedHLSMediaPlaylist(data: Data(derivedText.utf8), expectedResourceId: 42, resourceSize: 500))
        XCTAssertEqual(derivedPlaylist.initSegment, 0 ..< 100)
    }

    func testRejectsWrongResource() {
        XCTAssertNil(validatedHLSMediaPlaylist(data: self.playlistData(resourceURI: "mtproto:43"), expectedResourceId: 42, resourceSize: 500))
    }

    func testRejectsMalformedAndOverflowingRanges() {
        XCTAssertNil(validatedHLSMediaPlaylist(data: self.playlistData(segmentRanges: ["invalid"]), expectedResourceId: 42, resourceSize: 500))
        XCTAssertNil(validatedHLSMediaPlaylist(data: self.playlistData(segmentRanges: ["100@9223372036854775800"]), expectedResourceId: 42, resourceSize: 500))
    }

    func testRejectsIncompleteMedia() {
        XCTAssertNil(validatedHLSMediaPlaylist(data: self.playlistData(), expectedResourceId: 42, resourceSize: 499))
        XCTAssertNil(validatedHLSMediaPlaylist(data: self.playlistData(initRange: "501@0"), expectedResourceId: 42, resourceSize: 500))
        XCTAssertNil(validatedHLSMediaPlaylist(data: self.playlistData(segmentRanges: ["100@500", "100@200"]), expectedResourceId: 42, resourceSize: 500))
    }

    func testRejectsExcessiveSegmentCount() {
        XCTAssertNil(validatedHLSMediaPlaylist(data: self.playlistData(segmentRanges: Array(repeating: "1@0", count: 10_001)), expectedResourceId: 42, resourceSize: 500))
    }
}

