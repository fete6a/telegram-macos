import Foundation
import HLSPlayback

private let maximumHLSPlaylistDataLength = 4 * 1024 * 1024
private let maximumHLSPlaylistSegmentCount = 10_000

func validatedHLSMediaPlaylist(data: Data, expectedResourceId: Int64, resourceSize: Int64) -> HLSMediaPlaylist? {
    guard resourceSize > 0, data.count <= maximumHLSPlaylistDataLength, let text = String(data: data, encoding: .utf8) else {
        return nil
    }
    guard hlsPlaylistRangesAreSafeToParse(text, resourceSize: resourceSize), let playlist = try? HLSMediaPlaylist.parse(text) else {
        return nil
    }
    guard playlist.resourceURI == "mtproto:\(expectedResourceId)", playlist.segments.count <= maximumHLSPlaylistSegmentCount, playlist.totalDuration.isFinite else {
        return nil
    }
    guard hlsPlaylistRangeIsValid(playlist.initSegment, resourceSize: resourceSize) else {
        return nil
    }
    guard playlist.segments.allSatisfy({ hlsPlaylistRangeIsValid($0.byteRange, resourceSize: resourceSize) }) else {
        return nil
    }
    return playlist
}

private func hlsPlaylistRangeIsValid(_ range: Range<Int64>, resourceSize: Int64) -> Bool {
    return range.lowerBound >= 0 && range.lowerBound < range.upperBound && range.upperBound <= resourceSize
}

private func hlsPlaylistRangesAreSafeToParse(_ text: String, resourceSize: Int64) -> Bool {
    var pendingSegmentRange: (length: Int64, offset: Int64?)?
    var previousSegmentUpperBound: Int64?
    var segmentCount = 0

    for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
        let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
        if line.hasPrefix("#EXT-X-BYTERANGE:") {
            let value = String(line.dropFirst("#EXT-X-BYTERANGE:".count))
            guard let byteRange = hlsPlaylistByteRange(value) else {
                return false
            }
            pendingSegmentRange = byteRange
        } else if line.hasPrefix("#EXT-X-MAP:") {
            let value = String(line.dropFirst("#EXT-X-MAP:".count))
            let attributes = hlsPlaylistAttributes(value)
            if let byteRangeValue = attributes["BYTERANGE"] {
                guard let byteRange = hlsPlaylistByteRange(byteRangeValue), hlsPlaylistUpperBound(start: byteRange.offset ?? 0, length: byteRange.length, resourceSize: resourceSize) != nil else {
                    return false
                }
            }
        } else if !line.isEmpty && !line.hasPrefix("#") {
            guard let byteRange = pendingSegmentRange else {
                continue
            }
            let start = byteRange.offset ?? previousSegmentUpperBound ?? 0
            guard let upperBound = hlsPlaylistUpperBound(start: start, length: byteRange.length, resourceSize: resourceSize) else {
                return false
            }
            previousSegmentUpperBound = upperBound
            pendingSegmentRange = nil
            segmentCount += 1
            if segmentCount > maximumHLSPlaylistSegmentCount {
                return false
            }
        }
    }
    return true
}

private func hlsPlaylistByteRange(_ value: String) -> (length: Int64, offset: Int64?)? {
    let parts = value.trimmingCharacters(in: .whitespaces).split(separator: "@", maxSplits: 1, omittingEmptySubsequences: false)
    guard let lengthPart = parts.first, let length = Int64(lengthPart), length >= 0 else {
        return nil
    }
    if parts.count == 2 {
        guard let offset = Int64(parts[1]), offset >= 0 else {
            return nil
        }
        return (length, offset)
    }
    return (length, nil)
}

private func hlsPlaylistUpperBound(start: Int64, length: Int64, resourceSize: Int64) -> Int64? {
    guard start >= 0, length >= 0, length <= resourceSize, start <= resourceSize - length else {
        return nil
    }
    return start + length
}

private func hlsPlaylistAttributes(_ value: String) -> [String: String] {
    var result: [String: String] = [:]
    var index = value.startIndex
    while index < value.endIndex {
        guard let equals = value[index...].firstIndex(of: "=") else {
            break
        }
        let key = value[index ..< equals].trimmingCharacters(in: .whitespaces)
        var cursor = value.index(after: equals)
        let attributeValue: String
        if cursor < value.endIndex, value[cursor] == "\"" {
            let valueStart = value.index(after: cursor)
            let closing = value[valueStart...].firstIndex(of: "\"") ?? value.endIndex
            attributeValue = String(value[valueStart ..< closing])
            cursor = closing < value.endIndex ? value.index(after: closing) : closing
        } else {
            let end = value[cursor...].firstIndex(of: ",") ?? value.endIndex
            attributeValue = value[cursor ..< end].trimmingCharacters(in: .whitespaces)
            cursor = end
        }
        result[key] = attributeValue
        if let comma = value[cursor...].firstIndex(of: ",") {
            index = value.index(after: comma)
        } else {
            break
        }
    }
    return result
}

