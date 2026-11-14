import Foundation

enum ShareAttachmentAcquisition {
    static let applicationGroupIdentifiers = [
        "6N38VWS5BX.ru.keepcoder.Telegram.TelegramShare",
        "6N38VWS5BX.ru.keepcoder.Telegram"
    ]

    static func text(from value: NSSecureCoding?) -> String? {
        guard let url = url(from: value), !url.isFileURL else {
            return nil
        }
        return url.absoluteString
    }

    static func isFileURL(_ value: NSSecureCoding?) -> Bool {
        return url(from: value)?.isFileURL == true
    }

    static func protectedRootURLs(fileManager: FileManager = .default) -> [URL] {
        return applicationGroupIdentifiers.compactMap {
            fileManager.containerURL(forSecurityApplicationGroupIdentifier: $0)
        }
    }

    static func contains(_ candidateURL: URL, in rootURL: URL) -> Bool {
        let candidatePath = canonicalURL(candidateURL).path
        let rootPath = canonicalURL(rootURL).path
        return candidatePath == rootPath || candidatePath.hasPrefix(rootPath + "/")
    }

    static func copyProviderFile(
        at sourceURL: URL,
        preferredName: String?,
        fileManager: FileManager = .default,
        protectedRootURLs: [URL]? = nil,
        temporaryDirectoryURL: URL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
    ) -> URL? {
        guard sourceURL.isFileURL else {
            return nil
        }

        let isAccessingSecurityScopedResource = sourceURL.startAccessingSecurityScopedResource()
        defer {
            if isAccessingSecurityScopedResource {
                sourceURL.stopAccessingSecurityScopedResource()
            }
        }

        let canonicalSourceURL = canonicalURL(sourceURL)
        let resolvedProtectedRootURLs: [URL]
        if let providedProtectedRootURLs = protectedRootURLs {
            resolvedProtectedRootURLs = providedProtectedRootURLs
        } else {
            resolvedProtectedRootURLs = self.protectedRootURLs(fileManager: fileManager)
            guard resolvedProtectedRootURLs.count == applicationGroupIdentifiers.count else {
                return nil
            }
        }
        guard !resolvedProtectedRootURLs.contains(where: { contains(canonicalSourceURL, in: $0) }) else {
            return nil
        }

        let resourceKeys: Set<URLResourceKey> = [.isRegularFileKey, .isSymbolicLinkKey]
        guard let sourceValues = try? canonicalSourceURL.resourceValues(forKeys: resourceKeys),
              sourceValues.isRegularFile == true,
              sourceValues.isSymbolicLink != true else {
            return nil
        }

        let canonicalTemporaryDirectoryURL = canonicalURL(temporaryDirectoryURL)
        let destinationDirectoryURL = canonicalTemporaryDirectoryURL.appendingPathComponent("telegram-share-\(UUID().uuidString)", isDirectory: true)
        do {
            try fileManager.createDirectory(at: destinationDirectoryURL, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let destinationURL = destinationDirectoryURL.appendingPathComponent(fileName(preferredName: preferredName, sourceURL: sourceURL), isDirectory: false)
            try fileManager.copyItem(at: canonicalSourceURL, to: destinationURL)

            let canonicalDestinationURL = canonicalURL(destinationURL)
            let destinationValues = try canonicalDestinationURL.resourceValues(forKeys: resourceKeys)
            guard contains(canonicalDestinationURL, in: destinationDirectoryURL),
                  !resolvedProtectedRootURLs.contains(where: { contains(canonicalDestinationURL, in: $0) }),
                  destinationValues.isRegularFile == true,
                  destinationValues.isSymbolicLink != true else {
                try? fileManager.removeItem(at: destinationDirectoryURL)
                return nil
            }
            return canonicalDestinationURL
        } catch {
            try? fileManager.removeItem(at: destinationDirectoryURL)
            return nil
        }
    }

    private static func canonicalURL(_ url: URL) -> URL {
        return url.standardizedFileURL.resolvingSymlinksInPath()
    }

    private static func url(from value: NSSecureCoding?) -> URL? {
        if let value = value as? URL {
            return value
        } else if let data = value as? Data, let string = String(data: data, encoding: .utf8) {
            return URL(string: string)
        } else {
            return nil
        }
    }

    private static func fileName(preferredName: String?, sourceURL: URL) -> String {
        for value in [preferredName, sourceURL.lastPathComponent] {
            guard let value = value else {
                continue
            }
            let fileName = URL(fileURLWithPath: value).lastPathComponent
            if !fileName.isEmpty && fileName != "." && fileName != ".." {
                return fileName
            }
        }
        return UUID().uuidString
    }
}

