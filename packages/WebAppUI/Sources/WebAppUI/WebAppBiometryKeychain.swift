import Foundation
import Security

enum WebAppBiometryKeychain {
    static let service = "TelegramMiniApp"
    
    static func accountIdentifier(accountId: Int64, botId: Int64) -> String {
        return "account_id_\(accountId)_bot_id_\(botId)"
    }
    
    static func legacyAccountIdentifier(botId: Int64) -> String {
        return "bot_id_\(botId)"
    }
    
    static func query(accountId: Int64, botId: Int64) -> NSMutableDictionary {
        return [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: accountIdentifier(accountId: accountId, botId: botId)
        ]
    }
    
    static func legacyQuery(botId: Int64) -> NSMutableDictionary {
        return [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: legacyAccountIdentifier(botId: botId)
        ]
    }
    
    static func canUpdateToken(accessGranted: Bool) -> Bool {
        return accessGranted
    }
    
    static func canRequestAuthentication(accessGranted: Bool, tokenSaved: Bool) -> Bool {
        return accessGranted && tokenSaved
    }
}

