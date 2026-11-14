import XCTest
@testable import WebAppUI

final class WebAppBiometryKeychainTests: XCTestCase {
    func testSameBotIsIsolatedAcrossAccounts() {
        let firstAccount = WebAppBiometryKeychain.accountIdentifier(accountId: 100, botId: 300)
        let secondAccount = WebAppBiometryKeychain.accountIdentifier(accountId: 200, botId: 300)
        XCTAssertNotEqual(firstAccount, secondAccount)
    }
    
    func testDifferentBotsAreIsolatedWithinAccount() {
        let firstBot = WebAppBiometryKeychain.accountIdentifier(accountId: 100, botId: 300)
        let secondBot = WebAppBiometryKeychain.accountIdentifier(accountId: 100, botId: 400)
        XCTAssertNotEqual(firstBot, secondBot)
    }
    
    func testLegacyIdentifierCannotMatchScopedIdentifier() {
        let legacy = WebAppBiometryKeychain.legacyAccountIdentifier(botId: 300)
        let scoped = WebAppBiometryKeychain.accountIdentifier(accountId: 100, botId: 300)
        XCTAssertNotEqual(legacy, scoped)
    }
    
    func testAuthenticationRequiresConsentAndTokenState() {
        XCTAssertTrue(WebAppBiometryKeychain.canRequestAuthentication(accessGranted: true, tokenSaved: true))
        XCTAssertFalse(WebAppBiometryKeychain.canRequestAuthentication(accessGranted: false, tokenSaved: true))
        XCTAssertFalse(WebAppBiometryKeychain.canRequestAuthentication(accessGranted: true, tokenSaved: false))
        XCTAssertFalse(WebAppBiometryKeychain.canRequestAuthentication(accessGranted: false, tokenSaved: false))
    }
    
    func testTokenUpdateRequiresConsent() {
        XCTAssertTrue(WebAppBiometryKeychain.canUpdateToken(accessGranted: true))
        XCTAssertFalse(WebAppBiometryKeychain.canUpdateToken(accessGranted: false))
    }
}

