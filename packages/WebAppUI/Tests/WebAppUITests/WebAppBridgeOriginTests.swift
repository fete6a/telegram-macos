import XCTest
@testable import WebAppUI

final class WebAppBridgeOriginTests: XCTestCase {
    private let trustedOrigin = "https://miniapp.example"

    func testCrossOriginNavigationRevokesBridgeAuthority() {
        for destinationOrigin in ["https://redirect.example", "https://form.example", "https://script.example"] {
            XCTAssertFalse(webAppShouldAcceptMessage(isMainFrame: true, messageOrigin: destinationOrigin, currentOrigin: destinationOrigin, trustedOrigin: trustedOrigin))
            XCTAssertFalse(webAppShouldAcceptMessage(isMainFrame: true, messageOrigin: trustedOrigin, currentOrigin: destinationOrigin, trustedOrigin: trustedOrigin))
            XCTAssertFalse(webAppShouldDeliverEvent(currentOrigin: destinationOrigin, trustedOrigin: trustedOrigin))
        }
    }

    func testIframeCannotInvokeBridge() {
        XCTAssertFalse(webAppShouldAcceptMessage(isMainFrame: false, messageOrigin: trustedOrigin, currentOrigin: trustedOrigin, trustedOrigin: trustedOrigin))
    }

    func testSameOriginBridgeBehaviorRemainsAvailable() {
        XCTAssertTrue(webAppShouldAcceptMessage(isMainFrame: true, messageOrigin: trustedOrigin, currentOrigin: trustedOrigin, trustedOrigin: trustedOrigin))
        XCTAssertTrue(webAppShouldAcceptMessage(isMainFrame: true, messageOrigin: trustedOrigin, currentOrigin: nil, trustedOrigin: trustedOrigin))
        XCTAssertTrue(webAppShouldDeliverEvent(currentOrigin: trustedOrigin, trustedOrigin: trustedOrigin))
    }

    func testCallbackScriptRechecksDocumentOrigin() {
        let script = webAppSecuredEventSource(name: "location_requested", data: "{\"available\":true}", trustedOrigin: trustedOrigin)

        XCTAssertTrue(script.contains("window.location.origin !== \"https://miniapp.example\""))
        XCTAssertTrue(script.contains("window.TelegramGameProxy.receiveEvent(\"location_requested\", {\"available\":true})"))
    }

    func testProxyInjectionChecksDocumentOrigin() {
        let script = webAppSecuredEventProxySource(trustedOrigin: trustedOrigin)

        XCTAssertTrue(script.contains("window.location.origin !== \"https://miniapp.example\""))
        XCTAssertTrue(script.contains("window.TelegramWebviewProxy = new TelegramWebviewProxyProto()"))
    }

    func testOriginNormalizationPreservesDefaultPorts() {
        XCTAssertEqual(webAppOrigin(scheme: "HTTPS", host: "MINIAPP.EXAMPLE", port: 443), trustedOrigin)
        XCTAssertEqual(webAppOrigin(scheme: "https", host: "miniapp.example", port: 8443), "https://miniapp.example:8443")
    }

    func testMissingTrustedOriginFailsClosed() {
        XCTAssertFalse(webAppShouldAcceptMessage(isMainFrame: true, messageOrigin: trustedOrigin, currentOrigin: trustedOrigin, trustedOrigin: nil))
        XCTAssertFalse(webAppShouldDeliverEvent(currentOrigin: trustedOrigin, trustedOrigin: nil))
    }
}

