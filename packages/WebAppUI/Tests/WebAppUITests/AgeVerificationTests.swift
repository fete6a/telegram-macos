import XCTest
@testable import WebAppUI

final class AgeVerificationTests: XCTestCase {
    func testReportedFailureDoesNotPass() {
        XCTAssertFalse(isAgeVerificationPassed(reportedPassed: false, reportedAge: 21, minimumAge: 18))
    }

    func testUnderMinimumAgeDoesNotPass() {
        XCTAssertFalse(isAgeVerificationPassed(reportedPassed: true, reportedAge: 17, minimumAge: 18))
    }

    func testQualifyingVerificationPasses() {
        XCTAssertTrue(isAgeVerificationPassed(reportedPassed: true, reportedAge: 18, minimumAge: 18))
    }
}

