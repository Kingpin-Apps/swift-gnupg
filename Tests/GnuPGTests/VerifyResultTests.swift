import Testing
import Foundation
@testable import GnuPG

@Suite("VerifyResult Tests")
struct VerifyResultTests {
    
    // MARK: - Mock GPG for testing
    
    private func createMockGPG() throws -> GnuPG {
        // Create a GPG instance for testing VerifyResult
        // Use the actual GPG binary since these are just testing result parsing
        return try GnuPG(gpgBinary: "/opt/homebrew/bin/gpg")
    }
    
    // MARK: - VerifyResult Tests
    
    @Test("VerifyResult trust levels constants")
    func testVerifyResultTrustLevels() {
        #expect(VerifyResult.trustExpired == 0)
        #expect(VerifyResult.trustUndefined == 1)
        #expect(VerifyResult.trustNever == 2)
        #expect(VerifyResult.trustMarginal == 3)
        #expect(VerifyResult.trustFully == 4)
        #expect(VerifyResult.trustUltimate == 5)
        
        #expect(VerifyResult.trustLevels["TRUST_EXPIRED"] == 0)
        #expect(VerifyResult.trustLevels["TRUST_ULTIMATE"] == 5)
        #expect(VerifyResult.trustLevels["TRUST_FULLY"] == 4)
    }
    
    @Test("VerifyResult error codes")
    func testVerifyResultErrorCodes() {
        #expect(VerifyResult.gpgSystemErrorCodes[1] == "permission denied")
        #expect(VerifyResult.gpgSystemErrorCodes[81] == "file not found")
        #expect(VerifyResult.gpgErrorCodes[11] == "incorrect passphrase")
    }
    
    @Test("VerifyResult status message handling - GOODSIG")
    func testVerifyResultGoodSig() throws {
        let gpg = try createMockGPG()
        let result = VerifyResult(gpg: gpg)
        
        result.handleStatus(key: "GOODSIG", value: "1234567890ABCDEF John Doe <john@example.com>")
        
        #expect(result.valid)
        #expect(result.status == "signature good")
        #expect(result.keyId == "1234567890ABCDEF")
        #expect(result.username == "John Doe <john@example.com>")
    }
    
    @Test("VerifyResult status message handling - BADSIG")
    func testVerifyResultBadSig() throws {
        let gpg = try createMockGPG()
        let result = VerifyResult(gpg: gpg)
        
        result.handleStatus(key: "BADSIG", value: "1234567890ABCDEF John Doe <john@example.com>")
        
        #expect(!result.valid)
        #expect(result.status == "signature bad")
        #expect(result.keyId == "1234567890ABCDEF")
        #expect(result.username == "John Doe <john@example.com>")
        #expect(!result.problems.isEmpty)
    }
    
    @Test("VerifyResult status message handling - VALIDSIG")
    func testVerifyResultValidSig() throws {
        let gpg = try createMockGPG()
        let result = VerifyResult(gpg: gpg)
        
        let validSigValue = "ABCDEF1234567890FEDCBA0987654321 2023-10-01 1696118400 0 4 0 1 8 00 FEDCBA0987654321ABCDEF1234567890"
        result.handleStatus(key: "VALIDSIG", value: validSigValue)
        
        #expect(result.fingerprint == "ABCDEF1234567890FEDCBA0987654321")
        #expect(result.creationDate == "2023-10-01")
        #expect(result.sigTimestamp == "1696118400")
        #expect(result.expireTimestamp == "0")
        #expect(result.status == "signature valid")
    }
    
    @Test("VerifyResult status message handling - ERRSIG")
    func testVerifyResultErrSig() throws {
        let gpg = try createMockGPG()
        let result = VerifyResult(gpg: gpg)
        
        result.handleStatus(key: "ERRSIG", value: "1234567890ABCDEF 1 8 00 1696118400 2 FEDCBA0987654321")
        
        #expect(!result.valid)
        #expect(result.status == "signature error")
        #expect(result.keyId == "1234567890ABCDEF")
        #expect(result.timestamp == "1696118400")
        #expect(result.fingerprint == "FEDCBA0987654321")
        #expect(!result.problems.isEmpty)
    }
    
    @Test("VerifyResult status message handling - NO_PUBKEY")
    func testVerifyResultNoPubkey() throws {
        let gpg = try createMockGPG()
        let result = VerifyResult(gpg: gpg)
        
        result.handleStatus(key: "NO_PUBKEY", value: "1234567890ABCDEF")
        
        #expect(!result.valid)
        #expect(result.status == "no public key")
        #expect(result.keyId == "1234567890ABCDEF")
        #expect(!result.problems.isEmpty)
    }
    
    @Test("VerifyResult status message handling - EXPSIG")
    func testVerifyResultExpSig() throws {
        let gpg = try createMockGPG()
        let result = VerifyResult(gpg: gpg)
        
        result.handleStatus(key: "EXPSIG", value: "1234567890ABCDEF John Doe <john@example.com>")
        
        #expect(!result.valid)
        #expect(result.status == "signature expired")
        #expect(result.keyId == "1234567890ABCDEF")
        #expect(result.username == "John Doe <john@example.com>")
        #expect(!result.problems.isEmpty)
    }
    
    @Test("VerifyResult status message handling - Trust levels")
    func testVerifyResultTrustLevelHandling() throws {
        let gpg = try createMockGPG()
        let result = VerifyResult(gpg: gpg)
        
        // Set up a signature ID first
        result.handleStatus(key: "SIG_ID", value: "ABC123 2023-10-01 1696118400")
        
        result.handleStatus(key: "TRUST_ULTIMATE", value: "")
        
        #expect(result.trustText == "TRUST_ULTIMATE")
        #expect(result.trustLevel == 5)
        #expect(result.signatureId == nil) // Should be cleared after processing trust
    }
    
    @Test("VerifyResult status message handling - SIG_ID")
    func testVerifyResultSigId() throws {
        let gpg = try createMockGPG()
        let result = VerifyResult(gpg: gpg)
        
        result.handleStatus(key: "SIG_ID", value: "ABC123 2023-10-01 1696118400")
        
        #expect(result.signatureId == "ABC123")
        #expect(result.creationDate == "2023-10-01")
        #expect(result.timestamp == "1696118400")
        #expect(result.sigInfo["ABC123"] != nil)
    }
    
    @Test("VerifyResult status message handling - Key status")
    func testVerifyResultKeyStatus() throws {
        let gpg = try createMockGPG()
        let result = VerifyResult(gpg: gpg)
        
        // Test expired key signature
        result.handleStatus(key: "EXPKEYSIG", value: "1234567890ABCDEF John Doe <john@example.com>")
        
        #expect(!result.valid)
        #expect(result.status == "signing key has expired")
        #expect(result.keyId == "1234567890ABCDEF")
        #expect(result.username == "John Doe <john@example.com>")
        #expect(result.keyStatus == "signing key has expired")
    }
    
    @Test("VerifyResult status message handling - Revoked key")
    func testVerifyResultRevokedKey() throws {
        let gpg = try createMockGPG()
        let result = VerifyResult(gpg: gpg)
        
        // Test revoked key signature  
        result.handleStatus(key: "REVKEYSIG", value: "1234567890ABCDEF John Doe <john@example.com>")
        
        #expect(!result.valid)
        #expect(result.status == "signing key was revoked")
        #expect(result.keyId == "1234567890ABCDEF")
        #expect(result.username == "John Doe <john@example.com>")
        #expect(result.keyStatus == "signing key was revoked")
    }
    
    @Test("VerifyResult status message handling - NODATA")
    func testVerifyResultNoData() throws {
        let gpg = try createMockGPG()
        let result = VerifyResult(gpg: gpg)
        
        result.handleStatus(key: "NODATA", value: "")
        
        #expect(!result.valid)
        #expect(result.status == "signature expected but not found")
    }
    
    @Test("VerifyResult status message handling - FAILURE with error codes")
    func testVerifyResultFailureWithErrorCodes() throws {
        let gpg = try createMockGPG()
        let result = VerifyResult(gpg: gpg)
        
        // Test system error (with 0x8000 flag)
        result.handleStatus(key: "FAILURE", value: "test_operation 32849") // 32849 = 0x8051 (system error for file not found)
        
        #expect(!result.valid)
        #expect(result.status?.contains("file not found") == true)
    }
    
    @Test("VerifyResult sigInfo management")
    func testVerifyResultSigInfoManagement() throws {
        let gpg = try createMockGPG()
        let result = VerifyResult(gpg: gpg)
        
        // Set up signature ID
        result.handleStatus(key: "SIG_ID", value: "TEST123 2023-10-01 1696118400")
        
        // Add a GOODSIG which should update sigInfo
        result.handleStatus(key: "GOODSIG", value: "ABCD1234 Test User <test@example.com>")
        
        #expect(result.sigInfo["TEST123"] != nil)
        #expect(result.sigInfo["TEST123"]?["keyid"] as? String == "ABCD1234")
        #expect(result.sigInfo["TEST123"]?["username"] as? String == "Test User <test@example.com>")
        #expect(result.sigInfo["TEST123"]?["status"] as? String == "signature good")
    }
}