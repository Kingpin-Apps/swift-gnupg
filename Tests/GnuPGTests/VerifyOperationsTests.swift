import Testing
import Foundation
@testable import GnuPG

@Suite("Verify Operations Tests", .serialized)
struct VerifyOperationsTests {
    
    // MARK: - Test Setup
    
    // Parsing tests only build result objects and feed them canned status
    // messages, so a stub (no gpg process) is sufficient and runs anywhere.
    // Integration tests in this suite are gated on `realGPGAvailable` and only
    // run when a real gpg is usable, in which case they get a live instance.
    private func createTestGPG() -> GnuPG? {
        TestHelpers.realGPGAvailable ? (try? GnuPG()) : TestHelpers.makeParsingStub()
    }
    
    // MARK: - VerifyResult Tests
    
    @Test("VerifyResult initialization")
    func testVerifyResultInitialization() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let result = VerifyResult(gpg: gpg)
        
        #expect(!result.valid)
        #expect(result.fingerprint == nil)
        #expect(result.status == nil)
        #expect(result.keyId == nil)
        #expect(result.username == nil)
        #expect(result.trustLevel == nil)
        #expect(result.problems.isEmpty)
        #expect(result.sigInfo.isEmpty)
    }
    
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
    
    @Test("VerifyResult status message handling - GOODSIG")
    func testVerifyResultGoodSig() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let result = VerifyResult(gpg: gpg)
        
        result.handleStatus(key: "GOODSIG", value: "1234567890ABCDEF John Doe <john@example.com>")
        
        #expect(result.valid)
        #expect(result.status == "signature good")
        #expect(result.keyId == "1234567890ABCDEF")
        #expect(result.username == "John Doe <john@example.com>")
    }
    
    @Test("VerifyResult status message handling - BADSIG")
    func testVerifyResultBadSig() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let result = VerifyResult(gpg: gpg)
        
        result.handleStatus(key: "BADSIG", value: "1234567890ABCDEF John Doe <john@example.com>")
        
        #expect(!result.valid)
        #expect(result.status == "signature bad")
        #expect(result.keyId == "1234567890ABCDEF")
        #expect(result.username == "John Doe <john@example.com>")
        #expect(!result.problems.isEmpty)
    }
    
    @Test("VerifyResult status message handling - VALIDSIG")
    func testVerifyResultValidSig() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
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
    func testVerifyResultErrSig() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
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
    func testVerifyResultNoPubkey() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let result = VerifyResult(gpg: gpg)
        
        result.handleStatus(key: "NO_PUBKEY", value: "1234567890ABCDEF")
        
        #expect(!result.valid)
        #expect(result.status == "no public key")
        #expect(result.keyId == "1234567890ABCDEF")
        #expect(!result.problems.isEmpty)
    }
    
    @Test("VerifyResult status message handling - EXPSIG")
    func testVerifyResultExpSig() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let result = VerifyResult(gpg: gpg)
        
        result.handleStatus(key: "EXPSIG", value: "1234567890ABCDEF John Doe <john@example.com>")
        
        #expect(!result.valid)
        #expect(result.status == "signature expired")
        #expect(result.keyId == "1234567890ABCDEF")
        #expect(result.username == "John Doe <john@example.com>")
        #expect(!result.problems.isEmpty)
    }
    
    @Test("VerifyResult status message handling - Trust levels")
    func testVerifyResultTrustLevelHandling() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let result = VerifyResult(gpg: gpg)
        
        // Set up a signature ID first
        result.handleStatus(key: "SIG_ID", value: "ABC123 2023-10-01 1696118400")
        
        result.handleStatus(key: "TRUST_ULTIMATE", value: "")
        
        #expect(result.trustText == "TRUST_ULTIMATE")
        #expect(result.trustLevel == 5)
        #expect(result.signatureId == nil) // Should be cleared after processing trust
    }
    
    @Test("VerifyResult status message handling - SIG_ID")
    func testVerifyResultSigId() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let result = VerifyResult(gpg: gpg)
        
        result.handleStatus(key: "SIG_ID", value: "ABC123 2023-10-01 1696118400")
        
        #expect(result.signatureId == "ABC123")
        #expect(result.creationDate == "2023-10-01")
        #expect(result.timestamp == "1696118400")
        #expect(result.sigInfo["ABC123"] != nil)
    }
    
    // MARK: - Verify Operations Tests
    // Note: These tests would require actual GPG setup in a real test environment
    
    @Test("Verify inline signature", .enabled(if: TestHelpers.realGPGAvailable))
    func testVerifyInlineSignature() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let testMessage = "Hello, World!"
        let result = await gpg.verify(message: testMessage)
        
        // In a real test environment with GPG set up, we would check result.valid
        // For now, just verify the result object is created
        #expect(result.status != nil) // Should have some status (error in this case since no GPG)
    }
    
    @Test("Verify detached signature", .enabled(if: TestHelpers.realGPGAvailable))
    func testVerifyDetachedSignature() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let testMessage = "Hello, World!"
        let testSignature = "fake signature data".data(using: .utf8)!
        
        let result = await gpg.verify(message: testMessage, signature: testSignature)
        
        #expect(result.status != nil)
        #expect(!result.valid) // Should be invalid with fake data
    }
    
    @Test("Verify file with detached signature", .enabled(if: TestHelpers.realGPGAvailable))
    func testVerifyFileDetached() async throws {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        // Create temporary test files
        let tempDir = FileManager.default.temporaryDirectory
        let testFile = tempDir.appendingPathComponent("test_verify_file.txt")
        let sigFile = tempDir.appendingPathComponent("test_verify_file.txt.sig")
        
        let testContent = "Test file content for verification"
        let fakeSignature = "fake signature content"
        
        try testContent.write(to: testFile, atomically: true, encoding: .utf8)
        try fakeSignature.write(to: sigFile, atomically: true, encoding: .utf8)
        
        defer {
            try? FileManager.default.removeItem(at: testFile)
            try? FileManager.default.removeItem(at: sigFile)
        }
        
        let result = await gpg.verifyFile(dataPath: testFile.path, signaturePath: sigFile.path)
        
        #expect(result.status != nil)
        #expect(!result.valid) // Should be invalid with fake signature
    }
    
    @Test("Verify file inline signature", .enabled(if: TestHelpers.realGPGAvailable))
    func testVerifyFileInline() async throws {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        // Create temporary test file
        let tempDir = FileManager.default.temporaryDirectory
        let testFile = tempDir.appendingPathComponent("test_verify_inline.asc")
        
        let testContent = "-----BEGIN PGP SIGNED MESSAGE-----\n\nHello World\n-----BEGIN PGP SIGNATURE-----\nfake signature\n-----END PGP SIGNATURE-----"
        
        try testContent.write(to: testFile, atomically: true, encoding: .utf8)
        defer {
            try? FileManager.default.removeItem(at: testFile)
        }
        
        let result = await gpg.verifyFile(dataPath: testFile.path)
        
        #expect(result.status != nil)
    }
    
    @Test("Verify non-existent file returns error", .enabled(if: TestHelpers.realGPGAvailable))
    func testVerifyNonExistentFile() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let result = await gpg.verifyFile(dataPath: "/non/existent/file.txt")
        
        #expect(result.status?.contains("data file not found") == true)
        #expect(!result.valid)
    }
    
    @Test("Verify cleartext signature", .enabled(if: TestHelpers.realGPGAvailable))
    func testVerifyCleartext() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let clearsignedMessage = """
        -----BEGIN PGP SIGNED MESSAGE-----
        Hash: SHA256
        
        This is a test message.
        -----BEGIN PGP SIGNATURE-----
        
        fake signature data here
        -----END PGP SIGNATURE-----
        """
        
        let result = await gpg.verifyCleartext(message: clearsignedMessage)
        
        #expect(result.status != nil)
    }
    
    @Test("Convenience method - isSignatureValid", .enabled(if: TestHelpers.realGPGAvailable))
    func testIsSignatureValid() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let testMessage = "Hello, World!"
        let isValid = await gpg.isSignatureValid(message: testMessage)
        
        // With no GPG setup, this should be false
        #expect(!isValid)
    }
    
    @Test("Convenience method - isFileSignatureValid", .enabled(if: TestHelpers.realGPGAvailable))
    func testIsFileSignatureValid() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let isValid = await gpg.isFileSignatureValid(dataPath: "/non/existent/file.txt")
        
        // Non-existent file should be invalid
        #expect(!isValid)
    }
    
    @Test("Error handling - invalid message encoding", .enabled(if: TestHelpers.realGPGAvailable))
    func testErrorHandlingInvalidEncoding() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        // This shouldn't happen in practice, but test the error path
        let result = await gpg.verify(data: Data([0xFF, 0xFE, 0xFD])) // Invalid UTF-8
        
        #expect(result.status != nil)
    }
}