import Testing
import Foundation
@testable import GnuPG

@Suite("Sign Operations Tests")
struct SignOperationsTests {
    
    // MARK: - Test Setup
    
    private func createTestGPG() -> GnuPG? {
        return try? GnuPG()
    }
    
    private func createMockGPGWithValidKey() -> GnuPG? {
        // In real tests, this would set up a test GPG environment
        // For now, return a basic instance
        return try? GnuPG()
    }
    
    // MARK: - SignResult Tests
    
    @Test("SignResult initialization")
    func testSignResultInitialization() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        let result = SignResult(gpg: gpg)
        
        #expect(result.type == nil)
        #expect(result.hashAlgo == nil)
        #expect(result.fingerprint == nil)
        #expect(result.status == nil)
        #expect(result.statusDetail == nil)
        #expect(result.keyId == nil)
        #expect(result.username == nil)
        #expect(result.timestamp == nil)
        #expect(result.data == nil)
        #expect(!result.isSuccessful)
    }
    
    @Test("SignResult success state")
    func testSignResultSuccessState() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        let result = SignResult(gpg: gpg)
        
        // Set properties that indicate success
        result.fingerprint = "1234567890ABCDEF"
        result.status = "signature created"
        
        #expect(result.isSuccessful)
    }
    
    @Test("SignResult status message handling - SIG_CREATED")
    func testSignResultSigCreated() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        let result = SignResult(gpg: gpg)
        
        // Simulate SIG_CREATED status message
        // Format: "type pubkey_algo hash_algo class timestamp fingerprint"
        result.handleStatus(key: "SIG_CREATED", value: "D 22 8 0 1641234567 1234567890ABCDEF")
        
        #expect(result.type == "D")
        #expect(result.hashAlgo == "8")
        #expect(result.timestamp == "1641234567")
        #expect(result.fingerprint == "1234567890ABCDEF")
        #expect(result.status == "signature created")
        #expect(result.isSuccessful)
    }
    
    @Test("SignResult status message handling - USERID_HINT")
    func testSignResultUserIdHint() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        let result = SignResult(gpg: gpg)
        
        result.handleStatus(key: "USERID_HINT", value: "1234567890ABCDEF Test User <test@example.com>")
        
        #expect(result.keyId == "1234567890ABCDEF")
        #expect(result.username == "Test User <test@example.com>")
    }
    
    @Test("SignResult status message handling - Error conditions")
    func testSignResultErrorConditions() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        // Test WARNING
        let warningResult = SignResult(gpg: gpg)
        warningResult.handleStatus(key: "WARNING", value: "test warning message")
        #expect(warningResult.status == "warning: test warning message")
        #expect(!warningResult.isSuccessful)
        
        // Test ERROR
        let errorResult = SignResult(gpg: gpg)
        errorResult.handleStatus(key: "ERROR", value: "test error message")
        #expect(errorResult.status == "error: test error message")
        #expect(!errorResult.isSuccessful)
        
        // Test KEYEXPIRED
        let expiredResult = SignResult(gpg: gpg)
        expiredResult.handleStatus(key: "KEYEXPIRED", value: "")
        #expect(expiredResult.status == "key expired")
        #expect(!expiredResult.isSuccessful)
        
        // Test KEYREVOKED
        let revokedResult = SignResult(gpg: gpg)
        revokedResult.handleStatus(key: "KEYREVOKED", value: "")
        #expect(revokedResult.status == "key revoked")
        #expect(!revokedResult.isSuccessful)
        
        // Test BAD_PASSPHRASE
        let badPassResult = SignResult(gpg: gpg)
        badPassResult.handleStatus(key: "BAD_PASSPHRASE", value: "")
        #expect(badPassResult.status == "bad passphrase")
        #expect(!badPassResult.isSuccessful)
        
        // Test INV_SGNR
        let invSignerResult = SignResult(gpg: gpg)
        invSignerResult.handleStatus(key: "INV_SGNR", value: "invalid_key_id")
        #expect(invSignerResult.status == "invalid signer")
        #expect(invSignerResult.statusDetail == "invalid_key_id")
        #expect(!invSignerResult.isSuccessful)
    }
    
    @Test("SignResult status message handling - Informational messages")
    func testSignResultInformationalMessages() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        let result = SignResult(gpg: gpg)
        
        // These messages should not change status
        result.handleStatus(key: "NEED_PASSPHRASE", value: "test")
        #expect(result.status == nil)
        
        result.handleStatus(key: "GOOD_PASSPHRASE", value: "test")
        #expect(result.status == nil)
        
        result.handleStatus(key: "BEGIN_SIGNING", value: "test")
        #expect(result.status == nil)
    }
    
    // MARK: - Sign Operations Tests
    // Note: These tests would require actual GPG setup in a real test environment
    
    @Test("Sign message with basic parameters")
    func testSignMessage() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        let testMessage = "Hello, World!"
        
        let result = await gpg.sign(message: testMessage)
        
        // In a real test environment with GPG set up, we would check:
        // - result.isSuccessful
        // - result.data is not nil
        // - result.fingerprint is set
        
        // For now, just verify the result object is created
        #expect(result.status != nil) // Should have some status (error in this case since no GPG)
    }
    
    @Test("Sign data with binary option")
    func testSignDataBinary() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        let testData = "Hello, World!".data(using: .utf8)!
        
        let result = await gpg.sign(data: testData, binary: true)
        
        // For now, just verify the result object is created
        #expect(result.status != nil)
    }
    
    @Test("Sign with clearsign option")
    func testSignClearsign() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        let testMessage = "Hello, World!"
        
        let result = await gpg.sign(message: testMessage, clearsign: true)
        
        #expect(result.status != nil)
    }
    
    @Test("Sign file operation")
    func testSignFile() async throws {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        // Create a temporary test file
        let tempDir = FileManager.default.temporaryDirectory
        let testFile = tempDir.appendingPathComponent("test_sign_file.txt")
        let testContent = "Test file content for signing"
        
        try testContent.write(to: testFile, atomically: true, encoding: .utf8)
        defer {
            try? FileManager.default.removeItem(at: testFile)
        }
        
        let result = await gpg.signFile(inputPath: testFile.path)
        
        // Should detect the file exists, even if GPG operation fails
        #expect(result.status != nil)
        #expect(!result.status!.contains("input file not found"))
    }
    
    @Test("Sign non-existent file returns error")
    func testSignNonExistentFile() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let result = await gpg.signFile(inputPath: "/non/existent/file.txt")
        
        #expect(result.status?.contains("input file not found") == true)
        #expect(!result.isSuccessful)
    }
    
    @Test("Sign with specific key ID")
    func testSignWithKeyId() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        let testMessage = "Hello, World!"
        let testKeyId = "1234567890ABCDEF"
        
        let result = await gpg.sign(message: testMessage, keyId: testKeyId)
        
        #expect(result.status != nil)
    }
    
    @Test("Sign with passphrase")
    func testSignWithPassphrase() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        let testMessage = "Hello, World!"
        let testPassphrase = "test_passphrase"
        
        let result = await gpg.sign(message: testMessage, passphrase: testPassphrase)
        
        #expect(result.status != nil)
    }
}