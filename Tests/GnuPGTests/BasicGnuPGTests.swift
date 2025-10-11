import Testing
@testable import GnuPG

/// Basic tests for the GnuPG Swift wrapper foundation
@Suite("Basic GnuPG Tests")
struct BasicGnuPGTests {
    
    @Test("GPG Version Parsing") 
    func testGPGVersionParsing() async throws {
        // Test version parsing
        let versionData = "cfg:version:2.4.0".data(using: .ascii)!
        let version = GPGVersion.parse(from: versionData)
        
        #expect(version != nil)
        #expect(version?.major == 2)
        #expect(version?.minor == 4)
        #expect(version?.patch == 0)
    }
    
    @Test("GPG Version Comparison")
    func testGPGVersionComparison() async throws {
        let v1 = GPGVersion(major: 2, minor: 1, patch: 0)
        let v2 = GPGVersion(major: 2, minor: 4, patch: 0)
        let v3 = GPGVersion(major: 2, minor: 1, patch: 0)
        
        #expect(v1 < v2)
        #expect(v1 == v3)
        #expect(v2 > v1)
    }
    
    @Test("GPG Utilities Shell Quoting")
    func testShellQuoting() async throws {
        // Test basic shell quoting functionality
        #expect(GPGUtilities.shellQuote("simple") == "simple")
        #expect(GPGUtilities.shellQuote("") == "''")
        #expect(GPGUtilities.shellQuote("hello world") == "'hello world'")
        #expect(GPGUtilities.shellQuote("it's") == "'it'\\''s'")
    }
    
    @Test("GPG Utilities Passphrase Validation")
    func testPassphraseValidation() async throws {
        #expect(GPGUtilities.isValidPassphrase("valid-passphrase"))
        #expect(!GPGUtilities.isValidPassphrase("invalid\npassphrase"))
        #expect(!GPGUtilities.isValidPassphrase("invalid\rpassphrase"))
        #expect(!GPGUtilities.isValidPassphrase("invalid\0passphrase"))
    }
    
    @Test("VerifyResult Trust Levels")
    func testVerifyResultTrustLevels() async throws {
        #expect(VerifyResult.trustExpired == 0)
        #expect(VerifyResult.trustUndefined == 1)
        #expect(VerifyResult.trustNever == 2)
        #expect(VerifyResult.trustMarginal == 3)
        #expect(VerifyResult.trustFully == 4)
        #expect(VerifyResult.trustUltimate == 5)
        
        #expect(VerifyResult.trustLevels["TRUST_EXPIRED"] == 0)
        #expect(VerifyResult.trustLevels["TRUST_ULTIMATE"] == 5)
    }
    
    @Test("ImportResult Summary")
    func testImportResultSummary() async throws {
        // Create a mock GPG instance for testing (we'll need to make this work)
        // For now, we can't fully test without a working GPG binary
        // This is a placeholder for when we implement basic GPG operations
    }
    
    @Test("GPG Error Types")
    func testGPGErrorTypes() async throws {
        let error1 = GPGError.invalidPassphrase("test reason")
        let error2 = GPGError.gpgNotAvailable("test-gpg")
        let error3 = GPGError.fileNotFound("/nonexistent/path")
        
        #expect(error1.errorDescription != nil)
        #expect(error2.errorDescription != nil)
        #expect(error3.errorDescription != nil)
        
        // Test error equality
        #expect(error1 == GPGError.invalidPassphrase("test reason"))
        #expect(error2 == GPGError.gpgNotAvailable("test-gpg"))
        
        // Test failure reasons and recovery suggestions
        #expect(error1.failureReason != nil)
        #expect(error2.recoverySuggestion != nil)
        #expect(error3.failureReason != nil)
    }
}