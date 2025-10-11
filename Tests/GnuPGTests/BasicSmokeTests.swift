import Foundation
import Testing
@testable import GnuPG

/// Basic smoke tests that don't require GPG agent or key generation
@Suite("Basic Smoke Tests")
struct BasicSmokeTests {
    
    @Test("GPG binary initialization")
    func testGPGInitialization() throws {
        let (gpg, homeDir) = try TestHelpers.createTestGPG()
        defer { TestHelpers.cleanupTempGPGHome(homeDir) }
        
        // Test that GPG instance was created successfully
        #expect(gpg.gpgBinary.contains("gpg"), "Should have gpg binary path")
        #expect(gpg.gnupgHome == homeDir, "Should have correct home directory")
        
        // Test that GPG version was detected
        #expect(gpg.version != nil, "Should detect GPG version")
        
        if let version = gpg.version {
            #expect(version.major >= 2, "Should be GPG 2.x or higher")
            #expect(version.minor >= 0, "Should have valid minor version")
        }
    }
    
    @Test("Empty keyring listing")
    func testEmptyKeyringListing() async throws {
        let (gpg, homeDir) = try TestHelpers.createTestGPG()
        defer { TestHelpers.cleanupTempGPGHome(homeDir) }
        
        // List keys in empty keyring (should succeed with 0 results)
        let publicKeys = await gpg.listKeys()
        #expect(publicKeys.returnCode == 0, "Empty keyring listing should succeed")
        #expect(publicKeys.keys.isEmpty, "Empty keyring should have no keys")
        
        let secretKeys = await gpg.listKeys(secret: true) 
        #expect(secretKeys.returnCode == 0, "Empty secret keyring listing should succeed")
        #expect(secretKeys.keys.isEmpty, "Empty secret keyring should have no keys")
    }
    
    @Test("GPG configuration files")
    func testGPGConfiguration() throws {
        let (_, homeDir) = try TestHelpers.createTestGPG()
        defer { TestHelpers.cleanupTempGPGHome(homeDir) }
        
        // Check that config files were created
        let gpgConfPath = homeDir + "/gpg.conf"
        let agentConfPath = homeDir + "/gpg-agent.conf"
        
        #expect(FileManager.default.fileExists(atPath: gpgConfPath), "gpg.conf should exist")
        #expect(FileManager.default.fileExists(atPath: agentConfPath), "gpg-agent.conf should exist")
        
        // Check that config contains expected content
        let gpgConf = try String(contentsOfFile: gpgConfPath)
        #expect(gpgConf.contains("pinentry-mode loopback"), "Should have loopback pinentry mode")
        #expect(gpgConf.contains("batch"), "Should have batch mode")
        
        let agentConf = try String(contentsOfFile: agentConfPath)
        #expect(agentConf.contains("allow-loopback-pinentry"), "Should allow loopback pinentry")
    }
    
    @Test("Helper utilities")
    func testHelperUtilities() {
        // Test list length helper
        let testArray = [1, 2, 3]
        #expect(TestHelpers.isListWithLength(testArray, 3), "Should correctly identify array length")
        #expect(!TestHelpers.isListWithLength(testArray, 2), "Should correctly reject wrong length")
        #expect(!TestHelpers.isListWithLength(testArray, 4), "Should correctly reject wrong length")
        
        // Test with empty array
        let emptyArray: [Int] = []
        #expect(TestHelpers.isListWithLength(emptyArray, 0), "Should handle empty arrays")
        #expect(!TestHelpers.isListWithLength(emptyArray, 1), "Should reject non-zero length for empty array")
    }
    
    @Test("Data format handling")
    func testDataFormatHandling() {
        // Test encoding
        let testString = "Hello, GPG World! 🔐"
        let data = testString.data(using: .utf8)!
        
        #expect(data.count > 0, "Should convert string to data")
        
        let reconstructed = String(data: data, encoding: .utf8)
        #expect(reconstructed == testString, "Should round-trip string to data and back")
    }
}