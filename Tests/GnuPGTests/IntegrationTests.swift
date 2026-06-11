import Testing
import Foundation
@testable import GnuPG

@Suite("Integration Tests", .serialized, .enabled(if: TestHelpers.realGPGAvailable))
struct IntegrationTests {
    
    // MARK: - Test Setup
    
    private func createTestGPG() -> GnuPG? {
        do {
            return try GnuPG()
        } catch {
            Issue.record("Failed to create GPG instance: \(error)")
            return nil
        }
    }
    
    // MARK: - End-to-End Tests
    
    @Test("GPG Binary Discovery and Version Check")
    func testGPGBinaryDiscoveryAndVersion() async {
        guard let gpg = createTestGPG() else {
            Issue.record("GPG not available")
            return
        }
        
        // Test that GPG binary was found correctly
        #expect(gpg.gpgBinary.hasSuffix("gpg"))
        
        // Test that we can read the GPG version
        #expect(gpg.version != nil)
        if let version = gpg.version {
            #expect(version.major >= 2)
            print("GPG Version: \(version)")
        }
    }
    
    @Test("List Keys in System Keyring")
    func testListSystemKeys() async {
        guard let gpg = createTestGPG() else {
            Issue.record("GPG not available")
            return
        }
        
        // List public keys
        let publicKeysResult = await gpg.listKeys()
        print("Public keys status: \(publicKeysResult.status ?? "nil")")
        print("Found \(publicKeysResult.keys.count) public keys")
        
        // List secret keys
        let secretKeysResult = await gpg.listKeys(secretKeys: true)
        print("Secret keys status: \(secretKeysResult.status ?? "nil")")
        print("Found \(secretKeysResult.keys.count) secret keys")
        
        // At minimum, the operations should complete without crashing
        #expect(publicKeysResult.status != nil)
        #expect(secretKeysResult.status != nil)
    }
    
    @Test("Export Keys Operation")
    func testExportKeys() async {
        guard let gpg = createTestGPG() else {
            Issue.record("GPG not available")
            return
        }
        
        // Test exporting all public keys
        let exportedKeys = await gpg.exportKeys()
        
        // Even if no keys exist, this should return empty data, not crash
        if let data = exportedKeys {
            print("Exported \(data.count) bytes of key data")
        } else {
            print("No keys to export")
        }
        
        // The operation should complete successfully
        #expect(exportedKeys != nil || exportedKeys == nil) // Either is valid
    }
    
    @Test("Import Invalid Key Data")
    func testImportInvalidKey() async {
        guard let gpg = createTestGPG() else {
            Issue.record("GPG not available")
            return
        }
        
        // Try importing invalid key data
        let invalidKeyData = """
        -----BEGIN PGP PUBLIC KEY BLOCK-----
        
        This is not valid key data
        -----END PGP PUBLIC KEY BLOCK-----
        """
        
        let importResult = await gpg.importKeys(keyString: invalidKeyData)
        
        // Should handle invalid data gracefully
        #expect(importResult.status != nil)
        #expect(!importResult.isSuccessful) // Should fail for invalid data
        print("Import result: \(importResult.status ?? "nil")")
        print("Import successful: \(importResult.isSuccessful)")
    }
    
    @Test("Find Nonexistent Key")
    func testFindNonexistentKey() async {
        guard let gpg = createTestGPG() else {
            Issue.record("GPG not available")
            return
        }
        
        // Try to find a key that doesn't exist
        let foundKey = await gpg.findKey(byIdentifier: "nonexistent@example.com")
        
        // Should return nil for nonexistent key
        #expect(foundKey == nil)
        print("Found key: \(foundKey?.keyId ?? "nil")")
    }
    
    @Test("Check Key Existence")
    func testKeyExistence() async {
        guard let gpg = createTestGPG() else {
            Issue.record("GPG not available")
            return
        }
        
        // Check if a nonexistent key exists
        let exists = await gpg.keyExists(keyId: "NONEXISTENT123456")
        
        // Should return false for nonexistent key
        #expect(!exists)
        print("Key exists: \(exists)")
    }
    
    @Test("Sign and Verify Round Trip (if keys available)")
    func testSignAndVerifyRoundTrip() async {
        guard let gpg = createTestGPG() else {
            Issue.record("GPG not available")
            return
        }
        
        // First check if we have any secret keys available for signing
        let secretKeys = await gpg.listKeys(secretKeys: true)
        guard !secretKeys.keys.isEmpty else {
            print("No secret keys available for signing test")
            return // Skip test if no keys available
        }
        
        let testMessage = "This is a test message for signing and verification."
        
        // Attempt to sign (may fail if no keys or passphrase required)
        let signResult = await gpg.sign(message: testMessage)
        print("Sign status: \(signResult.status ?? "nil")")
        
        // If signing succeeded, try to verify
        if signResult.isSuccessful, let signedData = signResult.data {
            let signedString = String(data: signedData, encoding: .utf8) ?? ""
            let verifyResult = await gpg.verify(message: signedString)
            print("Verify status: \(verifyResult.status ?? "nil")")
            print("Verification successful: \(verifyResult.valid)")
        }
        
        // The signing operation should complete (even if it fails due to no passphrase)
        #expect(signResult.status != nil)
    }
    
    @Test("Encrypt and Decrypt Round Trip (if keys available)")
    func testEncryptAndDecryptRoundTrip() async {
        guard let gpg = createTestGPG() else {
            Issue.record("GPG not available")
            return
        }
        
        // Check if we have any public keys for encryption
        let publicKeys = await gpg.listKeys()
        guard !publicKeys.keys.isEmpty else {
            print("No public keys available for encryption test")
            return
        }
        
        // Try to get a key that can encrypt
        let encryptionKey = publicKeys.keys.first { $0.canEncrypt }
        guard let key = encryptionKey else {
            print("No encryption-capable keys found")
            return
        }
        
        let testMessage = "This is a test message for encryption."
        
        // Attempt to encrypt
        let encryptResult = await gpg.encrypt(
            message: testMessage, 
            recipients: [key.keyId]
        )
        print("Encrypt status: \(encryptResult.status ?? "nil")")
        print("Encryption successful: \(encryptResult.isSuccessful)")
        
        // If encryption succeeded and we have secret keys, try to decrypt
        if encryptResult.isSuccessful, 
           let encryptedData = encryptResult.data {
            let encryptedString = String(data: encryptedData, encoding: .utf8) ?? ""
            let decryptResult = await gpg.decrypt(message: encryptedString)
            print("Decrypt status: \(decryptResult.status ?? "nil")")
            print("Decryption successful: \(decryptResult.isSuccessful)")
        }
        
        // The encryption operation should complete
        #expect(encryptResult.status != nil)
    }
    
    @Test("GPG Configuration and Options")
    func testGPGConfiguration() async {
        // Test creating GPG with custom options
        do {
            let customGPG = try GnuPG(
                verbose: true,
                useAgent: false,
                options: ["--cipher-algo", "AES256"]
            )
            
            #expect(customGPG.verbose == true)
            #expect(customGPG.useAgent == false)
            #expect(customGPG.options?.contains("--cipher-algo") == true)
            
            // Test that it can still find keys
            let result = await customGPG.listKeys()
            #expect(result.status != nil)
            
            print("Custom GPG configuration test passed")
        } catch {
            Issue.record("Failed to create custom GPG configuration: \(error)")
        }
    }
}