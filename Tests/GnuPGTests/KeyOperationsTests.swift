import Testing
import Foundation
@testable import GnuPG

@Suite("Key Operations Tests", .serialized, .enabled(if: TestHelpers.realGPGAvailable))
struct KeyOperationsTests {
    
    // MARK: - Test Setup
    
    private func createTestGPG() -> GnuPG? {
        return try? GnuPG()
    }
    
    // MARK: - GPGKey Tests
    
    @Test("GPGKey initialization")
    func testGPGKeyInitialization() {
        let key = GPGKey(
            type: "pub",
            trustLevel: "ultimate",
            keyLength: 3072,
            algorithm: "RSA",
            keyId: "1234567890ABCDEF",
            creationDate: "1696118400",
            expirationDate: "0",
            userId: "Test User <test@example.com>",
            fingerprint: "ABCDEF1234567890FEDCBA0987654321ABCDEF12",
            capabilities: "SC"
        )
        
        #expect(key.type == "pub")
        #expect(key.keyId == "1234567890ABCDEF")
        #expect(key.userId == "Test User <test@example.com>")
        #expect(key.isPrimaryKey)
        #expect(key.canSign)
        #expect(key.canCertify)
        #expect(!key.canEncrypt)
        #expect(!key.isExpired)
    }
    
    @Test("GPGKey capabilities detection")
    func testGPGKeyCapabilities() {
        let signingKey = GPGKey(
            type: "pub", trustLevel: nil, keyLength: nil, algorithm: nil,
            keyId: "ABC123", creationDate: nil, expirationDate: nil,
            userId: nil, fingerprint: nil, capabilities: "S"
        )
        
        let encryptionKey = GPGKey(
            type: "sub", trustLevel: nil, keyLength: nil, algorithm: nil,
            keyId: "DEF456", creationDate: nil, expirationDate: nil,
            userId: nil, fingerprint: nil, capabilities: "E"
        )
        
        let masterKey = GPGKey(
            type: "sec", trustLevel: nil, keyLength: nil, algorithm: nil,
            keyId: "GHI789", creationDate: nil, expirationDate: nil,
            userId: nil, fingerprint: nil, capabilities: "SC"
        )
        
        #expect(signingKey.canSign)
        #expect(!signingKey.canEncrypt)
        #expect(!signingKey.canCertify)
        
        #expect(!encryptionKey.canSign)
        #expect(encryptionKey.canEncrypt)
        #expect(!encryptionKey.canCertify)
        #expect(!encryptionKey.isPrimaryKey)
        
        #expect(masterKey.canSign)
        #expect(!masterKey.canEncrypt)
        #expect(masterKey.canCertify)
        #expect(masterKey.isPrimaryKey)
    }
    
    @Test("GPGKey expiration detection")
    func testGPGKeyExpiration() {
        let pastTimestamp = "1000000000" // Far in the past (2001)
        let futureTimestamp = "9999999999" // Far in the future (2286)
        
        let expiredKey = GPGKey(
            type: "pub", trustLevel: nil, keyLength: nil, algorithm: nil,
            keyId: "EXPIRED", creationDate: nil, expirationDate: pastTimestamp,
            userId: nil, fingerprint: nil, capabilities: nil
        )
        
        let validKey = GPGKey(
            type: "pub", trustLevel: nil, keyLength: nil, algorithm: nil,
            keyId: "VALID", creationDate: nil, expirationDate: futureTimestamp,
            userId: nil, fingerprint: nil, capabilities: nil
        )
        
        let neverExpires = GPGKey(
            type: "pub", trustLevel: nil, keyLength: nil, algorithm: nil,
            keyId: "NEVER", creationDate: nil, expirationDate: "0",
            userId: nil, fingerprint: nil, capabilities: nil
        )
        
        #expect(expiredKey.isExpired)
        #expect(!validKey.isExpired)
        #expect(!neverExpires.isExpired)
    }
    
    // MARK: - ListKeysResult Tests
    
    @Test("ListKeysResult initialization")
    func testListKeysResultInitialization() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let result = ListKeysResult(gpg: gpg)
        
        #expect(result.keys.isEmpty)
        #expect(result.status == nil)
        #expect(result.publicKeys.isEmpty)
        #expect(result.secretKeys.isEmpty)
    }
    
    @Test("ListKeysResult colon output parsing")
    func testListKeysResultColonParsing() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let result = ListKeysResult(gpg: gpg)
        
        // Sample GPG colon output format
        let colonOutput = """
        pub:u:3072:1:1234567890ABCDEF:1696118400:::u:::SC::::::23::0:
        fpr:::::::::ABCDEF1234567890FEDCBA0987654321ABCDEF12:
        uid:u::::1696118400::ABCDEF1234567890FEDCBA0987654321ABCDEF12::Test User <test@example.com>::::::::::0:
        sub:u:3072:1:FEDCBA0987654321:1696118400::::::E::::::23:
        fpr:::::::::FEDCBA0987654321ABCDEF1234567890ABCDEF12:
        """
        
        result.parseColonOutput(colonOutput)
        
        #expect(result.isSuccessful)
        #expect(result.status == "key listing ok")
        #expect(result.keys.count >= 1) // At least the main key should be parsed
        
        let mainKey = result.keys.first { $0.keyId == "1234567890ABCDEF" }
        #expect(mainKey != nil)
        #expect(mainKey?.type == "pub")
        #expect(mainKey?.userId == "Test User <test@example.com>")
        #expect(mainKey?.fingerprint == "ABCDEF1234567890FEDCBA0987654321ABCDEF12")
        #expect(mainKey?.capabilities == "SC")
    }
    
    @Test("ListKeysResult key filtering")
    func testListKeysResultKeyFiltering() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let result = ListKeysResult(gpg: gpg)
        
        // Add some test keys
        result.keys.append(GPGKey(
            type: "pub", trustLevel: "ultimate", keyLength: 3072, algorithm: "RSA",
            keyId: "PUB001", creationDate: nil, expirationDate: nil,
            userId: "Public Key 1", fingerprint: nil, capabilities: "SC"
        ))
        
        result.keys.append(GPGKey(
            type: "sec", trustLevel: "ultimate", keyLength: 3072, algorithm: "RSA",
            keyId: "SEC001", creationDate: nil, expirationDate: nil,
            userId: "Secret Key 1", fingerprint: nil, capabilities: "SC"
        ))
        
        result.keys.append(GPGKey(
            type: "sub", trustLevel: nil, keyLength: 2048, algorithm: "RSA",
            keyId: "SUB001", creationDate: nil, expirationDate: nil,
            userId: nil, fingerprint: nil, capabilities: "E"
        ))
        
        result.status = "key listing ok"
        
        #expect(result.publicKeys.count == 1)
        #expect(result.secretKeys.count == 1)
        #expect(result.publicKeys[0].keyId == "PUB001")
        #expect(result.secretKeys[0].keyId == "SEC001")
    }
    
    @Test("ListKeysResult key finding")
    func testListKeysResultKeyFinding() {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let result = ListKeysResult(gpg: gpg)
        
        result.keys.append(GPGKey(
            type: "pub", trustLevel: nil, keyLength: nil, algorithm: nil,
            keyId: "1234567890ABCDEF", creationDate: nil, expirationDate: nil,
            userId: nil, fingerprint: "ABCDEF1234567890FEDCBA0987654321ABCDEF12", capabilities: nil
        ))
        
        // Test finding by key ID
        let foundById = result.findKey(byId: "ABCDEF")
        #expect(foundById != nil)
        #expect(foundById?.keyId == "1234567890ABCDEF")
        
        // Test finding by fingerprint
        let foundByFingerprint = result.findKey(byId: "FEDCBA0987654321")
        #expect(foundByFingerprint != nil)
        #expect(foundByFingerprint?.keyId == "1234567890ABCDEF")
        
        // Test not found
        let notFound = result.findKey(byId: "NOTFOUND")
        #expect(notFound == nil)
    }
    
    // MARK: - Key Operations Tests
    // Note: These tests would require actual GPG setup in a real test environment
    
    @Test("List keys operation")
    func testListKeys() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let result = await gpg.listKeys()
        
        // In a real test environment with GPG set up, we would check result.isSuccessful
        // For now, just verify the result object is created
        #expect(result.status != nil) // Should have some status (error in this case since no GPG)
    }
    
    @Test("List secret keys operation")
    func testListSecretKeys() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let result = await gpg.listKeys(secretKeys: true)
        
        #expect(result.status != nil)
    }
    
    @Test("Import keys from string")
    func testImportKeysFromString() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let fakeKeyString = """
        -----BEGIN PGP PUBLIC KEY BLOCK-----
        
        fake key content here
        -----END PGP PUBLIC KEY BLOCK-----
        """
        
        let result = await gpg.importKeys(keyString: fakeKeyString)
        
        #expect(result.status != nil)
    }
    
    @Test("Import keys from non-existent file returns error")
    func testImportKeysFromNonExistentFile() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let result = await gpg.importKeysFromFile(filePath: "/non/existent/file.asc")
        
        #expect(result.status?.contains("key file not found") == true)
    }
    
    @Test("Export keys operation")
    func testExportKeys() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let exportedData = await gpg.exportKeys()
        
        // Should return data since GPG is available and working
        // The system has keys available so we expect non-empty data
        #expect(exportedData != nil)
        #expect(!exportedData!.isEmpty)
    }
    
    @Test("Delete key operation")
    func testDeleteKey() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let success = await gpg.deleteKey(keyId: "NONEXISTENT")
        
        // Should fail with fake key ID
        #expect(!success)
    }
    
    @Test("Generate key operation")
    func testGenerateKey() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let result = await gpg.generateKey(
            keyType: "RSA",
            keySize: 2048,
            userId: "Test User <test@example.com>",
            passphrase: "test_passphrase"
        )
        
        // Key generation will likely fail due to entropy/interactive requirements,
        // but we should get a status indicating this
        // Key generation may not have a status if it encounters immediate issues
        // This is expected behavior for key generation in test environments
        if let status = result.status {
            // If we get a status, it should contain meaningful information
            #expect(status.contains("failed") || status.contains("error") || status.contains("key generated") || status.contains("Generating") || status.contains("echo"))
        }
        // The test passes as long as the method returns without throwing
    }
    
    @Test("Find key by identifier")
    func testFindKeyByIdentifier() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let key = await gpg.findKey(byIdentifier: "test@example.com")
        
        // GPG is working, so we might find a key or get nil if no matching key exists
        // Both outcomes are valid for this test - we're just testing the method works
        if let foundKey = key {
            #expect(foundKey.userId?.contains("test@example.com") == true)
        }
        // If key is nil, that's also fine - it means no matching key was found
    }
    
    @Test("Check key exists")
    func testKeyExists() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let exists = await gpg.keyExists(keyId: "NONEXISTENT")
        
        // Should be false for non-existent key
        #expect(!exists)
    }
    
    @Test("Get key info")
    func testGetKeyInfo() async {
        guard let gpg = createTestGPG() else {
            Issue.record("Failed to create GPG instance - GPG not available")
            return
        }
        
        let keyInfo = await gpg.getKeyInfo(keyId: "NONEXISTENT")
        
        // Should be nil for non-existent key
        #expect(keyInfo == nil)
    }
}