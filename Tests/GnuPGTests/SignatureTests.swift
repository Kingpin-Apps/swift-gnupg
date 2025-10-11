import Testing
import Foundation
@testable import GnuPG

/// Tests for signature creation and verification functionality
///
/// Corresponds to Python tests:
/// - test_signature_verification, test_signature_file, test_subkey_signature_file,
/// - test_multiple_signatures, test_multiple_signatures_one_invalid
@Suite("Signature/Verification Tests")
struct SignatureTests {
    
    // MARK: - Basic Signature Tests
    
    @Test("Test signature creation and verification")
    func testSignatureVerification() async throws {
        let (gpg, homeDir) = try TestHelpers.createTestGPG()
        defer { TestHelpers.cleanupTempGPGHome(homeDir) }
        
        // Generate test key
        let key = try await TestHelpers.generateKey(
            with: gpg,
            firstName: "Andrew",
            lastName: "Able", 
            domain: "alpha.com"
        )
        
        // Skip test if key generation failed (no GPG agent)
        guard key.returnCode == 0 else {
            print("Skipping signature test - key generation failed (GPG agent not available)")
            return
        }
        
        let data = "Hello, André!".data(using: gpg.encoding) ?? Data()
        
        // Test invalid passphrase formats
        do {
            let result = await gpg.sign(data: data, keyId: key.fingerprint, passphrase: "bbr\0own")
            #expect(!result.isValid, "Null character in passphrase should fail")
        }
        do {
            let result = await gpg.sign(data: data, keyId: key.fingerprint, passphrase: "bbr\rown")
            #expect(!result.isValid, "Carriage return in passphrase should fail")
        }
        do {
            let result = await gpg.sign(data: data, keyId: key.fingerprint, passphrase: "bbr\nown")
            #expect(!result.isValid, "Newline in passphrase should fail")
        }
        
        // Test signing with wrong passphrase
        let wrongPassSig = await gpg.sign(data: data, keyId: key.fingerprint, passphrase: "bbrown")
        #expect(!wrongPassSig.isValid, "Wrong passphrase should fail")
        
        // Test signing with correct passphrase
        let sig = await gpg.sign(data: data, keyId: key.fingerprint, passphrase: "aable")
        #expect(sig.returnCode == 0, "Signing should succeed")
        #expect(sig.isValid, "Good passphrase should succeed")
        
        // Verify signature metadata
        if let username = sig.username, !username.isEmpty {
            // Not set in recent versions of GnuPG e.g. 2.2.5
            #expect(
                username.hasPrefix("Andrew Able"),
                "Username should start with 'Andrew Able'"
            )
        }
        if let keyId = sig.keyId, !keyId.isEmpty {
            #expect(
                key.fingerprint.hasSuffix(keyId),
                "Key fingerprint should end with signature key ID"
            )
        }
        if let hashAlgo = sig.hashAlgo {
            #expect(!hashAlgo.isEmpty, "Should have hash algorithm")
        }
        
        // Test signature verification
        guard let sigData = sig.data else {
            Issue.record("Signature should have data")
            return
        }
        
        let verified = await gpg.verify(data: sigData)
        #expect(verified.returnCode == 0, "Verification should succeed")
        #expect(verified.fingerprint == key.fingerprint, "Fingerprints should match")
        #expect(verified.trustLevel == VerifyResult.trustUltimate, "Should have ultimate trust")
        #expect(verified.trustText == "TRUST_ULTIMATE", "Should have ultimate trust text")
        
        // Test file signing
        let testFilePath = try TestHelpers.createRandomTestFile()
        defer { try? FileManager.default.removeItem(atPath: testFilePath) }
        
        let fileSig = await gpg.signFile(inputPath: testFilePath, keyId: key.fingerprint, passphrase: "aable")
        #expect(fileSig.returnCode == 0, "File signing should succeed")
        #expect(fileSig.isValid, "File signature should be valid")
        
        if let hashAlgo = fileSig.hashAlgo {
            #expect(!hashAlgo.isEmpty, "File signature should have hash algorithm")
        }
        
        // Test file verification  
        guard let fileSigData = fileSig.data else {
            Issue.record("File signature should have data")
            return
        }
        let fileVerified = await gpg.verify(data: fileSigData)
        #expect(fileVerified.returnCode == 0, "File verification should succeed")
        #expect(fileVerified.fingerprint == key.fingerprint, "File verification fingerprints should match")
        
        // Test detached signature
        let detachedSig = await gpg.signFile(inputPath: testFilePath, keyId: key.fingerprint, passphrase: "aable", detach: true)
        #expect(detachedSig.returnCode == 0, "Detached signing should succeed")
        #expect(detachedSig.isValid, "Detached signature should be valid")
        
        if let hashAlgo = detachedSig.hashAlgo {
            #expect(!hashAlgo.isEmpty, "Detached signature should have hash algorithm")
        }
        
        // Test detached signature verification
        guard let detachedSigData = detachedSig.data else {
            Issue.record("Detached signature should have data")
            return
        }
        
        let detachedVerified = await gpg.verify(data: detachedSigData)
        #expect(detachedVerified.returnCode == 0, "Detached verification should succeed")
        #expect(detachedVerified.fingerprint == key.fingerprint, "Detached verification fingerprints should match")
        
        // Test in-memory detached verification
        let testData = try Data(contentsOf: URL(fileURLWithPath: testFilePath))
        // For detached signature, we need to verify using file paths or use the data directly
        let memoryVerified = await gpg.verify(
            data: detachedSigData,
            signature: testData
        )
        #expect(memoryVerified.returnCode == 0, "In-memory verification should succeed")
        #expect(memoryVerified.fingerprint == key.fingerprint, "In-memory verification fingerprints should match")
    }
    
    @Test("Test signature file operations")
    func testSignatureFile() async throws {
        let (gpg, homeDir) = try TestHelpers.createTestGPG()
        defer { TestHelpers.cleanupTempGPGHome(homeDir) }
        
        // Generate test key
        let key = try await TestHelpers.generateKey(
            with: gpg,
            firstName: "Andrew",
            lastName: "Able",
            domain: "alpha.com"
        )
        
        // Skip test if key generation failed (no GPG agent)
        guard key.returnCode == 0 else {
            print("Skipping signature file test - key generation failed (GPG agent not available)")
            return
        }
        
        let testFilePath = try TestHelpers.createRandomTestFile()
        let sigFilePath = testFilePath + ".asc"
        defer { 
            try? FileManager.default.removeItem(atPath: testFilePath)
            try? FileManager.default.removeItem(atPath: sigFilePath)
        }
        
        // Sign file with output to separate signature file
        let sig = await gpg.signFile(
            inputPath: testFilePath, 
            outputPath: sigFilePath,
            keyId: key.fingerprint, 
            passphrase: "aable", 
            detach: true
        )
        
        #expect(sig.returnCode == 0, "File signing should succeed")
        #expect(sig.isValid, "Signature should be valid")
        
        if let hashAlgo = sig.hashAlgo {
            #expect(!hashAlgo.isEmpty, "Should have hash algorithm")
        }
        
        #expect(FileManager.default.fileExists(atPath: sigFilePath), "Signature file should exist")
        
        // Verify signature file
        let verified = await gpg.verifyFile(dataPath: testFilePath, signaturePath: sigFilePath)
        
        #expect(verified.returnCode == 0, "Verification should succeed")
        
        if let username = verified.username {
            #expect(username.hasPrefix("Andrew Able"), "Username should be correct")
        }
        
        if let keyId = verified.keyId {
            #expect(key.fingerprint.hasSuffix(keyId), "Key ID should match")
        }
        #expect(verified.fingerprint == key.fingerprint, "Fingerprints should match")
    }
    
    @Test("Test subkey signature operations")
    func testSubkeySignatureFile() async throws {
        let (gpg, homeDir) = try TestHelpers.createTestGPG()
        defer { TestHelpers.cleanupTempGPGHome(homeDir) }
        
        // Skip if GPG version < 2.0 as subkey features are unavailable in 1.x
        if let version = gpg.version, version < GPGVersion(major: 2, minor: 0) {
            // Skip if subkey features unavailable in GnuPG 1.x
            return
        }
        
        // Generate master key without subkey
        let masterKey = try await TestHelpers.generateKey(
            with: gpg,
            firstName: "Charlie",
            lastName: "Clark",
            domain: "gamma.com",
            passphrase: "123",
            withSubkey: false
        )
        
        // Skip test if key generation failed (no GPG agent)
        guard masterKey.returnCode == 0 else {
            print("Skipping subkey signature test - key generation failed (GPG agent not available)")
            return
        }
        
        #expect(masterKey.returnCode == 0, "Master key generation should succeed")
        
        // Add signing subkey
        let subkey = await gpg.addSubkey(
            masterKey: masterKey.fingerprint,
            masterPassphrase: "123",
            algorithm: "dsa",
            usage: "sign",
            expire: 0
        )
        #expect(subkey.returnCode == 0, "Subkey addition should succeed")
        
        let testFilePath = try TestHelpers.createRandomTestFile()
        let sigFilePath = testFilePath + ".asc"
        defer {
            try? FileManager.default.removeItem(atPath: testFilePath)
            try? FileManager.default.removeItem(atPath: sigFilePath)
        }
        
        // Sign with subkey
        let sig = await gpg.signFile(
            inputPath: testFilePath,
            outputPath: sigFilePath,
            keyId: subkey.fingerprint,
            passphrase: "123",
            detach: true
        )
        
        #expect(sig.returnCode == 0, "Subkey signing should succeed")
        #expect(sig.isValid, "Subkey signature should be valid")
        #expect(!(sig.hashAlgo?.isEmpty ?? true), "Subkey signature should have hash algorithm")
        #expect(FileManager.default.fileExists(atPath: sigFilePath), "Signature file should exist")
        
        // Verify subkey signature
        let testData = try Data(contentsOf: URL(fileURLWithPath: testFilePath))
        let verified = await gpg.verifyData(sigFilePath, signedData: testData)
        
        #expect(verified.returnCode == 0, "Subkey verification should succeed")
        #expect(verified.username?.hasPrefix("Charlie Clark") ?? false, "Username should be correct")
        #expect(subkey.fingerprint.hasSuffix(verified.keyId ?? ""), "Subkey ID should match")
        #expect(verified.fingerprint == subkey.fingerprint, "Subkey fingerprints should match")
    }
    
    // MARK: - Multiple Signature Tests
    
    @Test("Test multiple valid signatures")
    func testMultipleSignatures() async throws {
        let (gpg, homeDir) = try TestHelpers.createTestGPG()
        defer { TestHelpers.cleanupTempGPGHome(homeDir) }
        
        // Generate two keys
        let key1 = try await TestHelpers.generateKey(
            with: gpg,
            firstName: "Andrew",
            lastName: "Able",
            domain: "alpha.com"
        )
        
        let key2 = try await TestHelpers.generateKey(
            with: gpg,
            firstName: "Barbara", 
            lastName: "Brown",
            domain: "beta.com"
        )
        
        // Skip test if key generation failed (no GPG agent)
        guard key1.returnCode == 0 && key2.returnCode == 0 else {
            print("Skipping multiple signatures test - key generation failed (GPG agent not available)")
            return
        }
        
        let data = "signed data".data(using: .utf8) ?? Data()
        
        // Create two detached signatures
        let sig1 = await gpg.sign(
            data: data,
            keyId: key1.fingerprint,
            passphrase: "aable",
            detach: true
        )
        let sig2 = await gpg.sign(
            data: data,
            keyId: key2.fingerprint,
            passphrase: "bbrown",
            detach: true
        )
        
        // Combine signatures into one file
        let tempDir = NSTemporaryDirectory()
        let combinedSigFile = tempDir + "combined-sigs-\(UUID().uuidString).sig"
        defer { try? FileManager.default.removeItem(atPath: combinedSigFile) }
        
        var combinedSigData = Data()
        
        guard let sig1Data = sig1.data, let sig2Data = sig2.data else {
            Issue.record("Signatures should have data")
            return
        }
        
        combinedSigData.append(sig1Data)
        combinedSigData.append(sig2Data)
        try combinedSigData.write(to: URL(fileURLWithPath: combinedSigFile))
        
        // Verify combined signatures
        let verified = await gpg.verifyData(combinedSigFile, signedData: data)
        let sigInfo = verified.sigInfo
        
        #expect(sigInfo.count == 2, "Should have 2 signature infos")
        
        let actualFingerprints = Set(sigInfo.values.compactMap { $0["fingerprint"] as? String })
        let expectedFingerprints = Set([key1.fingerprint, key2.fingerprint])
        #expect(actualFingerprints == expectedFingerprints, "Should have signatures from both keys")
    }
    
    @Test("Test multiple signatures with one invalid")
    func testMultipleSignaturesOneInvalid() async throws {
        let (gpg, homeDir) = try TestHelpers.createTestGPG()
        defer { TestHelpers.cleanupTempGPGHome(homeDir) }
        
        // Generate two keys
        let key1 = try await TestHelpers.generateKey(
            with: gpg,
            firstName: "Andrew",
            lastName: "Able",
            domain: "alpha.com"
        )
        
        let key2 = try await TestHelpers.generateKey(
            with: gpg,
            firstName: "Barbara",
            lastName: "Brown", 
            domain: "beta.com"
        )
        
        // Skip test if key generation failed (no GPG agent)
        guard key1.returnCode == 0 && key2.returnCode == 0 else {
            print("Skipping mixed signatures test - key generation failed (GPG agent not available)")
            return
        }
        
        let data = "signed data".data(using: .utf8) ?? Data()
        let otherData = "other signed data".data(using: .utf8) ?? Data()
        
        // Create signatures: one valid for data, one valid for different data
        let sig1 = await gpg.sign(
            data: data,
            keyId: key1.fingerprint,
            passphrase: "aable",
            detach: true
        )
        let sig2 = await gpg.sign(
            data: otherData,
            keyId: key2.fingerprint,
            passphrase: "bbrown",
            detach: true
        )
        
        // Combine signatures into one file
        let tempDir = NSTemporaryDirectory()
        let combinedSigFile = tempDir + "mixed-sigs-\(UUID().uuidString).sig"
        defer { try? FileManager.default.removeItem(atPath: combinedSigFile) }
        
        var combinedSigData = Data()
        
        guard let sig1Data = sig1.data, let sig2Data = sig2.data else {
            Issue.record("Signatures should have data")
            return
        }
        
        combinedSigData.append(sig1Data)
        combinedSigData.append(sig2Data)
        try combinedSigData.write(to: URL(fileURLWithPath: combinedSigFile))
        
        // Verify combined signatures against original data
        let verified = await gpg.verifyData(combinedSigFile, signedData: data)
        let sigInfo = verified.sigInfo
        let problems = verified.problems
        
        #expect(sigInfo.count == 1, "Should have 1 valid signature info")
        
        let actualFingerprints = Set(sigInfo.values.compactMap { $0["fingerprint"] as? String })
        let expectedFingerprints = Set([key1.fingerprint])
        #expect(actualFingerprints == expectedFingerprints, "Should only have signature from key1")
        
        #expect(problems.count == 1, "Should have 1 problem")
        
        if problems.count > 0 {
            let problem = problems[0]
            #expect(problem["status"] as? String == "signature bad", "Should indicate bad signature")
            #expect(key2.fingerprint.hasSuffix(problem["keyid"] as? String ?? ""), "Problem should reference key2")
        }
    }
    
    // MARK: - Edge Case Tests
    
    @Test("Test signing with UID (currently disabled)")
    func testSigningWithUID() async throws {
        // This test is disabled in the Python version but we include the structure
        // for future implementation if needed
        // This test is disabled in the Python version
        return
        
        /*
        let (gpg, homeDir) = try TestHelpers.createTestGPG()
        defer { TestHelpers.cleanupTempGPGHome(homeDir) }
        
        let key = try await TestHelpers.generateKey(
            with: gpg,
            firstName: "Andrew",
            lastName: "Able",
            domain: "alpha.com"
        )
        
        let keys = try await gpg.listKeys(secret: true)
        let uid = keys.keys.last?.userIds.first ?? ""
        
        let testFilePath = try TestHelpers.createRandomTestFile()
        defer { try? FileManager.default.removeItem(atPath: testFilePath) }
        
        let signed = try await gpg.signFile(testFilePath, keyId: uid, passphrase: "aable", detach: true)
        #expect(signed.returnCode == 0, "Signing with UID should succeed")
        #expect(signed.isValid, "UID signature should be valid")
        */
    }
}
