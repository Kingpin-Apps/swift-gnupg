import Testing
import Foundation
@testable import GnuPG

/// Tests for basic environment setup and GPG binary availability
/// 
/// Corresponds to Python tests: 
/// - test_environment, test_list_keys_initial, test_nogpg, test_invalid_home, test_make_args
@Suite("Basic Environment Tests", .serialized)
struct BasicEnvironmentTests {
    
    // MARK: - Environment Tests
    
    @Test("Test environment setup - GPG home directory exists and is accessible")
    func testEnvironment() async throws {
        let (_, homeDir) = try TestHelpers.createTestGPG()
        defer { TestHelpers.cleanupTempGPGHome(homeDir) }
        
        // Verify the home directory exists and is a directory
        let fileManager = FileManager.default
        var isDirectory: ObjCBool = false
        let exists = fileManager.fileExists(atPath: homeDir, isDirectory: &isDirectory)
        
        #expect(exists, "GPG home directory should exist: \(homeDir)")
        #expect(isDirectory.boolValue, "GPG home directory should be a directory: \(homeDir)")
    }
    
    @Test("Test initial key list - should be empty")
    func testListKeysInitial() async throws {
        let (gpg, homeDir) = try TestHelpers.createTestGPG()
        defer { TestHelpers.cleanupTempGPGHome(homeDir) }
        
        // Test public keys list
        let publicKeys = await gpg.listKeys()
        #expect(publicKeys.returnCode == 0, "List keys should succeed")
        #expect(TestHelpers.isListWithLength(publicKeys.keys, 0), "Public keys list should be empty initially")
        
        // Test private keys list  
        let privateKeys = await gpg.listKeys(secret: true)
        #expect(privateKeys.returnCode == 0, "List secret keys should succeed")
        #expect(TestHelpers.isListWithLength(privateKeys.keys, 0), "Private keys list should be empty initially")
    }
    
    @Test("Test GPG binary not found")
    func testNoGPG() async throws {
        #expect(throws: GPGError.gpgNotAvailable("/nonexistent-gpg")) {
            try GnuPG(gpgBinary: "/nonexistent-gpg")
        }
    }
    
    @Test("Test invalid home directory")
    func testInvalidHome() async throws {
        // Create a temporary directory then remove it
        let tempDir = NSTemporaryDirectory() + "nonexistent-\(UUID().uuidString)"
        
        #expect(throws: GPGError.invalidHomeDirecory(tempDir)) {
            try GnuPG(gnupgHome: tempDir)
        }
    }
    
    @Test("Test argument construction")
    func testMakeArgs() async throws {
        let (_, homeDir) = try TestHelpers.createTestGPG()
        defer { TestHelpers.cleanupTempGPGHome(homeDir) }
        
        // Create a GPG instance with some valid options
        let gpgWithOptions = try GnuPG(
            gnupgHome: homeDir,
            options: ["--verbose", "--armor"]
        )
        
        let args = gpgWithOptions.makeArgs(["a", "b"], hasPassphrase: false)
        
        #expect(args.count > 4, "Should have at least base arguments plus custom ones")
        #expect(args.contains("--verbose"), "Should contain custom option --verbose")
        #expect(args.contains("--armor"), "Should contain custom option --armor")
        #expect(args.contains("a"), "Should contain passed argument 'a'")
        #expect(args.contains("b"), "Should contain passed argument 'b'")
        
        // Check that custom options and arguments are at the end
        let suffixArgs = Array(args.suffix(4))
        #expect(suffixArgs == ["--verbose", "--armor", "a", "b"], "Custom options and args should be at the end")
    }
    
    // MARK: - Shell Quoting Tests (from Python test_quote_with_shell)
    
    @Test("Test shell quoting functionality")
    func testQuoteWithShell() async throws {
        #if os(macOS) || os(Linux)
        // Only run on POSIX systems like the Python version
        
        let testCases = [
            ("simple", "simple"),
            ("", "''"),
            ("hello world", "'hello world'"),
            ("it's", "'it'\\''s'")
        ]
        
        for (input, expected) in testCases {
            let quoted = GPGUtilities.shellQuote(input)
            #expect(quoted == expected, "Shell quote of '\(input)' should be '\(expected)', got '\(quoted)'")
        }
        
        // Test with actual shell execution (simplified version of Python test)
        let workdir = NSTemporaryDirectory() + "shell-quote-test-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: workdir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: workdir) }
        
        // Test that dangerous string doesn't create unwanted files
        let dangerousString = "'\\\\\\\"; touch \(workdir)/foo #'"
        let quotedDangerous = GPGUtilities.shellQuote(dangerousString)
        
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", "echo \(quotedDangerous)"]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        
        try process.run()
        process.waitUntilExit()
        
        #expect(process.terminationStatus == 0, "Shell command should succeed")
        
        // Verify no unwanted file was created
        let files = try FileManager.default.contentsOfDirectory(atPath: workdir)
        #expect(files.isEmpty, "No files should be created by dangerous string")
        
        #endif
    }
}
