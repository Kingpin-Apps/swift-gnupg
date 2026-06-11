import Testing
import Foundation
@testable import GnuPG

/// Result from key generation operations used for testing
struct GenerateKeyResult {
    let returnCode: Int32
    let data: Data?
    let fingerprint: String
    let status: String?
    
    init(importResult: ImportResult) {
        self.returnCode = importResult.isSuccessful ? 0 : 1
        self.data = nil // ImportResult doesn't expose raw data
        self.fingerprint = importResult.fingerprints.first ?? ""
        self.status = importResult.status
    }
    
    init(returnCode: Int32, data: Data?, fingerprint: String, status: String?) {
        self.returnCode = returnCode
        self.data = data
        self.fingerprint = fingerprint
        self.status = status
    }
}

/// Test helper utilities to mirror Python test functionality
struct TestHelpers {
    
    // MARK: - Constants
    
    /// Keys to import for testing (from Python test suite)
    static let keysToImport = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.9 (MingW32)

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
=sqld
-----END PGP PUBLIC KEY BLOCK-----
"""
    
    /// Secret key for testing
    static let secretKey = """
-----BEGIN PGP PRIVATE KEY BLOCK-----

lQPGBFztd1UBCACiHhlEJIGfXNEiUX4GwamgdLOkJ3mbn5OyV4M/Ie3YvvHxveq/
TFYbuV63iuDVhNXpDUNmGsTq4vFaMsseLl7eESw8UTa3XklHHjh56kw0AVkJA75A
Xq/VshFobLNxYZdtlOVkKe1a3uJVKs+BqFjhavEjQyhkpWvBY51OzCSc2AN/aQZA
F3AltZ8luIHZPs8zVbgH90WIpze+vzAd9FyXD0wV6gylGSifHj8zIhac80evQgD9
50De7EPnSdgZSNwnlrhQtAIB5UnTETxXk34/W0Rq+BKn6SuchtaP7hXIHC0+B0C7
zBzPYKMQ7vXc/hceNwSGtgovhaQPCcv1byFBABEBAAH+BwMCUNdAVY/RMdJg1q5n
FQOyVZl2tvd3krExjGYvhabwijbPz+TrVkPhKqdkp4Hbf3oXV/bcbQhG2dld4Ooc
+xtEpTqYw08bNDuk4NEAvggasUkgssHZccDmHySGfA9U8C7B0Hj8xT4SifnuVNL+
xp9iv1BS03s+UIEVZ2rGjDQy7/G/U6/ZpLqFg+C113VQs6yz0VMsnnAQOMgN0+gQ
aZb6VNPR7nZ5+/hRlx0DgXu++lei9HTmHRz+ZvbbYjeU9nj10eANhO0lEvlgtyXa
v4Y5ERwk86gbkSRGtN88qVK/+GXK60Q33EoGMlwPZrfFGx+N5QuPEnCjT1vvz7E3
HhCpe4u5Idusgui+tDkxq8BEz6iTGMO1hcb75MDdIQBhJzeJ7OIxyBfqLReF4+Ut
eNwy0wpN3xuEeYvP4ZIe7hj74WWIuKq2+lesPm4eWRPoaQ5MZXmEwbjr29e++V7D
EkHgCYio6TVwrHA0LRSNfm8VVBV2cdsqFOLLutudHoC8BnjetEetmYaA99u0Pevz
NscYwfaWLNW/d5FGyPUb+GQFYzmQWUfUzpg9hu7U79uA0kOwC+4nK6LEalILtoHn
YO3PvvcCEnpWBlDhCR3n0zkNQCulvQKS/ww5q/MDNqvibKiMJHJ1xP89tEU3lnHl
qgwHVmleqUR+yzdg5lo96Yey5yaDdhK5ZR1TFC4qK4Igcn2+WG109659bJUGpEre
Vktu530JutX38ZoyKdHO0uPs/ft/hgBhNd6MKmh7eejo84Wn6/lxkfMydkfKm5QY
dMHF3Ew+l7aACAs3l95V0YDNzA0FyOFkb/tqxyx8dP+O2NdZQZSvG+yxDav05bCq
kwz+7H7sJnUj1JJtUgPTL9yVH+LyUhL8AU13UKVjBFJ4VL5+KDD9KwPkk6aN7zDW
Qv0g8Cc7A8H0tB5BdXRvZ2VuZXJhdGVkIEtleSA8dXNlcjFAdGVzdD6JATgEEwEI
ACIFAlztd1UCGy8GCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEGP32fXSIJgg
IXgH/3o1rUzbjjz1sMoBwRv4qLmgeqlB2YJSVzLWOn4AcrHbxup5O9nJkqG+YFwH
OFmytuiPDKmA4ZXww8f+2rHXdDuwI5SWnfhuPpV863BulIhtjwiwqD9eIzQ9LX79
K7hXRJ4I0AkYEbDHOWlLHZCrjul/ZaS10QRVR21EYICha2I8tvxsRMPp0I93XnuB
T+z7ykRxRjpMv6MfhWVcw5B0s7lPedLhcx657HfY49t36/CIZ9/zMKsduX7cTOAh
tO8f06R3yfjxLRD8y89frVP3+tGMvt2yGOd5TT0zht5yYcG6QkiHlfdgXqeE8nsU
2392Xn/RETq6xCj3kG6K3wbWqh0=
=2A5s
-----END PGP PRIVATE KEY BLOCK-----
"""
    
    // MARK: - Environment Setup
    
    /// Create a temporary GPG home directory for isolated testing
    /// - Returns: Path to temporary directory
    static func createTempGPGHome() throws -> String {
        // Base the temp home on a short path (e.g. /tmp/gpg-test-<uuid>) rather
        // than NSTemporaryDirectory(). On macOS the latter is a ~94-char
        // /var/folders/... path; appending /S.gpg-agent overflows the ~104-char
        // UNIX-socket limit and gpg-agent dies with "File name too long".
        let gpgHome = "/tmp/gpg-test-\(UUID().uuidString)"

        let fileManager = FileManager.default
        try fileManager.createDirectory(atPath: gpgHome, withIntermediateDirectories: true)
        
        // Set proper permissions (0700)
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: gpgHome)
        
        // Create comprehensive GPG configuration for testing
        let gpgConf = """
pinentry-mode loopback
use-agent
batch
quiet
no-tty
personal-cipher-preferences AES256 AES192 AES CAST5
personal-digest-preferences SHA256 SHA1 SHA384 SHA512 SHA224
default-preference-list SHA256 SHA1 SHA384 SHA512 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed
"""
        let gpgConfPath = gpgHome + "/gpg.conf"
        try gpgConf.write(toFile: gpgConfPath, atomically: true, encoding: .utf8)
        
        // Create GPG agent configuration for testing
        // NB: `batch` and `loopback` are gpg options, NOT gpg-agent options.
        // Including them here makes gpg-agent refuse to start ("IPC connect
        // call failed"), so they must stay out of gpg-agent.conf.
        let agentConf = """
allow-loopback-pinentry
max-cache-ttl 3600
default-cache-ttl 3600
no-grab
pinentry-timeout 0
quiet
"""
        let agentConfPath = gpgHome + "/gpg-agent.conf"
        try agentConf.write(toFile: agentConfPath, atomically: true, encoding: .utf8)
        
        // Try to configure GPG agent for the test environment
        let agentInfoFile = gpgHome + "/gpg-agent-info"
        let agentPidFile = gpgHome + "/gpg-agent.pid"
        
        do {
            // First, try to kill any existing agent for this home directory
            let killProcess = Process()
            killProcess.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            killProcess.arguments = ["gpgconf", "--homedir", gpgHome, "--kill", "gpg-agent"]
            killProcess.environment = ["GNUPGHOME": gpgHome]
            killProcess.standardOutput = Pipe()
            killProcess.standardError = Pipe()
            try killProcess.run()
            killProcess.waitUntilExit()
            
            // Clean up any existing pid files
            try? FileManager.default.removeItem(atPath: agentInfoFile)
            try? FileManager.default.removeItem(atPath: agentPidFile)
            
            // Give a moment for cleanup
            Thread.sleep(forTimeInterval: 0.1)
            
            // Try to launch agent with proper configuration
            let launchProcess = Process()
            launchProcess.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            launchProcess.arguments = [
                "gpg-agent", 
                "--homedir", gpgHome,
                "--daemon", 
                "--allow-loopback-pinentry",
                "--quiet",
                "--batch"
            ]
            launchProcess.environment = ["GNUPGHOME": gpgHome]
            launchProcess.standardOutput = Pipe()
            launchProcess.standardError = Pipe()
            
            try launchProcess.run()
            // Don't wait for daemon to finish as it runs in background
            
            // Give the agent more time to start and create its socket
            Thread.sleep(forTimeInterval: 0.2)
            
            // Try to reload the agent to ensure it's running
            let reloadProcess = Process()
            reloadProcess.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            reloadProcess.arguments = ["gpgconf", "--homedir", gpgHome, "--reload", "gpg-agent"]
            reloadProcess.environment = ["GNUPGHOME": gpgHome]
            reloadProcess.standardOutput = Pipe()
            reloadProcess.standardError = Pipe()
            try reloadProcess.run()
            reloadProcess.waitUntilExit()
            
        } catch {
            // If agent setup fails, continue - GPG will try to start it as needed
        }
        
        return gpgHome
    }
    
    /// Clean up temporary GPG home directory
    /// - Parameter path: Path to directory to remove
    static func cleanupTempGPGHome(_ path: String) {
        try? FileManager.default.removeItem(atPath: path)
    }
    
    // MARK: - GPG Instance Creation
    
    /// Create a GPG instance for testing with isolated home directory
    /// - Parameter customHome: Optional custom home directory (if nil, creates temporary)
    /// - Returns: GPG instance and home directory path
    static func createTestGPG(customHome: String? = nil) throws -> (gpg: GnuPG, homeDir: String) {
        let homeDir: String
        if let customHome = customHome {
            homeDir = customHome
        } else {
            homeDir = try createTempGPGHome()
        }
        
        // Create GPG instance with testing-friendly options
        let testOptions = [
            "--pinentry-mode", "loopback",
            "--batch",
            "--no-tty",
            "--quiet",
            "--trust-model", "always"  // Trust all keys automatically in tests
        ]
        
        let gpg = try GnuPG(
            gnupgHome: homeDir, 
            verbose: false,
            useAgent: true,  // Use agent but configured for batch mode
            options: testOptions
        )
        return (gpg, homeDir)
    }

    // MARK: - Test Doubles & Capability Gating

    /// Build a `GnuPG` instance for parsing / result-construction unit tests.
    ///
    /// This launches no subprocess and requires no installed `gpg`, so tests that
    /// only feed canned status messages to a result type (e.g. `VerifyResult`)
    /// run anywhere, including headless Linux CI. Do **not** invoke real gpg
    /// operations through the returned instance.
    static func makeParsingStub() -> GnuPG {
        GnuPG(unprobedBinary: "gpg")
    }

    /// Whether the current environment can perform real `gpg` crypto operations
    /// (binary present, agent reachable, key generation succeeds).
    ///
    /// Integration tests gate on this via `.enabled(if:)` so they *skip* — rather
    /// than fail — on environments without a working gpg-agent (e.g. the Swift
    /// Package Index Linux compatibility containers). The probe runs once and the
    /// result is cached for the lifetime of the test process.
    static let realGPGAvailable: Bool = probeRealGPG()

    private static func probeRealGPG() -> Bool {
        // Generate a real key in an isolated home. This requires a working
        // gpg-agent (loopback passphrase), so it succeeds only where genuine
        // secret-key crypto works and fails on headless environments — letting
        // the gpg-dependent tests skip rather than fail there.
        //
        // This runs gpg directly and synchronously (no Task/await, no
        // semaphore). `.enabled(if:)` needs a synchronous Bool and is evaluated
        // — possibly concurrently — during test discovery; bridging to the async
        // API here would block Swift's cooperative thread pool waiting on work
        // that itself needs that pool, deadlocking the parallel runner. A plain
        // subprocess + waitUntilExit() runs in the OS, not the cooperative pool.
        guard let home = try? createTempGPGHome() else { return false }
        defer { try? FileManager.default.removeItem(atPath: home) }

        let keyParams = """
        %echo SwiftGnuPG probe
        Key-Type: RSA
        Key-Length: 2048
        Name-Real: SwiftGnuPG Probe
        Name-Email: probe@example.com
        Expire-Date: 0
        Passphrase: probe
        %commit
        """

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["gpg", "--homedir", home, "--batch",
                             "--pinentry-mode", "loopback", "--generate-key"]
        // Inherit the parent environment (PATH etc.) and point gpg at the
        // isolated home; replacing the environment outright would drop PATH so
        // `/usr/bin/env gpg` couldn't find the binary.
        var environment = ProcessInfo.processInfo.environment
        environment["GNUPGHOME"] = home
        process.environment = environment

        let stdin = Pipe()
        process.standardInput = stdin
        // Discard output so the subprocess never blocks on a full pipe.
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            stdin.fileHandleForWriting.write(Data(keyParams.utf8))
            try? stdin.fileHandleForWriting.close()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }

    // MARK: - Key Generation Helpers

    /// Parameters for key generation matching Python test suite
    struct KeyGenParams {
        let keyType: String
        let keyLength: Int?
        let subkeyType: String?
        let subkeyLength: Int?
        let nameReal: String
        let nameComment: String?
        let nameEmail: String
        let expireDate: String
        let passphrase: String?
        let withSubkey: Bool
        var keyCurve: String?
        var subkeyCurve: String?
        
        init(
            keyType: String = "RSA",
            keyLength: Int? = 3072,
            subkeyType: String? = "RSA",
            subkeyLength: Int? = 3072,
            nameReal: String,
            nameComment: String? = "A test user",
            nameEmail: String,
            expireDate: String = "0",
            passphrase: String? = nil,
            withSubkey: Bool = true,
            keyCurve: String? = nil,
            subkeyCurve: String? = nil
        ) {
            self.keyType = keyType
            self.keyLength = keyLength
            self.subkeyType = withSubkey ? subkeyType : nil
            self.subkeyLength = withSubkey ? subkeyLength : nil
            self.nameReal = nameReal
            self.nameComment = nameComment
            self.nameEmail = nameEmail
            self.expireDate = expireDate
            self.passphrase = passphrase
            self.withSubkey = withSubkey
            self.keyCurve = keyCurve
            self.subkeyCurve = subkeyCurve
        }
    }
    
    /// Generate a test key with given parameters
    /// - Parameters:
    ///   - gpg: GPG instance
    ///   - firstName: First name for key
    ///   - lastName: Last name for key
    ///   - domain: Domain for email
    ///   - passphrase: Passphrase (if nil, auto-generated)
    ///   - withSubkey: Whether to include subkey
    /// - Returns: Generated key result
    static func generateKey(
        with gpg: GnuPG,
        firstName: String,
        lastName: String,
        domain: String,
        passphrase: String? = nil,
        withSubkey: Bool = true
    ) async throws -> GenerateKeyResult {
        let actualPassphrase = passphrase ?? "\(firstName.lowercased().first!)\(lastName.lowercased())"
        let nameReal = "\(firstName) \(lastName)"
        let nameEmail = "\(firstName.lowercased()).\(lastName.lowercased())@\(domain)"
        
        var comment = "A test user"
        // For insecure/test RNG, we might need to add (insecure!) to comment
        if let options = gpg.options, options.contains("--quick-random") || options.contains("--debug-quick-random") {
            comment = "A test user (insecure!)"
        }
        
        let params = KeyGenParams(
            nameReal: nameReal,
            nameComment: comment,
            nameEmail: nameEmail,
            passphrase: actualPassphrase,
            withSubkey: withSubkey
        )
        
        let result = try await generateKey(with: gpg, params: params)
        
        // If key generation failed due to agent issues, fall back to importing pre-generated keys
        if result.returnCode != 0 {
            let importResult = await gpg.importKeys(keyString: keysToImport + "\n" + secretKey)
            if importResult.returnCode == 0 && !importResult.fingerprints.isEmpty {
                return GenerateKeyResult(
                    returnCode: 0,
                    data: nil,
                    fingerprint: importResult.fingerprints[0],
                    status: "imported pre-generated key"
                )
            }
        }
        
        return result
    }
    
    /// Generate a key with detailed parameters
    /// - Parameters:
    ///   - gpg: GPG instance
    ///   - params: Key generation parameters
    /// - Returns: Generated key result
    static func generateKey(with gpg: GnuPG, params: KeyGenParams) async throws -> GenerateKeyResult {
        let userIdString = params.nameComment.flatMap { comment in
            "\(params.nameReal) (\(comment)) <\(params.nameEmail)>"
        } ?? "\(params.nameReal) <\(params.nameEmail)>"
        
        let result = await gpg.generateKey(
            keyType: params.keyType,
            keySize: params.keyLength ?? 3072,
            userId: userIdString,
            passphrase: params.passphrase ?? "",
            expirationDate: params.expireDate == "0" ? nil : params.expireDate
        )
        
        return GenerateKeyResult(importResult: result)
    }
    
    // MARK: - Test Data Helpers
    
    /// Get path to test data file
    /// - Parameter filename: Name of test data file
    /// - Returns: Full path to test data file
    static func testDataPath(filename: String) -> String? {
        // Use the test bundle to find resources
        let bundle = testBundle
        return bundle.path(forResource: filename.replacingOccurrences(of: ".gpg", with: ""), ofType: "gpg", inDirectory: "data")
    }
    
    /// Load test key ring data
    /// - Parameter filename: Name of keyring file (test_pubring.gpg or test_secring.gpg)
    /// - Returns: Data content of keyring file
    static func loadTestKeyring(_ filename: String) throws -> Data {
        guard let path = testDataPath(filename: filename) else {
            throw NSError(domain: "TestHelpers", code: 1, userInfo: [NSLocalizedDescriptionKey: "Could not find test data file: \(filename)"])
        }
        return try Data(contentsOf: URL(fileURLWithPath: path))
    }
    
    // MARK: - List Checking Helpers
    
    /// Check if object is a list with specific length (mirrors Python helper)
    /// - Parameters:
    ///   - array: Array to check
    ///   - expectedCount: Expected count
    /// - Returns: True if array has expected count
    static func isListWithLength<T>(_ array: [T], _ expectedCount: Int) -> Bool {
        return array.count == expectedCount
    }
    
    // MARK: - Data Generation
    
    /// Create random binary test data
    /// - Parameter size: Size in bytes
    /// - Returns: Random data
    static func createRandomTestData(size: Int) -> Data {
        var data = Data(capacity: size)
        for _ in 0..<size {
            data.append(UInt8.random(in: 0...255))
        }
        return data
    }
    
    // MARK: - Key Comparison
    
    /// Compare two ASCII armored keys (mirrors Python compare_keys function)
    /// - Parameters:
    ///   - k1: First key string
    ///   - k2: Second key string
    /// - Returns: 0 if keys match, non-zero if different
    static func compareKeys(_ k1: String, _ k2: String) -> Int {
        // Extract only the base64 key data, ignoring headers/footers and whitespace
        let keyData1 = getKeyData(k1)
        let keyData2 = getKeyData(k2)
        return keyData1 == keyData2 ? 0 : 1
    }
    
    /// Extract base64 key data from PGP key string (mirrors Python get_key_data)
    /// - Parameter keyString: PGP key string
    /// - Returns: Base64 key data only
    private static func getKeyData(_ keyString: String) -> String {
        let lines = keyString.components(separatedBy: .newlines)
        let base64Pattern = try! NSRegularExpression(pattern: "^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$", options: .caseInsensitive)
        
        var result = ""
        for line in lines {
            let trimmedLine = line.trimmingCharacters(in: .whitespacesAndNewlines)
            let range = NSRange(location: 0, length: trimmedLine.utf16.count)
            if base64Pattern.firstMatch(in: trimmedLine, options: [], range: range) != nil {
                result += trimmedLine
            }
        }
        return result
    }
    
    /// Create isolated GPG instance for testing
    /// - Returns: GPG instance with isolated temporary home directory
    static func createIsolatedGPG() async throws -> GnuPG {
        let tempDir = try createTempGPGHome()
        return try GnuPG(gnupgHome: tempDir, verbose: false)
    }
    
    /// Create test file with random data (mirrors Python setup)
    /// - Parameter filename: Name of test file to create
    /// - Returns: Path to created test file
    static func createRandomTestFile(filename: String = "random_binary_data") throws -> String {
        // Use a unique path per call. A fixed shared filename is a cross-test data
        // race once the suite runs in parallel (and its `.asc`/`.sig` sidecars
        // collide), so each caller gets its own file to clean up.
        let tempDir = NSTemporaryDirectory()
        let testFilePath = tempDir + "\(filename)-\(UUID().uuidString)"

        let testData = createRandomTestData(size: 5120 * 1024) // 5MB like Python version
        try testData.write(to: URL(fileURLWithPath: testFilePath))

        return testFilePath
    }
}

// MARK: - Extensions for Bundle Access

extension TestHelpers {
    private class BundleMarker {}
    
    static var testBundle: Bundle {
        return Bundle(for: BundleMarker.self)
    }
}