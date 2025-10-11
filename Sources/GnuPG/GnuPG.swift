import Foundation
//import SystemPackage
#if canImport(os)
import os
#endif

/// Swift wrapper for the GnuPG `gpg` command.
/// 
/// This is a Swift port of python-gnupg, providing a high-level programmatic interface
/// for GPG operations including signing, verification, encryption, decryption, and key management.
/// 
/// Original Python implementation: https://gnupg.readthedocs.io/
public final class GnuPG: @unchecked Sendable {
    
    // MARK: - Public Properties
    
    /// The path to the GPG binary
    public let gpgBinary: String
    
    /// The GPG home directory path
    public let gnupgHome: String?
    
    /// Whether to enable verbose output
    public let verbose: Bool
    
    /// Whether to use GPG agent
    public let useAgent: Bool
    
    /// Alternative keyring file paths
    public let keyring: [String]?
    
    /// Alternative secret keyring file paths  
    public let secretKeyring: [String]?
    
    /// Additional options to pass to GPG
    public let options: [String]?
    
    /// Environment variables for GPG subprocess
    public let environment: [String: String]?
    
    /// The encoding to use for GPG communication (defaults to latin-1 like python-gnupg)
    public var encoding: String.Encoding = .isoLatin1
    
    /// Buffer size for data operations
    public var bufferSize: Int = 16384
    
    /// GPG version detected during initialization
    public private(set) var version: GPGVersion?
    
    /// Whether to check for fingerprint collisions
    public var checkFingerprintCollisions: Bool = false
    
    /// Logger instance for this GPG instance
    public var logger: GPGLogger = GPGLogger.shared
    
    // MARK: - Internal Properties
    
    private let fileManager = FileManager.default
    
    // MARK: - Initialization
    
    /// Initialize a GPG process wrapper.
    /// 
    /// - Parameters:
    ///   - gpgBinary: A pathname for the GPG binary to use (defaults to "gpg")
    ///   - gnupgHome: A pathname to the GPG home directory (defaults to GPG's default)
    ///   - keyring: Alternative keyring file(s) to use instead of default
    ///   - secretKeyring: Alternative secret keyring file(s) to use
    ///   - verbose: Whether to enable verbose output
    ///   - useAgent: Whether to use GPG agent
    ///   - options: Additional options to pass to GPG
    ///   - environment: Environment variables for GPG subprocess
    /// - Throws: `GPGError` if GPG binary is not available or home directory is invalid
    public init(
        gpgBinary: String? = nil,
        gnupgHome: String? = nil,
        keyring: [String]? = nil,
        secretKeyring: [String]? = nil,
        verbose: Bool = false,
        useAgent: Bool = false,
        options: [String]? = nil,
        environment: [String: String]? = nil
    ) throws {
        // Try to find the actual GPG binary path if just "gpg" is specified
        self.gpgBinary = try Self.findGPGBinary(gpgBinary ?? "gpg")
        self.gnupgHome = gnupgHome
        self.verbose = verbose
        self.useAgent = useAgent
        self.keyring = keyring
        self.secretKeyring = secretKeyring
        self.options = options
        self.environment = environment
        
        // Validate gnupgHome is a directory if specified
        if let home = gnupgHome {
            var isDirectory: ObjCBool = false
            if !fileManager.fileExists(atPath: home, isDirectory: &isDirectory) || !isDirectory.boolValue {
                throw GPGError.invalidHomeDirecory(home)
            }
        }
        
        // Test GPG binary availability and get version
        try initializeGPG()
    }
    
    // MARK: - Private Methods
    
    /// Find the GPG binary in common locations
    /// - Parameter preferredPath: Preferred binary path (if absolute path, use as-is)
    /// - Returns: Full path to GPG binary
    /// - Throws: GPGError if binary cannot be found
    private static func findGPGBinary(_ preferredPath: String) throws -> String {
        // If it's an absolute path, check if it exists and use it
        if preferredPath.hasPrefix("/") {
            if FileManager.default.fileExists(atPath: preferredPath) {
                return preferredPath
            } else {
                throw GPGError.gpgNotAvailable(preferredPath)
            }
        }
        
        // For relative paths like "gpg", try to find the binary using 'which'
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        process.arguments = [preferredPath]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        
        do {
            try process.run()
            process.waitUntilExit()
            
            if process.terminationStatus == 0 {
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                if let path = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                   !path.isEmpty {
                    return path
                }
            }
        } catch {
            // Fall through to try common locations
        }
        
        // Try common locations for GPG
        let commonPaths = [
            "/opt/homebrew/bin/gpg",    // Homebrew on Apple Silicon
            "/usr/local/bin/gpg",       // Homebrew on Intel Mac
            "/usr/bin/gpg",             // System installation
            "/opt/local/bin/gpg"        // MacPorts
        ]
        
        for path in commonPaths {
            if FileManager.default.fileExists(atPath: path) {
                return path
            }
        }
        
        throw GPGError.gpgNotAvailable(preferredPath)
    }
    
    private func initializeGPG() throws {
        logger.info("Initializing GPG with binary: \(gpgBinary)", category: "Initialization")
        
        do {
            // Try to run gpg --list-config to verify it works and get version
            logger.debug("Testing GPG binary availability", category: "Initialization")
            let process = try openSubprocess(["--list-config", "--with-colons"])
            let result = VerifyResult(gpg: self)
            try collectOutput(process: process, result: result)
            
            if process.terminationStatus != 0 {
                logger.error("GPG binary test failed with exit code: \(process.terminationStatus)", category: "Initialization")
                throw GPGError.gpgNotAvailable(gpgBinary)
            }
            
            // Extract version from config output
            if let data = result.data {
                self.version = GPGVersion.parse(from: data)
                if let version = self.version {
                    logger.info("GPG initialized successfully. Version: \(version.major).\(version.minor)\(version.patch.map { ".\($0)" } ?? "")", category: "Initialization")
                } else {
                    logger.warning("GPG initialized but version could not be determined", category: "Initialization")
                }
            } else {
                logger.warning("GPG initialized but no config data received", category: "Initialization")
            }
        } catch {
            logger.error("GPG initialization failed: \(error)", category: "Initialization")
            throw error
        }
    }
    
    // MARK: - Subprocess Management
    
    /// Make a list of command line arguments for GPG
    /// - Parameters:
    ///   - args: Additional arguments to append
    ///   - hasPassphrase: Whether a passphrase will be provided
    /// - Returns: Array of command line arguments
    public func makeArgs(_ args: [String], hasPassphrase: Bool = false) -> [String] {
        var cmd = [gpgBinary, "--status-fd", "2", "--no-tty", "--no-verbose"]
        
        // Set pinentry mode for GnuPG >= 2.1 when using passphrases
        if hasPassphrase, let version = version, version >= GPGVersion(major: 2, minor: 1) {
            cmd.insert(contentsOf: ["--pinentry-mode", "loopback"], at: 1)
        }
        
        cmd.append(contentsOf: ["--fixed-list-mode", "--batch", "--with-colons"])
        
        if let home = gnupgHome {
            cmd.append(contentsOf: ["--homedir", GPGUtilities.noQuote(home)])
        }
        
        if let keyrings = keyring {
            cmd.append("--no-default-keyring")
            for keyring in keyrings {
                cmd.append(contentsOf: ["--keyring", GPGUtilities.noQuote(keyring)])
            }
        }
        
        if let secretKeyrings = secretKeyring {
            for secretKeyring in secretKeyrings {
                cmd.append(contentsOf: ["--secret-keyring", GPGUtilities.noQuote(secretKeyring)])
            }
        }
        
        if hasPassphrase {
            cmd.append(contentsOf: ["--passphrase-fd", "0"])
        }
        
        if useAgent {
            cmd.append("--use-agent")
        } else {
            // For modern GPG versions, agent is always used but we can configure
            // it to work in batch mode without requiring user interaction
            if hasPassphrase, let version = version, version >= GPGVersion(major: 2, minor: 1) {
                // Already added pinentry-mode loopback above for passphrases
                // This allows the agent to get passphrases from stdin in batch mode
            }
        }
        
        if let additionalOptions = options {
            cmd.append(contentsOf: additionalOptions)
        }
        
        cmd.append(contentsOf: args)
        return cmd
    }
    
    /// Open a subprocess to GPG
    /// - Parameters:
    ///   - args: Arguments to pass to GPG
    ///   - hasPassphrase: Whether a passphrase will be provided
    /// - Returns: The Process instance
    /// - Throws: GPGError if the process cannot be created
    func openSubprocess(_ args: [String], hasPassphrase: Bool = false) throws -> Process {
        let cmd = makeArgs(args, hasPassphrase: hasPassphrase)
        
        logger.logCommand(cmd, category: "Process")
        
        let process = Process()
        process.executableURL = URL(fileURLWithPath: cmd[0])
        process.arguments = Array(cmd.dropFirst())
        
        // Set up pipes
        process.standardInput = Pipe()
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        
        // Set environment if provided
        if let env = environment {
            var processEnv = ProcessInfo.processInfo.environment
            for (key, value) in env {
                processEnv[key] = value
            }
            process.environment = processEnv
            logger.debug("Set \(env.count) custom environment variables", category: "Process")
        }
        
        do {
            try process.run()
            logger.debug("Started GPG process with PID: \(process.processIdentifier)", category: "Process")
            return process
        } catch {
            logger.error("Failed to launch GPG process: \(error)", category: "Process")
            throw GPGError.processLaunchFailed(error.localizedDescription)
        }
    }
    
    /// Read response from GPG stderr and parse status messages
    /// - Parameters:
    ///   - pipe: The stderr pipe from GPG
    ///   - result: The status handler to process messages
    private func readResponse(from pipe: Pipe, result: StatusHandler) {
        let handle = pipe.fileHandleForReading
        var lines: [String] = []
        var partialLine = ""
        
        // Use a buffer to read chunks of data until EOF
        let bufferSize = 4096
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }
        
        while true {
            let data: Data
            if #available(macOS 10.15.4, *) {
                do {
                    data = try handle.read(upToCount: bufferSize) ?? Data()
                } catch {
                    break
                }
            } else {
                data = handle.readData(ofLength: bufferSize)
            }
            
            if data.isEmpty {
                break
            }
            
            guard let string = String(data: data, encoding: encoding) else {
                continue
            }
            
            // Handle partial lines from previous read
            let fullString = partialLine + string
            let components = fullString.components(separatedBy: .newlines)
            
            // If the string doesn't end with a newline, save the last component as partial
            if !string.hasSuffix("\n") && !string.hasSuffix("\r") {
                partialLine = components.last ?? ""
                let completeLines = Array(components.dropLast())
                lines.append(contentsOf: completeLines)
            } else {
                partialLine = ""
                lines.append(contentsOf: components.dropLast()) // Drop empty last element from split
            }
            
            // Process complete lines
            let linesToProcess = partialLine.isEmpty ? Array(components.dropLast()) : Array(components.dropLast())
            for line in linesToProcess {
                let trimmedLine = line.trimmingCharacters(in: .whitespacesAndNewlines)
                if trimmedLine.isEmpty { continue }
                
                if verbose {
                    print(trimmedLine)
                }
                
                if trimmedLine.hasPrefix("[GNUPG:] ") {
                    let statusLine = String(trimmedLine.dropFirst(9)) // Remove "[GNUPG:] "
                    let statusComponents = statusLine.split(separator: " ", maxSplits: 1).map(String.init)
                    let keyword = statusComponents[0]
                    let value = statusComponents.count > 1 ? statusComponents[1] : ""
                    self.logger.logStatusMessage(key: keyword, value: value, category: "Status")
                    result.handleStatus(key: keyword, value: value)
                }
            }
        }
        
        // Handle any remaining partial line
        if !partialLine.isEmpty {
            lines.append(partialLine)
            let trimmedLine = partialLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmedLine.isEmpty {
                if verbose {
                    print(trimmedLine)
                }
                
                if trimmedLine.hasPrefix("[GNUPG:] ") {
                    let statusLine = String(trimmedLine.dropFirst(9))
                    let statusComponents = statusLine.split(separator: " ", maxSplits: 1).map(String.init)
                    let keyword = statusComponents[0]
                    let value = statusComponents.count > 1 ? statusComponents[1] : ""
                    self.logger.logStatusMessage(key: keyword, value: value, category: "Status")
                    result.handleStatus(key: keyword, value: value)
                }
            }
        }
        
        result.stderr = lines.joined(separator: "\n")
    }
    
    /// Read data from GPG stdout
    /// - Parameters:
    ///   - pipe: The stdout pipe from GPG
    ///   - result: The status handler to store data
    private func readData(from pipe: Pipe, result: StatusHandler) {
        let handle = pipe.fileHandleForReading
        var chunks: [Data] = []
        
        // Use a buffer to read chunks of data until EOF
        let bufferSize = 4096
        
        while true {
            let data: Data
            if #available(macOS 10.15.4, *) {
                do {
                    data = try handle.read(upToCount: bufferSize) ?? Data()
                } catch {
                    break
                }
            } else {
                data = handle.readData(ofLength: bufferSize)
            }
            
            if data.isEmpty {
                break
            }
            
            chunks.append(data)
        }
        
        result.data = chunks.reduce(Data(), +)
    }
    
    /// Collect output from GPG subprocess
    /// - Parameters:
    ///   - process: The GPG process
    ///   - result: The status handler to collect output
    /// - Throws: GPGError if the process fails
    func collectOutput(process: Process, result: StatusHandler) throws {
        guard let stdout = process.standardOutput as? Pipe,
              let stderr = process.standardError as? Pipe else {
            logger.error("Failed to get process pipes", category: "Process")
            throw GPGError.internalError("Failed to get process pipes")
        }
        
        logger.debug("Starting to collect GPG process output", category: "Process")
        
        // Read stderr in background for status messages
        let stderrGroup = DispatchGroup()
        stderrGroup.enter()
        DispatchQueue.global().async {
            defer { stderrGroup.leave() }
            self.readResponse(from: stderr, result: result)
        }
        
        // Read stdout in background for data
        let stdoutGroup = DispatchGroup()
        stdoutGroup.enter()
        DispatchQueue.global().async {
            defer { stdoutGroup.leave() }
            self.readData(from: stdout, result: result)
        }
        
        // Wait for process to complete and all reading to finish
        process.waitUntilExit()
        stderrGroup.wait()
        stdoutGroup.wait()
        
        result.returnCode = process.terminationStatus
        
        logger.logProcessResult(exitCode: process.terminationStatus, stderr: result.stderr, category: "Process")
        
        if let data = result.data {
            logger.debug("Collected \(data.count) bytes of output data", category: "Process")
        }
    }
    
    // MARK: - File Handling Utilities
    
    /// Check if an object is a valid file-like object
    public func isValidFile(_ object: Any) -> Bool {
        return object is InputStream || object is URL || object is String
    }
    
    /// Get file handle from various input types
    /// - Parameter input: File path, URL, or InputStream
    /// - Returns: InputStream for reading the file
    /// - Throws: GPGError for invalid input
    private func getFileHandle(from input: Any) throws -> InputStream {
        if let stream = input as? InputStream {
            return stream
        } else if let url = input as? URL {
            guard let stream = InputStream(url: url) else {
                throw GPGError.fileNotFound(url.path)
            }
            return stream
        } else if let path = input as? String {
            guard fileManager.fileExists(atPath: path) else {
                throw GPGError.fileNotFound(path)
            }
            guard let stream = InputStream(fileAtPath: path) else {
                throw GPGError.fileNotFound(path)
            }
            return stream
        } else {
            throw GPGError.invalidInput("Not a valid file or path: \(input)")
        }
    }
    
    /// Handle I/O operations with GPG subprocess
    /// - Parameters:
    ///   - args: Arguments to pass to GPG
    ///   - input: Input data or file
    ///   - result: Status handler for the operation
    ///   - passphrase: Optional passphrase
    /// - Throws: GPGError for various failure conditions
    private func handleIO(
        args: [String],
        input: Any,
        result: StatusHandler,
        passphrase: String? = nil
    ) throws {
        let inputStream = try getFileHandle(from: input)
        let process = try openSubprocess(args, hasPassphrase: passphrase != nil)
        
        guard let stdinPipe = process.standardInput as? Pipe else {
            throw GPGError.unknownError("Failed to get stdin pipe")
        }
        
        let stdinHandle = stdinPipe.fileHandleForWriting
        
        // Write passphrase if provided
        if let passphrase = passphrase {
            guard GPGUtilities.isValidPassphrase(passphrase) else {
                throw GPGError.invalidPassphrase("contains newline or null characters")
            }
            let passphraseData = "\(passphrase)\n".data(using: encoding)!
            if #available(macOS 10.15.4, *) {
                try stdinHandle.write(contentsOf: passphraseData)
            } else {
                stdinHandle.write(passphraseData)
            }
        }
        
        // Copy input data to GPG stdin synchronously for now
        // TODO: Fix async handling of InputStream (non-Sendable issue)
        let bufferSize = self.bufferSize
        inputStream.open()
        defer {
            inputStream.close()
            if #available(macOS 10.15, *) {
                try? stdinHandle.close()
            } else {
                stdinHandle.closeFile()
            }
        }
        
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }
        
        while inputStream.hasBytesAvailable {
            let bytesRead = inputStream.read(buffer, maxLength: bufferSize)
            if bytesRead > 0 {
                let data = Data(bytes: buffer, count: bytesRead)
                if #available(macOS 10.15.4, *) {
                    try stdinHandle.write(contentsOf: data)
                } else {
                    stdinHandle.write(data)
                }
            } else if bytesRead < 0 {
                break
            }
        }
        
        try collectOutput(process: process, result: result)
        
        if process.terminationStatus != 0 {
            throw GPGError.processTerminated(process.terminationStatus, stderr: "process terminated")
        }
    }
    
    // MARK: - Command Execution
    
    /// Execute a GPG command with input data and return the result
    /// - Parameters:
    ///   - arguments: GPG command arguments
    ///   - input: Optional input data
    ///   - statusHandler: Status handler to collect output
    ///   - passphrase: Optional passphrase for operations
    /// - Returns: Process result information
    /// - Throws: GPGError on failure
    func executeCommand(
        arguments: [String],
        input: Data? = nil,
        statusHandler: StatusHandler,
        passphrase: String? = nil
    ) async throws -> (output: Data?, exitCode: Int32) {
        
        let process = try openSubprocess(arguments, hasPassphrase: passphrase != nil)
        
        guard let stdinPipe = process.standardInput as? Pipe else {
            throw GPGError.unknownError("Failed to get stdin pipe")
        }
        
        let stdinHandle = stdinPipe.fileHandleForWriting
        
        // Write passphrase if provided
        if let passphrase = passphrase {
            guard GPGUtilities.isValidPassphrase(passphrase) else {
                throw GPGError.invalidPassphrase("contains newline or null characters")
            }
            let passphraseData = "\(passphrase)\n".data(using: encoding)!
            if #available(macOS 10.15.4, *) {
                try stdinHandle.write(contentsOf: passphraseData)
            } else {
                stdinHandle.write(passphraseData)
            }
        }
        
        // Write input data if provided
        if let inputData = input {
            if #available(macOS 10.15.4, *) {
                try stdinHandle.write(contentsOf: inputData)
            } else {
                stdinHandle.write(inputData)
            }
        }
        
        // Close stdin to signal end of input
        if #available(macOS 10.15, *) {
            try? stdinHandle.close()
        } else {
            stdinHandle.closeFile()
        }
        
        // Collect output
        try collectOutput(process: process, result: statusHandler)
        
        return (output: statusHandler.data, exitCode: process.terminationStatus)
    }
    
    /// Execute a GPG command with file input
    /// - Parameters:
    ///   - arguments: GPG command arguments
    ///   - statusHandler: Status handler to collect output
    ///   - passphrase: Optional passphrase for operations
    /// - Returns: Process result information
    /// - Throws: GPGError on failure
    func executeCommand(
        arguments: [String],
        statusHandler: StatusHandler,
        passphrase: String? = nil
    ) async throws -> (output: Data?, exitCode: Int32) {
        
        let process = try openSubprocess(arguments, hasPassphrase: passphrase != nil)
        
        guard let stdinPipe = process.standardInput as? Pipe else {
            throw GPGError.unknownError("Failed to get stdin pipe")
        }
        
        let stdinHandle = stdinPipe.fileHandleForWriting
        
        // Write passphrase if provided
        if let passphrase = passphrase {
            guard GPGUtilities.isValidPassphrase(passphrase) else {
                throw GPGError.invalidPassphrase("contains newline or null characters")
            }
            let passphraseData = "\(passphrase)\n".data(using: encoding)!
            if #available(macOS 10.15.4, *) {
                try stdinHandle.write(contentsOf: passphraseData)
            } else {
                stdinHandle.write(passphraseData)
            }
        }
        
        // Close stdin to signal end of input (for file operations, GPG handles file input)
        if #available(macOS 10.15, *) {
            try? stdinHandle.close()
        } else {
            stdinHandle.closeFile()
        }
        
        // Collect output
        try collectOutput(process: process, result: statusHandler)
        
        return (output: statusHandler.data, exitCode: process.terminationStatus)
    }
}
