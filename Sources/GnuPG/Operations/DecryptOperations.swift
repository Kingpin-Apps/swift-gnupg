import Foundation

extension GnuPG {
    
    // MARK: - Decrypt Operations
    
    /// Decrypt encrypted data
    /// - Parameters:
    ///   - message: The encrypted data as a String
    ///   - passphrase: Optional passphrase for decryption (required for encrypted messages)
    ///   - extraArgs: Additional GPG command-line arguments (default: nil)
    /// - Returns: A DecryptResult with the decrypted data and status information
    @discardableResult
    public func decrypt(message: String,
                       passphrase: String? = nil,
                       extraArgs: [String]? = nil) async -> DecryptResult {
        
        guard let messageData = message.data(using: .utf8) else {
            let result = DecryptResult(gpg: self)
            result.status = "error: failed to convert message to data"
            return result
        }
        
        return await decrypt(data: messageData, passphrase: passphrase, extraArgs: extraArgs)
    }
    
    /// Decrypt encrypted data
    /// - Parameters:
    ///   - data: The encrypted data
    ///   - passphrase: Optional passphrase for decryption (required for encrypted messages)
    ///   - extraArgs: Additional GPG command-line arguments (default: nil)
    /// - Returns: A DecryptResult with the decrypted data and status information
    @discardableResult
    public func decrypt(data: Data,
                       passphrase: String? = nil,
                       extraArgs: [String]? = nil) async -> DecryptResult {
        
        let result = DecryptResult(gpg: self)
        
        do {
            var args = ["--decrypt"]
            
            // Add extra arguments if provided
            if let extraArgs = extraArgs {
                args.append(contentsOf: extraArgs)
            }
            
            let processResult = try await self.executeCommand(
                arguments: args,
                input: data,
                statusHandler: result,
                passphrase: passphrase
            )
            
            // Store the decrypted data if successful
            result.data = processResult.output
            
            // Set success status if not already set by status messages
            if result.status == nil && processResult.exitCode == 0 {
                result.status = "decryption ok"
            }
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Decrypt an encrypted file
    /// - Parameters:
    ///   - inputPath: Path to the encrypted file
    ///   - outputPath: Optional path for the decrypted output (if nil, removes .gpg/.asc extension)
    ///   - passphrase: Optional passphrase for decryption
    ///   - extraArgs: Additional GPG command-line arguments (default: nil)
    /// - Returns: A DecryptResult indicating success or failure
    @discardableResult
    public func decryptFile(inputPath: String,
                           outputPath: String? = nil,
                           passphrase: String? = nil,
                           extraArgs: [String]? = nil) async -> DecryptResult {
        
        let result = DecryptResult(gpg: self)
        
        do {
            // Check if input file exists
            guard FileManager.default.fileExists(atPath: inputPath) else {
                result.status = "error: input file not found: \(inputPath)"
                return result
            }
            
            var args = ["--decrypt"]
            
            // Add output file if specified
            if let outputPath = outputPath {
                args.append(contentsOf: ["--output", outputPath])
            }
            
            // Add extra arguments if provided
            if let extraArgs = extraArgs {
                args.append(contentsOf: extraArgs)
            }
            
            // Add input file
            args.append(inputPath)
            
            let processResult = try await self.executeCommand(
                arguments: args,
                statusHandler: result,
                passphrase: passphrase
            )
            
            // For file operations, check if we should store output data
            if outputPath == nil, let outputData = processResult.output {
                result.data = outputData
            }
            
            // Set success status if not already set
            if result.status == nil && processResult.exitCode == 0 {
                result.status = "decryption ok"
            }
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Decrypt and verify a message in one operation
    /// - Parameters:
    ///   - message: The encrypted and signed message
    ///   - passphrase: Optional passphrase for decryption
    ///   - extraArgs: Additional GPG command-line arguments (default: nil)
    /// - Returns: A DecryptResult with both decryption and signature verification information
    @discardableResult
    public func decryptAndVerify(message: String,
                               passphrase: String? = nil,
                               extraArgs: [String]? = nil) async -> DecryptResult {
        
        guard let messageData = message.data(using: .utf8) else {
            let result = DecryptResult(gpg: self)
            result.status = "error: failed to convert message to data"
            return result
        }
        
        return await decryptAndVerify(data: messageData, passphrase: passphrase, extraArgs: extraArgs)
    }
    
    /// Decrypt and verify data in one operation
    /// - Parameters:
    ///   - data: The encrypted and signed data
    ///   - passphrase: Optional passphrase for decryption
    ///   - extraArgs: Additional GPG command-line arguments (default: nil)
    /// - Returns: A DecryptResult with both decryption and signature verification information
    @discardableResult
    public func decryptAndVerify(data: Data,
                               passphrase: String? = nil,
                               extraArgs: [String]? = nil) async -> DecryptResult {
        
        let result = DecryptResult(gpg: self)
        
        do {
            // Use --decrypt which also verifies signatures if present
            var args = ["--decrypt"]
            
            // Add extra arguments if provided
            if let extraArgs = extraArgs {
                args.append(contentsOf: extraArgs)
            }
            
            let processResult = try await self.executeCommand(
                arguments: args,
                input: data,
                statusHandler: result,
                passphrase: passphrase
            )
            
            // Store the decrypted data if successful
            result.data = processResult.output
            
            // Set success status if not already set
            if result.status == nil && processResult.exitCode == 0 {
                result.status = "decryption ok"
            }
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Decrypt a file and verify its signature
    /// - Parameters:
    ///   - inputPath: Path to the encrypted and signed file
    ///   - outputPath: Optional path for the decrypted output
    ///   - passphrase: Optional passphrase for decryption
    ///   - extraArgs: Additional GPG command-line arguments (default: nil)
    /// - Returns: A DecryptResult with both decryption and signature verification information
    @discardableResult
    public func decryptAndVerifyFile(inputPath: String,
                                   outputPath: String? = nil,
                                   passphrase: String? = nil,
                                   extraArgs: [String]? = nil) async -> DecryptResult {
        
        let result = DecryptResult(gpg: self)
        
        do {
            // Check if input file exists
            guard FileManager.default.fileExists(atPath: inputPath) else {
                result.status = "error: input file not found: \(inputPath)"
                return result
            }
            
            var args = ["--decrypt"]
            
            // Add output file if specified
            if let outputPath = outputPath {
                args.append(contentsOf: ["--output", outputPath])
            }
            
            // Add extra arguments if provided
            if let extraArgs = extraArgs {
                args.append(contentsOf: extraArgs)
            }
            
            // Add input file
            args.append(inputPath)
            
            let processResult = try await self.executeCommand(
                arguments: args,
                statusHandler: result,
                passphrase: passphrase
            )
            
            // For file operations, check if we should store output data
            if outputPath == nil, let outputData = processResult.output {
                result.data = outputData
            }
            
            // Set success status if not already set
            if result.status == nil && processResult.exitCode == 0 {
                result.status = "decryption ok"
            }
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Convenience method to check if decryption would be successful
    /// - Parameters:
    ///   - data: The encrypted data to test
    ///   - passphrase: Optional passphrase for testing
    /// - Returns: True if decryption would succeed, false otherwise
    public func canDecrypt(data: Data, passphrase: String? = nil) async -> Bool {
        let result = await decrypt(data: data, passphrase: passphrase)
        return result.isSuccessful
    }
    
    /// Convenience method to check if a file can be decrypted
    /// - Parameters:
    ///   - path: Path to the encrypted file
    ///   - passphrase: Optional passphrase for testing
    /// - Returns: True if decryption would succeed, false otherwise
    public func canDecryptFile(path: String, passphrase: String? = nil) async -> Bool {
        let result = await decryptFile(inputPath: path, passphrase: passphrase)
        return result.isSuccessful
    }
}