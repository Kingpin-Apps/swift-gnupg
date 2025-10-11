import Foundation

extension GnuPG {
    
    // MARK: - Encrypt Operations
    
    /// Encrypt data using public key encryption
    /// - Parameters:
    ///   - message: The data to encrypt as a String
    ///   - recipients: Array of recipient key IDs or email addresses
    ///   - signKeyId: Optional key ID to use for signing the encrypted data
    ///   - passphrase: Optional passphrase for signing key
    ///   - armor: Whether to create ASCII armored output (default: true)
    ///   - alwaysTrust: Whether to trust recipient keys without verification (default: false)
    /// - Returns: An EncryptResult indicating success or failure
    @discardableResult
    public func encrypt(message: String,
                       recipients: [String],
                       signKeyId: String? = nil,
                       passphrase: String? = nil,
                       armor: Bool = true,
                       alwaysTrust: Bool = false) async -> EncryptResult {
        
        guard let messageData = message.data(using: .utf8) else {
            let result = EncryptResult(gpg: self)
            result.status = "error: failed to convert message to data"
            return result
        }
        
        return await encrypt(data: messageData,
                           recipients: recipients,
                           signKeyId: signKeyId,
                           passphrase: passphrase,
                           armor: armor,
                           alwaysTrust: alwaysTrust)
    }
    
    /// Encrypt data using public key encryption
    /// - Parameters:
    ///   - data: The data to encrypt
    ///   - recipients: Array of recipient key IDs or email addresses
    ///   - signKeyId: Optional key ID to use for signing the encrypted data
    ///   - passphrase: Optional passphrase for signing key
    ///   - armor: Whether to create ASCII armored output (default: true)
    ///   - alwaysTrust: Whether to trust recipient keys without verification (default: false)
    /// - Returns: An EncryptResult indicating success or failure
    @discardableResult
    public func encrypt(data: Data,
                       recipients: [String],
                       signKeyId: String? = nil,
                       passphrase: String? = nil,
                       armor: Bool = true,
                       alwaysTrust: Bool = false) async -> EncryptResult {
        
        let result = EncryptResult(gpg: self)
        
        do {
            guard !recipients.isEmpty else {
                result.status = "error: no recipients specified"
                return result
            }
            
            var args = ["--encrypt"]
            
            // Add signing if requested
            if signKeyId != nil {
                args[0] = "--encrypt-sign"
                if let keyId = signKeyId {
                    args.append(contentsOf: ["--local-user", keyId])
                }
            }
            
            // Add output format options
            if armor {
                args.append("--armor")
            }
            
            // Add trust options
            if alwaysTrust {
                args.append("--trust-model")
                args.append("always")
            }
            
            // Add recipients
            for recipient in recipients {
                args.append(contentsOf: ["--recipient", recipient])
            }
            
            let processResult = try await self.executeCommand(
                arguments: args,
                input: data,
                statusHandler: result,
                passphrase: passphrase
            )
            
            // Store the encrypted data if successful
            result.data = processResult.output
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Encrypt data using symmetric encryption (passphrase-based)
    /// - Parameters:
    ///   - message: The data to encrypt as a String
    ///   - passphrase: The passphrase to use for encryption
    ///   - armor: Whether to create ASCII armored output (default: true)
    ///   - cipher: Optional cipher algorithm to use
    /// - Returns: An EncryptResult indicating success or failure
    @discardableResult
    public func encryptSymmetric(message: String,
                               passphrase: String,
                               armor: Bool = true,
                               cipher: String? = nil) async -> EncryptResult {
        
        guard let messageData = message.data(using: .utf8) else {
            let result = EncryptResult(gpg: self)
            result.status = "error: failed to convert message to data"
            return result
        }
        
        return await encryptSymmetric(data: messageData,
                                    passphrase: passphrase,
                                    armor: armor,
                                    cipher: cipher)
    }
    
    /// Encrypt data using symmetric encryption (passphrase-based)
    /// - Parameters:
    ///   - data: The data to encrypt
    ///   - passphrase: The passphrase to use for encryption
    ///   - armor: Whether to create ASCII armored output (default: true)
    ///   - cipher: Optional cipher algorithm to use
    /// - Returns: An EncryptResult indicating success or failure
    @discardableResult
    public func encryptSymmetric(data: Data,
                               passphrase: String,
                               armor: Bool = true,
                               cipher: String? = nil) async -> EncryptResult {
        
        let result = EncryptResult(gpg: self)
        
        do {
            var args = ["--symmetric"]
            
            // Add output format options
            if armor {
                args.append("--armor")
            }
            
            // Add cipher algorithm if specified
            if let cipherAlg = cipher {
                args.append(contentsOf: ["--cipher-algo", cipherAlg])
            }
            
            let processResult = try await self.executeCommand(
                arguments: args,
                input: data,
                statusHandler: result,
                passphrase: passphrase
            )
            
            // Store the encrypted data if successful
            result.data = processResult.output
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Encrypt a file using public key encryption
    /// - Parameters:
    ///   - inputPath: Path to the file to encrypt
    ///   - outputPath: Optional path for the encrypted output (if nil, creates inputPath.gpg or inputPath.asc)
    ///   - recipients: Array of recipient key IDs or email addresses
    ///   - signKeyId: Optional key ID to use for signing the encrypted file
    ///   - passphrase: Optional passphrase for signing key
    ///   - armor: Whether to create ASCII armored output (default: true)
    ///   - alwaysTrust: Whether to trust recipient keys without verification (default: false)
    /// - Returns: An EncryptResult indicating success or failure
    @discardableResult
    public func encryptFile(inputPath: String,
                           outputPath: String? = nil,
                           recipients: [String],
                           signKeyId: String? = nil,
                           passphrase: String? = nil,
                           armor: Bool = true,
                           alwaysTrust: Bool = false) async -> EncryptResult {
        
        let result = EncryptResult(gpg: self)
        
        do {
            // Check if input file exists
            guard FileManager.default.fileExists(atPath: inputPath) else {
                result.status = "error: input file not found: \(inputPath)"
                return result
            }
            
            guard !recipients.isEmpty else {
                result.status = "error: no recipients specified"
                return result
            }
            
            var args = ["--encrypt"]
            
            // Add signing if requested
            if signKeyId != nil {
                args[0] = "--encrypt-sign"
                if let keyId = signKeyId {
                    args.append(contentsOf: ["--local-user", keyId])
                }
            }
            
            // Add output format options
            if armor {
                args.append("--armor")
            }
            
            // Add trust options
            if alwaysTrust {
                args.append("--trust-model")
                args.append("always")
            }
            
            // Add output file if specified
            if let outputPath = outputPath {
                args.append(contentsOf: ["--output", outputPath])
            }
            
            // Add recipients
            for recipient in recipients {
                args.append(contentsOf: ["--recipient", recipient])
            }
            
            // Add input file
            args.append(inputPath)
            
            _ = try await self.executeCommand(
                arguments: args,
                statusHandler: result,
                passphrase: passphrase
            )
            
            // For file operations, the output is written to a file
            // Set success if no errors occurred
            if result.status == nil || result.status == "encryption started" {
                result.status = "encryption ok"
            }
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Encrypt a file using symmetric encryption
    /// - Parameters:
    ///   - inputPath: Path to the file to encrypt
    ///   - outputPath: Optional path for the encrypted output
    ///   - passphrase: The passphrase to use for encryption
    ///   - armor: Whether to create ASCII armored output (default: true)
    ///   - cipher: Optional cipher algorithm to use
    /// - Returns: An EncryptResult indicating success or failure
    @discardableResult
    public func encryptFileSymmetric(inputPath: String,
                                   outputPath: String? = nil,
                                   passphrase: String,
                                   armor: Bool = true,
                                   cipher: String? = nil) async -> EncryptResult {
        
        let result = EncryptResult(gpg: self)
        
        do {
            // Check if input file exists
            guard FileManager.default.fileExists(atPath: inputPath) else {
                result.status = "error: input file not found: \(inputPath)"
                return result
            }
            
            var args = ["--symmetric"]
            
            // Add output format options
            if armor {
                args.append("--armor")
            }
            
            // Add cipher algorithm if specified
            if let cipherAlg = cipher {
                args.append(contentsOf: ["--cipher-algo", cipherAlg])
            }
            
            // Add output file if specified
            if let outputPath = outputPath {
                args.append(contentsOf: ["--output", outputPath])
            }
            
            // Add input file
            args.append(inputPath)
            
            _ = try await self.executeCommand(
                arguments: args,
                statusHandler: result,
                passphrase: passphrase
            )
            
            // Set success if no errors occurred
            if result.status == nil || result.status == "encryption started" {
                result.status = "encryption ok"
            }
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
}