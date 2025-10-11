import Foundation

extension GnuPG {
    
    // MARK: - Sign Operations
    
    /// Sign data using a specified key
    /// - Parameters:
    ///   - message: The data to sign as a String
    ///   - keyId: The ID of the key to use for signing (optional)
    ///   - passphrase: The passphrase for the signing key (optional)
    ///   - clearsign: Whether to create a clear signature (default: false)
    ///   - detach: Whether to create a detached signature (default: true)
    ///   - binary: Whether to create a binary signature (default: false)
    ///   - extraArgs: Additional GPG command-line arguments (default: nil)
    /// - Returns: A SignResult indicating success or failure
    @discardableResult
    public func sign(message: String,
                    keyId: String? = nil,
                    passphrase: String? = nil,
                    clearsign: Bool = false,
                    detach: Bool = true,
                    binary: Bool = false,
                    extraArgs: [String]? = nil) async -> SignResult {
        
        let result = SignResult(gpg: self)
        
        do {
            var args = ["--sign"]
            
            // Add signature type options
            if clearsign {
                args[0] = "--clearsign"
            } else if detach {
                args[0] = "--detach-sign"
            }
            
            // Add output format options
            if binary && !clearsign {
                args.append("--armor")
            } else if !binary {
                args.append("--armor")
            }
            
            // Add key ID if specified
            if let keyId = keyId {
                args.append(contentsOf: ["--local-user", keyId])
            }
            
            // Add extra arguments if provided
            if let extraArgs = extraArgs {
                args.append(contentsOf: extraArgs)
            }
            
            let process = try await self.executeCommand(
                arguments: args,
                input: message.data(using: .utf8),
                statusHandler: result,
                passphrase: passphrase
            )
            
            // Store the signed data if successful
            if let output = process.output {
                result.data = output
            }
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Sign data from a Data object
    /// - Parameters:
    ///   - data: The data to sign
    ///   - keyId: The ID of the key to use for signing (optional)
    ///   - passphrase: The passphrase for the signing key (optional)
    ///   - clearsign: Whether to create a clear signature (default: false)
    ///   - detach: Whether to create a detached signature (default: true)
    ///   - binary: Whether to create a binary signature (default: false)
    ///   - extraArgs: Additional GPG command-line arguments (default: nil)
    /// - Returns: A SignResult indicating success or failure
    @discardableResult
    public func sign(data: Data,
                    keyId: String? = nil,
                    passphrase: String? = nil,
                    clearsign: Bool = false,
                    detach: Bool = true,
                    binary: Bool = false,
                    extraArgs: [String]? = nil) async -> SignResult {
        
        let result = SignResult(gpg: self)
        
        do {
            var args = ["--sign"]
            
            // Add signature type options
            if clearsign {
                args[0] = "--clearsign"
            } else if detach {
                args[0] = "--detach-sign"
            }
            
            // Add output format options
            if binary && !clearsign {
                args.append("--armor")
            } else if !binary {
                args.append("--armor")
            }
            
            // Add key ID if specified
            if let keyId = keyId {
                args.append(contentsOf: ["--local-user", keyId])
            }
            
            // Add extra arguments if provided
            if let extraArgs = extraArgs {
                args.append(contentsOf: extraArgs)
            }
            
            let process = try await self.executeCommand(
                arguments: args,
                input: data,
                statusHandler: result,
                passphrase: passphrase
            )
            
            // Store the signed data if successful
            if let output = process.output {
                result.data = output
            }
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
    
    /// Sign a file
    /// - Parameters:
    ///   - inputPath: Path to the file to sign
    ///   - outputPath: Optional path for the signed output (if nil, creates inputPath.asc or inputPath.sig)
    ///   - keyId: The ID of the key to use for signing (optional)
    ///   - passphrase: The passphrase for the signing key (optional)
    ///   - clearsign: Whether to create a clear signature (default: false)
    ///   - detach: Whether to create a detached signature (default: true)
    ///   - binary: Whether to create a binary signature (default: false)
    ///   - extraArgs: Additional GPG command-line arguments (default: nil)
    /// - Returns: A SignResult indicating success or failure
    @discardableResult
    public func signFile(inputPath: String,
                        outputPath: String? = nil,
                        keyId: String? = nil,
                        passphrase: String? = nil,
                        clearsign: Bool = false,
                        detach: Bool = true,
                        binary: Bool = false,
                        extraArgs: [String]? = nil) async -> SignResult {
        
        let result = SignResult(gpg: self)
        
        do {
            // Check if input file exists
            guard FileManager.default.fileExists(atPath: inputPath) else {
                result.status = "error: input file not found: \(inputPath)"
                return result
            }
            
            var args = ["--sign"]
            
            // Add signature type options
            if clearsign {
                args[0] = "--clearsign"
            } else if detach {
                args[0] = "--detach-sign"
            }
            
            // Add output format options
            if binary && !clearsign {
                // Binary mode, don't add --armor
            } else {
                args.append("--armor")
            }
            
            // Add key ID if specified
            if let keyId = keyId {
                args.append(contentsOf: ["--local-user", keyId])
            }
            
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
            
            _ = try await self.executeCommand(
                arguments: args,
                statusHandler: result,
                passphrase: passphrase
            )
            
            // For file operations, the output is written to a file
            // Set success if no errors occurred
            if result.status == nil && result.fingerprint != nil {
                result.status = "signature created"
            }
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
        }
        
        return result
    }
}