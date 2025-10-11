import Foundation

extension GnuPG {
    
    // MARK: - Verify Operations
    
    /// Verify a signature
    /// - Parameters:
    ///   - message: The signed data as a String
    ///   - signature: Optional detached signature data (if nil, expects inline signature)
    ///   - extraArgs: Additional GPG command-line arguments (default: nil)
    /// - Returns: A VerifyResult indicating verification status
    @discardableResult
    public func verify(message: String, signature: Data? = nil, extraArgs: [String]? = nil) async -> VerifyResult {
        guard let messageData = message.data(using: .utf8) else {
            let result = VerifyResult(gpg: self)
            result.status = "error: failed to convert message to data"
            return result
        }
        
        return await verify(data: messageData, signature: signature, extraArgs: extraArgs)
    }
    
    /// Verify a signature on data
    /// - Parameters:
    ///   - data: The signed data
    ///   - signature: Optional detached signature data (if nil, expects inline signature)
    ///   - extraArgs: Additional GPG command-line arguments (default: nil)
    /// - Returns: A VerifyResult indicating verification status
    @discardableResult
    public func verify(data: Data, signature: Data? = nil, extraArgs: [String]? = nil) async -> VerifyResult {
        let result = VerifyResult(gpg: self)
        
        do {
            var args = ["--verify"]
            
            // Add extra arguments if provided
            if let extraArgs = extraArgs {
                args.append(contentsOf: extraArgs)
            }
            
            if let sigData = signature {
                // Detached signature verification
                // Create temporary files for signature and data
                let tempDir = FileManager.default.temporaryDirectory
                let sigFile = tempDir.appendingPathComponent(UUID().uuidString + ".sig")
                let dataFile = tempDir.appendingPathComponent(UUID().uuidString + ".dat")
                
                defer {
                    try? FileManager.default.removeItem(at: sigFile)
                    try? FileManager.default.removeItem(at: dataFile)
                }
                
                try sigData.write(to: sigFile)
                try data.write(to: dataFile)
                
                args.append(contentsOf: [sigFile.path, dataFile.path])
                
                _ = try await self.executeCommand(
                    arguments: args,
                    statusHandler: result
                )
            } else {
                // Inline signature verification - GPG reads from stdin
                _ = try await self.executeCommand(
                    arguments: args,
                    input: data,
                    statusHandler: result
                )
            }
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
            result.valid = false
        }
        
        return result
    }
    
    /// Verify signature on a file
    /// - Parameters:
    ///   - dataPath: Path to the file to verify
    ///   - signaturePath: Optional path to detached signature file (if nil, expects inline signature in dataPath)
    /// - Returns: A VerifyResult indicating verification status
    @discardableResult
    public func verifyFile(dataPath: String, signaturePath: String? = nil) async -> VerifyResult {
        let result = VerifyResult(gpg: self)
        
        do {
            // Check if data file exists
            guard FileManager.default.fileExists(atPath: dataPath) else {
                result.status = "error: data file not found: \(dataPath)"
                result.valid = false
                return result
            }
            
            var args = ["--verify"]
            
            if let sigPath = signaturePath {
                // Detached signature verification
                guard FileManager.default.fileExists(atPath: sigPath) else {
                    result.status = "error: signature file not found: \(sigPath)"
                    result.valid = false
                    return result
                }
                
                args.append(contentsOf: [sigPath, dataPath])
                
                _ = try await self.executeCommand(
                    arguments: args,
                    statusHandler: result
                )
            } else {
                // Inline signature verification
                args.append(dataPath)
                
                _ = try await self.executeCommand(
                    arguments: args,
                    statusHandler: result
                )
            }
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
            result.valid = false
        }
        
        return result
    }
    
    /// Verify signature and extract plain text from clearsigned message
    /// - Parameters:
    ///   - message: The clearsigned message
    /// - Returns: A VerifyResult with the extracted plain text in the data property
    @discardableResult
    public func verifyCleartext(message: String) async -> VerifyResult {
        guard let messageData = message.data(using: .utf8) else {
            let result = VerifyResult(gpg: self)
            result.status = "error: failed to convert message to data"
            result.valid = false
            return result
        }
        
        return await verifyCleartext(data: messageData)
    }
    
    /// Verify signature and extract plain text from clearsigned data
    /// - Parameters:
    ///   - data: The clearsigned data
    /// - Returns: A VerifyResult with the extracted plain text in the data property
    @discardableResult
    public func verifyCleartext(data: Data) async -> VerifyResult {
        let result = VerifyResult(gpg: self)
        
        do {
            let args = ["--decrypt"]
            
            let processResult = try await self.executeCommand(
                arguments: args,
                input: data,
                statusHandler: result
            )
            
            // Store the decrypted/extracted plain text
            result.data = processResult.output
            
        } catch {
            result.status = "error: \(error.localizedDescription)"
            result.valid = false
        }
        
        return result
    }
    
    /// Convenience method to check if a signature is valid
    /// - Parameters:
    ///   - message: The signed message
    ///   - signature: Optional detached signature
    /// - Returns: True if the signature is valid, false otherwise
    public func isSignatureValid(message: String, signature: Data? = nil) async -> Bool {
        let result = await verify(message: message, signature: signature)
        return result.valid
    }
    
    /// Convenience method to check if a file signature is valid
    /// - Parameters:
    ///   - dataPath: Path to the signed file
    ///   - signaturePath: Optional path to detached signature file
    /// - Returns: True if the signature is valid, false otherwise
    public func isFileSignatureValid(dataPath: String, signaturePath: String? = nil) async -> Bool {
        let result = await verifyFile(dataPath: dataPath, signaturePath: signaturePath)
        return result.valid
    }
    
    /// Verify detached signature data
    /// - Parameters:
    ///   - signatureFile: Path to signature file or signature data as string
    ///   - signedData: The data that was signed
    /// - Returns: A VerifyResult indicating verification status
    @discardableResult
    public func verifyData(_ signatureFile: String, signedData: Data) async -> VerifyResult {
        // If signatureFile looks like a path, treat it as file verification
        if signatureFile.contains("/") && FileManager.default.fileExists(atPath: signatureFile) {
            // Create temporary file for signed data
            let tempDir = FileManager.default.temporaryDirectory
            let dataFile = tempDir.appendingPathComponent(UUID().uuidString + ".dat")
            
            do {
                try signedData.write(to: dataFile)
                defer { try? FileManager.default.removeItem(at: dataFile) }
                
                return await verifyFile(dataPath: dataFile.path, signaturePath: signatureFile)
            } catch {
                let result = VerifyResult(gpg: self)
                result.status = "error: failed to write temporary data file"
                result.valid = false
                return result
            }
        } else {
            // Treat as signature data with the signed data
            guard let sigData = signatureFile.data(using: .utf8) else {
                let result = VerifyResult(gpg: self)
                result.status = "error: failed to convert signature to data"
                result.valid = false
                return result
            }
            
            return await verify(data: sigData, signature: signedData)
        }
    }
}
