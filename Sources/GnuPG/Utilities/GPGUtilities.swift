import Foundation

/// Utilities for GPG operations
public enum GPGUtilities {
    
    /// Shell quote a string for safe use in command line (equivalent to python-gnupg's shell_quote)
    /// On macOS/Unix, this handles shell metacharacters safely
    public static func shellQuote(_ string: String) -> String {
        // Check if string needs quoting
        let unsafePattern = #"[^\w%+,./:=@-]"#
        let regex = try! NSRegularExpression(pattern: unsafePattern)
        let range = NSRange(location: 0, length: string.utf16.count)
        
        if string.isEmpty {
            return "''"
        } else if regex.firstMatch(in: string, options: [], range: range) == nil {
            return string
        } else {
            // Escape single quotes and wrap in single quotes
            let escaped = string.replacingOccurrences(of: "'", with: "'\\''")
            return "'\(escaped)'"
        }
    }
    
    /// No-op quote function (equivalent to python-gnupg's no_quote)
    /// Since we use shell=false in Swift Process, we don't need to quote arguments
    public static func noQuote(_ string: String) -> String {
        return string
    }
    
    /// Check if a passphrase is valid (no newlines or null characters)
    public static func isValidPassphrase(_ passphrase: String) -> Bool {
        return !passphrase.contains("\n") && 
               !passphrase.contains("\r") && 
               !passphrase.contains("\0")
    }
    
    /// Create a memory stream from data
    public static func makeMemoryStream(from data: Data) -> InputStream {
        return InputStream(data: data)
    }
    
    /// Create a binary stream from string with encoding
    public static func makeBinaryStream(from string: String, encoding: String.Encoding) -> InputStream? {
        guard let data = string.data(using: encoding) else { return nil }
        return InputStream(data: data)
    }
    
    /// Check if an object is a sequence (equivalent to python's _is_sequence)
    public static func isSequence<T>(_ object: T) -> Bool {
        return object is Array<Any> || object is NSArray
    }
}