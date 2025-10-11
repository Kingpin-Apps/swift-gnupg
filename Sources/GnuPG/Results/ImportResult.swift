import Foundation

/// Handles status messages during key import
public final class ImportResult: BaseStatusHandler, @unchecked Sendable {
    
    // MARK: - Properties
    
    public var count = 0
    public var noUserId = 0
    public var imported = 0
    public var importedRsa = 0
    public var unchanged = 0
    public var nUids = 0
    public var nSubk = 0
    public var nSigs = 0
    public var nRevoc = 0
    public var secRead = 0
    public var secImported = 0
    public var secDups = 0
    public var notImported = 0
    
    public var results: [[String: Any]] = []
    public var fingerprints: [String] = []
    public var status: String?
    
    /// Primary fingerprint (first fingerprint for compatibility)
    public var fingerprint: String {
        return fingerprints.first ?? ""
    }
    
    // Logger removed for initial implementation
    
    // MARK: - Import Reason Codes
    
    private static let okReasons: [String: String] = [
        "0": "Not actually changed",
        "1": "Entirely new key",
        "2": "New user IDs", 
        "4": "New signatures",
        "8": "New subkeys",
        "16": "Contains private key"
    ]
    
    private static let problemReasons: [String: String] = [
        "0": "No specific reason given",
        "1": "Invalid Certificate",
        "2": "Issuer Certificate missing",
        "3": "Certificate Chain too long",
        "4": "Error storing certificate"
    ]
    
    public override func handleStatus(key: String, value: String) {
        if key == "WARNING" || key == "ERROR" {
            // Warning logging removed
            if status == nil {
                status = "\(key.lowercased()): \(value)"
            }
        } else if key == "IMPORTED" || key == "KEY_CONSIDERED" {
            // This duplicates info we already see in import_ok & import_problem
            return
        } else if key == "NODATA" {
            results.append(["fingerprint": NSNull(), "problem": "0", "text": "No valid data found"])
        } else if key == "IMPORT_OK" {
            let parts = value.split(separator: " ").map(String.init)
            if parts.count >= 2 {
                let reasonCode = parts[0]
                let fingerprint = parts[1]
                
                var reasons: [String] = []
                if let reasonInt = Int(reasonCode) {
                    for (code, text) in ImportResult.okReasons {
                        if let codeInt = Int(code), (reasonInt | codeInt) == reasonInt {
                            reasons.append(text)
                        }
                    }
                }
                
                let reasonText = reasons.joined(separator: "\\n") + "\\n"
                results.append(["fingerprint": fingerprint, "ok": reasonCode, "text": reasonText])
                fingerprints.append(fingerprint)
            }
        } else if key == "IMPORT_PROBLEM" {
            var reasonCode: String
            var fingerprint: String
            
            let parts = value.split(separator: " ").map(String.init)
            if parts.count >= 2 {
                reasonCode = parts[0]
                fingerprint = parts[1]
            } else {
                reasonCode = value
                fingerprint = "<unknown>"
            }
            
            let reasonText = ImportResult.problemReasons[reasonCode] ?? "Unknown problem"
            results.append(["fingerprint": fingerprint, "problem": reasonCode, "text": reasonText])
        } else if key == "IMPORT_RES" {
            let importRes = value.split(separator: " ").compactMap { Int($0) }
            let counts = [
                "count", "noUserId", "imported", "importedRsa", "unchanged",
                "nUids", "nSubk", "nSigs", "nRevoc", "secRead", "secImported", "secDups", "notImported"
            ]
            
            for (index, countName) in counts.enumerated() {
                if index < importRes.count {
                    switch countName {
                    case "count": count = importRes[index]
                    case "noUserId": noUserId = importRes[index]
                    case "imported": imported = importRes[index]
                    case "importedRsa": importedRsa = importRes[index]
                    case "unchanged": unchanged = importRes[index]
                    case "nUids": nUids = importRes[index]
                    case "nSubk": nSubk = importRes[index]
                    case "nSigs": nSigs = importRes[index]
                    case "nRevoc": nRevoc = importRes[index]
                    case "secRead": secRead = importRes[index]
                    case "secImported": secImported = importRes[index]
                    case "secDups": secDups = importRes[index]
                    case "notImported": notImported = importRes[index]
                    default: break
                    }
                }
            }
        } else if key == "KEYEXPIRED" {
            results.append(["fingerprint": NSNull(), "problem": "0", "text": "Key expired"])
        } else if key == "SIGEXPIRED" {
            results.append(["fingerprint": NSNull(), "problem": "0", "text": "Signature expired"])
        } else if key == "FAILURE" {
            results.append(["fingerprint": NSNull(), "problem": "0", "text": "Other failure"])
            if status == nil {
                status = "failure: \(value)"
            }
        } else {
            // Debug logging removed
        }
    }
    
    /// Return a summary indicating how many keys were imported and how many were not imported
    public func summary() -> String {
        var result: [String] = []
        result.append("\(imported) imported")
        if notImported > 0 {
            result.append("\(notImported) not imported")
        }
        return result.joined(separator: ", ")
    }
    
    /// Whether the import was successful (has imported keys and no failures)
    public var isSuccessful: Bool {
        if let status = status, status.contains("error") || status.contains("failure") {
            return false
        }
        return imported > 0 && !fingerprints.isEmpty
    }
}