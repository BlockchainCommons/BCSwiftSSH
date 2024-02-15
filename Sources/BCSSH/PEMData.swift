import Foundation

public struct PEMData {
    public let type: String
    public let data: Data
    
    public init(type: String, data: Data) {
        self.type = type
        self.data = data
    }
    
    public enum Error: Swift.Error {
        case invalidFormat
    }
    
    public init(_ string: String) throws {
        let pattern = #/-----BEGIN ([A-Z0-9 -]+)-----\r?\n([\s\S]+?)\r?\n-----END \1-----/#
        
        guard let match = string.firstMatch(of: pattern) else {
            throw Error.invalidFormat
        }
        
        let (_, typeMatch, base64Match) = match.output
        self.type = String(typeMatch)
        
        let base64String = base64Match
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
        
        guard let data = Data(base64Encoded: base64String) else {
            throw Error.invalidFormat
        }
        
        self.data = data
    }
    
    public var string: String {
        let base64String = data.base64EncodedString()
        let formattedBase64 = base64String.insertingLineBreaks(every: 70)

        return """
        -----BEGIN \(type)-----
        \(formattedBase64)
        -----END \(type)-----
        """
    }
}

extension PEMData: CustomStringConvertible {
    public var description: String {
        let s: KeyValuePairs = [
            "type": type.quoted(),
            "data": data.hex
        ]
        return "PEMData(\(s.joined(separator: ", ")))"
    }
}
