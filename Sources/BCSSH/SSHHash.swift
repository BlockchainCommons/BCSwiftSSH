import Foundation
import WolfBase
import BCCrypto

public struct SSHHash: CustomStringConvertible {
    let algorithm: Algorithm
    let data: Data
    
    public enum Algorithm: String, RawRepresentable, CustomStringConvertible {
        case sha256 = "SHA256"
        case md5 = "MD5"
        
        public var description: String {
            rawValue
        }
    }
    
    public enum Error: Swift.Error {
        case invalid
    }
    
    public init(data: Data, algorithm: Algorithm) throws {
        switch algorithm {
        case .sha256:
            guard data.count == 32 else {
                throw Error.invalid
            }
        case .md5:
            guard data.count == 16 else {
                throw Error.invalid
            }
        }
        self.data = data
        self.algorithm = algorithm
    }
    
    public init(hashImage: Data, algorithm: Algorithm = .sha256) throws {
        let data = switch algorithm {
        case .sha256:
            sha256(hashImage)
        case .md5:
            unimplemented()
        }
        try self.init(data: data, algorithm: algorithm)
    }
    
    public init(_ string: String, algorithm: Algorithm = .sha256) throws {
        let data: Data
        switch algorithm {
        case .sha256:
            guard
                string.count == 43,
                let d = Data(base64Encoded: string + "=")
            else {
                throw Error.invalid
            }
            data = d
        case .md5:
            let a = string.replacingOccurrences(of: ":", with: "")
            guard
                let d = a.hexData,
                d.count == 16
            else {
                throw Error.invalid
            }
            data = d
        }
        try self.init(data: data, algorithm: algorithm)
    }
    
    public init(_ string: String) throws {
        let components = string.split(separator: ":", maxSplits: 1).map(String.init)
        guard
            components.count == 2,
            let algorithm = Algorithm(rawValue: components[0])
        else {
            throw Error.invalid
        }
        try self.init(components[1], algorithm: algorithm)
    }
    
    public var string: String {
        let s = switch algorithm {
        case .sha256:
            String(data.base64EncodedString().dropLast())
        case .md5:
            Array(data)
                .map { $0.hex }
                .joined(separator: ":")
        }
        return "\(algorithm):\(s)"
    }
    
    public var description: String {
        string
    }
}
