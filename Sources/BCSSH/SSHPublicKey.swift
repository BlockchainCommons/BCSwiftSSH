import Foundation
import WolfBase
import BCCrypto

public struct SSHPublicKey: Equatable {
    public let keyData: SSHPublicKeyData
    public let comment: String
    
    public var type: SSHKeyType {
        keyData.type
    }
    
    public enum Error: Swift.Error {
        case invalid
        case keySignatureTypeMismatch
        case unsupportedSignatureHashAlgorithm
        case namespaceMismatch
    }
    
    public init(keyData: SSHPublicKeyData, comment: String = "") {
        self.keyData = keyData
        self.comment = comment
    }
    
    public init(_ string: String) throws {
        let sanitizedString = string.trimmingCharacters(in: .whitespacesAndNewlines)
        let components = sanitizedString.components(separatedBy: .whitespacesAndNewlines).filter { !$0.isEmpty }
        guard
            components.count >= 2,
            let frontType = SSHKeyType(components[0])
        else {
            throw Error.invalid
        }
        
        guard let decodedData = Data(base64Encoded: components[1]) else {
            throw Error.invalid
        }
        
        let comment: String
        if components.count >= 3 {
            comment = components[2]
        } else {
            comment = ""
        }
        
        var buf = SSHReadBuffer(decodedData)
        let keyData = try parsePublicKeyData(buf: &buf, checkType: frontType)
        try check(buf.isAtEnd)
        
        self.init(keyData: keyData, comment: comment)
    }
    
    public var chunks: [Data] {
        var result: [Data] = [type.description.utf8Data]
        result.append(contentsOf: keyData.chunks)
        return result
    }
    
    public var base64String: String {
        SSHWriteBuffer.writeChunks(chunks).base64EncodedString()
    }
    
    public var string: String {
        return [type.description, base64String, comment]
            .compactJoined(separator: " ")
    }
    
    // https://man.openbsd.org/ssh-keygen#ALLOWED_SIGNERS
    public func allowedSignerString(identity: String) -> String {
        return [identity, type.description, base64String]
            .joined(separator: " ")
    }
    
    public func hash(algorithm: SSHHash.Algorithm = .sha256) -> SSHHash {
        keyData.hash(algorithm: algorithm)
    }
    
    public func hashString(algorithm: SSHHash.Algorithm = .sha256) -> String {
        return [
            keyData.keySize†,
            hash(algorithm: algorithm)†,
            comment,
            type.hashName.parenthesized()
        ].joined(separator: " ")
    }
    
    public func randomArt(algorithm: SSHHash.Algorithm = .sha256) -> String {
        let randomArt = RandomArt(hash(algorithm: algorithm))
        let topText = "\(type.hashName) \(keyData.keySize)"
        let bottomText = algorithm.description
        return randomArt.contentWithBorder(topText: topText, bottomText: bottomText)
    }
    
    public func verify(message: Data, signature: SSHSignature, namespace: String) throws -> Bool {
        guard type == signature.type else {
            throw Error.keySignatureTypeMismatch
        }
        
        guard signature.hashAlgorithm == .sha512 else {
            throw Error.unsupportedSignatureHashAlgorithm
        }
        
        guard namespace == signature.namespace else {
            throw Error.namespaceMismatch
        }
        
        switch keyData {
        case .ed25519(let publicKey):
            return ed25519Verify(publicKey: publicKey, signature: signature.data, message: signature.wrapMessage(message))
        default:
            unimplemented()
        }
    }
}

extension SSHPublicKey: CustomStringConvertible {
    public var description: String {
        let s: KeyValuePairs = [
            "type": type.description,
            "keyData": keyData.description,
            "comment": comment
        ]
        return "SSHPublicKey(\(s.joined(separator: ", ")))"
    }
}

fileprivate func check(_ pred: @autoclosure () -> Bool) throws {
    guard pred() else {
        throw SSHPublicKey.Error.invalid
    }
}

func parsePublicKeyData(buf: inout SSHReadBuffer, checkType: SSHKeyType? = nil) throws -> SSHPublicKeyData {
    let typeString = try buf.readLengthPrefixedString()
    
    guard let type = SSHKeyType(typeString) else {
        throw SSHPublicKey.Error.invalid
    }

    if let checkType {
        try check(type == checkType)
    }
    
    return try SSHPublicKeyData(buf: &buf, type: type)
}
