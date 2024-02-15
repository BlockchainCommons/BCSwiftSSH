import Foundation
import WolfBase
import BCCrypto

// https://coolaj86.com/articles/the-openssh-private-key-format/

public struct SSHPrivateKey: Equatable {
    public let publicKeyData: SSHPublicKeyData
    public let checkNum: UInt32
    public let privateKeyData: SSHPrivateKeyData
    public let comment: String

    static let magic = "openssh-key-v1"
    static let pemHeader = "OPENSSH PRIVATE KEY"
    static let none = "none"

    public var type: SSHKeyType {
        publicKeyData.type
    }

    public enum Error: Swift.Error {
        case invalid
    }
    
    public init(type: SSHKeyType, comment: String) {
        var rng = SecureRandomNumberGenerator()
        self.init(type: type, comment: comment, using: &rng)
    }
    
    public init<R: RandomNumberGenerator>(type: SSHKeyType, comment: String, using rng: inout R) {
        self.privateKeyData = SSHPrivateKeyData(type: type, using: &rng)
        self.publicKeyData = privateKeyData.publicKeyData
        self.comment = comment
        self.checkNum = UInt32.random(in: 0...UInt32.max, using: &rng)
    }

    public init(publicKeyData: SSHPublicKeyData, checkNum: UInt32, privateKeyData: SSHPrivateKeyData, comment: String = "") {
        self.publicKeyData = publicKeyData
        self.checkNum = checkNum
        self.privateKeyData = privateKeyData
        self.comment = comment
    }

    public init(_ string: String) throws {
        let pemData = try PEMData(string)
        try check(pemData.type == Self.pemHeader)

        var buf = SSHReadBuffer(pemData.data)
        let magic = try buf.readNullTerminatedString()
        try check(magic == Self.magic)

        let cipherName = try buf.readLengthPrefixedString()
        try check(cipherName == Self.none)

        let kdfName = try buf.readLengthPrefixedString()
        try check(kdfName == Self.none)

        let kdf = try buf.readChunk()
        try check(kdf.isEmpty)

        let keysCount = try buf.readInt()
        try check(keysCount == 1)

        let publicKeyChunk = try buf.readChunk()
        var pubBuf = SSHReadBuffer(publicKeyChunk)
        let publicKeyData = try parsePublicKeyData(buf: &pubBuf)
        try check(pubBuf.isAtEnd)

        let privateKeyChunk = try buf.readChunk()
        try check(buf.isAtEnd)

        var privBuf = SSHReadBuffer(privateKeyChunk)

        let checkNum1 = UInt32(try privBuf.readInt())
        let checkNum2 = UInt32(try privBuf.readInt())
        try check(checkNum1 == checkNum2)

        let type = publicKeyData.type
        let privateKeyData: SSHPrivateKeyData
        switch type {
        case .rsa:
            privateKeyData = try SSHPrivateKeyData(buf: &privBuf, type: .rsa)
        case .dsa:
            let publicKey2 = try parsePublicKeyData(buf: &privBuf, checkType: type)
            try check(publicKeyData == publicKey2)
            privateKeyData = try SSHPrivateKeyData(buf: &privBuf, type: .dsa)
        case .ecdsa:
            let publicKey2 = try parsePublicKeyData(buf: &privBuf, checkType: type)
            try check(publicKeyData == publicKey2)
            privateKeyData = try SSHPrivateKeyData(buf: &privBuf, type: .dsa)
        case .ed25519:
            let publicKey2 = try parsePublicKeyData(buf: &privBuf, checkType: type)
            try check(publicKeyData == publicKey2)
            let chunk = try privBuf.readChunk()
            guard chunk.count == 64 else {
                throw Error.invalid
            }
            let privatePart = chunk.subdata(in: 0..<32)
            let publicPart = chunk.subdata(in: 32..<64)
            guard 
                case .ed25519(let publicKey) = publicKey2,
                publicKey == publicPart
            else {
                throw Error.invalid
            }

            privateKeyData = .ed25519(privateKey: privatePart, publicKey: publicPart)
        }

        let comment = try privBuf.readLengthPrefixedString()

        try privBuf.expectPadding()
        try check(privBuf.isAtEnd)

        self.init(publicKeyData: publicKeyData, checkNum: checkNum1, privateKeyData: privateKeyData, comment: comment)
    }

    public var string: String {
        var buf = SSHWriteBuffer()
        buf.writeNullTerminatedString(Self.magic)
        buf.writeLengthPrefixedString(Self.none) // cipherName
        buf.writeLengthPrefixedString(Self.none) // kdfName
        buf.writeEmptyChunk() // kdf
        buf.writeInt(1) // keysCount

        var pubBuf = SSHWriteBuffer()
        pubBuf.writeLengthPrefixedString(type.description)
        pubBuf.writeChunks(publicKeyData.chunks)
        buf.writeChunk(pubBuf.data)

        var privBuf = SSHWriteBuffer()
        privBuf.writeInt(checkNum)
        privBuf.writeInt(checkNum)
        privBuf.writeLengthPrefixedString(type.description)
        switch privateKeyData.type {
        case .rsa:
            break
        case .dsa:
            privBuf.writeChunks(publicKeyData.chunks)
        case .ecdsa(_):
            privBuf.writeChunks(publicKeyData.chunks)
        case .ed25519:
            privBuf.writeChunks(publicKeyData.chunks)
        }
        privBuf.writeChunks(privateKeyData.chunks)
        privBuf.writeLengthPrefixedString(comment)
        privBuf.writePadding()
        buf.writeChunk(privBuf.data)

        let pemData = PEMData(type: Self.pemHeader, data: buf.data)
        return pemData.string
    }

    public var publicKey: SSHPublicKey {
        SSHPublicKey(keyData: publicKeyData, comment: comment)
    }
    
    public func derivePublicKey() -> SSHPublicKey {
        SSHPublicKey(keyData: privateKeyData.derivePublicKeyData(), comment: comment)
    }
    
    public func sign(message: Data, namespace: String, hashAlgorithm: SSHSignature.HashAlgorithm = .sha512) -> SSHSignature {
        let wrappedMessage = SSHSignature.wrapMessage(message, namespace: namespace, hashAlgorithm: hashAlgorithm)
        let data = switch privateKeyData {
        case .ed25519(let privateKey, _):
            ed25519Sign(privateKey: privateKey, message: wrappedMessage)
        default:
            unimplemented()
        }
        return SSHSignature(publicKeyData: publicKeyData, data: data, hashAlgorithm: hashAlgorithm, namespace: namespace)
    }
}

extension SSHPrivateKey: CustomStringConvertible {
    public var description: String {
        let s: KeyValuePairs = [
            "type": type.description,
            "publicKeyData": publicKeyData.description,
            "checkNum": checkNum.hex,
            "privateKeyData": privateKeyData.description,
            "comment": comment
        ]
        return "SSHPrivateKey(\(s.joined(separator: ", ")))"
    }
}

fileprivate func check(_ pred: @autoclosure () -> Bool) throws {
    guard pred() else {
        throw SSHPrivateKey.Error.invalid
    }
}

fileprivate func parseKeyData(buf: inout SSHReadBuffer, checkType: SSHKeyType? = nil) throws -> SSHPrivateKeyData {
    let typeString = try buf.readLengthPrefixedString()

    guard let type = SSHKeyType(typeString) else {
        throw SSHPublicKey.Error.invalid
    }

    if let checkType {
        try check(type == checkType)
    }

    return try SSHPrivateKeyData(buf: &buf, type: type)
}
