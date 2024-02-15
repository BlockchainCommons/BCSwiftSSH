import Foundation
import WolfBase
import BCCrypto

public struct SSHSignature: Equatable {
    public let publicKeyData: SSHPublicKeyData
    public let data: Data
    public let hashAlgorithm: HashAlgorithm
    public let namespace: String
    
    static let magic = "SSHSIG".utf8Data
    static let pemHeader = "SSH SIGNATURE"

    public var type: SSHKeyType {
        publicKeyData.type
    }

    public enum Error: Swift.Error {
        case invalid
        case unsupportedHashAlgorithm
    }
    
    public enum HashAlgorithm: String, RawRepresentable, CustomStringConvertible {
        case sha512
        
        public var description: String {
            rawValue
        }
        
        public func hash(_ message: Data) -> Data {
            switch self {
            case .sha512:
                BCCrypto.sha512(message)
            }
        }
    }
    
    public init(publicKeyData: SSHPublicKeyData, data: Data, hashAlgorithm: HashAlgorithm, namespace: String) {
        self.publicKeyData = publicKeyData
        self.data = data
        self.hashAlgorithm = hashAlgorithm
        self.namespace = namespace
    }

    public init(_ string: String) throws {
        let pemData = try PEMData(string)
        try check(pemData.type == Self.pemHeader)

        var buf = SSHReadBuffer(pemData.data)
        let magic = try buf.read(UInt32(Self.magic.count))
        try check(magic == Self.magic)
        
        let version = try buf.readInt()
        try check(version == 1)
        
        let publicKeyChunk = try buf.readChunk()
        var pubBuf = SSHReadBuffer(publicKeyChunk)
        let publicKeyData = try parsePublicKeyData(buf: &pubBuf)
        try check(pubBuf.isAtEnd)

        let namespace = try buf.readLengthPrefixedString()
        
        let reserved = try buf.readChunk()
        try check(reserved.isEmpty)
        
        let hashAlgorithmString = try buf.readLengthPrefixedString()
        guard let hashAlgorithm = HashAlgorithm(rawValue: hashAlgorithmString) else {
            throw Error.unsupportedHashAlgorithm
        }
        
        let sigChunk = try buf.readChunk()
        var sigBuf = SSHReadBuffer(sigChunk)
        let sigKeyTypeString = try sigBuf.readLengthPrefixedString()
        let sigKeyType = SSHKeyType(sigKeyTypeString)
        try check(sigKeyType == publicKeyData.type)
        let data = try sigBuf.readChunk()
        try check(sigBuf.isAtEnd)
        
        self.init(publicKeyData: publicKeyData, data: data, hashAlgorithm: hashAlgorithm, namespace: namespace)
    }
    
    public var string: String {
        var buf = SSHWriteBuffer()
        buf.write(Self.magic)
        
        buf.writeInt(1) // version

        var pubBuf = SSHWriteBuffer()
        pubBuf.writeLengthPrefixedString(type.description)
        pubBuf.writeChunks(publicKeyData.chunks)
        buf.writeChunk(pubBuf.data)
        
        buf.writeLengthPrefixedString(namespace)
        
        buf.writeEmptyChunk() // reserved
        
        buf.writeLengthPrefixedString(hashAlgorithm.description)
        
        var sigBuf = SSHWriteBuffer()
        sigBuf.writeLengthPrefixedString(type.description)
        sigBuf.writeChunk(data)
        buf.writeChunk(sigBuf.data)

        let pemData = PEMData(type: Self.pemHeader, data: buf.data)
        return pemData.string
    }
    
    public static func wrapMessage(_ message: Data, namespace: String, hashAlgorithm: HashAlgorithm) -> Data {
        // MessageWrapper:
        // https://github.com/sigstore/rekor/blob/v1.3.5/pkg/pki/ssh/sign.go#L29
        var wrapper = SSHWriteBuffer()
        wrapper.write(Self.magic)
        wrapper.writeLengthPrefixedString(namespace)
        wrapper.writeEmptyChunk() // reserved
        wrapper.writeLengthPrefixedString(hashAlgorithm.description)
        wrapper.writeChunk(hashAlgorithm.hash(message))
        return wrapper.data
    }
    
    public func wrapMessage(_ message: Data) -> Data {
        Self.wrapMessage(message, namespace: namespace, hashAlgorithm: hashAlgorithm)
    }
}

extension SSHSignature: CustomStringConvertible {
    public var description: String {
        let s: KeyValuePairs = [
            "type": type.description,
            "hashAlgorithm": hashAlgorithm.description,
            "namespace": namespace,
            "publicKeyData": publicKeyData.description,
            "data": data.hex,
        ]
        return "SSHSignature(\(s.joined(separator: ", ")))"
    }
}

fileprivate func check(_ pred: @autoclosure () -> Bool) throws {
    guard pred() else {
        throw SSHPrivateKey.Error.invalid
    }
}
