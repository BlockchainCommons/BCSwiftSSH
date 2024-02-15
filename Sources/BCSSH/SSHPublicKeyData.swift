import Foundation

public enum SSHPublicKeyData: Equatable, CustomStringConvertible {
    case rsa(exponent: Data, modulus: Data)
    case dsa(p: Data, q: Data, g: Data, y: Data)
    case ecdsa(subtype: ECDSAType, data: Data)
    case ed25519(Data)

    init(buf: inout SSHReadBuffer, type: SSHKeyType) throws {
        let keyData: SSHPublicKeyData
        switch type {
        case .rsa:
            let exponent = try buf.readChunk()
            let modulus = try buf.readChunk()
            keyData = .rsa(exponent: exponent, modulus: modulus)
        case .dsa:
            let p = try buf.readChunk()
            let q = try buf.readChunk()
            let g = try buf.readChunk()
            let y = try buf.readChunk()
            keyData = .dsa(p: p, q: q, g: g, y: y)
        case .ecdsa(let ecdsaType):
            let typeString = try buf.readLengthPrefixedString()
            guard
                let internalType = ECDSAType(typeString),
                ecdsaType == internalType
            else {
                throw SSHPublicKey.Error.invalid
            }
            let data = try buf.readChunk()
            keyData = .ecdsa(subtype: ecdsaType, data: data)
        case .ed25519:
            let data = try buf.readChunk()
            keyData = .ed25519(data)
        }
        self = keyData
    }

    public var type: SSHKeyType {
        switch self {
        case .rsa(_, _):
                .rsa
        case .dsa(_, _, _, _):
                .dsa
        case .ecdsa(let type, _):
                .ecdsa(type)
        case .ed25519(_):
                .ed25519
        }
    }
    
    public var chunks: [Data] {
        switch self {
        case .rsa(let exponent, let modulus):
            [exponent, modulus]
        case .dsa(let p, let q, let g, let y):
            [p, q, g, y]
        case .ecdsa(let type, let data):
            [type.description.utf8Data, data]
        case .ed25519(let data):
            [data]
        }
    }

    public var description: String {
        switch self {
        case .rsa(let exponent, let modulus):
            "(exponent: \(exponent.hex), modulus: \(modulus.hex))"
        case .dsa(let p, let q, let g, let y):
            "(p: \(p.hex), q: \(q.hex), g: \(g.hex), y: \(y.hex))"
        case .ecdsa(_, let data):
            data.hex
        case .ed25519(let data):
            data.hex
        }
    }
    
    public var hashImage: Data {
        var buf = SSHWriteBuffer()
        buf.writeLengthPrefixedString(type.description)
        switch self {
        case .rsa(let exponent, let modulus):
            buf.writeChunks([exponent, modulus])
        case .dsa(let p, let q, let g, let y):
            buf.writeChunks([p, q, g, y])
        case .ecdsa(let type, let data):
            buf.writeLengthPrefixedString(type.description)
            buf.writeChunk(data)
        case .ed25519(let data):
            buf.writeChunk(data)
        }
        return buf.data
    }
    
    public func hash(algorithm: SSHHash.Algorithm = .sha256) -> SSHHash {
        try! SSHHash(hashImage: hashImage, algorithm: algorithm)
    }
    
    public var keySize: Int {
        switch self {
        case .rsa(_, let modulus):
            // If the value is odd, then a leading zero byte was added that is not part of the modulus.
            let count = modulus.count.isMultiple(of: 2) ? modulus.count : modulus.count - 1
            return count * 8
        case .dsa(let p, _, _, _):
            let count = p.count.isMultiple(of: 2) ? p.count : p.count - 1
            return count * 8
        case .ecdsa(let subtype, _):
            return subtype.keySize
        case .ed25519(_):
            return 32 * 8
        }
    }
}

