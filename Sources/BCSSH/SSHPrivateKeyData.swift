import Foundation
import WolfBase
import BCCrypto

// https://coolaj86.com/articles/the-openssh-private-key-format/

public enum SSHPrivateKeyData: Equatable, CustomStringConvertible {
    case rsa(modulus: Data, exponent: Data, d1: Data, d2: Data, d3: Data, d4: Data)
    case dsa(Data)
    case ecdsa(type: ECDSAType, data: Data)
    case ed25519(privateKey: Data, publicKey: Data)
    
    init(type: SSHKeyType) {
        var rng = SecureRandomNumberGenerator()
        self.init(type: type, using: &rng)
    }
    
    init<R: RandomNumberGenerator>(type: SSHKeyType, using rng: inout R) {
        switch type {
        case .ed25519:
            let privateKey = ed25519NewPrivateKey(using: &rng)
            let publicKey = ed25519PublicKeyFromPrivateKey(privateKey: privateKey)
            self = .ed25519(privateKey: privateKey, publicKey: publicKey)
        default:
            unimplemented()
        }
    }
    
    init(buf: inout SSHReadBuffer, type: SSHKeyType) throws {
        let keyData: SSHPrivateKeyData
        switch type {
        case .rsa:
            let typeString = try buf.readLengthPrefixedString()
            guard typeString == type.description else {
                throw SSHPrivateKey.Error.invalid
            }
            let modulus = try buf.readChunk()
            let exponent = try buf.readChunk()
            let d1 = try buf.readChunk()
            let d2 = try buf.readChunk()
            let d3 = try buf.readChunk()
            let d4 = try buf.readChunk()
            keyData = .rsa(modulus: modulus, exponent: exponent, d1: d1, d2: d2, d3: d3, d4: d4)
        case .dsa:
            let x = try buf.readChunk()
            keyData = .dsa(x)
        case .ecdsa(let ecdsaType):
            let typeString = try buf.readLengthPrefixedString()
            guard
                let internalType = ECDSAType(typeString),
                ecdsaType == internalType
            else {
                throw SSHPublicKey.Error.invalid
            }
            let data = try buf.readChunk()
            keyData = .ecdsa(type: ecdsaType, data: data)
        case .ed25519:
            let data = try buf.readChunk()
            guard data.count == 64 else {
                throw SSHPrivateKey.Error.invalid
            }
            let privateKey = data.subdata(in: 0..<32)
            let publicKey = data.subdata(in: 32..<64)
            keyData = .ed25519(privateKey: privateKey, publicKey: publicKey)
        }
        self = keyData
    }
    
    public var type: SSHKeyType {
        switch self {
        case .rsa(_, _, _, _, _, _):
                .rsa
        case .dsa(_):
                .dsa
        case .ecdsa(let type, _):
                .ecdsa(type)
        case .ed25519(_, _):
                .ed25519
        }
    }
    
    public var chunks: [Data] {
        switch self {
        case .rsa(let modulus, let exponent, let d1, let d2, let d3, let d4):
            [modulus, exponent, d1, d2, d3, d4]
        case .dsa(let x):
            [x]
        case .ecdsa(let type, let data):
            [type.description.utf8Data, data]
        case .ed25519(let privateKey, let publicKey):
            [privateKey + publicKey]
        }
    }
    
    public var description: String {
        switch self {
        case .rsa(let modulus, let exponent, let d1, let d2, let d3, let d4):
            "(modulus: \(modulus.hex), exponent: \(exponent.hex), d1: \(d1.hex), d2: \(d2.hex), d3: \(d3.hex), d4: \(d4.hex))"
        case .dsa(let x):
            x.hex
        case .ecdsa(_, let data):
            data.hex
        case .ed25519(let privateKey, let publicKey):
            (privateKey + publicKey).hex
        }
    }
    
    public var publicKeyData: SSHPublicKeyData {
        switch self {
        case .ed25519(_, let publicKey):
            SSHPublicKeyData.ed25519(publicKey)
        default:
            unimplemented()
        }
    }
    
    public func derivePublicKeyData() -> SSHPublicKeyData {
        switch self {
        case .ed25519(let privateKey, _):
            SSHPublicKeyData.ed25519(ed25519PublicKeyFromPrivateKey(privateKey: privateKey))
        default:
            unimplemented()
        }
    }
}
