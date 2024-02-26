import XCTest
import WolfBase
import BCCrypto
@testable import BCSSH

final class PrivateKeyTests: XCTestCase {
    func testED25519PrivateKey() throws {
        let key = try SSHPrivateKey(ed25519PrivateKey)
        XCTAssertEqual(key.description, "SSHPrivateKey(type: ssh-ed25519, publicKeyData: 0f2954f7a55e51303fe401d241f7bcb31495411ce66a09dfd9ed626721facde0, checkNum: c90f110e, privateKeyData: b6e2cd022947a7a79ded37ab4fe5d6678bdea762b60a8604984899e2455f130c0f2954f7a55e51303fe401d241f7bcb31495411ce66a09dfd9ed626721facde0, comment: wolf@Wolfs-MacBook-Pro.local)")
        XCTAssertEqual(key.string, ed25519PrivateKey)
        XCTAssertEqual(key.publicKey.string, ed25519PublicKey)
        XCTAssertEqual(key.derivePublicKey().string, ed25519PublicKey)
    }
    
    func testRSAPrivateKey() throws {
        let key = try SSHPrivateKey(rsaPrivateKey)
        XCTAssertEqual(key.description, "SSHPrivateKey(type: ssh-rsa, publicKeyData: (publicExponent: 010001, modulus: 00991cfbb8f5b5e6c56fb5b0f77e4c416ae3dbd25012bcb3c5c8918f638141484420d13d41e351e80a503e2bac33650c999816a22a8ef7028924aa3691677956216f8fb2a341b5b2bc4379982f3e9a1da30462f31a79a9ac2c1645fe7254e51b4e1275b15de88d01555a9ea3910aaea46c129038ff9d29d19101151dc3e9f813d87fcf269387d620975d840ab9292a65d95f6f3c2f08c8348ab9117115da0b03f41fd39dd96c0c21eb5fc7936061829f246cff7e0189a01012fd174e241d6346f48ac0b13fd4aaf2fb8c4496e95b170acbdc4013450d5cd7a7dc3ac68c9adb10799e0fe4a3b468b04be58d847f57024fcc52a95c7fd8b5e52fc6716ed148e952cf), checkNum: 4cbff639, privateKeyData: (modulus: 00991cfbb8f5b5e6c56fb5b0f77e4c416ae3dbd25012bcb3c5c8918f638141484420d13d41e351e80a503e2bac33650c999816a22a8ef7028924aa3691677956216f8fb2a341b5b2bc4379982f3e9a1da30462f31a79a9ac2c1645fe7254e51b4e1275b15de88d01555a9ea3910aaea46c129038ff9d29d19101151dc3e9f813d87fcf269387d620975d840ab9292a65d95f6f3c2f08c8348ab9117115da0b03f41fd39dd96c0c21eb5fc7936061829f246cff7e0189a01012fd174e241d6346f48ac0b13fd4aaf2fb8c4496e95b170acbdc4013450d5cd7a7dc3ac68c9adb10799e0fe4a3b468b04be58d847f57024fcc52a95c7fd8b5e52fc6716ed148e952cf, publicExponent: 010001, privateExponent: 21b37070889cae1bbcf7d7e8d1c2c50f5af1f27baf741b79a828e9cfb40e8372836aaaba0ae7e75405cf795b60c09822628870cf3f427d2b64879695309a536bee9b496d87b40f9042a5cbea723407dbeec63cce120357a3288fe56e92e30ebc8371a6458e3f2310ff6e35806242886c4535bb65ffd8c988ca1d34bcff8d9c084f0722a151fe9d1e0aae17e9f26cfbf347f9226153f9c8b7730463584b5ae15c0035b092026356c659d1e01e6ebd6558692a507a3cccd873cafd449cd446ec0515b6f05b67aa8ffb316c898edf5caead3353a210062272784947e2ecd32f1aa0b475e9ec041f9d53f46d03255e611069a432d7b42c02ed4720d14c4e5d3f0229, prime1: 00c7ad2afa19d06489d9fa7a475bae98ed739048630fe053bad238cf9f6b262c46a3f0f48936efb9e3ebd81a79bc8738e8b7a51d05e7fbf601224741157257a51a3e77e9fd45c5176b8d50d50305d0e4a0b74d8c48797ec5f109c9d1294404237688d2f02661cd671d250319a13c9c0137932b308748089722d7f3c9c0c101825e, prime2: 00c90b81e7ab422e31fd08fd5a49c59361dbf8894a9c23d87dd52de887098d076168e8fe58c472b7b9013ad89b896b765bff45ba8fad56db53a6396389d185952bf20e0a9990b417b680de36335d5a68f91b6f734e9e882fada40708c44114bd27d4493295c413e8ed666f6ffcc9ebd8619526328bdc5ea49e73e893bb4d638415, coefficient: 00c2f75d2daff6951fc255c5e720b8bda9a66af637506c1ff904b02647e29747f6de48e61af71e046c64307248eb66f745b69066d044f94e01fd35462858542afec85da4487460eb2ce23b52ee96708cd931fd848cb5f3c18096149c08736710268e15061af6d9d1dd7f8b445de4f20009d030faba66dfc645b7f7fc30a0ef8053), comment: wolf@Wolfs-MacBook-Pro.local)")
        XCTAssertEqual(key.string, rsaPrivateKey)
        XCTAssertEqual(key.publicKey.string, rsaPublicKey)
    }
    
    func testDSAPrivateKey() throws {
        let key = try SSHPrivateKey(dsaPrivateKey)
        XCTAssertEqual(key.description, "SSHPrivateKey(type: ssh-dss, publicKeyData: (p: 00f18ef2966db8c0cfd11263ccbea4a193c0e299110372e580a18f57e73f8c1377f43f1945fbe44a1198dec7d47c0b392e54e7f00ba4407284b17b03eee3743432c19518a1c803ce0acc1893e62f87c413eb4f56433c75ea7dc4c6359fc7dee88a2014b17e04cb02c40c94c35edd7f54c74c878ee8c951768b8daafa8e98785cdb, q: 00ada9dd93b5719df33fdec0a598b152770401226b, g: 7cb016eae63db653572c293b5e3baf58c5a68f9f17499f6153bde12ad9f6d1e894b3e47d896dc9cbcf5a5b3470192951fc9f1b65a525445f7498c67073a493ad018c0e0077c0b5170edcb464c712d40d7161ec12c02edc3f2672b5e49e6f94fcbfa751eae6bdf3c7f9de9715da4f7242c05bbd58da166b4274cbfa38be6146c0, y: 235a8f1d68a83a8525b91269d823b2e4557ef3756cad0f2ba16bc4a9ad79c4b76e084fa92b09f4d5baf442834749b1acc56278eb88b86fe7d12a09b38991882e022f291cc325b8d2c3e4bac6059a092ae9405221bf94a64d897303237ca80fd4fe636bffb17bc444a05fb08cdc7a6a9f0e268d06c44678227a0f2cc49d4ea9d8), checkNum: 8c2301b5, privateKeyData: 008676a664d501ba9802c103967ec6b03e09202320, comment: wolf@Wolfs-MacBook-Pro.local)")
        XCTAssertEqual(key.string, dsaPrivateKey)
        XCTAssertEqual(key.publicKey.string, dsaPublicKey)
    }
    
    func testECDSAPrivateKey() throws {
        let key = try SSHPrivateKey(ecdsaPrivateKey)
        XCTAssertEqual(key.description, "SSHPrivateKey(type: ecdsa-sha2-nistp256, publicKeyData: 048d9320a7acb219babd96b2ffd06cdadca99647ff39b1c7ba58c40b5493769767d59fd557b92f3b10be4f5179abc1d8882d1aa37693ea5c5bf91a582d0be3da20, checkNum: 4f193f66, privateKeyData: 00e461ff94992dd07a77da51be4732a84f5ae4b6391fb735f1f1804c1fc6686cee, comment: wolf@Wolfs-MacBook-Pro.local)")
        XCTAssertEqual(key.string, ecdsaPrivateKey)
        XCTAssertEqual(key.publicKey.string, ecdsaPublicKey)
    }
    
    func testGenerateKey() throws {
        var rng = makeFakeRandomNumberGenerator()
        let key = SSHPrivateKey(type: .ed25519, comment: "wolf@Wolf.local", using: &rng)
        XCTAssertEqual(key.string,
        """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACB2+GPhAk2P9s2K1WxDTgHbvymZz8LxMvx/QcoZ/tepfAAAAJgtvpBRLb6Q
        UQAAAAtzc2gtZWQyNTUxOQAAACB2+GPhAk2P9s2K1WxDTgHbvymZz8LxMvx/QcoZ/tepfA
        AAAEB+tVm7v2zOJjLPnxlK61CUPefhy61U3PqyekJ1n14v7Xb4Y+ECTY/2zYrVbENOAdu/
        KZnPwvEy/H9Byhn+16l8AAAAD3dvbGZAV29sZi5sb2NhbAECAwQFBg==
        -----END OPENSSH PRIVATE KEY-----
        """
        )
        // This has been verified with `ssh-keygen -y -f test_key`
        XCTAssertEqual(key.publicKey.string, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHb4Y+ECTY/2zYrVbENOAdu/KZnPwvEy/H9Byhn+16l8 wolf@Wolf.local")
    }
}
