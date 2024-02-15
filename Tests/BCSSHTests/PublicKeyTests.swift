import XCTest
import WolfBase
@testable import BCSSH

final class PublicKeyTests: XCTestCase {
    func testED25519PublicKey() throws {
        let key = try SSHPublicKey(ed25519PublicKey)
        XCTAssertEqual(key.description, "SSHPublicKey(type: ssh-ed25519, keyData: 0f2954f7a55e51303fe401d241f7bcb31495411ce66a09dfd9ed626721facde0, comment: wolf@Wolfs-MacBook-Pro.local)")
        XCTAssertEqual(key.string, ed25519PublicKey)
        XCTAssertEqual(key.hashString(), "256 SHA256:5sBUPsdkmQP1FqMPL6pzqqF6S0BVdRL7+LDcA2Ophzk wolf@Wolfs-MacBook-Pro.local (ED25519)")
        XCTAssertEqual(key.randomArt(),
        """
        +--[ED25519 256]--+
        |   ....++++oo    |
        |  .    o+++o o   |
        | .    ..o =.o    |
        |.    o  +o =     |
        |.     oBS.. o    |
        | .    *+B. .     |
        |  . .E +o+       |
        | ... .+.. .      |
        |.oo...o+         |
        +----[SHA256]-----+
        """
        )
    }
    
    func testRSAPublicKey() throws {
        let key = try SSHPublicKey(rsaPublicKey)
        XCTAssertEqual(key.description, "SSHPublicKey(type: ssh-rsa, keyData: (exponent: 010001, modulus: 00991cfbb8f5b5e6c56fb5b0f77e4c416ae3dbd25012bcb3c5c8918f638141484420d13d41e351e80a503e2bac33650c999816a22a8ef7028924aa3691677956216f8fb2a341b5b2bc4379982f3e9a1da30462f31a79a9ac2c1645fe7254e51b4e1275b15de88d01555a9ea3910aaea46c129038ff9d29d19101151dc3e9f813d87fcf269387d620975d840ab9292a65d95f6f3c2f08c8348ab9117115da0b03f41fd39dd96c0c21eb5fc7936061829f246cff7e0189a01012fd174e241d6346f48ac0b13fd4aaf2fb8c4496e95b170acbdc4013450d5cd7a7dc3ac68c9adb10799e0fe4a3b468b04be58d847f57024fcc52a95c7fd8b5e52fc6716ed148e952cf), comment: wolf@Wolfs-MacBook-Pro.local)")
        XCTAssertEqual(key.string, rsaPublicKey)
        XCTAssertEqual(key.hashString(), "2048 SHA256:Ft/TLHhhrJUunfYdyeEDMHFfNWHtLTnQc1VHUQ1kH58 wolf@Wolfs-MacBook-Pro.local (RSA)")
        XCTAssertEqual(key.randomArt(),
        """
        +---[RSA 2048]----+
        |           +.++O^|
        |           .=o=.@|
        |        .   *o E+|
        |         o O =B =|
        |        S = X oO |
        |       .   + + .o|
        |              . .|
        |                 |
        |                 |
        +----[SHA256]-----+
        """
        )
    }
    
    func testDSAPublicKey() throws {
        let key = try SSHPublicKey(dsaPublicKey)
        XCTAssertEqual(key.description, "SSHPublicKey(type: ssh-dss, keyData: (p: 00f18ef2966db8c0cfd11263ccbea4a193c0e299110372e580a18f57e73f8c1377f43f1945fbe44a1198dec7d47c0b392e54e7f00ba4407284b17b03eee3743432c19518a1c803ce0acc1893e62f87c413eb4f56433c75ea7dc4c6359fc7dee88a2014b17e04cb02c40c94c35edd7f54c74c878ee8c951768b8daafa8e98785cdb, q: 00ada9dd93b5719df33fdec0a598b152770401226b, g: 7cb016eae63db653572c293b5e3baf58c5a68f9f17499f6153bde12ad9f6d1e894b3e47d896dc9cbcf5a5b3470192951fc9f1b65a525445f7498c67073a493ad018c0e0077c0b5170edcb464c712d40d7161ec12c02edc3f2672b5e49e6f94fcbfa751eae6bdf3c7f9de9715da4f7242c05bbd58da166b4274cbfa38be6146c0, y: 235a8f1d68a83a8525b91269d823b2e4557ef3756cad0f2ba16bc4a9ad79c4b76e084fa92b09f4d5baf442834749b1acc56278eb88b86fe7d12a09b38991882e022f291cc325b8d2c3e4bac6059a092ae9405221bf94a64d897303237ca80fd4fe636bffb17bc444a05fb08cdc7a6a9f0e268d06c44678227a0f2cc49d4ea9d8), comment: wolf@Wolfs-MacBook-Pro.local)")
        XCTAssertEqual(key.string, dsaPublicKey)
        XCTAssertEqual(key.hashString(), "1024 SHA256:Cb7jWCZ9Ey37P6pa7AtVXjbrJfRk+55VoWLEZLQx1ek wolf@Wolfs-MacBook-Pro.local (DSA)")
        XCTAssertEqual(key.randomArt(),
        """
        +---[DSA 1024]----+
        |          .*... .|
        |          + +  o |
        |      .   .+= +. |
        |     . . =.+ *.E.|
        |      . S ooo.+ .|
        |     . + +...o ..|
        |    . B *   .   o|
        |     * * o  .  .o|
        |    . o.+ooo.. ..|
        +----[SHA256]-----+
        """
        )
    }
    
    func testECDSAPublicKey() throws {
        let key = try SSHPublicKey(ecdsaPublicKey)
        XCTAssertEqual(key.description, "SSHPublicKey(type: ecdsa-sha2-nistp256, keyData: 048d9320a7acb219babd96b2ffd06cdadca99647ff39b1c7ba58c40b5493769767d59fd557b92f3b10be4f5179abc1d8882d1aa37693ea5c5bf91a582d0be3da20, comment: wolf@Wolfs-MacBook-Pro.local)")
        XCTAssertEqual(key.string, ecdsaPublicKey)
        XCTAssertEqual(key.hashString(), "256 SHA256:auPD86cNL0AFoBVNqHE4kBv7zcMcgJ3vFcT1G6efZNo wolf@Wolfs-MacBook-Pro.local (ECDSA)")
        XCTAssertEqual(key.randomArt(),
        """
        +---[ECDSA 256]---+
        |.= o+O+o.        |
        |+ Boo + ..       |
        | +.B   o  o .    |
        |o . o o    =     |
        | . * +  S o o    |
        |  . B ..   * .   |
        |     o+.. . E    |
        |     o+..+.      |
        |      .+o+o      |
        +----[SHA256]-----+
        """
        )
    }
}
