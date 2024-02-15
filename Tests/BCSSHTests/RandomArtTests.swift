import XCTest
import WolfBase
@testable import BCSSH

final class RandomArtTests: XCTestCase {
    func testDecodeMD5() throws {
        let hash = try SSHHash("42:6d:f8:5b:18:bf:f6:fd:4c:9f:6c:05:5f:de:44:2c", algorithm: .md5)
        XCTAssertEqual(hash.data, ‡"426df85b18bff6fd4c9f6c055fde442c")
    }
    
    func testDecodeSHA256() throws {
        let hash = try SSHHash("wjqs7Nq/4Yg/OVm0bZgera0u40GHzj3IargfNJOiOvA", algorithm: .sha256)
        XCTAssertEqual(hash.data, ‡"c23aacecdabfe1883f3959b46d981eadad2ee34187ce3dc86ab81f3493a23af0")
    }
    
    func testToBitPairs() throws {
        let hash = try SSHHash("42:6d:f8:5b:18:bf:f6:fd:4c:9f:6c:05:5f:de:44:2c", algorithm: .md5)
        XCTAssertEqual(RandomArt.toBitPairs(hash.data), ["10", "00", "00", "01", "01", "11", "10", "01", "00", "10", "11", "11", "11", "10", "01", "01", "00", "10", "01", "00", "11", "11", "11", "10", "10", "01", "11", "11", "01", "11", "11", "11", "00", "11", "00", "01", "11", "11", "01", "10", "00", "11", "10", "01", "01", "01", "00", "00", "11", "11", "01", "01", "10", "11", "01", "11", "00", "01", "00", "01", "00", "11", "10", "00"])
    }
    
    func testHorizontalBorder() throws {
        XCTAssertEqual(
            RandomArt.horizontalBorder(),
            "+-----------------+"
        )
        XCTAssertEqual(
            RandomArt.horizontalBorder(text: "RSA 2048"),
            "+---[RSA 2048]----+"
        )
        XCTAssertEqual(
            RandomArt.horizontalBorder(text: "MD5"),
            "+------[MD5]------+"
        )
        XCTAssertEqual(
            RandomArt.horizontalBorder(text: "SHA256"),
            "+----[SHA256]-----+"
        )
    }
    
    func testPositionTypeField() {
        let f = String(RandomArt.positionTypeField)
        let lines = f.chunked(into: 17).joined(separator: "\n")
        XCTAssertEqual(lines,
        """
        aTTTTTTTTTTTTTTTb
        LMMMMMMMMMMMMMMMR
        LMMMMMMMMMMMMMMMR
        LMMMMMMMMMMMMMMMR
        LMMMMMMMMMMMMMMMR
        LMMMMMMMMMMMMMMMR
        LMMMMMMMMMMMMMMMR
        LMMMMMMMMMMMMMMMR
        cBBBBBBBBBBBBBBBd
        """
        )
    }
    
    // https://github.com/AbsurdlySuspicious/bishop.rs/blob/master/README.md
    func test2() throws {
        let art = try RandomArt(SSHHash(data: ‡"c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2", algorithm: .sha256))
        XCTAssertEqual(art.contentWithBorder(),
           """
           +-----------------+
           |    .     .      |
           | . + .   +       |
           |o + + + = .      |
           | * + + O =       |
           |  E o.o S        |
           | . +.=.o.=       |
           |  o.B.=...       |
           |   +.+.*  o      |
           |    o.o.o. .     |
           +-----------------+
           """
        )
    }
    
    // http://www.dirk-loss.de/sshvis/drunken_bishop.pdf
    // Page 16
    func test3() throws {
        let art = try RandomArt(SSHHash(data: ‡"fc94b0c1e5b0987c5843997697ee9fb7", algorithm: .md5))
        XCTAssertEqual(art.contentWithBorder(),
           """
           +-----------------+
           |       .=o.  .   |
           |     . *+*. o    |
           |      =.*..o     |
           |       o + ..    |
           |        S o.     |
           |         o  .    |
           |          .  . . |
           |              o .|
           |               E.|
           +-----------------+
           """
        )
    }
    
    // http://www.dirk-loss.de/sshvis/drunken_bishop.pdf
    // Page 16
    func test4() throws {
        let art = try RandomArt(SSHHash(data: ‡"731ee54c82233359e3d5e9f6ccf87e1f", algorithm: .md5))
        XCTAssertEqual(art.contentWithBorder(),
           """
           +-----------------+
           |        o .. .   |
           |       + +  o    |
           |      = + ..o    |
           |       + . *o    |
           |        S o.o=   |
           |         + .. +  |
           |          .  . E |
           |              . o|
           |             ...o|
           +-----------------+
           """
        )
    }

    // https://github.com/Chris-Kiese/SSH-Randomart/blob/master/README.md
    func test5() throws {
        let hash = try SSHHash("wjqs7Nq/4Yg/OVm0bZgera0u40GHzj3IargfNJOiOvA", algorithm: .sha256)
        let art = RandomArt(hash)
        XCTAssertEqual(art.contentWithBorder(topText: "RSA 2048", bottomText: hash.algorithm.description),
           """
           +---[RSA 2048]----+
           |                 |
           |                 |
           |                 |
           |   o..           |
           |. B..*o S        |
           |oB B*.+.         |
           |+.B=B=           |
           |+*E*o+.          |
           |BOXB*o           |
           +----[SHA256]-----+
           """
        )
    }

    // https://github.com/Chris-Kiese/SSH-Randomart/blob/master/README.md
    // As corrected per: https://github.com/Chris-Kiese/SSH-Randomart/issues/1
    func test6() throws {
        let hash = try SSHHash("42:6d:f8:5b:18:bf:f6:fd:4c:9f:6c:05:5f:de:44:2c", algorithm: .md5)
        let art = RandomArt(hash)
        XCTAssertEqual(art.contentWithBorder(topText: "RSA 2048", bottomText: hash.algorithm.description),
           """
           +---[RSA 2048]----+
           |               . |
           |       o      E o|
           |      o +      o |
           |     . o +    . o|
           |      . S o    =o|
           |       . o .    =|
           |        . o     o|
           |         . . ..+o|
           |            . o++|
           +------[MD5]------+
           """
        )
    }
    
    func test7() throws {
        let hash = try SSHHash("5sBUPsdkmQP1FqMPL6pzqqF6S0BVdRL7+LDcA2Ophzk", algorithm: .sha256)
        let art = RandomArt(hash)
        XCTAssertEqual(art.contentWithBorder(topText: "ED25519 256", bottomText: hash.algorithm.description),
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
}

