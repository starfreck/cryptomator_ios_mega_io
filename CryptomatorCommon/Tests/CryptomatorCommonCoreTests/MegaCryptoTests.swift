//
//  MegaCryptoTests.swift
//  CryptomatorCommonCore
//

@testable import CryptomatorCommonCore
import XCTest

class MegaCryptoTests: XCTestCase {
	func testBase64UrlRoundTrip() {
		let original = "Hello, MEGA encryption test!".data(using: .utf8)!
		let encoded = MegaCrypto.base64urlEncode(original)
		let decoded = MegaCrypto.base64urlDecode(encoded)
		XCTAssertEqual(decoded, original)
	}

	func testA32ToBytesRoundTrip() {
		let a32: [UInt32] = [0x12345678, 0x9ABCDEF0, 0xDEADBEEF, 0xCAFEBABE]
		let bytes = MegaCrypto.a32ToBytes(a32)
		XCTAssertEqual(bytes.count, 16)
		let roundTripped = MegaCrypto.bytesToA32(bytes)
		XCTAssertEqual(roundTripped, a32)
	}

	func testDeriveKeyV2() {
		let salt = [UInt8]("c2FsdHNhbHQ=".utf8)
		guard let keys = MegaCrypto.deriveKeyV2(password: "password123", salt: salt) else {
			XCTFail("deriveKeyV2 returned nil")
			return
		}
		XCTAssertEqual(keys.aesKey.count, 16)
		XCTAssertEqual(keys.authKey.count, 16)
	}

	func testAes128EcbRoundTrip() {
		let key = [UInt8](repeating: 0x42, count: 16)
		let plain = [UInt8](repeating: 0x13, count: 32)
		guard let enc = MegaCrypto.aesEcbEncrypt(data: plain, key: key),
		      let dec = MegaCrypto.aesEcbDecrypt(data: enc, key: key) else {
			XCTFail("ECB crypt failed")
			return
		}
		XCTAssertEqual(dec, plain)
	}

	func testAes128CbcRoundTrip() {
		let key = [UInt8](repeating: 0x55, count: 16)
		let iv = [UInt8](repeating: 0x00, count: 16)
		let plain = [UInt8]("This is a 32-byte secret string.".utf8)
		guard let enc = MegaCrypto.aesCbcEncrypt(data: plain, key: key, iv: iv),
		      let dec = MegaCrypto.aesCbcDecrypt(data: enc, key: key, iv: iv) else {
			XCTFail("CBC crypt failed")
			return
		}
		XCTAssertEqual(dec, plain)
	}

	func testAttrEncryptionRoundTrip() {
		let key = [UInt8](repeating: 0x77, count: 16)
		let name = "secret_vault_file.txt"
		guard let encAttr = MegaCrypto.encryptAttr(key: key, name: name),
		      let decName = MegaCrypto.decryptAttr(key: key, dataString: encAttr) else {
			XCTFail("Attr encrypt/decrypt failed")
			return
		}
		XCTAssertEqual(decName, name)
	}

	func testAttrEncryptionSpecialCharacters() {
		let key = [UInt8](repeating: 0x88, count: 16)
		let names = [
			"File with \"quotes\" and 'single' quotes.pdf",
			"Emoji file 📁 🚀 🔒.mp4",
			"Special symbols !@#$%^&*()_+-=[]{}|;:,.<>?.txt",
			"Non-ASCII name: 日本語_테스트_Привет.dat"
		]
		for name in names {
			guard let encAttr = MegaCrypto.encryptAttr(key: key, name: name),
			      let decName = MegaCrypto.decryptAttr(key: key, dataString: encAttr) else {
				XCTFail("Attr encrypt/decrypt failed for: \(name)")
				continue
			}
			XCTAssertEqual(decName, name)
		}
	}

	func testChunkSizes() {
		let fileSize: Int64 = 5 * 1024 * 1024 // 5 MB
		let chunks = MegaCrypto.chunkSizes(fileSize: fileSize)
		XCTAssertFalse(chunks.isEmpty)
		let total = chunks.reduce(0) { $0 + Int64($1.length) }
		XCTAssertEqual(total, fileSize)
	}

	func testChunkSizesZeroByte() {
		let chunks = MegaCrypto.chunkSizes(fileSize: 0)
		XCTAssertTrue(chunks.isEmpty)
	}
}
