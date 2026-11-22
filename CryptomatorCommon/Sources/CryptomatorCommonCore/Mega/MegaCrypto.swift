//
//  MegaCrypto.swift
//  CryptomatorCommonCore
//

import BigInt
import CommonCrypto
import Foundation

public enum MegaCrypto {
	// MARK: - Base64URL

	public static func base64urlEncode(_ data: Data) -> String {
		return data.base64EncodedString()
			.replacingOccurrences(of: "+", with: "-")
			.replacingOccurrences(of: "/", with: "_")
			.replacingOccurrences(of: "=", with: "")
	}

	public static func base64urlEncode(_ bytes: [UInt8]) -> String {
		return base64urlEncode(Data(bytes))
	}

	public static func base64urlDecode(_ string: String) -> Data? {
		var base64 = string
			.replacingOccurrences(of: "-", with: "+")
			.replacingOccurrences(of: "_", with: "/")
		let remainder = base64.count % 4
		if remainder > 0 {
			base64.append(String(repeating: "=", count: 4 - remainder))
		}
		return Data(base64Encoded: base64)
	}

	public static func base64urlDecodeBytes(_ string: String) -> [UInt8]? {
		guard let data = base64urlDecode(string) else { return nil }
		return [UInt8](data)
	}

	// MARK: - A32 Array Conversions

	public static func bytesToA32(_ bytes: [UInt8]) -> [UInt32] {
		var padded = bytes
		let remainder = padded.count % 4
		if remainder != 0 {
			padded.append(contentsOf: [UInt8](repeating: 0, count: 4 - remainder))
		}
		var result = [UInt32](repeating: 0, count: padded.count / 4)
		for i in 0..<result.count {
			let b0 = UInt32(padded[i * 4])
			let b1 = UInt32(padded[i * 4 + 1])
			let b2 = UInt32(padded[i * 4 + 2])
			let b3 = UInt32(padded[i * 4 + 3])
			result[i] = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
		}
		return result
	}

	public static func a32ToBytes(_ a32: [UInt32]) -> [UInt8] {
		var result = [UInt8](repeating: 0, count: a32.count * 4)
		for (i, val) in a32.enumerated() {
			result[i * 4] = UInt8((val >> 24) & 0xFF)
			result[i * 4 + 1] = UInt8((val >> 16) & 0xFF)
			result[i * 4 + 2] = UInt8((val >> 8) & 0xFF)
			result[i * 4 + 3] = UInt8(val & 0xFF)
		}
		return result
	}

	// MARK: - Password & Key Derivation

	/// MEGA v1 password key derivation
	public static func passwordKey(password: String) -> [UInt8] {
		let pwBytes = [UInt8](password.utf8)
		let a32 = bytesToA32(pwBytes)
		var pkey: [UInt32] = [0x93C467E3, 0x7B5B329C, 0xD1E2B799, 0x0152D026]

		for _ in 0..<65536 {
			for i in stride(from: 0, to: a32.count, by: 4) {
				var keySlice: [UInt32] = [0, 0, 0, 0]
				for j in 0..<4 {
					if i + j < a32.count {
						keySlice[j] = a32[i + j]
					}
				}
				let keyBytes = a32ToBytes(keySlice)
				let pkeyBytes = a32ToBytes(pkey)
				if let encrypted = aesEcbEncrypt(data: pkeyBytes, key: keyBytes) {
					pkey = bytesToA32(encrypted)
				}
			}
		}
		return a32ToBytes(pkey)
	}

	/// MEGA v2 PBKDF2-HMAC-SHA512 key derivation
	public static func deriveKeyV2(password: String, salt: [UInt8]) -> (aesKey: [UInt8], authKey: [UInt8])? {
		let pwBytes = [UInt8](password.utf8)
		var derived = [UInt8](repeating: 0, count: 32)
		let status = CCKeyDerivationPBKDF(
			CCPBKDFAlgorithm(kCCPBKDF2),
			password,
			pwBytes.count,
			salt,
			salt.count,
			CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
			100_000,
			&derived,
			derived.count
		)
		guard status == kCCSuccess else { return nil }
		let aesKey = Array(derived[0..<16])
		let authKey = Array(derived[16..<32])
		return (aesKey, authKey)
	}

	/// String hash calculation for email and AES key
	public static func stringHash(string: String, aesKey: [UInt8]) -> String {
		let sBytes = [UInt8](string.utf8)
		let s32 = bytesToA32(sBytes)
		var h32: [UInt32] = [0, 0, 0, 0]
		for i in 0..<s32.count {
			h32[i % 4] ^= s32[i]
		}
		var hBytes = a32ToBytes(h32)
		for _ in 0..<16384 {
			if let enc = aesEcbEncrypt(data: hBytes, key: aesKey) {
				hBytes = enc
			}
		}
		let finalA32 = bytesToA32(hBytes)
		let resultA32: [UInt32] = [finalA32[0], finalA32[2]]
		return base64urlEncode(a32ToBytes(resultA32))
	}

	// MARK: - AES Operations

	public static func aesEcbEncrypt(data: [UInt8], key: [UInt8]) -> [UInt8]? {
		return cryptWithMode(data: data, key: key, iv: nil, mode: CCMode(kCCModeECB), op: CCOperation(kCCEncrypt))
	}

	public static func aesEcbDecrypt(data: [UInt8], key: [UInt8]) -> [UInt8]? {
		return cryptWithMode(data: data, key: key, iv: nil, mode: CCMode(kCCModeECB), op: CCOperation(kCCDecrypt))
	}

	public static func aesCbcEncrypt(data: [UInt8], key: [UInt8], iv: [UInt8] = [UInt8](repeating: 0, count: 16)) -> [UInt8]? {
		return cryptWithMode(data: data, key: key, iv: iv, mode: CCMode(kCCModeCBC), op: CCOperation(kCCEncrypt))
	}

	public static func aesCbcDecrypt(data: [UInt8], key: [UInt8], iv: [UInt8] = [UInt8](repeating: 0, count: 16)) -> [UInt8]? {
		return cryptWithMode(data: data, key: key, iv: iv, mode: CCMode(kCCModeCBC), op: CCOperation(kCCDecrypt))
	}

	public static func aesCtrCrypt(data: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8]? {
		return cryptWithMode(data: data, key: key, iv: iv, mode: CCMode(kCCModeCTR), op: CCOperation(kCCEncrypt))
	}

	private static func cryptWithMode(data: [UInt8], key: [UInt8], iv: [UInt8]?, mode: CCMode, op: CCOperation) -> [UInt8]? {
		var cryptor: CCCryptorRef?
		let status = CCCryptorCreateWithMode(
			op,
			mode,
			CCAlgorithm(kCCAlgorithmAES),
			CCPadding(ccNoPadding),
			iv,
			key,
			key.count,
			nil,
			0,
			0,
			0,
			&cryptor
		)
		guard status == kCCSuccess, let cryptorRef = cryptor else { return nil }
		defer { CCCryptorRelease(cryptorRef) }

		var outData = [UInt8](repeating: 0, count: data.count)
		var outLength = 0
		let updateStatus = CCCryptorUpdate(cryptorRef, data, data.count, &outData, outData.count, &outLength)
		guard updateStatus == kCCSuccess else { return nil }
		return outData
	}

	// MARK: - Node Attributes & File Keys

	public static func decryptAttr(key: [UInt8], dataString: String) -> String? {
		guard let decoded = base64urlDecodeBytes(dataString) else { return nil }
		guard decoded.count >= 16, decoded.count % 16 == 0 else { return nil }
		guard let decrypted = aesCbcDecrypt(data: decoded, key: key, iv: [UInt8](repeating: 0, count: 16)) else { return nil }
		guard decrypted.count >= 4 else { return nil }
		let prefix = String(decoding: decrypted[0..<4], as: UTF8.self)
		guard prefix == "MEGA" else { return nil }
		guard let fullStr = String(bytes: decrypted[4...], encoding: .utf8) else { return nil }
		// Extract JSON substring {"n": "..."}
		guard let start = fullStr.firstIndex(of: "{"),
		      let end = fullStr.lastIndex(of: "}") else { return nil }
		let jsonStr = String(fullStr[start...end])
		guard let jsonData = jsonStr.data(using: .utf8),
		      let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any],
		      let name = json["n"] as? String else { return nil }
		return name
	}

	public static func encryptAttr(key: [UInt8], name: String) -> String? {
		let jsonStr = "{\"n\":\"\(name)\"}"
		let fullStr = "MEGA" + jsonStr
		var bytes = [UInt8](fullStr.utf8)
		let remainder = bytes.count % 16
		if remainder != 0 {
			bytes.append(contentsOf: [UInt8](repeating: 0, count: 16 - remainder))
		}
		guard let enc = aesCbcEncrypt(data: bytes, key: key, iv: [UInt8](repeating: 0, count: 16)) else { return nil }
		return base64urlEncode(enc)
	}

	public static func chunkSizes(fileSize: Int64) -> [(offset: Int64, length: Int)] {
		var result = [(offset: Int64, length: Int)]()
		var offset: Int64 = 0
		var remaining = fileSize
		var chunkIdx = 1

		while remaining > 0 {
			let chunkSize: Int
			if chunkIdx <= 8 {
				chunkSize = chunkIdx * 131072
			} else {
				chunkSize = 1048576
			}
			let actualSize = Int(min(Int64(chunkSize), remaining))
			result.append((offset: offset, length: actualSize))
			offset += Int64(actualSize)
			remaining -= Int64(actualSize)
			chunkIdx += 1
		}
		return result
	}

	public static func makeCtrIv(baseIv: [UInt8], offset: Int64) -> [UInt8] {
		let ivA32 = bytesToA32(baseIv)
		var iv: [UInt32] = [0, 0, 0, 0]
		if ivA32.count >= 2 {
			iv[0] = ivA32[0]
			iv[1] = ivA32[1]
		}
		iv[2] = UInt32((offset / 68719476736) & 0xFFFFFFFF)
		iv[3] = UInt32((offset / 16) & 0xFFFFFFFF)
		return a32ToBytes(iv)
	}

	public static func computeChunkMac(chunkData: [UInt8], key: [UInt8], initialIv: [UInt8]) -> (mac: [UInt8], nextIv: [UInt8]) {
		let ivA32 = bytesToA32(initialIv)
		var iv: [UInt32] = [0, 0, 0, 0]
		if ivA32.count >= 2 {
			iv[0] = ivA32[0]
			iv[1] = ivA32[1]
			iv[2] = ivA32[0]
			iv[3] = ivA32[1]
		}
		var currentIv = a32ToBytes(iv)
		for i in stride(from: 0, to: chunkData.count, by: 16) {
			let end = min(i + 16, chunkData.count)
			var block = Array(chunkData[i..<end])
			if block.count < 16 {
				block.append(contentsOf: [UInt8](repeating: 0, count: 16 - block.count))
			}
			if let enc = aesCbcEncrypt(data: block, key: key, iv: currentIv) {
				currentIv = enc
			}
		}
		return (currentIv, currentIv)
	}

	// MARK: - RSA & Session Decryption

	public static func getMPI(from bytes: [UInt8]) -> (bint: BInt, remainder: [UInt8])? {
		guard bytes.count >= 2 else { return nil }
		let bitLength = (Int(bytes[0]) << 8) | Int(bytes[1])
		let byteLength = (bitLength + 7) / 8
		guard bytes.count >= 2 + byteLength else { return nil }
		let mpiBytes = Array(bytes[2..<(2 + byteLength)])
		let bint = BInt(magnitude: mpiBytes)
		let remainder = Array(bytes[(2 + byteLength)...])
		return (bint, remainder)
	}

	public static func decryptSessionId(privkEncrypted: String, csidEncrypted: String, masterKey: [UInt8]) -> String? {
		guard let privkBytes = base64urlDecodeBytes(privkEncrypted),
		      let csidBytes = base64urlDecodeBytes(csidEncrypted) else {
			return nil
		}

		guard let privkDecrypted = aesEcbDecrypt(data: privkBytes, key: masterKey) else {
			return nil
		}

		guard let (pBInt, rem1) = getMPI(from: privkDecrypted),
		      let (qBInt, rem2) = getMPI(from: rem1),
		      let (dBInt, _) = getMPI(from: rem2),
		      let (csidBInt, _) = getMPI(from: csidBytes) else {
			return nil
		}

		let n = pBInt * qBInt
		let decryptedBInt = csidBInt.expMod(dBInt, n)
		var decryptedBytes = decryptedBInt.asMagnitudeBytes()
		if decryptedBytes.first == 0 {
			decryptedBytes.removeFirst()
		}
		guard decryptedBytes.count >= 43 else { return nil }
		let sidBytes = Array(decryptedBytes[0..<43])
		return base64urlEncode(sidBytes)
	}

	// MARK: - Node Key Decryption

	public static func decryptNodeKey(keyString: String, type: Int, masterKey: [UInt8]) -> (nodeKey: [UInt8], aesKey: [UInt8], iv: [UInt8]?)? {
		let parts = keyString.components(separatedBy: ":")
		guard parts.count >= 2 else { return nil }
		var keyPart = parts[1]
		if let slashIdx = keyPart.firstIndex(of: "/") {
			keyPart = String(keyPart[..<slashIdx])
		}
		guard let encKeyBytes = base64urlDecodeBytes(keyPart) else { return nil }
		guard let decryptedKeyBytes = aesEcbDecrypt(data: encKeyBytes, key: masterKey) else { return nil }

		let a32 = bytesToA32(decryptedKeyBytes)
		if type == 0 { // File
			guard a32.count >= 8 else { return nil }
			let keyA32: [UInt32] = [
				a32[0] ^ a32[4],
				a32[1] ^ a32[5],
				a32[2] ^ a32[6],
				a32[3] ^ a32[7]
			]
			let aesKey = a32ToBytes(keyA32)
			let ivA32: [UInt32] = [a32[4], a32[5]]
			let iv = a32ToBytes(ivA32)
			return (decryptedKeyBytes, aesKey, iv)
		} else { // Directory / Root
			guard a32.count >= 4 else { return nil }
			let keyA32: [UInt32] = [a32[0], a32[1], a32[2], a32[3]]
			let aesKey = a32ToBytes(keyA32)
			return (decryptedKeyBytes, aesKey, nil)
		}
	}
}
