//
//  MegaClient.swift
//  CryptomatorCommonCore
//

import Foundation
import os

public enum MegaClientError: LocalizedError, Sendable {
	case invalidCredentials
	case twoFactorRequired
	case sessionExpired
	case itemNotFound
	case itemAlreadyExists
	case quotaExceeded
	case apiError(code: Int)
	case networkError(String)
	case invalidResponse
	case cryptoError

	public var errorDescription: String? {
		switch self {
		case .invalidCredentials:
			return "Invalid email or password."
		case .twoFactorRequired:
			return "Two-factor authentication code required."
		case .sessionExpired:
			return "Session expired. Please log in again."
		case .itemNotFound:
			return "Item not found on MEGA."
		case .itemAlreadyExists:
			return "Item already exists on MEGA."
		case .quotaExceeded:
			return "MEGA storage quota exceeded."
		case let .apiError(code):
			return "MEGA API error code: \(code)."
		case let .networkError(message):
			return "Network error: \(message)"
		case .invalidResponse:
			return "Invalid response from MEGA server."
		case .cryptoError:
			return "Cryptographic operation failed."
		}
	}
}

public final class MegaClient: Sendable {
	private struct State {
		var sessionId: String?
		var masterKey: [UInt8]?
		var sequenceNumber: Int = 0
		var nodesByHandle: [String: MegaNode] = [:]
		var rootHandle: String?
	}

	private let baseURL = URL(string: "https://g.api.mega.co.nz/cs")!
	private let session: URLSession
	private let state = OSAllocatedUnfairLock(initialState: State())

	public init(session: URLSession = .shared) {
		self.session = session
	}

	public var isAuthenticated: Bool {
		state.withLock { $0.sessionId != nil && $0.masterKey != nil }
	}

	public func dumpSession() -> String? {
		state.withLock { state in
			guard let sid = state.sessionId, let mk = state.masterKey else { return nil }
			return "\(sid):\(MegaCrypto.base64urlEncode(mk))"
		}
	}

	public func fastLogin(sessionToken: String) throws {
		let parts = sessionToken.components(separatedBy: ":")
		guard parts.count == 2,
		      let mk = MegaCrypto.base64urlDecodeBytes(parts[1]) else {
			throw MegaClientError.invalidCredentials
		}
		state.withLock {
			$0.sessionId = parts[0]
			$0.masterKey = mk
		}
	}

	// MARK: - Login & Authentication

	public func login(email: String, password: String, twoFactorCode: String? = nil) async throws -> String {
		let cleanEmail = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
		let cleanPassword = password

		// Step 1: Pre-login (us0)
		let preloginReq: [[String: Any]] = [["a": "us0", "user": cleanEmail]]
		let preloginRes = try await apiRequest(payload: preloginReq)

		var version = 1
		var salt: [UInt8]?
		if let first = preloginRes.first as? [String: Any] {
			if let v = first["v"] as? Int {
				version = v
			}
			if let s = first["s"] as? String {
				salt = MegaCrypto.base64urlDecodeBytes(s)
			}
		}

		var derivedAesKey: [UInt8]
		var userHash: String
		var sekString: String?

		if version == 2, let saltBytes = salt {
			guard let (aesKey, authKey) = MegaCrypto.deriveKeyV2(password: cleanPassword, salt: saltBytes) else {
				throw MegaClientError.cryptoError
			}
			derivedAesKey = aesKey
			userHash = MegaCrypto.base64urlEncode(authKey)
			let randomBytes = (0..<16).map { _ in UInt8.random(in: 0...255) }
			sekString = MegaCrypto.base64urlEncode(randomBytes)
		} else {
			let pwKey = MegaCrypto.passwordKey(password: cleanPassword)
			derivedAesKey = pwKey
			userHash = MegaCrypto.stringHash(string: cleanEmail, aesKey: pwKey)
		}

		// Step 2: User Session (us)
		var loginPayload: [String: Any] = [
			"a": "us",
			"user": cleanEmail,
			"uh": userHash
		]
		if let sek = sekString {
			loginPayload["sek"] = sek
		}
		if let mfa = twoFactorCode, !mfa.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
			loginPayload["mfa"] = mfa.trimmingCharacters(in: .whitespacesAndNewlines)
		}

		let loginRes: [Any]
		do {
			loginRes = try await apiRequest(payload: [loginPayload])
		} catch let MegaClientError.apiError(code) {
			if code == -26 {
				throw MegaClientError.twoFactorRequired
			}
			if code == -9 {
				throw MegaClientError.invalidCredentials
			}
			throw MegaClientError.apiError(code: code)
		}

		guard let respDict = loginRes.first as? [String: Any] else {
			throw MegaClientError.invalidResponse
		}

		guard let kStr = respDict["k"] as? String,
		      let encMasterKey = MegaCrypto.base64urlDecodeBytes(kStr) else {
			throw MegaClientError.invalidResponse
		}

		guard let decMasterKey = MegaCrypto.aesEcbDecrypt(data: encMasterKey, key: derivedAesKey) else {
			throw MegaClientError.cryptoError
		}

		var sid: String?
		if let tsid = respDict["tsid"] as? String {
			sid = tsid
		} else if let csid = respDict["csid"] as? String,
		          let privk = respDict["privk"] as? String {
			sid = MegaCrypto.decryptSessionId(privkEncrypted: privk, csidEncrypted: csid, masterKey: decMasterKey)
		}

		guard let finalSid = sid else {
			throw MegaClientError.cryptoError
		}

		state.withLock {
			$0.sessionId = finalSid
			$0.masterKey = decMasterKey
		}

		return cleanEmail
	}

	public func logout() async throws {
		if isAuthenticated {
			_ = try? await apiRequest(payload: [["a": "sml"]])
		}
		state.withLock {
			$0.sessionId = nil
			$0.masterKey = nil
			$0.nodesByHandle.removeAll()
			$0.rootHandle = nil
		}
	}

	// MARK: - Quota

	public func getQuota() async throws -> (used: Int64, total: Int64) {
		let res = try await apiRequest(payload: [["a": "uq", "strg": 1]])
		guard let dict = res.first as? [String: Any] else {
			throw MegaClientError.invalidResponse
		}
		let used = (dict["cstrg"] as? NSNumber)?.int64Value ?? 0
		let total = (dict["mstrg"] as? NSNumber)?.int64Value ?? 0
		return (used, total)
	}

	// MARK: - File System Navigation & Tree

	public func fetchFileSystem() async throws {
		let mk = try state.withLock { state -> [UInt8] in
			guard let masterKey = state.masterKey else { throw MegaClientError.sessionExpired }
			return masterKey
		}

		let res = try await apiRequest(payload: [["a": "f", "c": 1]])
		guard let dict = res.first as? [String: Any],
		      let fArray = dict["f"] as? [[String: Any]] else {
			throw MegaClientError.invalidResponse
		}

		var newNodes: [String: MegaNode] = [:]
		var newRoot: String?

		for item in fArray {
			guard let handle = item["h"] as? String,
			      let type = item["t"] as? Int else { continue }

			let parentHandle = item["p"] as? String
			let size = (item["s"] as? NSNumber)?.int64Value ?? 0
			let ts = (item["ts"] as? NSNumber)?.int64Value ?? 0

			if type == 2 {
				newRoot = handle
			}

			var name = ""
			var nodeKeyData = Data()
			var aesKeyData = Data()
			var ivData: Data?

			if let kStr = item["k"] as? String,
			   let (nodeKey, aesKey, iv) = MegaCrypto.decryptNodeKey(keyString: kStr, type: type, masterKey: mk) {
				nodeKeyData = Data(nodeKey)
				aesKeyData = Data(aesKey)
				if let ivBytes = iv {
					ivData = Data(ivBytes)
				}
				if let aStr = item["a"] as? String,
				   let decryptedName = MegaCrypto.decryptAttr(key: aesKey, dataString: aStr) {
					name = decryptedName
				}
			}

			let node = MegaNode(
				handle: handle,
				parentHandle: parentHandle,
				name: name,
				type: type,
				size: size,
				timestamp: ts,
				nodeKey: nodeKeyData,
				aesKey: aesKeyData,
				iv: ivData
			)
			newNodes[handle] = node
		}

		let finalNodes = newNodes
		let finalRoot = newRoot
		state.withLock {
			$0.nodesByHandle = finalNodes
			$0.rootHandle = finalRoot
		}
	}

	public func getRootNode() -> MegaNode? {
		state.withLock { state in
			guard let rh = state.rootHandle else { return nil }
			return state.nodesByHandle[rh]
		}
	}

	public func getNode(handle: String) -> MegaNode? {
		state.withLock { $0.nodesByHandle[handle] }
	}

	public func getChildren(of parentHandle: String) -> [MegaNode] {
		state.withLock { state in
			state.nodesByHandle.values.filter { $0.parentHandle == parentHandle }
		}
	}

	public func resolvePath(_ path: String) -> MegaNode? {
		let (rootNode, nodes) = state.withLock { state -> (MegaNode?, [String: MegaNode]) in
			guard let rh = state.rootHandle, let root = state.nodesByHandle[rh] else {
				return (nil, [:])
			}
			return (root, state.nodesByHandle)
		}
		guard let currentRoot = rootNode else { return nil }

		let clean = path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
		if clean.isEmpty {
			return currentRoot
		}

		let components = clean.components(separatedBy: "/").filter { !$0.isEmpty }
		var current = currentRoot

		for comp in components {
			let children = nodes.values.filter { $0.parentHandle == current.handle }
			guard let match = children.first(where: { $0.name == comp }) else {
				return nil
			}
			current = match
		}
		return current
	}

	// MARK: - Directory Operations

	public func createFolder(name: String, parentHandle: String) async throws -> MegaNode {
		let mk = try state.withLock { state -> [UInt8] in
			guard let masterKey = state.masterKey else { throw MegaClientError.sessionExpired }
			return masterKey
		}

		// Generate random 16 bytes for folder key
		var folderKey = [UInt8](repeating: 0, count: 16)
		_ = SecRandomCopyBytes(kSecRandomDefault, folderKey.count, &folderKey)

		guard let encAttr = MegaCrypto.encryptAttr(key: folderKey, name: name),
		      let encKey = MegaCrypto.aesEcbEncrypt(data: folderKey, key: mk) else {
			throw MegaClientError.cryptoError
		}

		let nodePayload: [String: Any] = [
			"h": "xxxxxxxx",
			"t": 1,
			"a": encAttr,
			"k": MegaCrypto.base64urlEncode(encKey)
		]

		let payload: [[String: Any]] = [
			[
				"a": "p",
				"t": parentHandle,
				"n": [nodePayload]
			]
		]

		let res = try await apiRequest(payload: payload)
		guard let dict = res.first as? [String: Any],
		      let fArray = dict["f"] as? [[String: Any]],
		      let createdNodeDict = fArray.first,
		      let handle = createdNodeDict["h"] as? String else {
			throw MegaClientError.invalidResponse
		}

		let createdNode = MegaNode(
			handle: handle,
			parentHandle: parentHandle,
			name: name,
			type: 1,
			size: 0,
			timestamp: Int64(Date().timeIntervalSince1970),
			nodeKey: Data(folderKey),
			aesKey: Data(folderKey),
			iv: nil
		)

		state.withLock {
			$0.nodesByHandle[handle] = createdNode
		}

		return createdNode
	}

	public func deleteNode(handle: String) async throws {
		_ = try await apiRequest(payload: [["a": "d", "n": handle]])
		state.withLock {
			_ = $0.nodesByHandle.removeValue(forKey: handle)
		}
	}

	public func moveNode(handle: String, toParentHandle: String) async throws {
		_ = try await apiRequest(payload: [["a": "m", "n": handle, "t": toParentHandle]])
		state.withLock { state in
			if let existing = state.nodesByHandle[handle] {
				let updated = MegaNode(
					handle: existing.handle,
					parentHandle: toParentHandle,
					name: existing.name,
					type: existing.type,
					size: existing.size,
					timestamp: existing.timestamp,
					nodeKey: existing.nodeKey,
					aesKey: existing.aesKey,
					iv: existing.iv
				)
				state.nodesByHandle[handle] = updated
			}
		}
	}

	// MARK: - File Download

	public func downloadFile(node: MegaNode, to localURL: URL, progress: Progress? = nil) async throws {
		guard node.isFile, let iv = node.iv else {
			throw MegaClientError.cryptoError
		}

		let res = try await apiRequest(payload: [["a": "g", "g": 1, "n": node.handle]])
		guard let dict = res.first as? [String: Any],
		      let downloadURLString = dict["g"] as? String,
		      let downloadURL = URL(string: downloadURLString) else {
			throw MegaClientError.invalidResponse
		}

		var req = URLRequest(url: downloadURL)
		req.httpMethod = "GET"

		let (tempURL, response) = try await session.download(for: req)
		guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
			throw MegaClientError.invalidResponse
		}

		let fileData = try Data(contentsOf: tempURL)
		try? FileManager.default.removeItem(at: tempURL)

		let baseIvBytes = [UInt8](iv)
		let keyBytes = [UInt8](node.aesKey)

		var decryptedData = Data()
		decryptedData.reserveCapacity(fileData.count)

		let chunkList = MegaCrypto.chunkSizes(fileSize: Int64(fileData.count))
		for chunk in chunkList {
			let start = Int(chunk.offset)
			let end = start + chunk.length
			let chunkCiphertext = [UInt8](fileData[start..<end])
			let ctrIv = MegaCrypto.makeCtrIv(baseIv: baseIvBytes, offset: chunk.offset)
			guard let chunkPlaintext = MegaCrypto.aesCtrCrypt(data: chunkCiphertext, key: keyBytes, iv: ctrIv) else {
				throw MegaClientError.cryptoError
			}
			decryptedData.append(contentsOf: chunkPlaintext)
			progress?.completedUnitCount += Int64(chunk.length)
		}

		try FileManager.default.createDirectory(at: localURL.deletingLastPathComponent(), withIntermediateDirectories: true)
		try decryptedData.write(to: localURL)
	}

	// MARK: - File Upload

	public func uploadFile(from localURL: URL, name: String, parentHandle: String, progress: Progress? = nil) async throws -> MegaNode {
		let mk = try state.withLock { state -> [UInt8] in
			guard let masterKey = state.masterKey else { throw MegaClientError.sessionExpired }
			return masterKey
		}

		let fileData = try Data(contentsOf: localURL)
		let fileSize = Int64(fileData.count)

		let res = try await apiRequest(payload: [["a": "u", "s": fileSize]])
		guard let dict = res.first as? [String: Any],
		      let uploadURLString = dict["p"] as? String,
		      let uploadURL = URL(string: uploadURLString) else {
			throw MegaClientError.invalidResponse
		}

		var randA32 = [UInt32](repeating: 0, count: 6)
		for i in 0..<6 {
			var val: UInt32 = 0
			_ = SecRandomCopyBytes(kSecRandomDefault, 4, &val)
			randA32[i] = val
		}

		let ivA32: [UInt32] = [randA32[4], randA32[5]]
		let baseIv = MegaCrypto.a32ToBytes(ivA32)

		var encryptedData = Data()
		encryptedData.reserveCapacity(fileData.count)

		let chunkList = MegaCrypto.chunkSizes(fileSize: fileSize)
		var chunkMacIv = baseIv

		let rawKeyA32: [UInt32] = [randA32[0], randA32[1], randA32[2], randA32[3]]
		let tempKeyBytes = MegaCrypto.a32ToBytes(rawKeyA32)

		var macA32: [UInt32] = [0, 0]
		for chunk in chunkList {
			let start = Int(chunk.offset)
			let end = start + chunk.length
			let chunkPlaintext = [UInt8](fileData[start..<end])

			let (chunkMac, nextIv) = MegaCrypto.computeChunkMac(chunkData: chunkPlaintext, key: tempKeyBytes, initialIv: chunkMacIv)
			chunkMacIv = nextIv
			let macBytesA32 = MegaCrypto.bytesToA32(chunkMac)
			if macBytesA32.count >= 2 {
				macA32[0] ^= macBytesA32[0]
				macA32[1] ^= macBytesA32[1]
			}
		}

		let fileAesKeyA32: [UInt32] = [
			randA32[0] ^ randA32[4],
			randA32[1] ^ randA32[5],
			randA32[2] ^ macA32[0],
			randA32[3] ^ macA32[1]
		]
		let fileAesKey = MegaCrypto.a32ToBytes(fileAesKeyA32)

		for chunk in chunkList {
			let start = Int(chunk.offset)
			let end = start + chunk.length
			let chunkPlaintext = [UInt8](fileData[start..<end])
			let ctrIv = MegaCrypto.makeCtrIv(baseIv: baseIv, offset: chunk.offset)
			guard let chunkCiphertext = MegaCrypto.aesCtrCrypt(data: chunkPlaintext, key: fileAesKey, iv: ctrIv) else {
				throw MegaClientError.cryptoError
			}
			encryptedData.append(contentsOf: chunkCiphertext)
			progress?.completedUnitCount += Int64(chunk.length)
		}

		var uploadReq = URLRequest(url: uploadURL)
		uploadReq.httpMethod = "POST"
		uploadReq.httpBody = encryptedData

		let (uploadResData, uploadResponse) = try await session.data(for: uploadReq)
		guard let uploadHttp = uploadResponse as? HTTPURLResponse, (200...299).contains(uploadHttp.statusCode),
		      let uploadHandle = String(data: uploadResData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) else {
			throw MegaClientError.invalidResponse
		}

		let fullA32: [UInt32] = [
			randA32[0], randA32[1], randA32[2], randA32[3],
			randA32[4], randA32[5], macA32[0], macA32[1]
		]
		let fullKeyBytes = MegaCrypto.a32ToBytes(fullA32)

		guard let encAttr = MegaCrypto.encryptAttr(key: fileAesKey, name: name),
		      let encKey = MegaCrypto.aesEcbEncrypt(data: fullKeyBytes, key: mk) else {
			throw MegaClientError.cryptoError
		}

		let commitNodePayload: [String: Any] = [
			"h": uploadHandle,
			"t": 0,
			"a": encAttr,
			"k": MegaCrypto.base64urlEncode(encKey)
		]

		let commitPayload: [[String: Any]] = [
			[
				"a": "p",
				"t": parentHandle,
				"n": [commitNodePayload]
			]
		]

		let commitRes = try await apiRequest(payload: commitPayload)
		guard let commitDict = commitRes.first as? [String: Any],
		      let fArray = commitDict["f"] as? [[String: Any]],
		      let nodeDict = fArray.first,
		      let finalHandle = nodeDict["h"] as? String else {
			throw MegaClientError.invalidResponse
		}

		let createdNode = MegaNode(
			handle: finalHandle,
			parentHandle: parentHandle,
			name: name,
			type: 0,
			size: fileSize,
			timestamp: Int64(Date().timeIntervalSince1970),
			nodeKey: Data(fullKeyBytes),
			aesKey: Data(fileAesKey),
			iv: Data(baseIv)
		)

		state.withLock {
			$0.nodesByHandle[finalHandle] = createdNode
		}

		return createdNode
	}

	// MARK: - Low-Level API Request

	private func apiRequest(payload: [[String: Any]]) async throws -> [Any] {
		let (seq, currentSid) = state.withLock { state -> (Int, String?) in
			state.sequenceNumber += 1
			return (state.sequenceNumber, state.sessionId)
		}

		var urlComponents = URLComponents(url: baseURL, resolvingAgainstBaseURL: false)!
		var queryItems: [URLQueryItem] = [URLQueryItem(name: "id", value: "\(seq)")]
		if let sid = currentSid {
			queryItems.append(URLQueryItem(name: "sid", value: sid))
		}
		urlComponents.queryItems = queryItems

		guard let requestURL = urlComponents.url else {
			throw MegaClientError.invalidResponse
		}

		var request = URLRequest(url: requestURL)
		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Content-Type")
		request.httpBody = try JSONSerialization.data(withJSONObject: payload)

		let (data, response): (Data, URLResponse)
		do {
			(data, response) = try await session.data(for: request)
		} catch {
			throw MegaClientError.networkError(error.localizedDescription)
		}

		guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
			throw MegaClientError.invalidResponse
		}

		if let intError = try? JSONDecoder().decode(Int.self, from: data), intError < 0 {
			throw MegaClientError.apiError(code: intError)
		}

		let json = try JSONSerialization.jsonObject(with: data)
		if let array = json as? [Any] {
			if let firstInt = array.first as? Int, firstInt < 0 {
				throw MegaClientError.apiError(code: firstInt)
			}
			return array
		} else if let dict = json as? [String: Any] {
			return [dict]
		}

		throw MegaClientError.invalidResponse
	}
}
