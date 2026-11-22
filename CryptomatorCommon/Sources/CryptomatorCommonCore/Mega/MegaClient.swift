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
		var childrenByParent: [String: [String]] = [:]
		var pathToHandleCache: [String: String] = [:]
		var rootHandle: String?
		var lastFetchTime: Date?
	}

	private let baseURL = URL(string: "https://g.api.mega.co.nz/cs")!
	private let session: URLSession
	private let state = OSAllocatedUnfairLock(initialState: State())

	public init(session: URLSession? = nil) {
		if let s = session {
			self.session = s
		} else {
			let config = URLSessionConfiguration.default
			config.timeoutIntervalForRequest = 45
			config.timeoutIntervalForResource = 3600
			config.waitsForConnectivity = true
			self.session = URLSession(configuration: config)
		}
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
			$0.childrenByParent.removeAll()
			$0.pathToHandleCache.removeAll()
			$0.rootHandle = nil
			$0.lastFetchTime = nil
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

	public func fetchFileSystem(force: Bool = false) async throws {
		let (mk, shouldFetch, existingNodes) = state.withLock { state -> ([UInt8]?, Bool, [String: MegaNode]) in
			guard let masterKey = state.masterKey else { return (nil, false, [:]) }
			if !force, let lastFetch = state.lastFetchTime, !state.nodesByHandle.isEmpty, Date().timeIntervalSince(lastFetch) < 15.0 {
				return (masterKey, false, state.nodesByHandle)
			}
			return (masterKey, true, state.nodesByHandle)
		}

		guard let masterKey = mk else {
			throw MegaClientError.sessionExpired
		}

		if !shouldFetch {
			return
		}

		let res = try await apiRequest(payload: [["a": "f", "c": 1]])
		guard let dict = res.first as? [String: Any],
		      let fArray = dict["f"] as? [[String: Any]] else {
			throw MegaClientError.invalidResponse
		}

		var newNodes: [String: MegaNode] = [:]
		var newChildren: [String: [String]] = [:]
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

			if let ph = parentHandle {
				newChildren[ph, default: []].append(handle)
			}

			if let existing = existingNodes[handle], existing.timestamp == ts, existing.type == type, !existing.name.isEmpty {
				newNodes[handle] = existing
				continue
			}

			var name = ""
			var nodeKeyData = Data()
			var aesKeyData = Data()
			var ivData: Data?

			if let kStr = item["k"] as? String,
			   let (nodeKey, aesKey, iv) = MegaCrypto.decryptNodeKey(keyString: kStr, type: type, masterKey: masterKey) {
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
		let finalChildren = newChildren
		let finalRoot = newRoot
		let now = Date()

		state.withLock {
			$0.nodesByHandle = finalNodes
			$0.childrenByParent = finalChildren
			$0.rootHandle = finalRoot
			$0.lastFetchTime = now
			$0.pathToHandleCache.removeAll()
		}
	}

	public func invalidateCache() {
		state.withLock {
			$0.lastFetchTime = nil
			$0.pathToHandleCache.removeAll()
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
			guard let handles = state.childrenByParent[parentHandle] else {
				return []
			}
			return handles.compactMap { state.nodesByHandle[$0] }
		}
	}

	public func resolvePath(_ path: String) -> MegaNode? {
		let clean = path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))

		let (rootNode, cachedHandle, nodes, childrenByParent) = state.withLock { state -> (MegaNode?, String?, [String: MegaNode], [String: [String]]) in
			guard let rh = state.rootHandle, let root = state.nodesByHandle[rh] else {
				return (nil, nil, [:], [:])
			}
			return (root, state.pathToHandleCache[clean], state.nodesByHandle, state.childrenByParent)
		}

		guard let currentRoot = rootNode else { return nil }
		if clean.isEmpty {
			return currentRoot
		}

		if let ch = cachedHandle, let node = nodes[ch] {
			return node
		}

		let components = clean.components(separatedBy: "/").filter { !$0.isEmpty }
		var current = currentRoot
		var currentPath = ""
		var resolvedPaths: [(String, String)] = []

		for comp in components {
			currentPath = currentPath.isEmpty ? comp : "\(currentPath)/\(comp)"
			guard let childHandles = childrenByParent[current.handle] else {
				return nil
			}
			guard let matchHandle = childHandles.first(where: { nodes[$0]?.name == comp }),
			      let matchNode = nodes[matchHandle] else {
				return nil
			}
			current = matchNode
			resolvedPaths.append((currentPath, matchNode.handle))
		}

		let finalResolved = resolvedPaths
		state.withLock { state in
			for (p, h) in finalResolved {
				state.pathToHandleCache[p] = h
			}
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
			$0.childrenByParent[parentHandle, default: []].append(handle)
			$0.pathToHandleCache.removeAll()
		}

		return createdNode
	}

	public func deleteNode(handle: String) async throws {
		_ = try await apiRequest(payload: [["a": "d", "n": handle]])
		state.withLock {
			if let parent = $0.nodesByHandle[handle]?.parentHandle {
				$0.childrenByParent[parent]?.removeAll(where: { $0 == handle })
			}
			_ = $0.nodesByHandle.removeValue(forKey: handle)
			$0.pathToHandleCache.removeAll()
		}
	}

	public func moveNode(handle: String, toParentHandle: String) async throws {
		_ = try await apiRequest(payload: [["a": "m", "n": handle, "t": toParentHandle]])
		state.withLock { state in
			if let existing = state.nodesByHandle[handle] {
				if let oldParent = existing.parentHandle {
					state.childrenByParent[oldParent]?.removeAll(where: { $0 == handle })
				}
				state.childrenByParent[toParentHandle, default: []].append(handle)
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
				state.pathToHandleCache.removeAll()
			}
		}
	}

	public func renameNode(handle: String, newName: String) async throws {
		let node = try state.withLock { state -> MegaNode in
			guard let n = state.nodesByHandle[handle] else { throw MegaClientError.itemNotFound }
			return n
		}

		guard let encAttr = MegaCrypto.encryptAttr(key: [UInt8](node.aesKey), name: newName) else {
			throw MegaClientError.cryptoError
		}

		_ = try await apiRequest(payload: [["a": "a", "n": handle, "at": encAttr]])
		state.withLock { state in
			if let existing = state.nodesByHandle[handle] {
				let updated = MegaNode(
					handle: existing.handle,
					parentHandle: existing.parentHandle,
					name: newName,
					type: existing.type,
					size: existing.size,
					timestamp: existing.timestamp,
					nodeKey: existing.nodeKey,
					aesKey: existing.aesKey,
					iv: existing.iv
				)
				state.nodesByHandle[handle] = updated
				state.pathToHandleCache.removeAll()
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
		      let downloadURLString = dict["g"] as? String else {
			throw MegaClientError.invalidResponse
		}

		var urlStr = downloadURLString
		if urlStr.hasPrefix("http://") {
			urlStr = "https://" + urlStr.dropFirst(7)
		}
		guard let downloadURL = URL(string: urlStr) else {
			throw MegaClientError.invalidResponse
		}

		var req = URLRequest(url: downloadURL)
		req.httpMethod = "GET"

		let (tempURL, response) = try await session.download(for: req)
		guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
			try? FileManager.default.removeItem(at: tempURL)
			throw MegaClientError.invalidResponse
		}

		defer {
			try? FileManager.default.removeItem(at: tempURL)
		}

		try FileManager.default.createDirectory(at: localURL.deletingLastPathComponent(), withIntermediateDirectories: true)
		if FileManager.default.fileExists(atPath: localURL.path) {
			try? FileManager.default.removeItem(at: localURL)
		}
		FileManager.default.createFile(atPath: localURL.path, contents: nil, attributes: nil)

		let readHandle = try FileHandle(forReadingFrom: tempURL)
		defer { try? readHandle.close() }

		let writeHandle = try FileHandle(forWritingTo: localURL)
		defer { try? writeHandle.close() }

		let fileSize = (try? FileManager.default.attributesOfItem(atPath: tempURL.path)[.size] as? Int64) ?? 0
		progress?.totalUnitCount = fileSize
		let chunkList = MegaCrypto.chunkSizes(fileSize: fileSize)
		let baseIvBytes = [UInt8](iv)
		let keyBytes = [UInt8](node.aesKey)

		for chunk in chunkList {
			try Task.checkCancellation()
			try autoreleasepool {
				try readHandle.seek(toOffset: UInt64(chunk.offset))
				guard let chunkData = try readHandle.read(upToCount: chunk.length), !chunkData.isEmpty else {
					throw MegaClientError.invalidResponse
				}
				let chunkCiphertext = [UInt8](chunkData)
				let ctrIv = MegaCrypto.makeCtrIv(baseIv: baseIvBytes, offset: chunk.offset)
				guard let chunkPlaintext = MegaCrypto.aesCtrCrypt(data: chunkCiphertext, key: keyBytes, iv: ctrIv) else {
					throw MegaClientError.cryptoError
				}
				try writeHandle.write(contentsOf: Data(chunkPlaintext))
				progress?.completedUnitCount += Int64(chunk.length)
			}
		}
	}

	// MARK: - File Upload

	public func uploadFile(from localURL: URL, name: String, parentHandle: String, progress: Progress? = nil) async throws -> MegaNode {
		let mk = try state.withLock { state -> [UInt8] in
			guard let masterKey = state.masterKey else { throw MegaClientError.sessionExpired }
			return masterKey
		}

		let fileSize = (try? FileManager.default.attributesOfItem(atPath: localURL.path)[.size] as? Int64) ?? 0
		progress?.totalUnitCount = fileSize

		let res = try await apiRequest(payload: [["a": "u", "s": fileSize]])
		guard let dict = res.first as? [String: Any],
		      let uploadURLString = dict["p"] as? String else {
			throw MegaClientError.invalidResponse
		}

		var urlStr = uploadURLString
		if urlStr.hasPrefix("http://") {
			urlStr = "https://" + urlStr.dropFirst(7)
		}
		guard let uploadURL = URL(string: urlStr) else {
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

		let chunkList = MegaCrypto.chunkSizes(fileSize: fileSize)
		var chunkMacIv = baseIv

		let rawKeyA32: [UInt32] = [randA32[0], randA32[1], randA32[2], randA32[3]]
		let tempKeyBytes = MegaCrypto.a32ToBytes(rawKeyA32)

		let readHandle = try FileHandle(forReadingFrom: localURL)
		defer { try? readHandle.close() }

		var macA32: [UInt32] = [0, 0]
		for chunk in chunkList {
			try Task.checkCancellation()
			try autoreleasepool {
				try readHandle.seek(toOffset: UInt64(chunk.offset))
				guard let chunkData = try readHandle.read(upToCount: chunk.length) else {
					throw MegaClientError.invalidResponse
				}
				let chunkPlaintext = [UInt8](chunkData)
				let (chunkMac, nextIv) = MegaCrypto.computeChunkMac(chunkData: chunkPlaintext, key: tempKeyBytes, initialIv: chunkMacIv)
				chunkMacIv = nextIv
				let macBytesA32 = MegaCrypto.bytesToA32(chunkMac)
				if macBytesA32.count >= 2 {
					macA32[0] ^= macBytesA32[0]
					macA32[1] ^= macBytesA32[1]
				}
			}
		}

		let fileAesKeyA32: [UInt32] = [
			randA32[0] ^ randA32[4],
			randA32[1] ^ randA32[5],
			randA32[2] ^ macA32[0],
			randA32[3] ^ macA32[1]
		]
		let fileAesKey = MegaCrypto.a32ToBytes(fileAesKeyA32)

		let tempEncryptedURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
		FileManager.default.createFile(atPath: tempEncryptedURL.path, contents: nil, attributes: nil)
		let encWriteHandle = try FileHandle(forWritingTo: tempEncryptedURL)
		defer {
			try? encWriteHandle.close()
			try? FileManager.default.removeItem(at: tempEncryptedURL)
		}

		for chunk in chunkList {
			try Task.checkCancellation()
			try autoreleasepool {
				try readHandle.seek(toOffset: UInt64(chunk.offset))
				guard let chunkData = try readHandle.read(upToCount: chunk.length) else {
					throw MegaClientError.invalidResponse
				}
				let chunkPlaintext = [UInt8](chunkData)
				let ctrIv = MegaCrypto.makeCtrIv(baseIv: baseIv, offset: chunk.offset)
				guard let chunkCiphertext = MegaCrypto.aesCtrCrypt(data: chunkPlaintext, key: fileAesKey, iv: ctrIv) else {
					throw MegaClientError.cryptoError
				}
				try encWriteHandle.write(contentsOf: Data(chunkCiphertext))
				progress?.completedUnitCount += Int64(chunk.length)
			}
		}
		try encWriteHandle.close()

		var uploadReq = URLRequest(url: uploadURL)
		uploadReq.httpMethod = "POST"

		let (uploadResData, uploadResponse) = try await session.upload(for: uploadReq, fromFile: tempEncryptedURL)
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
			$0.childrenByParent[parentHandle, default: []].append(finalHandle)
			$0.pathToHandleCache.removeAll()
		}

		return createdNode
	}

	// MARK: - Low-Level API Request

	private func apiRequest(payload: [[String: Any]]) async throws -> [Any] {
		var lastError: Error = MegaClientError.invalidResponse
		for attempt in 0..<3 {
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

			let data: Data
			let response: URLResponse
			do {
				(data, response) = try await session.data(for: request)
			} catch {
				lastError = MegaClientError.networkError(error.localizedDescription)
				if attempt < 2 {
					try? await Task.sleep(nanoseconds: UInt64(500_000_000 * (attempt + 1)))
					continue
				}
				throw lastError
			}

			guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
				lastError = MegaClientError.invalidResponse
				if attempt < 2 {
					try? await Task.sleep(nanoseconds: UInt64(500_000_000 * (attempt + 1)))
					continue
				}
				throw lastError
			}

			if let intError = try? JSONDecoder().decode(Int.self, from: data), intError < 0 {
				if intError == -3 && attempt < 2 { // EAGAIN - temporary congestion retry
					try? await Task.sleep(nanoseconds: UInt64(500_000_000 * (attempt + 1)))
					continue
				}
				throw MegaClientError.apiError(code: intError)
			}

			let json = try JSONSerialization.jsonObject(with: data)
			if let array = json as? [Any] {
				if let firstInt = array.first as? Int, firstInt < 0 {
					if firstInt == -3 && attempt < 2 { // EAGAIN - temporary congestion retry
						try? await Task.sleep(nanoseconds: UInt64(500_000_000 * (attempt + 1)))
						continue
					}
					throw MegaClientError.apiError(code: firstInt)
				}
				return array
			} else if let dict = json as? [String: Any] {
				return [dict]
			}
			break
		}
		throw lastError
	}
}
