//
//  MegaCloudProvider.swift
//  CryptomatorCommonCore
//

import CryptomatorCloudAccessCore
import Foundation

public final class MegaCloudProvider: CloudProvider, @unchecked Sendable {
	public let client: MegaClient
	public let credential: MegaCredential

	public init(credential: MegaCredential, client: MegaClient = MegaClient()) throws {
		self.credential = credential
		self.client = client
		try client.fastLogin(sessionToken: credential.sessionToken)
	}

	private func ensureFileSystemFresh(force: Bool = false) async throws {
		do {
			try await client.fetchFileSystem(force: force)
		} catch let error as MegaClientError {
			throw mapError(error, cloudPath: CloudPath("/"))
		}
	}

	private func mapError(_ error: Error, cloudPath: CloudPath) -> Error {
		if let megaError = error as? MegaClientError {
			switch megaError {
			case .invalidCredentials, .sessionExpired:
				return CloudProviderError.unauthorized
			case .itemNotFound:
				return CloudProviderError.itemNotFound
			case .itemAlreadyExists:
				return CloudProviderError.itemAlreadyExists
			case .quotaExceeded:
				return CloudProviderError.quotaInsufficient
			case .networkError:
				return CloudProviderError.noInternetConnection
			case let .apiError(code):
				switch code {
				case -9:
					return CloudProviderError.itemNotFound
				case -11, -15, -16:
					return CloudProviderError.unauthorized
				case -12:
					return CloudProviderError.itemAlreadyExists
				case -17:
					return CloudProviderError.quotaInsufficient
				case -18:
					return CloudProviderError.noInternetConnection
				default:
					return CloudProviderError.itemNotFound
				}
			default:
				return CloudProviderError.itemNotFound
			}
		}
		return error
	}

	// MARK: - CloudProvider Protocol Implementation

	@concurrent
	public func fetchItemMetadata(at cloudPath: CloudPath) async throws -> CloudItemMetadata {
		try Task.checkCancellation()
		try await ensureFileSystemFresh()
		guard let node = client.resolvePath(cloudPath.path) else {
			throw CloudProviderError.itemNotFound
		}
		let itemType: CloudItemType = node.isDirectory ? .folder : .file
		let lastModified = node.timestamp > 0 ? Date(timeIntervalSince1970: TimeInterval(node.timestamp)) : nil
		let name = (node.type == 2 || node.name.isEmpty) ? (cloudPath.lastPathComponent.isEmpty ? "/" : cloudPath.lastPathComponent) : node.name
		return CloudItemMetadata(
			name: name,
			cloudPath: cloudPath,
			itemType: itemType,
			lastModifiedDate: lastModified,
			size: node.isFile ? Int(node.size) : nil
		)
	}

	@concurrent
	public func fetchItemList(forFolderAt cloudPath: CloudPath, withPageToken pageToken: String?) async throws -> CloudItemList {
		try Task.checkCancellation()
		guard pageToken == nil else {
			throw CloudProviderError.pageTokenInvalid
		}
		try await ensureFileSystemFresh()
		guard let parentNode = client.resolvePath(cloudPath.path) else {
			throw CloudProviderError.itemNotFound
		}
		guard parentNode.isDirectory else {
			throw CloudProviderError.itemTypeMismatch
		}
		let children = client.getChildren(of: parentNode.handle)
		let items: [CloudItemMetadata] = children.map { child in
			let childPath = cloudPath.appendingPathComponent(child.name)
			let itemType: CloudItemType = child.isDirectory ? .folder : .file
			let lastModified = child.timestamp > 0 ? Date(timeIntervalSince1970: TimeInterval(child.timestamp)) : nil
			return CloudItemMetadata(
				name: child.name,
				cloudPath: childPath,
				itemType: itemType,
				lastModifiedDate: lastModified,
				size: child.isFile ? Int(child.size) : nil
			)
		}
		return CloudItemList(items: items, nextPageToken: nil)
	}

	@concurrent
	public func downloadFile(
		from cloudPath: CloudPath,
		to localURL: URL,
		progress: Progress?,
		onTaskCreation: (@concurrent @Sendable (URLSessionDownloadTask) async -> Void)?
	) async throws -> CloudItemMetadata {
		precondition(localURL.isFileURL)
		try Task.checkCancellation()

		if FileManager.default.fileExists(atPath: localURL.path) {
			throw CloudProviderError.itemAlreadyExists
		}

		try await ensureFileSystemFresh()
		guard let node = client.resolvePath(cloudPath.path) else {
			throw CloudProviderError.itemNotFound
		}
		guard node.isFile else {
			throw CloudProviderError.itemTypeMismatch
		}

		let stagingURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
		defer {
			try? FileManager.default.removeItem(at: stagingURL)
		}

		do {
			try await client.downloadFile(node: node, to: stagingURL, progress: progress)
			try Task.checkCancellation()

			try FileManager.default.createDirectory(at: localURL.deletingLastPathComponent(), withIntermediateDirectories: true)
			do {
				try FileManager.default.moveItem(at: stagingURL, to: localURL)
			} catch CocoaError.fileWriteFileExists {
				throw CloudProviderError.itemAlreadyExists
			}

			let lastModified = node.timestamp > 0 ? Date(timeIntervalSince1970: TimeInterval(node.timestamp)) : nil
			return CloudItemMetadata(
				name: node.name,
				cloudPath: cloudPath,
				itemType: .file,
				lastModifiedDate: lastModified,
				size: Int(node.size)
			)
		} catch {
			throw mapError(error, cloudPath: cloudPath)
		}
	}

	@concurrent
	public func uploadFile(
		from localURL: URL,
		to cloudPath: CloudPath,
		replaceExisting: Bool,
		progress: Progress?,
		onTaskCreation: (@concurrent @Sendable (URLSessionUploadTask) async -> Void)?
	) async throws -> CloudItemMetadata {
		precondition(localURL.isFileURL)
		try Task.checkCancellation()

		var isDirectory: ObjCBool = false
		let fileExists = FileManager.default.fileExists(atPath: localURL.path, isDirectory: &isDirectory)
		if !fileExists {
			throw CloudProviderError.itemNotFound
		}
		if isDirectory.boolValue {
			throw CloudProviderError.itemTypeMismatch
		}

		try await ensureFileSystemFresh()
		let parentPath = cloudPath.deletingLastPathComponent()
		guard let parentNode = client.resolvePath(parentPath.path) else {
			throw CloudProviderError.parentFolderDoesNotExist
		}
		guard parentNode.isDirectory else {
			throw CloudProviderError.parentFolderDoesNotExist
		}

		let fileName = cloudPath.lastPathComponent
		let existingNode = client.getChildren(of: parentNode.handle).first(where: { $0.name == fileName })
		if let existing = existingNode {
			if existing.isDirectory {
				throw CloudProviderError.itemAlreadyExists
			}
			if !replaceExisting {
				throw CloudProviderError.itemAlreadyExists
			}
		}

		do {
			let createdNode = try await client.uploadFile(from: localURL, name: fileName, parentHandle: parentNode.handle, progress: progress)
			if replaceExisting, let old = existingNode {
				try? await client.deleteNode(handle: old.handle)
			}
			let lastModified = createdNode.timestamp > 0 ? Date(timeIntervalSince1970: TimeInterval(createdNode.timestamp)) : nil
			return CloudItemMetadata(
				name: createdNode.name,
				cloudPath: cloudPath,
				itemType: .file,
				lastModifiedDate: lastModified,
				size: Int(createdNode.size)
			)
		} catch {
			throw mapError(error, cloudPath: cloudPath)
		}
	}

	@concurrent
	public func createFolder(at cloudPath: CloudPath) async throws {
		try Task.checkCancellation()
		try await ensureFileSystemFresh()
		let folderName = cloudPath.lastPathComponent
		guard !folderName.isEmpty else {
			throw CloudProviderError.itemAlreadyExists
		}
		let parentPath = cloudPath.deletingLastPathComponent()
		guard let parentNode = client.resolvePath(parentPath.path) else {
			throw CloudProviderError.parentFolderDoesNotExist
		}
		guard parentNode.isDirectory else {
			throw CloudProviderError.parentFolderDoesNotExist
		}

		if client.getChildren(of: parentNode.handle).contains(where: { $0.name == folderName }) {
			throw CloudProviderError.itemAlreadyExists
		}

		do {
			_ = try await client.createFolder(name: folderName, parentHandle: parentNode.handle)
		} catch {
			throw mapError(error, cloudPath: cloudPath)
		}
	}

	@concurrent
	public func deleteFile(at cloudPath: CloudPath) async throws {
		try Task.checkCancellation()
		try await ensureFileSystemFresh()
		guard let node = client.resolvePath(cloudPath.path) else {
			throw CloudProviderError.itemNotFound
		}
		guard node.isFile else {
			throw CloudProviderError.itemTypeMismatch
		}
		do {
			try await client.deleteNode(handle: node.handle)
		} catch {
			throw mapError(error, cloudPath: cloudPath)
		}
	}

	@concurrent
	public func deleteFolder(at cloudPath: CloudPath) async throws {
		try Task.checkCancellation()
		try await ensureFileSystemFresh()
		guard let node = client.resolvePath(cloudPath.path) else {
			throw CloudProviderError.itemNotFound
		}
		guard node.isDirectory else {
			throw CloudProviderError.itemTypeMismatch
		}
		do {
			try await client.deleteNode(handle: node.handle)
		} catch {
			throw mapError(error, cloudPath: cloudPath)
		}
	}

	@concurrent
	public func moveFile(from sourceCloudPath: CloudPath, to targetCloudPath: CloudPath) async throws {
		try Task.checkCancellation()
		try await ensureFileSystemFresh()
		guard let sourceNode = client.resolvePath(sourceCloudPath.path) else {
			throw CloudProviderError.itemNotFound
		}
		guard sourceNode.isFile else {
			throw CloudProviderError.itemTypeMismatch
		}

		let targetParentPath = targetCloudPath.deletingLastPathComponent()
		guard let targetParentNode = client.resolvePath(targetParentPath.path) else {
			throw CloudProviderError.parentFolderDoesNotExist
		}
		guard targetParentNode.isDirectory else {
			throw CloudProviderError.parentFolderDoesNotExist
		}

		let targetName = targetCloudPath.lastPathComponent
		if client.getChildren(of: targetParentNode.handle).contains(where: { $0.name == targetName }) {
			throw CloudProviderError.itemAlreadyExists
		}

		do {
			if sourceNode.parentHandle != targetParentNode.handle {
				try await client.moveNode(handle: sourceNode.handle, toParentHandle: targetParentNode.handle)
			}
			if sourceNode.name != targetName {
				try await client.renameNode(handle: sourceNode.handle, newName: targetName)
			}
		} catch {
			throw mapError(error, cloudPath: sourceCloudPath)
		}
	}

	@concurrent
	public func moveFolder(from sourceCloudPath: CloudPath, to targetCloudPath: CloudPath) async throws {
		try Task.checkCancellation()
		try await ensureFileSystemFresh()
		guard let sourceNode = client.resolvePath(sourceCloudPath.path) else {
			throw CloudProviderError.itemNotFound
		}
		guard sourceNode.isDirectory else {
			throw CloudProviderError.itemTypeMismatch
		}

		let targetParentPath = targetCloudPath.deletingLastPathComponent()
		guard let targetParentNode = client.resolvePath(targetParentPath.path) else {
			throw CloudProviderError.parentFolderDoesNotExist
		}
		guard targetParentNode.isDirectory else {
			throw CloudProviderError.parentFolderDoesNotExist
		}

		let targetName = targetCloudPath.lastPathComponent
		if client.getChildren(of: targetParentNode.handle).contains(where: { $0.name == targetName }) {
			throw CloudProviderError.itemAlreadyExists
		}

		do {
			if sourceNode.parentHandle != targetParentNode.handle {
				try await client.moveNode(handle: sourceNode.handle, toParentHandle: targetParentNode.handle)
			}
			if sourceNode.name != targetName {
				try await client.renameNode(handle: sourceNode.handle, newName: targetName)
			}
		} catch {
			throw mapError(error, cloudPath: sourceCloudPath)
		}
	}
}
