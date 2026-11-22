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
			default:
				return CloudProviderError.itemNotFound
			}
		}
		return error
	}

	// MARK: - CloudProvider Protocol Implementation

	public func fetchItemMetadata(at cloudPath: CloudPath) async throws -> CloudItemMetadata {
		try await ensureFileSystemFresh()
		guard let node = client.resolvePath(cloudPath.path) else {
			throw CloudProviderError.itemNotFound
		}
		let itemType: CloudItemType = node.isDirectory ? .folder : .file
		let lastModified = node.timestamp > 0 ? Date(timeIntervalSince1970: TimeInterval(node.timestamp)) : nil
		return CloudItemMetadata(
			name: node.name.isEmpty ? cloudPath.lastPathComponent : node.name,
			cloudPath: cloudPath,
			itemType: itemType,
			lastModifiedDate: lastModified,
			size: node.isFile ? Int(node.size) : nil
		)
	}

	public func fetchItemList(forFolderAt cloudPath: CloudPath, withPageToken pageToken: String?) async throws -> CloudItemList {
		try await ensureFileSystemFresh()
		guard let parentNode = client.resolvePath(cloudPath.path) else {
			throw CloudProviderError.itemNotFound
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

	public func downloadFile(
		from cloudPath: CloudPath,
		to localURL: URL,
		progress: Progress?,
		onTaskCreation: (@concurrent @Sendable (URLSessionDownloadTask) async -> Void)?
	) async throws -> CloudItemMetadata {
		try await ensureFileSystemFresh()
		guard let node = client.resolvePath(cloudPath.path) else {
			throw CloudProviderError.itemNotFound
		}
		do {
			try await client.downloadFile(node: node, to: localURL, progress: progress)
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

	public func uploadFile(
		from localURL: URL,
		to cloudPath: CloudPath,
		replaceExisting: Bool,
		progress: Progress?,
		onTaskCreation: (@concurrent @Sendable (URLSessionUploadTask) async -> Void)?
	) async throws -> CloudItemMetadata {
		try await ensureFileSystemFresh()
		let parentPath = cloudPath.deletingLastPathComponent()
		guard let parentNode = client.resolvePath(parentPath.path) else {
			throw CloudProviderError.parentFolderDoesNotExist
		}

		let fileName = cloudPath.lastPathComponent
		if let existing = client.getChildren(of: parentNode.handle).first(where: { $0.name == fileName }) {
			if replaceExisting {
				try await client.deleteNode(handle: existing.handle)
			} else {
				throw CloudProviderError.itemAlreadyExists
			}
		}

		do {
			let createdNode = try await client.uploadFile(from: localURL, name: fileName, parentHandle: parentNode.handle, progress: progress)
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

	public func createFolder(at cloudPath: CloudPath) async throws {
		try await ensureFileSystemFresh()
		let parentPath = cloudPath.deletingLastPathComponent()
		guard let parentNode = client.resolvePath(parentPath.path) else {
			throw CloudProviderError.parentFolderDoesNotExist
		}

		let folderName = cloudPath.lastPathComponent
		if client.getChildren(of: parentNode.handle).contains(where: { $0.name == folderName }) {
			throw CloudProviderError.itemAlreadyExists
		}

		do {
			_ = try await client.createFolder(name: folderName, parentHandle: parentNode.handle)
		} catch {
			throw mapError(error, cloudPath: cloudPath)
		}
	}

	public func deleteFile(at cloudPath: CloudPath) async throws {
		try await deleteItem(at: cloudPath)
	}

	public func deleteFolder(at cloudPath: CloudPath) async throws {
		try await deleteItem(at: cloudPath)
	}

	private func deleteItem(at cloudPath: CloudPath) async throws {
		try await ensureFileSystemFresh()
		guard let node = client.resolvePath(cloudPath.path) else {
			throw CloudProviderError.itemNotFound
		}
		do {
			try await client.deleteNode(handle: node.handle)
		} catch {
			throw mapError(error, cloudPath: cloudPath)
		}
	}

	public func moveFile(from sourceCloudPath: CloudPath, to targetCloudPath: CloudPath) async throws {
		try await moveItem(from: sourceCloudPath, to: targetCloudPath)
	}

	public func moveFolder(from sourceCloudPath: CloudPath, to targetCloudPath: CloudPath) async throws {
		try await moveItem(from: sourceCloudPath, to: targetCloudPath)
	}

	private func moveItem(from sourceCloudPath: CloudPath, to targetCloudPath: CloudPath) async throws {
		try await ensureFileSystemFresh()
		guard let sourceNode = client.resolvePath(sourceCloudPath.path) else {
			throw CloudProviderError.itemNotFound
		}
		let targetParentPath = targetCloudPath.deletingLastPathComponent()
		guard let targetParentNode = client.resolvePath(targetParentPath.path) else {
			throw CloudProviderError.parentFolderDoesNotExist
		}
		do {
			try await client.moveNode(handle: sourceNode.handle, toParentHandle: targetParentNode.handle)
		} catch {
			throw mapError(error, cloudPath: sourceCloudPath)
		}
	}
}
