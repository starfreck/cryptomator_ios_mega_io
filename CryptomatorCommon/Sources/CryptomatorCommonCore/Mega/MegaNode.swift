//
//  MegaNode.swift
//  CryptomatorCommonCore
//

import Foundation

public struct MegaNode: Sendable {
	public let handle: String
	public let parentHandle: String?
	public let name: String
	public let type: Int // 0: file, 1: folder, 2: root, 3: inbox, 4: trash
	public let size: Int64
	public let timestamp: Int64
	public let nodeKey: Data
	public let aesKey: Data
	public let iv: Data?

	public var isDirectory: Bool {
		return type == 1 || type == 2
	}

	public var isFile: Bool {
		return type == 0
	}

	public init(
		handle: String,
		parentHandle: String?,
		name: String,
		type: Int,
		size: Int64,
		timestamp: Int64,
		nodeKey: Data,
		aesKey: Data,
		iv: Data?
	) {
		self.handle = handle
		self.parentHandle = parentHandle
		self.name = name
		self.type = type
		self.size = size
		self.timestamp = timestamp
		self.nodeKey = nodeKey
		self.aesKey = aesKey
		self.iv = iv
	}
}
