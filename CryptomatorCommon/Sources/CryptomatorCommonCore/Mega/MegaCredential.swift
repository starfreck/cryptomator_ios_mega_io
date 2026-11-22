//
//  MegaCredential.swift
//  CryptomatorCommonCore
//

import Foundation

public struct MegaCredential: Codable, Equatable, Sendable {
	public let identifier: String
	public let email: String
	public let sessionToken: String
	public let masterKey: Data
	public var userHandle: String?
	public var rootHandle: String?
	public var inboxHandle: String?
	public var trashHandle: String?

	public init(identifier: String, email: String, sessionToken: String, masterKey: Data = Data(), userHandle: String? = nil, rootHandle: String? = nil, inboxHandle: String? = nil, trashHandle: String? = nil) {
		self.identifier = identifier
		self.email = email
		self.sessionToken = sessionToken
		self.masterKey = masterKey
		self.userHandle = userHandle
		self.rootHandle = rootHandle
		self.inboxHandle = inboxHandle
		self.trashHandle = trashHandle
	}
}
