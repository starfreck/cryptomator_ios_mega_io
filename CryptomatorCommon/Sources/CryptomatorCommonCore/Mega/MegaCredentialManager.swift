//
//  MegaCredentialManager.swift
//  CryptomatorCommonCore
//

import CocoaLumberjackSwift
import CryptomatorCloudAccessCore
import Dependencies
import Foundation
import GRDB

public protocol MegaCredentialManagerType: Sendable {
	func save(credential: MegaCredential, displayName: String) throws
	func removeCredential(with identifier: String) throws
	func getDisplayName(for identifier: String) throws -> String?
	func getCredential(with identifier: String) -> MegaCredential?
}

public extension MegaCredentialManagerType {
	func getDisplayName(for credential: MegaCredential) throws -> String? {
		return try getDisplayName(for: credential.identifier)
	}

	func removeCredential(_ credential: MegaCredential) throws {
		return try removeCredential(with: credential.identifier)
	}
}

public struct MegaDisplayName: Codable, Equatable, Sendable {
	public let id: String
	public let displayName: String
}

extension MegaDisplayName: FetchableRecord, PersistableRecord {
	public static let databaseTableName = "megaDisplayNames"
	static let accountForeignKey = ForeignKey(["id"])
}

public extension CloudProviderAccount {
	static let megaDisplayName = hasOne(MegaDisplayName.self, using: MegaDisplayName.accountForeignKey)
}

public struct MegaCredentialManager: MegaCredentialManagerType, Sendable {
	@Dependency(\.database) var database
	public static let shared = MegaCredentialManager(keychain: CryptomatorKeychain.mega)
	let keychain: CryptomatorKeychainType

	init(keychain: CryptomatorKeychainType) {
		self.keychain = keychain
	}

	public func save(credential: MegaCredential, displayName: String) throws {
		do {
			try database.write { db in
				let entry = MegaDisplayName(id: credential.identifier, displayName: displayName)
				try entry.save(db)
				try keychain.saveMegaCredential(credential)
			}
		}
	}

	public func removeCredential(with identifier: String) throws {
		do {
			try database.write { db in
				let entry = try MegaDisplayName.filter(Column("id") == identifier).fetchOne(db)
				try entry?.delete(db)
				try keychain.removeMegaCredential(identifier)
			}
		}
	}

	public func getDisplayName(for identifier: String) throws -> String? {
		try database.read { db in
			let entry = try MegaDisplayName.filter(Column("id") == identifier).fetchOne(db)
			return entry?.displayName
		}
	}

	public func getCredential(with identifier: String) -> MegaCredential? {
		return keychain.getMegaCredential(identifier)
	}
}
