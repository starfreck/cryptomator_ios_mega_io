//
//  CryptomatorKeychain+Mega.swift
//  CryptomatorCommonCore
//

import Foundation

extension CryptomatorKeychainType {
	func getMegaCredential(_ identifier: String) -> MegaCredential? {
		guard let data = getAsData(identifier) else {
			return nil
		}
		do {
			let jsonDecoder = JSONDecoder()
			return try jsonDecoder.decode(MegaCredential.self, from: data)
		} catch {
			return nil
		}
	}

	func saveMegaCredential(_ credential: MegaCredential) throws {
		let identifier = credential.identifier
		let jsonEncoder = JSONEncoder()
		let encodedCredential = try jsonEncoder.encode(credential)
		try set(identifier, value: encodedCredential)
	}

	func removeMegaCredential(_ identifier: String) throws {
		try delete(identifier)
	}
}
