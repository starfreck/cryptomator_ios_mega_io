//
//  MegaAuthenticationViewModel.swift
//  Cryptomator
//

import Combine
import CryptomatorCommonCore
import Foundation

public enum MegaLoginState {
	case error(Error)
	case verifyingCredentials
	case loggedIn(MegaCredential)
	case notLoggedIn
}

public class MegaAuthenticationViewModel: ObservableObject {
	@Published public var email = ""
	@Published public var password = ""
	@Published public var twoFactorCode = ""
	@Published public var displayName = ""
	@Published public var loginState = MegaLoginState.notLoggedIn

	public let title = "MEGA"

	public lazy var saveDisabled: AnyPublisher<Bool, Never> = $email.combineLatest($password)
		.map { email, password in
			email.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || password.isEmpty
		}
		.eraseToAnyPublisher()

	public let credentialManager: MegaCredentialManager
	public let credentialIdentifier: String

	public init(
		displayName: String = "",
		credential: MegaCredential? = nil,
		credentialManager: MegaCredentialManager = MegaCredentialManager.shared
	) {
		self.credentialManager = credentialManager
		self.displayName = displayName
		if let credential = credential {
			self.email = credential.email
			self.credentialIdentifier = credential.identifier
		} else {
			self.credentialIdentifier = UUID().uuidString
		}
	}

	public func saveMegaCredential() {
		let cleanEmail = email.trimmingCharacters(in: .whitespacesAndNewlines)
		guard !cleanEmail.isEmpty, !password.isEmpty else {
			loginState = .error(MegaClientError.invalidCredentials)
			return
		}

		loginState = .verifyingCredentials
		Task { @MainActor in
			do {
				let client = MegaClient()
				_ = try await client.login(email: cleanEmail, password: password, twoFactorCode: twoFactorCode)
				guard let sessionToken = client.dumpSession() else {
					throw MegaClientError.cryptoError
				}

				var quotaStr = ""
				if let quota = try? await client.getQuota() {
					let usedGb = Double(quota.used) / (1024.0 * 1024.0 * 1024.0)
					let totalGb = Double(quota.total) / (1024.0 * 1024.0 * 1024.0)
					quotaStr = String(format: " (%.1f GB / %.1f GB)", usedGb, totalGb)
				}

				let credential = MegaCredential(
					identifier: credentialIdentifier,
					email: cleanEmail + quotaStr,
					sessionToken: sessionToken
				)

				let finalDisplayName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
				try credentialManager.save(
					credential: credential,
					displayName: finalDisplayName.isEmpty ? cleanEmail : finalDisplayName
				)

				loginState = .loggedIn(credential)
			} catch {
				loginState = .error(error)
			}
		}
	}
}
