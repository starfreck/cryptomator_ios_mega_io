//
//  MegaAuthenticationView.swift
//  Cryptomator
//

import Combine
import CryptomatorCommonCore
import SwiftUI

enum MegaLoginField: Hashable {
	case displayName
	case email
	case password
	case twoFactorCode
}

struct MegaAuthenticationView: View {
	@FocusState private var focusedField: MegaLoginField?
	@ObservedObject var viewModel: MegaAuthenticationViewModel

	var body: some View {
		SwiftUI.Form {
			TextField("Display Name (Optional)", text: $viewModel.displayName)
				.focused($focusedField, equals: .displayName)
				.disableAutocorrection(true)

			TextField("Email", text: $viewModel.email)
				.focused($focusedField, equals: .email)
				.disableAutocorrection(true)
				.autocapitalization(.none)
				.keyboardType(.emailAddress)

			SecureField("Password", text: $viewModel.password)
				.focused($focusedField, equals: .password)
				.disableAutocorrection(true)
				.autocapitalization(.none)

			TextField("2FA Code (Optional)", text: $viewModel.twoFactorCode)
				.focused($focusedField, equals: .twoFactorCode)
				.disableAutocorrection(true)
				.autocapitalization(.none)
				.keyboardType(.numberPad)
		}
	}
}
