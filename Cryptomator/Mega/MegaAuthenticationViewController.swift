//
//  MegaAuthenticationViewController.swift
//  Cryptomator
//

import Combine
import CryptomatorCommonCore
import SwiftUI
import UIKit

public protocol MegaAuthenticating: AnyObject {
	func authenticated(with credential: MegaCredential)
	func cancel()
}

class MegaAuthenticationViewController: UIViewController {
	weak var coordinator: (Coordinator & MegaAuthenticating)?
	let viewModel: MegaAuthenticationViewModel
	private var subscriptions = Set<AnyCancellable>()

	init(viewModel: MegaAuthenticationViewModel) {
		self.viewModel = viewModel
		super.init(nibName: nil, bundle: nil)
	}

	@available(*, unavailable)
	required init?(coder: NSCoder) {
		fatalError("init(coder:) has not been implemented")
	}

	override func viewDidLoad() {
		super.viewDidLoad()
		setupSwiftUIView()

		let doneButton = UIBarButtonItem(barButtonSystemItem: .done, target: self, action: #selector(done))
		navigationItem.rightBarButtonItem = doneButton
		let cancelButton = UIBarButtonItem(barButtonSystemItem: .cancel, target: self, action: #selector(cancel))
		navigationItem.leftBarButtonItem = cancelButton
		title = viewModel.title

		viewModel.saveDisabled.sink { disabled in
			doneButton.isEnabled = !disabled
		}.store(in: &subscriptions)

		let hud = ProgressHUD()
		hud.text = LocalizedString.getValue("common.hud.authenticating")
		viewModel.$loginState.sink { [weak self] state in
			switch state {
			case let .error(error):
				Task {
					await hud.dismiss(animated: true)
					let alert = UIAlertController(
						title: "Authentication Failed",
						message: error.localizedDescription,
						preferredStyle: .alert
					)
					alert.addAction(UIAlertAction(title: "OK", style: .default))
					self?.present(alert, animated: true)
				}
			case .verifyingCredentials:
				guard let self = self else { return }
				hud.show(presentingViewController: self)
			case let .loggedIn(credential):
				Task {
					await hud.dismiss(animated: true)
					self?.coordinator?.authenticated(with: credential)
				}
			case .notLoggedIn:
				break
			}
		}.store(in: &subscriptions)
	}

	@objc func done() {
		viewModel.saveMegaCredential()
	}

	@objc func cancel() {
		coordinator?.cancel()
	}

	private func setupSwiftUIView() {
		let child = UIHostingController(rootView: MegaAuthenticationView(viewModel: viewModel))
		addChild(child)
		view.addSubview(child.view)
		child.didMove(toParent: self)
		child.view.translatesAutoresizingMaskIntoConstraints = false
		NSLayoutConstraint.activate(child.view.constraints(equalTo: view))
	}
}
