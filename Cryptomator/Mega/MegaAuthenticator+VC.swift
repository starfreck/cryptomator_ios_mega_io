//
//  MegaAuthenticator+VC.swift
//  Cryptomator
//

import CryptomatorCommonCore
import UIKit

public enum MegaAuthenticator {
	@MainActor private static var coordinator: MegaAuthenticationCoordinator?

	public static func authenticate(from viewController: UIViewController) async throws -> MegaCredential {
		let navigationController = BaseNavigationController()
		let megaCoordinator = MegaAuthenticationCoordinator(navigationController: navigationController)
		coordinator = megaCoordinator
		defer {
			coordinator = nil
		}
		viewController.present(navigationController, animated: true)
		megaCoordinator.start()
		return try await megaCoordinator.pendingAuthentication.value
	}
}

class MegaAuthenticationCoordinator: Coordinator, MegaAuthenticating {
	let pendingAuthentication = OneShotSignal<MegaCredential>()
	var navigationController: UINavigationController
	var childCoordinators = [Coordinator]()
	weak var parentCoordinator: Coordinator?

	init(navigationController: UINavigationController) {
		self.navigationController = navigationController
	}

	func start() {
		let viewController = MegaAuthenticationViewController(viewModel: .init())
		viewController.coordinator = self
		navigationController.pushViewController(viewController, animated: false)
	}

	func authenticated(with credential: MegaCredential) {
		pendingAuthentication.fulfill(credential)
		close()
	}

	func cancel() {
		pendingAuthentication.reject(CocoaError(.userCancelled))
		close()
	}

	private func close() {
		navigationController.dismiss(animated: true)
		parentCoordinator?.childDidFinish(self)
	}
}
