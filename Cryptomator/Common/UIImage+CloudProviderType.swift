//
//  UIImage+CloudProviderType.swift
//  Cryptomator
//
//  Created by Philipp Schmid on 07.01.21.
//  Copyright © 2021 Skymatic GmbH. All rights reserved.
//

import CryptomatorCloudAccessCore
import CryptomatorCommonCore
import UIKit

extension UIImage {
	enum State {
		case normal
		case highlighted
	}

	convenience init?(vaultIconFor cloudProviderType: CloudProviderType, state: UIImage.State) {
		var assetName: String
		switch cloudProviderType {
		case .box:
			assetName = "box-vault"
		case .dropbox:
			assetName = "dropbox-vault"
		case .googleDrive:
			assetName = "google-drive-vault"
		case let .localFileSystem(type):
			assetName = UIImage.getVaultIcon(for: type)
		case let .microsoftGraph(type):
			assetName = UIImage.getVaultIcon(for: type)
		case .pCloud:
			assetName = "pcloud-vault"
		case .s3:
			assetName = "s3-vault"
		case .webDAV:
			assetName = "webdav-vault"
		case .mega:
			assetName = "mega-vault"
		}
		if state == .highlighted {
			assetName += "-selected"
		}
		if let image = UIImage(named: assetName), let cgImage = image.cgImage {
			self.init(cgImage: cgImage, scale: image.scale, orientation: image.imageOrientation)
			return
		}
		if case .mega = cloudProviderType {
			let fallback = UIImage.createMegaVaultIcon(state: state)
			if let cgImage = fallback.cgImage {
				self.init(cgImage: cgImage, scale: fallback.scale, orientation: fallback.imageOrientation)
				return
			}
		}
		self.init(named: assetName)
	}

	private static func getVaultIcon(for type: LocalFileSystemType) -> String {
		switch type {
		case .custom:
			return "file-provider-vault"
		case .iCloudDrive:
			return "icloud-drive-vault"
		}
	}

	private static func getVaultIcon(for type: MicrosoftGraphType) -> String {
		switch type {
		case .oneDrive:
			return "onedrive-vault"
		case .sharePoint:
			return "sharepoint-vault"
		}
	}

	convenience init?(storageIconFor cloudProviderType: CloudProviderType) {
		var assetName: String
		switch cloudProviderType {
		case .box:
			assetName = "box"
		case .dropbox:
			assetName = "dropbox"
		case .googleDrive:
			assetName = "google-drive"
		case let .localFileSystem(type):
			assetName = UIImage.getStorageIcon(for: type)
		case let .microsoftGraph(type):
			assetName = UIImage.getStorageIcon(for: type)
		case .pCloud:
			assetName = "pcloud"
		case .s3:
			assetName = "s3"
		case .webDAV:
			assetName = "webdav"
		case .mega:
			assetName = "mega"
		}
		if let image = UIImage(named: assetName), let cgImage = image.cgImage {
			self.init(cgImage: cgImage, scale: image.scale, orientation: image.imageOrientation)
			return
		}
		if case .mega = cloudProviderType {
			let fallback = UIImage.createMegaStorageIcon()
			if let cgImage = fallback.cgImage {
				self.init(cgImage: cgImage, scale: fallback.scale, orientation: fallback.imageOrientation)
				return
			}
		}
		self.init(named: assetName)
	}

	private static func createMegaStorageIcon() -> UIImage {
		let size = CGSize(width: 44, height: 44)
		let renderer = UIGraphicsImageRenderer(size: size)
		return renderer.image { _ in
			let bounds = CGRect(origin: .zero, size: size)
			let redColor = UIColor(red: 217/255, green: 39/255, blue: 46/255, alpha: 1.0)
			redColor.setFill()
			UIBezierPath(ovalIn: bounds.insetBy(dx: 2, dy: 2)).fill()

			let paragraphStyle = NSMutableParagraphStyle()
			paragraphStyle.alignment = .center
			let attrs: [NSAttributedString.Key: Any] = [
				.font: UIFont.systemFont(ofSize: 22, weight: .bold),
				.foregroundColor: UIColor.white,
				.paragraphStyle: paragraphStyle
			]
			let text = "M"
			let textSize = text.size(withAttributes: attrs)
			let textRect = CGRect(
				x: (size.width - textSize.width) / 2,
				y: (size.height - textSize.height) / 2,
				width: textSize.width,
				height: textSize.height
			)
			text.draw(in: textRect, withAttributes: attrs)
		}
	}

	private static func createMegaVaultIcon(state: UIImage.State) -> UIImage {
		let size = CGSize(width: 60, height: 60)
		let renderer = UIGraphicsImageRenderer(size: size)
		return renderer.image { _ in
			let bounds = CGRect(origin: .zero, size: size)
			let ringColor = state == .highlighted
				? UIColor(red: 0/255, green: 200/255, blue: 100/255, alpha: 1.0)
				: UIColor(red: 0/255, green: 168/255, blue: 89/255, alpha: 1.0)
			ringColor.setFill()
			UIBezierPath(ovalIn: bounds.insetBy(dx: 3, dy: 3)).fill()

			let innerBounds = bounds.insetBy(dx: 14, dy: 14)
			let redColor = UIColor(red: 217/255, green: 39/255, blue: 46/255, alpha: 1.0)
			redColor.setFill()
			UIBezierPath(ovalIn: innerBounds).fill()

			let paragraphStyle = NSMutableParagraphStyle()
			paragraphStyle.alignment = .center
			let attrs: [NSAttributedString.Key: Any] = [
				.font: UIFont.systemFont(ofSize: 18, weight: .bold),
				.foregroundColor: UIColor.white,
				.paragraphStyle: paragraphStyle
			]
			let text = "M"
			let textSize = text.size(withAttributes: attrs)
			let textRect = CGRect(
				x: (size.width - textSize.width) / 2,
				y: (size.height - textSize.height) / 2,
				width: textSize.width,
				height: textSize.height
			)
			text.draw(in: textRect, withAttributes: attrs)
		}
	}

	private static func getStorageIcon(for type: LocalFileSystemType) -> String {
		switch type {
		case .custom:
			return "file-provider"
		case .iCloudDrive:
			return "icloud-drive"
		}
	}

	private static func getStorageIcon(for type: MicrosoftGraphType) -> String {
		switch type {
		case .oneDrive:
			return "onedrive"
		case .sharePoint:
			return "sharepoint"
		}
	}
}
