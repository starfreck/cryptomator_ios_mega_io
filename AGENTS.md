# AI Agent Guide: Cryptomator iOS Fork (MEGA Cloud Support)

This guide provides instructions and architectural context for AI agents maintaining this fork.

## 1. Fork Overview & Goals

- **Upstream Repository**: `https://github.com/cryptomator/ios.git` (`upstream`)
- **Fork Repository**: `https://github.com/starfreck/cryptomator_ios_mega_io.git` (`origin`)
- **Primary Goal**: Provide native MEGA (`mega.nz`) cloud storage support in Cryptomator iOS with minimal maintenance overhead when rebasing against upstream updates.

---

## 2. Git Branching & Maintenance Strategy

To keep maintenance trivial and avoid merge conflicts with upstream:

1. **`develop` branch**:
   - Must remain **100% clean and identical to `upstream/develop`**.
   - NEVER commit custom features or fork-specific changes directly onto `develop`.

2. **`feature/mega-support` branch**:
   - Contains all MEGA cloud integration commits.
   - Kept on top of `develop` via git rebase.

### How to Sync with Upstream

When upstream releases updates, follow this exact procedure:

```bash
# 1. Update local develop from upstream
git checkout develop
git fetch upstream develop
git merge upstream/develop
git push origin develop

# 2. Rebase feature branch on top of updated develop
git checkout feature/mega-support
git rebase develop

# 3. Verify tests and build
xcodebuild build-for-testing -scheme CryptomatorCommonCore -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO
xcodebuild -scheme Cryptomator -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build

# 4. Push updated feature branch
git push --force-with-lease origin feature/mega-support
```

---

## 3. Architecture & Code Structure

The MEGA integration is built natively using pure Swift + `CommonCrypto` + `BigInt` (for RSA modular exponentiation), matching the Carlsen MEGA protocol used in Cryptomator Android.

### Modified / Core Extension Points
- **Core SPM Package (`CryptomatorCommonCore`)**:
  - `CryptomatorCommon/Package.swift`: Added `BigInt` dependency (`leif-ibsen/BigInt`).
  - `CryptomatorKeychain.swift`: Added `.mega` service namespace.
  - `CryptomatorDatabase.swift`: Registered `megaDisplayNameMigration`.
  - `Manager/CloudProviderType.swift`: Added `case mega`.
  - `Manager/CloudProviderDBManager.swift`: Dispatches `.mega` to `MegaCloudProvider`.
  - `Mega/`:
    - `MegaCredential.swift`: Model for MEGA account credentials, session ID, user hash, master key.
    - `CryptomatorKeychain+Mega.swift`: Keychain storage helper.
    - `MegaCredentialManager.swift`: Credential manager with GRDB persistence.
    - `MegaCrypto.swift`: Full MEGA cryptographic primitives:
      - Base64URL encode/decode.
      - A32 / byte array conversions.
      - v1 `passwordKey` & stringHash.
      - v2 PBKDF2-HMAC-SHA512 (`deriveKeyV2`).
      - AES-128-ECB, CBC, and CTR operations using `CommonCrypto`.
      - Chunk sizing logic & chunk CBC-MAC calculation.
      - MPI parsing (`getMPI`) and RSA modular exponentiation (`csidBInt.expMod(dBInt, n)`) via `BigInt.BInt` to decrypt MEGA `csid` session tokens.
      - Node key decryption (`decryptNodeKey`) and attribute encryption/decryption (`encryptAttr`/`decryptAttr`).
    - `MegaNode.swift`: Node representation (handle, parent, type, size, attributes).
    - `MegaClient.swift`: Native async networking client for MEGA API (`https://g.api.mega.co.nz/cs`), thread-safe via `os.OSAllocatedUnfairLock`. Handles login (v1 & v2 with 2FA MFA code error `-26`), fast session resumption, folder listing & tree resolution, streaming download/upload, directory creation, deletion, moving, quota retrieval, and session revocation (`sml`).
    - `MegaCloudProvider.swift`: Conforms to `CloudProvider`, providing item metadata, folder listing, file downloads, uploads, directory creation, deletion, and moving.
- **Presentation Layer (`Cryptomator`)**:
  - `Cryptomator/Common/CloudProviderType+Localization.swift`: Added `"MEGA"`.
  - `Cryptomator/Common/CloudProviderType+AccountRecovery.swift`: Added `.mega` -> `.editExisting`.
  - `Cryptomator/Common/CloudAccountList/AccountListViewModel.swift`: Cell creation for MEGA accounts.
  - `Cryptomator/VaultDetail/VaultDetailInfoFooterViewModel.swift`: Footer text.
  - `Cryptomator/Common/UIImage+CloudProviderType.swift`: Storage and vault icons with fallback vector rendering.
  - `CryptomatorIntents/SaveFileIntentHandler.swift`: Added `.mega` icon mapping.
  - Coordinators (`CreateNewVaultCoordinator.swift`, `OpenExistingVaultCoordinator.swift`, `SettingsCoordinator.swift`): Added `.mega` to cloud service picker.
  - `Cryptomator/Common/CloudAuthenticator.swift`: Added `authenticateMega` and `deauthenticate` case with session revocation (`client.logout()`).
  - `Cryptomator/Mega/`:
    - `MegaAuthenticationViewModel.swift`: Handles login state, validation, 2FA code requirement.
    - `MegaAuthenticationView.swift`: SwiftUI Form UI for email, password, optional 2FA code, and display name.
    - `MegaAuthenticationViewController.swift`: UIHostingController hosting `MegaAuthenticationView`.
    - `MegaAuthenticator+VC.swift`: Presents authentication UI modally.
- **FileProvider & Cache Eviction**:
  - `CryptomatorFileProvider/FileProviderAdapterManager.swift`: In `lockVault(with:)`, calls `CachedFileDBManagerFactory.shared.createCachedFileManager(for: domain).clearCache()` to evict decrypted file cache on vault lock.

---

## 4. Verification & Testing

Always verify before committing or pushing changes:

```bash
# Build test target
xcodebuild build-for-testing -scheme CryptomatorCommonCore -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO

# Build main application & app extensions
xcodebuild -scheme Cryptomator -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build
```

Unit test suites for MEGA:
- `CryptomatorCommon/Tests/CryptomatorCommonCoreTests/MegaCryptoTests.swift`

---

## 5. Security & Privacy Rules

- **NEVER** commit real user credentials, email addresses, passwords, or session tokens.
- Ensure remote session revocation (`client.logout()`) is executed whenever a cloud account is removed or logged out.
