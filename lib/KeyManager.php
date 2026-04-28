<?php

declare(strict_types=1);
/**
 * @author Björn Schießle <bjoern@schiessle.org>
 * @author Clark Tomlinson <fallen013@gmail.com>
 * @author Lukas Reschke <lukas@statuscode.ch>
 * @author Thomas Müller <thomas.mueller@tmit.eu>
 * @author Vincent Petry <pvince81@owncloud.com>
 *
 * @copyright Copyright (c) 2019, ownCloud GmbH
 * Modified by BW-Tech GmbH for owncloud.online (PHP 8.4).
 *
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */
namespace OCA\Encryption;

use OC\Encryption\Exceptions\DecryptionFailedException;
use OC\Files\View;
use OCA\Encryption\Crypto\Encryption;
use OCA\Encryption\Exceptions\PrivateKeyMissingException;
use OCA\Encryption\Exceptions\PublicKeyMissingException;
use OCA\Encryption\Crypto\Crypt;
use OCP\Encryption\Keys\IStorage;
use OCP\IConfig;
use OCP\ILogger;
use OCP\IUserSession;

class KeyManager {
	private string $recoveryKeyId;
	private string $publicShareKeyId;
	private string $masterKeyId;
	/** @var string|false UserID */
	private $keyId;
	private string $publicKeyId = 'publicKey';
	private string $privateKeyId = 'privateKey';
	private string $shareKeyId = 'shareKey';
	private string $fileKeyId = 'fileKey';

	public function __construct(
		private readonly IStorage $keyStorage,
		private readonly Crypt $crypt,
		private readonly IConfig $config,
		?IUserSession $userSession,
		protected readonly Session $session,
		private readonly ILogger $log,
		private readonly Util $util
	) {
		$this->recoveryKeyId = $this->config->getAppValue(
			'encryption',
			'recoveryKeyId'
		);
		if (empty($this->recoveryKeyId)) {
			$this->recoveryKeyId = 'recoveryKey_' . \substr(\md5((string)\time()), 0, 8);
			$this->config->setAppValue(
				'encryption',
				'recoveryKeyId',
				$this->recoveryKeyId
			);
		}

		$this->setPublicShareKeyIDAndMasterKeyId();

		$this->keyId = $userSession !== null && $userSession->isLoggedIn() ? $userSession->getUser()->getUID() : false;
	}

	/**
	 * check if key pair for public link shares exists, if not we create one
	 */
	public function validateShareKey(): void {
		$shareKey = $this->getPublicShareKey();
		if (empty($shareKey)) {
			$keyPair = $this->crypt->createKeyPair();

			// Save public key
			$this->keyStorage->setSystemUserKey(
				$this->publicShareKeyId . '.publicKey',
				$keyPair['publicKey'],
				Encryption::ID
			);

			// Encrypt private key empty passphrase
			$encryptedKey = $this->crypt->encryptPrivateKey($keyPair['privateKey'], '');
			$header = $this->crypt->generateHeader();
			$this->setSystemPrivateKey($this->publicShareKeyId, $header . $encryptedKey);
		}
	}

	/**
	 * check if a key pair for the master key exists, if not we create one
	 */
	public function validateMasterKey(): void {
		if ($this->util->isMasterKeyEnabled() === false) {
			return;
		}

		$masterKey = $this->getPublicMasterKey();
		if (empty($masterKey)) {
			$keyPair = $this->crypt->createKeyPair();

			// Save public key
			$this->keyStorage->setSystemUserKey(
				$this->masterKeyId . '.publicKey',
				$keyPair['publicKey'],
				Encryption::ID
			);

			// Encrypt private key with system password
			$encryptedKey = $this->crypt->encryptPrivateKey($keyPair['privateKey'], $this->getMasterKeyPassword(), $this->masterKeyId);
			$header = $this->crypt->generateHeader();
			$this->setSystemPrivateKey($this->masterKeyId, $header . $encryptedKey);
		}
	}

	public function recoveryKeyExists(): bool {
		$key = $this->getRecoveryKey();
		return (!empty($key));
	}

	/**
	 * get recovery key
	 */
	public function getRecoveryKey(): string {
		return $this->keyStorage->getSystemUserKey($this->recoveryKeyId . '.publicKey', Encryption::ID);
	}

	/**
	 * get recovery key ID
	 */
	public function getRecoveryKeyId(): string {
		return $this->recoveryKeyId;
	}

	public function checkRecoveryPassword(string $password): bool {
		$recoveryKey = $this->keyStorage->getSystemUserKey($this->recoveryKeyId . '.privateKey', Encryption::ID);
		$decryptedRecoveryKey = $this->crypt->decryptPrivateKey($recoveryKey, $password);

		if ($decryptedRecoveryKey) {
			return true;
		}
		return false;
	}

	public function storeKeyPair(string $uid, string $password, array $keyPair): bool {
		// Save Public Key
		$this->setPublicKey($uid, $keyPair['publicKey']);

		$encryptedKey = $this->crypt->encryptPrivateKey($keyPair['privateKey'], $password, $uid);

		$header = $this->crypt->generateHeader();

		if ($encryptedKey) {
			$this->setPrivateKey($uid, $header . $encryptedKey);
			return true;
		}
		return false;
	}

	public function setRecoveryKey(string $password, array $keyPair): bool {
		// Save Public Key
		$this->keyStorage->setSystemUserKey(
			$this->getRecoveryKeyId() .
			'.publicKey',
			$keyPair['publicKey'],
			Encryption::ID
		);

		$encryptedKey = $this->crypt->encryptPrivateKey($keyPair['privateKey'], $password);
		$header = $this->crypt->generateHeader();

		if ($encryptedKey) {
			$this->setSystemPrivateKey($this->getRecoveryKeyId(), $header . $encryptedKey);
			return true;
		}
		return false;
	}

	public function setPublicKey(string $userId, string $key): bool {
		return $this->keyStorage->setUserKey($userId, $this->publicKeyId, $key, Encryption::ID);
	}

	public function setPrivateKey(string $userId, string $key): bool {
		return $this->keyStorage->setUserKey(
			$userId,
			$this->privateKeyId,
			$key,
			Encryption::ID
		);
	}

	/**
	 * write file key to key storage
	 */
	public function setFileKey(string $path, string $key): bool {
		return $this->keyStorage->setFileKey($path, $this->fileKeyId, $key, Encryption::ID);
	}

	/**
	 * set all file keys (the file key and the corresponding share keys)
	 */
	public function setAllFileKeys(string $path, array $keys): void {
		$this->setFileKey($path, $keys['data']);
		foreach ($keys['keys'] as $uid => $keyFile) {
			$this->setShareKey($path, $uid, $keyFile);
		}
	}

	/**
	 * write share key to the key storage
	 */
	public function setShareKey(string $path, string $uid, string $key): bool {
		$keyId = $uid . '.' . $this->shareKeyId;
		return $this->keyStorage->setFileKey($path, $keyId, $key, Encryption::ID);
	}

	/**
	 * Decrypt private key and store it
	 *
	 * @param string $uid user id
	 * @param string $passPhrase users password
	 */
	public function init(string $uid, string $passPhrase): bool {
		$this->session->setStatus(Session::INIT_EXECUTED);

		try {
			if ($this->util->isMasterKeyEnabled()) {
				$uid = $this->getMasterKeyId();
				$passPhrase = $this->getMasterKeyPassword();
				$privateKey = $this->getSystemPrivateKey($uid);
			} else {
				$privateKey = $this->getPrivateKey($uid);
			}
			$privateKey = $this->crypt->decryptPrivateKey($privateKey, $passPhrase, $uid);
		} catch (PrivateKeyMissingException $e) {
			return false;
		} catch (DecryptionFailedException $e) {
			return false;
		} catch (\Exception $e) {
			$this->log->warning(
				'Could not decrypt the private key from user "' . $uid . '"" during login. ' .
				'Assume password change on the user back-end. Error message: '
				. $e->getMessage()
			);
			return false;
		}

		if ($privateKey) {
			$this->session->setPrivateKey($privateKey);
			$this->session->setStatus(Session::INIT_SUCCESSFUL);
			return true;
		}

		return false;
	}

	/**
	 * @throws PrivateKeyMissingException
	 */
	public function getPrivateKey(string $userId): string {
		$privateKey = $this->keyStorage->getUserKey(
			$userId,
			$this->privateKeyId,
			Encryption::ID
		);

		if (\strlen($privateKey) !== 0) {
			return $privateKey;
		}
		throw new PrivateKeyMissingException($userId);
	}

	public function getFileKey(string $path, string $uid): string {
		if ($uid === '') {
			$uid = null;
		}
		$publicAccess = ($uid === null);
		$encryptedFileKey = $this->keyStorage->getFileKey($path, $this->fileKeyId, Encryption::ID);

		if (empty($encryptedFileKey)) {
			return '';
		}

		if ($this->util->isMasterKeyEnabled()) {
			$uid = $this->getMasterKeyId();
			$shareKey = $this->getShareKey($path, $uid);
			if ($publicAccess) {
				$privateKey = $this->getSystemPrivateKey($uid);
				$privateKey = $this->crypt->decryptPrivateKey($privateKey, $this->getMasterKeyPassword(), $uid);
			} else {
				// when logged in, the master key is already decrypted in the session
				$privateKey = $this->session->getPrivateKey();
			}
		} elseif ($publicAccess) {
			// use public share key for public links
			$uid = $this->getPublicShareKeyId();
			$shareKey = $this->getShareKey($path, $uid);
			$privateKey = $this->keyStorage->getSystemUserKey($this->publicShareKeyId . '.privateKey', Encryption::ID);
			$privateKey = $this->crypt->decryptPrivateKey($privateKey);
		} else {
			$shareKey = $this->getShareKey($path, $uid);
			$privateKey = $this->session->getPrivateKey();
		}

		if ($shareKey && $privateKey) {
			return $this->crypt->multiKeyDecrypt(
				$encryptedFileKey,
				$shareKey,
				$privateKey
			);
		}

		return '';
	}

	/**
	 * Get the current version of a file
	 */
	public function getVersion(string $path, View $view): int {
		$fileInfo = $view->getFileInfo($path);
		if ($fileInfo === false) {
			return 0;
		}
		return $fileInfo->getEncryptedVersion();
	}

	/**
	 * Set the current version of a file
	 */
	public function setVersion(string $path, int $version, View $view): void {
		$fileInfo = $view->getFileInfo($path);

		if ($fileInfo !== false) {
			$cache = $fileInfo->getStorage()->getCache();
			$cache->update($fileInfo->getId(), ['encrypted' => $version, 'encryptedVersion' => $version]);
		}
	}

	/**
	 * get the encrypted file key
	 */
	public function getEncryptedFileKey(string $path): string {
		$encryptedFileKey = $this->keyStorage->getFileKey(
			$path,
			$this->fileKeyId,
			Encryption::ID
		);

		return $encryptedFileKey;
	}

	/**
	 * delete share key
	 */
	public function deleteShareKey(string $path, string $keyId): bool {
		return $this->keyStorage->deleteFileKey(
			$path,
			$keyId . '.' . $this->shareKeyId,
			Encryption::ID
		);
	}

	/**
	 * @return mixed
	 */
	public function getShareKey(string $path, string $uid) {
		$keyId = $uid . '.' . $this->shareKeyId;
		return $this->keyStorage->getFileKey($path, $keyId, Encryption::ID);
	}

	/**
	 * check if user has a private and a public key
	 *
	 * @throws PrivateKeyMissingException
	 * @throws PublicKeyMissingException
	 */
	public function userHasKeys(string $userId): bool {
		$privateKey = $publicKey = true;
		$exception = null;

		try {
			$this->getPrivateKey($userId);
		} catch (PrivateKeyMissingException $e) {
			$privateKey = false;
			$exception = $e;
		}
		try {
			$this->getPublicKey($userId);
		} catch (PublicKeyMissingException $e) {
			$publicKey = false;
			$exception = $e;
		}

		if ($privateKey && $publicKey) {
			return true;
		} elseif (!$privateKey && !$publicKey) {
			return false;
		} else {
			throw $exception;
		}
	}

	/**
	 * @return mixed
	 * @throws PublicKeyMissingException
	 */
	public function getPublicKey(string $userId) {
		$publicKey = $this->keyStorage->getUserKey($userId, $this->publicKeyId, Encryption::ID);

		if (\strlen($publicKey) !== 0) {
			return $publicKey;
		}
		throw new PublicKeyMissingException($userId);
	}

	public function getPublicShareKeyId(): string {
		return $this->publicShareKeyId;
	}

	/**
	 * get public key for public link shares
	 */
	public function getPublicShareKey(): string {
		return $this->keyStorage->getSystemUserKey($this->publicShareKeyId . '.publicKey', Encryption::ID);
	}

	public function backupAllKeys(string $purpose, bool $timestamp = true, bool $includeUserKeys = true): void {
//		$backupDir = $this->keyStorage->;
	}

	/**
	 * creat a backup of the users private and public key and then  delete it
	 */
	public function deleteUserKeys(string $uid): void {
		$this->backupAllKeys('password_reset');
		$this->deletePublicKey($uid);
		$this->deletePrivateKey($uid);
	}

	public function deletePublicKey(string $uid): bool {
		return $this->keyStorage->deleteUserKey($uid, $this->publicKeyId, Encryption::ID);
	}

	private function deletePrivateKey(string $uid): bool {
		return $this->keyStorage->deleteUserKey($uid, $this->privateKeyId, Encryption::ID);
	}

	public function deleteAllFileKeys(string $path): bool {
		return $this->keyStorage->deleteAllFileKeys($path);
	}

	/**
	 * @throws PublicKeyMissingException
	 */
	public function getPublicKeys(array $userIds): array {
		$keys = [];

		foreach ($userIds as $userId) {
			try {
				$keys[$userId] = $this->getPublicKey($userId);
			} catch (PublicKeyMissingException $e) {
				continue;
			}
		}

		return $keys;
	}

	/**
	 * @return string returns openssl key
	 */
	public function getSystemPrivateKey(string $keyId): string {
		return $this->keyStorage->getSystemUserKey($keyId . '.' . $this->privateKeyId, Encryption::ID);
	}

	/**
	 * @return string returns openssl key
	 */
	public function setSystemPrivateKey(string $keyId, string $key) {
		return $this->keyStorage->setSystemUserKey(
			$keyId . '.' . $this->privateKeyId,
			$key,
			Encryption::ID
		);
	}

	/**
	 * add system keys such as the public share key and the recovery key
	 *
	 * @throws PublicKeyMissingException
	 */
	public function addSystemKeys(array $accessList, array $publicKeys, string $uid): array {
		if (!empty($accessList['public'])) {
			$publicShareKey = $this->getPublicShareKey();
			if (empty($publicShareKey)) {
				throw new PublicKeyMissingException($this->getPublicShareKeyId());
			}
			$publicKeys[$this->getPublicShareKeyId()] = $publicShareKey;
		}

		if ($this->recoveryKeyExists() &&
			$this->util->isRecoveryEnabledForUser($uid)) {
			$publicKeys[$this->getRecoveryKeyId()] = $this->getRecoveryKey();
		}

		return $publicKeys;
	}

	/**
	 * get master key password
	 *
	 * @throws \Exception
	 */
	public function getMasterKeyPassword(): string {
		$password = $this->config->getSystemValue('secret');
		if (empty($password)) {
			throw new \Exception('Can not get secret from ownCloud instance');
		}

		return $password;
	}

	/**
	 * return master key id
	 */
	public function getMasterKeyId(): string {
		if ($this->config->getAppValue('encryption', 'masterKeyId') !== $this->masterKeyId) {
			$this->masterKeyId = $this->config->getAppValue('encryption', 'masterKeyId');
		}
		return $this->masterKeyId;
	}

	/**
	 * get public master key
	 */
	public function getPublicMasterKey(): string {
		return $this->keyStorage->getSystemUserKey($this->masterKeyId . '.publicKey', Encryption::ID);
	}

	/**
	 * set publicShareKeyId and masterKeyId if not set
	 */
	public function setPublicShareKeyIDAndMasterKeyId(): void {
		$this->publicShareKeyId = $this->config->getAppValue(
			'encryption',
			'publicShareKeyId'
		);
		if (($this->publicShareKeyId === null) || ($this->publicShareKeyId === '')) {
			$this->publicShareKeyId = 'pubShare_' . \substr(\md5((string)\time()), 0, 8);
			$this->config->setAppValue('encryption', 'publicShareKeyId', $this->publicShareKeyId);
		}

		$this->masterKeyId = $this->config->getAppValue(
			'encryption',
			'masterKeyId'
		);
		if (($this->masterKeyId === null) || ($this->masterKeyId === '')) {
			$this->masterKeyId = 'master_' . \substr(\md5((string)\time()), 0, 8);
			$this->config->setAppValue('encryption', 'masterKeyId', $this->masterKeyId);
		}
	}
}
