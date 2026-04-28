<?php

declare(strict_types=1);
/**
 * @author Björn Schießle <bjoern@schiessle.org>
 * @author Clark Tomlinson <fallen013@gmail.com>
 * @author Lukas Reschke <lukas@statuscode.ch>
 * @author Thomas Müller <thomas.mueller@tmit.eu>
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

use OCA\Encryption\Crypto\Crypt;
use OCP\Encryption\Keys\IStorage;
use OCP\IConfig;
use OCP\IUser;
use OCP\IUserSession;
use OCP\PreConditionNotMetException;
use OCP\Security\ISecureRandom;
use OC\Files\View;
use OCP\Encryption\IFile;
use OCP\Files\FileInfo;

class Recovery {
	/** @var null|IUser|false */
	protected $user;

	public function __construct(
		?IUserSession $user,
		protected readonly Crypt $crypt,
		private readonly ISecureRandom $random,
		private readonly KeyManager $keyManager,
		private readonly IConfig $config,
		private readonly IStorage $keyStorage,
		private readonly IFile $file,
		private readonly View $view
	) {
		$this->user = ($user !== null && $user->isLoggedIn()) ? $user->getUser() : false;
	}

	public function enableAdminRecovery(string $password): bool {
		$appConfig = $this->config;
		$keyManager = $this->keyManager;

		if (!$keyManager->recoveryKeyExists()) {
			$keyPair = $this->crypt->createKeyPair();
			if (!\is_array($keyPair)) {
				return false;
			}

			$this->keyManager->setRecoveryKey($password, $keyPair);
		}

		if ($keyManager->checkRecoveryPassword($password)) {
			$appConfig->setAppValue('encryption', 'recoveryAdminEnabled', '1');
			return true;
		}

		return false;
	}

	/**
	 * change recovery key id
	 */
	public function changeRecoveryKeyPassword(string $newPassword, string $oldPassword): bool {
		$recoveryKey = $this->keyManager->getSystemPrivateKey($this->keyManager->getRecoveryKeyId());
		$decryptedRecoveryKey = $this->crypt->decryptPrivateKey($recoveryKey, $oldPassword);
		if ($decryptedRecoveryKey === false) {
			return false;
		}
		$encryptedRecoveryKey = $this->crypt->encryptPrivateKey($decryptedRecoveryKey, $newPassword);
		$header = $this->crypt->generateHeader();
		if ($encryptedRecoveryKey) {
			$this->keyManager->setSystemPrivateKey($this->keyManager->getRecoveryKeyId(), $header . $encryptedRecoveryKey);
			return true;
		}
		return false;
	}

	public function disableAdminRecovery(string $recoveryPassword): bool {
		$keyManager = $this->keyManager;

		if ($keyManager->checkRecoveryPassword($recoveryPassword)) {
			// Set recoveryAdmin as disabled
			$this->config->setAppValue('encryption', 'recoveryAdminEnabled', '0');
			return true;
		}
		return false;
	}

	/**
	 * check if recovery is enabled for user
	 *
	 * @param string $user if no user is given we check the current logged-in user
	 */
	public function isRecoveryEnabledForUser(string $user = ''): bool {
		$uid = empty($user) ? $this->user->getUID() : $user;
		$recoveryMode = $this->config->getUserValue(
			$uid,
			'encryption',
			'recoveryEnabled',
			0
		);

		return ($recoveryMode === '1');
	}

	/**
	 * check if recovery is key is enabled by the administrator
	 */
	public function isRecoveryKeyEnabled(): bool {
		$enabled = $this->config->getAppValue('encryption', 'recoveryAdminEnabled', 0);

		return ($enabled === '1');
	}

	public function setRecoveryForUser(string $value): bool {
		try {
			$this->config->setUserValue(
				$this->user->getUID(),
				'encryption',
				'recoveryEnabled',
				$value
			);

			if ($value === '1') {
				$this->addRecoveryKeys('/' . $this->user->getUID() . '/files/');
			} else {
				$this->removeRecoveryKeys('/' . $this->user->getUID() . '/files/');
			}

			return true;
		} catch (PreConditionNotMetException $e) {
			return false;
		}
	}

	/**
	 * add recovery key to all encrypted files
	 */
	private function addRecoveryKeys(string $path): void {
		$dirContent = $this->view->getDirectoryContent($path);
		foreach ($dirContent as $item) {
			if ($this->isSharedStorage($item)) {
				continue;
			}
			$filePath = $item->getPath();
			if ($item['type'] === 'dir') {
				$this->addRecoveryKeys($filePath . '/');
			} else {
				$fileKey = $this->keyManager->getFileKey($filePath, $this->user->getUID());
				if (!empty($fileKey)) {
					$accessList = $this->file->getAccessList($filePath);
					$publicKeys = [];
					foreach ($accessList['users'] as $uid) {
						$publicKeys[$uid] = $this->keyManager->getPublicKey($uid);
					}

					$publicKeys = $this->keyManager->addSystemKeys($accessList, $publicKeys, $this->user->getUID());

					$encryptedKeyfiles = $this->crypt->multiKeyEncrypt($fileKey, $publicKeys);
					$this->keyManager->setAllFileKeys($filePath, $encryptedKeyfiles);
				}
			}
		}
	}

	/**
	 * remove recovery key to all encrypted files
	 */
	private function removeRecoveryKeys(string $path): void {
		$dirContent = $this->view->getDirectoryContent($path);
		foreach ($dirContent as $item) {
			if ($this->isSharedStorage($item)) {
				continue;
			}
			$filePath = $item->getPath();
			if ($item['type'] === 'dir') {
				$this->removeRecoveryKeys($filePath . '/');
			} else {
				$this->keyManager->deleteShareKey($filePath, $this->keyManager->getRecoveryKeyId());
			}
		}
	}

	/**
	 * recover users files with the recovery key
	 */
	public function recoverUsersFiles(string $recoveryPassword, string $user): void {
		$encryptedKey = $this->keyManager->getSystemPrivateKey($this->keyManager->getRecoveryKeyId());

		$privateKey = $this->crypt->decryptPrivateKey($encryptedKey, $recoveryPassword);
		if ($privateKey !== false) {
			$this->recoverAllFiles('/' . $user . '/files/', $privateKey, $user);
		}
	}

	/**
	 * recover users files
	 */
	private function recoverAllFiles(string $path, string $privateKey, string $uid): void {
		$dirContent = $this->view->getDirectoryContent($path);

		foreach ($dirContent as $item) {
			// Get relative path from encryption/keyfiles
			$filePath = $item->getPath();
			if ($this->view->is_dir($filePath)) {
				$this->recoverAllFiles($filePath . '/', $privateKey, $uid);
			} else {
				$this->recoverFile($filePath, $privateKey, $uid);
			}
		}
	}

	/**
	 * recover file
	 */
	private function recoverFile(string $path, string $privateKey, string $uid): void {
		$encryptedFileKey = $this->keyManager->getEncryptedFileKey($path);
		$shareKey = $this->keyManager->getShareKey($path, $this->keyManager->getRecoveryKeyId());

		if ($encryptedFileKey && $shareKey && $privateKey) {
			$fileKey = $this->crypt->multiKeyDecrypt(
				$encryptedFileKey,
				$shareKey,
				$privateKey
			);
		}

		if (!empty($fileKey)) {
			$accessList = $this->file->getAccessList($path);
			$publicKeys = [];
			foreach ($accessList['users'] as $user) {
				$publicKeys[$user] = $this->keyManager->getPublicKey($user);
			}

			$publicKeys = $this->keyManager->addSystemKeys($accessList, $publicKeys, $uid);

			$encryptedKeyfiles = $this->crypt->multiKeyEncrypt($fileKey, $publicKeys);
			$this->keyManager->setAllFileKeys($path, $encryptedKeyfiles);
		}
	}

	/**
	 * check if the item is on a shared storage
	 */
	protected function isSharedStorage(FileInfo $item): bool {
		/**
		 * hardcoded class to prevent dependency on files_sharing app and federated share
		 * TODO: add filter callback to view::getDirectoryContent() or its successor
		 * so we can filter by more than just mimetype
		 */
		if ($item->getStorage()->instanceOfStorage('OCA\Files_Sharing\ISharedStorage')) {
			return true;
		}
		return false;
	}
}
