<?php

declare(strict_types=1);
/**
 * @author Björn Schießle <bjoern@schiessle.org>
 * @author Clark Tomlinson <fallen013@gmail.com>
 * @author Phil Davis <phil.davis@inf.org>
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

use OC\Files\View;
use OCA\Encryption\Crypto\Crypt;
use OCP\IConfig;
use OCP\ILogger;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\PreConditionNotMetException;

class Util {
	/** @var bool|IUser */
	private $user;

	public function __construct(
		private readonly View $files,
		private readonly Crypt $crypt,
		private readonly ILogger $logger,
		?IUserSession $userSession,
		private readonly IConfig $config,
		private readonly IUserManager $userManager
	) {
		$this->user = $userSession !== null && $userSession->isLoggedIn() ? $userSession->getUser() : false;
	}

	/**
	 * check if recovery key is enabled for user
	 */
	public function isRecoveryEnabledForUser(string $uid): bool {
		$recoveryMode = $this->config->getUserValue(
			$uid,
			'encryption',
			'recoveryEnabled',
			'0'
		);

		return ($recoveryMode === '1');
	}

	/**
	 * check if the home storage should be encrypted
	 */
	public function shouldEncryptHomeStorage(): bool {
		$encryptHomeStorage = $this->config->getAppValue(
			'encryption',
			'encryptHomeStorage',
			'1'
		);

		return ($encryptHomeStorage === '1');
	}

	/**
	 * set the home storage encryption on/off
	 */
	public function setEncryptHomeStorage(bool $encryptHomeStorage): void {
		$value = $encryptHomeStorage ? '1' : '0';
		$this->config->setAppValue(
			'encryption',
			'encryptHomeStorage',
			$value
		);
	}

	/**
	 * check if master key is enabled
	 */
	public function isMasterKeyEnabled(): bool {
		$userMasterKey = $this->config->getAppValue('encryption', 'useMasterKey', '0');
		return ($userMasterKey === '1');
	}

	public function setRecoveryForUser(bool $enabled): bool {
		$value = $enabled ? '1' : '0';

		try {
			$this->config->setUserValue(
				$this->user->getUID(),
				'encryption',
				'recoveryEnabled',
				$value
			);
			return true;
		} catch (PreConditionNotMetException $e) {
			return false;
		}
	}

	public function userHasFiles(string $uid): bool {
		return $this->files->file_exists($uid . '/files');
	}

	/**
	 * get owner from give path, path relative to data/ expected
	 *
	 * @param string $path relative to data/
	 * @throws \BadMethodCallException
	 */
	public function getOwner(string $path): string {
		$owner = '';
		$parts = \explode('/', $path, 3);
		if (\count($parts) > 1) {
			$owner = $parts[1];
			if ($this->userManager->userExists($owner) === false) {
				throw new \BadMethodCallException('Unknown user: ' .
				'method expects path to a user folder relative to the data folder');
			}
		}

		return $owner;
	}

	/**
	 * get storage of path
	 *
	 * @return \OC\Files\Storage\Storage
	 */
	public function getStorage(string $path) {
		$storage = $this->files->getMount($path)->getStorage();
		return $storage;
	}

	/**
	 * Deletes the encryption settings for the masterkey
	 */
	public function removeEncryptionAppSettings(): void {
		$this->config->setAppValue('core', 'encryption_enabled', 'no');
		$this->config->deleteAppValue('encryption', 'useMasterKey');
		$this->config->deleteAppValue('encryption', 'masterKeyId');
		$this->config->deleteAppValue('encryption', 'recoveryKeyId');
		$this->config->deleteAppValue('encryption', 'publicShareKeyId');
		$this->config->deleteAppValue('files_encryption', 'installed_version');
	}
}
