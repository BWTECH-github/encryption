<?php

declare(strict_types=1);

/**
 * @author Björn Schießle <bjoern@schiessle.org>
 * @author Joas Schilling <coding@schilljs.com>
 * @author Robin Appelman <icewind@owncloud.com>
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

use OC\Files\View;
use OCA\Encryption\Crypto\Encryption;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\ILogger;

class Migration {
	private readonly string $moduleId;
	protected readonly string $installedVersion;

	public function __construct(
		private readonly IConfig $config,
		private readonly View $view,
		private readonly IDBConnection $connection,
		private readonly ILogger $logger
	) {
		$this->view->disableCacheUpdate();
		$this->moduleId = Encryption::ID;
		$this->installedVersion = $this->config->getAppValue('files_encryption', 'installed_version', '-1');
	}

	public function finalCleanUp(): void {
		$this->view->deleteAll('files_encryption/public_keys');
		$this->updateFileCache();
		$this->config->deleteAppValue('files_encryption', 'installed_version');
	}

	/**
	 * update file cache, copy unencrypted_size to the 'size' column
	 */
	private function updateFileCache(): void {
		// make sure that we don't update the file cache multiple times
		// only update during the first run
		if ($this->installedVersion !== '-1') {
			$query = $this->connection->getQueryBuilder();
			$query->update('filecache')
				->set('size', 'unencrypted_size')
				->where($query->expr()->eq('encrypted', $query->createParameter('encrypted')))
				->setParameter('encrypted', 1);
			$query->execute();
		}
	}

	/**
	 * iterate through users and reorganize the folder structure
	 */
	public function reorganizeFolderStructure(): void {
		$this->reorganizeSystemFolderStructure();

		$limit = 500;
		$offset = 0;
		do {
			$users = \OC::$server->getUserManager()->search('', $limit, $offset);
			foreach ($users as $user) {
				$this->reorganizeFolderStructureForUser($user->getUID());
			}
			$offset += $limit;
		} while (\count($users) >= $limit);
	}

	/**
	 * reorganize system wide folder structure
	 */
	public function reorganizeSystemFolderStructure(): void {
		$this->createPathForKeys('/files_encryption');

		// backup system wide folders
		$this->backupSystemWideKeys();

		// rename system wide mount point
		$this->renameFileKeys('', '/files_encryption/keys');

		// rename system private keys
		$this->renameSystemPrivateKeys();

		$storage = $this->view->getMount('')->getStorage();
		$storage->getScanner()->scan('files_encryption');
	}

	/**
	 * reorganize folder structure for user
	 *
	 * @param string $user
	 */
	public function reorganizeFolderStructureForUser(string $user): void {
		// backup all keys
		\OC_Util::tearDownFS();
		\OC_Util::setupFS($user);
		if ($this->backupUserKeys($user)) {
			// rename users private key
			$this->renameUsersPrivateKey($user);
			$this->renameUsersPublicKey($user);
			// rename file keys
			$path = '/files_encryption/keys';
			$this->renameFileKeys($user, $path);
			$trashPath = '/files_trashbin/keys';
			if (\OC_App::isEnabled('files_trashbin') && $this->view->is_dir($user . '/' . $trashPath)) {
				$this->renameFileKeys($user, $trashPath, true);
				$this->view->deleteAll($trashPath);
			}
			// delete old folders
			$this->deleteOldKeys($user);
			$this->view->getMount('/' . $user)->getStorage()->getScanner()->scan('files_encryption');
		}
	}

	/**
	 * update database
	 */
	public function updateDB(): void {
		// make sure that we don't update the file cache multiple times
		// only update during the first run
		if ($this->installedVersion === '-1') {
			return;
		}

		// delete left-over from old encryption which is no longer needed
		$this->config->deleteAppValue('files_encryption', 'ocsid');
		$this->config->deleteAppValue('files_encryption', 'types');
		$this->config->deleteAppValue('files_encryption', 'enabled');

		$oldAppValues = $this->connection->getQueryBuilder();
		$oldAppValues->select('*')
			->from('appconfig')
			->where($oldAppValues->expr()->eq('appid', $oldAppValues->createParameter('appid')))
			->setParameter('appid', 'files_encryption');
		$appSettings = $oldAppValues->execute();

		/** @phan-suppress-next-line PhanDeprecatedFunction */
		while ($row = $appSettings->fetch()) {
			// 'installed_version' gets deleted at the end of the migration process
			if ($row['configkey'] !== 'installed_version') {
				$this->config->setAppValue('encryption', $row['configkey'], $row['configvalue']);
				$this->config->deleteAppValue('files_encryption', $row['configkey']);
			}
		}

		$oldPreferences = $this->connection->getQueryBuilder();
		$oldPreferences->select('*')
			->from('preferences')
			->where($oldPreferences->expr()->eq('appid', $oldPreferences->createParameter('appid')))
			->setParameter('appid', 'files_encryption');
		$preferenceSettings = $oldPreferences->execute();

		/** @phan-suppress-next-line PhanDeprecatedFunction */
		while ($row = $preferenceSettings->fetch()) {
			$this->config->setUserValue($row['userid'], 'encryption', $row['configkey'], $row['configvalue']);
			$this->config->deleteUserValue($row['userid'], 'files_encryption', $row['configkey']);
		}
	}

	/**
	 * create backup of system-wide keys
	 */
	private function backupSystemWideKeys(): void {
		$backupDir = 'encryption_migration_backup_' . \date("Y-m-d_H-i-s");
		$this->view->mkdir($backupDir);
		$this->view->copy('files_encryption', $backupDir . '/files_encryption');
	}

	/**
	 * create backup of user specific keys
	 *
	 * @param string $user
	 * @return bool
	 */
	private function backupUserKeys(string $user): bool {
		$encryptionDir = $user . '/files_encryption';
		if ($this->view->is_dir($encryptionDir)) {
			$backupDir = $user . '/encryption_migration_backup_' . \date("Y-m-d_H-i-s");
			$this->view->mkdir($backupDir);
			$this->view->copy($encryptionDir, $backupDir);
			return true;
		}
		return false;
	}

	/**
	 * rename system-wide private keys
	 */
	private function renameSystemPrivateKeys(): void {
		$dh = $this->view->opendir('files_encryption');
		$this->createPathForKeys('/files_encryption/' . $this->moduleId);

		// PHP 8.0+ returns Directory object or resource, both work with readdir
		// Check for false to handle failure case
		if ($dh !== false) {
			while (($privateKey = \readdir($dh)) !== false) {
				if (!\OC\Files\Filesystem::isIgnoredDir($privateKey)) {
					if (!$this->view->is_dir('/files_encryption/' . $privateKey)) {
						$this->view->rename('files_encryption/' . $privateKey, 'files_encryption/' . $this->moduleId . '/' . $privateKey);
						$this->renameSystemPublicKey($privateKey);
					}
				}
			}
			\closedir($dh);
		}
	}

	/**
	 * rename system wide public key
	 *
	 * @param string $privateKey private key for which we want to rename the corresponding public key
	 */
	private function renameSystemPublicKey(string $privateKey): void {
		$pos = \strrpos($privateKey, '.privateKey');
		if ($pos !== false) {
			$publicKey = \substr($privateKey, 0, $pos) . '.publicKey';
			$this->view->rename('files_encryption/public_keys/' . $publicKey, 'files_encryption/' . $this->moduleId . '/' . $publicKey);
		}
	}

	/**
	 * rename user-specific private keys
	 *
	 * @param string $user
	 */
	private function renameUsersPrivateKey(string $user): void {
		$oldPrivateKey = $user . '/files_encryption/' . $user . '.privateKey';
		$newPrivateKey = $user . '/files_encryption/' . $this->moduleId . '/' . $user . '.privateKey';
		if ($this->view->file_exists($oldPrivateKey)) {
			$this->createPathForKeys(\dirname($newPrivateKey));
			$this->view->rename($oldPrivateKey, $newPrivateKey);
		}
	}

	/**
	 * rename user-specific public keys
	 *
	 * @param string $user
	 */
	private function renameUsersPublicKey(string $user): void {
		$oldPublicKey = '/files_encryption/public_keys/' . $user . '.publicKey';
		$newPublicKey = $user . '/files_encryption/' . $this->moduleId . '/' . $user . '.publicKey';
		if ($this->view->file_exists($oldPublicKey)) {
			$this->createPathForKeys(\dirname($newPublicKey));
			$this->view->rename($oldPublicKey, $newPublicKey);
		}
	}

	/**
	 * rename file keys
	 *
	 * @param string $user
	 * @param string $path
	 * @param bool $trash
	 */
	private function renameFileKeys(string $user, string $path, bool $trash = false): void {
		if ($this->view->is_dir($user . '/' . $path) === false) {
			$this->logger->info('Skip dir /' . $user . '/' . $path . ': does not exist');
			return;
		}

		$dh = $this->view->opendir($user . '/' . $path);

		// PHP 8.0+ returns Directory object or resource, both work with readdir
		// Check for false to handle failure case
		if ($dh !== false) {
			while (($file = \readdir($dh)) !== false) {
				if (!\OC\Files\Filesystem::isIgnoredDir($file)) {
					if ($this->view->is_dir($user . '/' . $path . '/' . $file)) {
						$this->renameFileKeys($user, $path . '/' . $file, $trash);
					} else {
						$target = $this->getTargetDir($user, $path, $file, $trash);
						if ($target !== false) {
							$this->createPathForKeys(\dirname($target));
							$this->view->rename($user . '/' . $path . '/' . $file, $target);
						} else {
							$this->logger->warning(
								'did not move key "' . $file
								. '" could not find the corresponding file in /data/' . $user . '/files.'
							. 'Most likely the key was already moved in a previous migration run and is already on the right place.'
							);
						}
					}
				}
			}
			\closedir($dh);
		}
	}

	/**
	 * get system mount points
	 * wrap static method so that it can be mocked for testing
	 *
	 * @internal
	 * @return array
	 */
	protected function getSystemMountPoints(): array {
		/** @phan-suppress-next-line PhanDeprecatedFunction */
		return \OC\Files\External\LegacyUtil::getSystemMountPoints();
	}

	/**
	 * generate target directory
	 *
	 * @param string $user
	 * @param string $keyPath
	 * @param string $filename
	 * @param bool $trash
	 * @return string|false
	 */
	private function getTargetDir(string $user, string $keyPath, string $filename, bool $trash) {
		if ($trash) {
			$filePath = \substr($keyPath, \strlen('/files_trashbin/keys/'));
			$targetDir = $user . '/files_encryption/keys/files_trashbin/' . $filePath . '/' . $this->moduleId . '/' . $filename;
		} else {
			$filePath = \substr($keyPath, \strlen('/files_encryption/keys/'));
			$targetDir = $user . '/files_encryption/keys/files/' . $filePath . '/' . $this->moduleId . '/' . $filename;
		}

		if ($user === '') {
			// for system wide mounts we need to check if the mount point really exists
			$normalized = \OC\Files\Filesystem::normalizePath($filePath);
			$systemMountPoints = $this->getSystemMountPoints();
			foreach ($systemMountPoints as $mountPoint) {
				$normalizedMountPoint = \OC\Files\Filesystem::normalizePath($mountPoint['mountpoint']) . '/';
				if (\strpos($normalized, $normalizedMountPoint) === 0) {
					return $targetDir;
				}
			}
		} elseif ($trash === false && $this->view->file_exists('/' . $user . '/files/' . $filePath)) {
			return $targetDir;
		} elseif ($trash === true && $this->view->file_exists('/' . $user . '/files_trashbin/' . $filePath)) {
			return $targetDir;
		}

		return false;
	}

	/**
	 * delete old keys
	 *
	 * @param string $user
	 */
	private function deleteOldKeys(string $user): void {
		$this->view->deleteAll($user . '/files_encryption/keyfiles');
		$this->view->deleteAll($user . '/files_encryption/share-keys');
	}

	/**
	 * create directories for the keys recursively
	 *
	 * @param string $path
	 */
	private function createPathForKeys(string $path): void {
		if (!$this->view->file_exists($path)) {
			$sub_dirs = \explode('/', $path);
			$dir = '';
			foreach ($sub_dirs as $sub_dir) {
				$dir .= '/' . $sub_dir;
				if (!$this->view->is_dir($dir)) {
					$this->view->mkdir($dir);
				}
			}
		}
	}
}
