<?php

declare(strict_types=1);
/**
 * @author Björn Schießle <bjoern@schiessle.org>
 * @author Clark Tomlinson <fallen013@gmail.com>
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

namespace OCA\Encryption\Hooks;

use OC\Files\Filesystem;
use OCP\IConfig;
use OCP\IUserManager;
use OCA\Encryption\Hooks\Contracts\IHook;
use OCA\Encryption\KeyManager;
use OCA\Encryption\Crypto\Crypt;
use OCA\Encryption\Users\Setup;
use OCP\App;
use OCP\ILogger;
use OCP\IUserSession;
use OCA\Encryption\Util;
use OCA\Encryption\Session;
use OCA\Encryption\Recovery;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\GenericEvent;

class UserHooks implements IHook {
	public function __construct(
		private readonly KeyManager $keyManager,
		private readonly IUserManager $userManager,
		private readonly ILogger $logger,
		private readonly Setup $userSetup,
		private readonly IUserSession $user,
		private readonly Util $util,
		private readonly Session $session,
		private readonly Crypt $crypt,
		private readonly Recovery $recovery,
		private readonly IConfig $config,
		private readonly EventDispatcherInterface $eventDispatcher
	) {
	}

	/**
	 * Connects Hooks
	 */
	#[\Override]
	public function addHooks(): void {
		$this->eventDispatcher->addListener('user.afterlogin', [$this, 'login']);
		$this->eventDispatcher->addListener('user.beforelogout', [$this, 'logout']);

		// this hooks only make sense if no master key is used
		if ($this->util->isMasterKeyEnabled() === false) {
			$this->eventDispatcher->addListener('user.aftersetpassword', [$this, 'setPassphrase']);
			$this->eventDispatcher->addListener('user.beforesetpassword', [$this, 'preSetPassphrase']);
			$this->eventDispatcher->addListener('user.aftercreate', [$this, 'postCreateUser']);
			$this->eventDispatcher->addListener('user.afterdelete', [$this, 'postDeleteUser']);
		}
	}

	/**
	 * Startup encryption backend upon user login
	 *
	 * @note This method should never be called for users using client side encryption
	 * @return boolean|null|void
	 */
	public function login(GenericEvent $params) {
		if (!App::isEnabled('encryption')) {
			return true;
		}

		// ensure filesystem is loaded
		if (!\OC\Files\Filesystem::$loaded) {
			$this->setupFS($params->getArgument('uid'));
		}
		if ($this->util->isMasterKeyEnabled() === false) {
			$this->userSetup->setupUser($params->getArgument('uid'), $params->getArgument('password'));
		}

		$this->keyManager->init($params->getArgument('uid'), $params->getArgument('password'));
	}

	/**
	 * remove keys from session during logout
	 */
	public function logout(): void {
		$this->session->clear();
	}

	/**
	 * setup encryption backend upon user created
	 *
	 * @note This method should never be called for users using client side encryption
	 */
	public function postCreateUser(GenericEvent $params): void {
		if (App::isEnabled('encryption')) {
			$this->userSetup->setupUser($params->getArgument('uid'), $params->getArgument('password'));
		}
	}

	/**
	 * cleanup encryption backend upon user deleted
	 *
	 * @note This method should never be called for users using client side encryption
	 */
	public function postDeleteUser(GenericEvent $params): void {
		if (App::isEnabled('encryption')) {
			/**
			 * Adding a safe condition to make sure the uid is not
			 * empty or null.
			 */
			if ($params->getArgument('uid') !== null && $params->getArgument('uid') !== '') {
				$this->keyManager->deletePublicKey($params->getArgument('uid'));
				\OC::$server->getEncryptionKeyStorage()->deleteAltUserStorageKeys($params->getArgument('uid'));
			}
		}
	}

	/**
	 * If the password can't be changed within ownCloud, than update the key password in advance.
	 *
	 * @param GenericEvent $params : uid, password
	 */
	public function preSetPassphrase(GenericEvent $params): void {
		if (App::isEnabled('encryption')) {
			$user = $params->getArgument('user');
			if ($user && !$user->canChangePassword()) {
				$this->setPassphrase($params);
			}
		}
	}

	/**
	 * Change a user's encryption passphrase
	 *
	 * @param GenericEvent $params keys: uid, password
	 */
	public function setPassphrase(GenericEvent $params): void {
		$privateKey = null;
		$user = null;
		$userFromParams = $params->getArgument('user');
		$userIdFromParams = $userFromParams->getUID();

		//Check if the session is there or not
		if ($this->user->getUser() !== null) {
			// Get existing decrypted private key
			$privateKey = $this->session->getPrivateKey();
			$user = $this->user->getUser();
		}

		// current logged in user changes his own password
		if ($user !== null && $userIdFromParams === $user->getUID() && $privateKey) {
			// Encrypt private key with new user pwd as passphrase
			$encryptedPrivateKey = $this->crypt->encryptPrivateKey($privateKey, $params->getArgument('password'), $userIdFromParams);

			// Save private key
			if ($encryptedPrivateKey) {
				$this->keyManager->setPrivateKey(
					$this->user->getUser()->getUID(),
					$this->crypt->generateHeader() . $encryptedPrivateKey
				);
			} else {
				$this->logger->error('Encryption could not update users encryption password');
			}

			// NOTE: Session does not need to be updated as the
			// private key has not changed, only the passphrase
			// used to decrypt it has changed
		} else { // admin changed the password for a different user, create new keys and re-encrypt file keys
			$user = $userIdFromParams;
			$this->initMountPoints($user);
			$recoveryPassword = $params->hasArgument('recoveryPassword') ? $params->getArgument('recoveryPassword') : null;

			// we generate new keys if...
			// ...we have a recovery password and the user enabled the recovery key
			// ...encryption was activated for the first time (no keys exists)
			// ...the user doesn't have any files
			if (
				($this->recovery->isRecoveryEnabledForUser($user) && $recoveryPassword)
				|| !$this->keyManager->userHasKeys($user)
				|| !$this->util->userHasFiles($user)
			) {
				// backup old keys
				//$this->backupAllKeys('recovery');

				$newUserPassword = $params->getArgument('password');

				$keyPair = $this->crypt->createKeyPair();

				// Save public key
				$this->keyManager->setPublicKey($user, $keyPair['publicKey']);

				// Encrypt private key with new password
				$encryptedKey = $this->crypt->encryptPrivateKey($keyPair['privateKey'], $newUserPassword, $user);

				if ($encryptedKey) {
					$this->keyManager->setPrivateKey($user, $this->crypt->generateHeader() . $encryptedKey);

					if ($recoveryPassword) { // if recovery key is set we can re-encrypt the key files
						$this->recovery->recoverUsersFiles($recoveryPassword, $user);
					}
				} else {
					$this->logger->error('Encryption Could not update users encryption password');
				}
			}
		}
	}

	/**
	 * init mount points for given user
	 *
	 * @throws \OC\User\NoUserException
	 */
	protected function initMountPoints(string $user): void {
		Filesystem::initMountPoints($user);
	}

	/**
	 * after password reset we create a new key pair for the user
	 */
	public function postPasswordReset(array $params): void {
		$password = $params['password'];

		$this->keyManager->deleteUserKeys($params['uid']);
		$this->userSetup->setupUser($params['uid'], $password);
	}

	/**
	 * setup file system for user
	 *
	 * @param string $uid user id
	 */
	protected function setupFS(string $uid): void {
		\OC_Util::setupFS($uid);
	}
}
