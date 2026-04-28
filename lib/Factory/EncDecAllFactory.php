<?php

declare(strict_types=1);
/**
 * @author Sujith Haridasan <sharidasan@owncloud.com>
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

namespace OCA\Encryption\Factory;

use OC\Encryption\DecryptAll;
use OC\Encryption\Manager;
use OC\Files\View;
use OCA\Encryption\Crypto\Crypt;
use OCA\Encryption\Crypto\CryptHSM;
use OCA\Encryption\Crypto\EncryptAll;
use OCA\Encryption\KeyManager;
use OCA\Encryption\Session;
use OCA\Encryption\Users\Setup;
use OCA\Encryption\Util;
use OCP\Encryption\Keys\IStorage;
use OCP\IConfig;
use OCP\IL10N;
use OCP\ILogger;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Mail\IMailer;
use OCP\Security\ISecureRandom;
use Symfony\Component\Console\Helper\QuestionHelper;

class EncDecAllFactory {
	public function __construct(
		private readonly Manager $encryptionManager,
		private readonly IUserManager $userManager,
		private readonly ILogger $logger,
		private readonly Util $encUtil,
		private readonly IConfig $config,
		private readonly IMailer $mailer,
		private readonly IL10N $l10n,
		private readonly QuestionHelper $questionHelper,
		private readonly ISecureRandom $secureRandom,
		private readonly IStorage $encStorage,
		private readonly Session $encSession,
		private readonly CryptHSM $cryptHSM,
		private readonly Crypt $crypt,
		private readonly IUserSession $userSession
	) {
	}

	/**
	 * Returns DecryptAll object
	 */
	public function getDecryptAllObj(): DecryptAll {
		$rootView = new View("/");
		return new DecryptAll($this->encryptionManager, $this->userManager, $rootView, $this->logger);
	}

	/**
	 * Returns EncryptAll object
	 */
	public function getEncryptAllObj(): EncryptAll {
		$rootView = new View("/");

		/**
		 * The new KeyManager object is used here because of two reasons:
		 * 1. Setup class depends on KeyManager, which depends on crypto engine
		 * 2. EncryptAll also depends on KeyManager, which depends on crypto engine
		 */
		$keyManager = new KeyManager(
			$this->encStorage,
			$this->getCryptoEngine(),
			$this->config,
			$this->userSession,
			$this->encSession,
			$this->logger,
			$this->encUtil
		);
		$userSetup = new Setup($this->logger, $this->userSession, $this->getCryptoEngine(), $keyManager);
		return new EncryptAll(
			$userSetup,
			$this->userManager,
			$rootView,
			$keyManager,
			$this->encUtil,
			$this->config,
			$this->mailer,
			$this->l10n,
			$this->questionHelper,
			$this->secureRandom
		);
	}

	/**
	 * Returns CryptHSM if crypto engine set to
	 * hsm else returns Crypt
	 *
	 * @return Crypt|CryptHSM
	 */
	private function getCryptoEngine() {
		if ($this->config->getAppValue('crypto.engine', 'internal', '') === 'hsm') {
			return $this->cryptHSM;
		}

		return $this->crypt;
	}
}
