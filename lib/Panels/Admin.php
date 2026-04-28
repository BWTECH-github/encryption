<?php

declare(strict_types=1);
/**
 * @author Tom Needham <tom@owncloud.com>
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
namespace OCA\Encryption\Panels;

use OCP\IL10N;
use OCP\Settings\ISettings;
use OCP\Template;
use OCA\Encryption\Crypto\Crypt;
use OCA\Encryption\Util;
use OC\Files\View;
use OCP\IConfig;
use OCA\Encryption\Session;
use OCP\ILogger;
use OCP\IUserManager;
use OCP\ISession;
use OCP\IUserSession;

class Admin implements ISettings {
	public function __construct(
		protected readonly IConfig $config,
		protected readonly ILogger $logger,
		protected readonly IUserSession $userSession,
		protected readonly IUserManager $userManager,
		protected readonly ISession $session,
		protected readonly IL10N $l
	) {
	}

	#[\Override]
	public function getPriority(): int {
		return 0;
	}

	#[\Override]
	public function getSectionID(): string {
		return 'encryption';
	}

	#[\Override]
	public function getPanel() {
		$tmpl = new Template('encryption', 'settings-admin');
		$crypt = new Crypt(
			$this->logger,
			$this->userSession,
			$this->config,
			$this->l
		);
		$util = new Util(
			new View(),
			$crypt,
			$this->logger,
			$this->userSession,
			$this->config,
			$this->userManager
		);
		// Check if an adminRecovery account is enabled for recovering files after lost pwd
		$recoveryAdminEnabled = $this->config->getAppValue('encryption', 'recoveryAdminEnabled', '0');
		$session = new Session($this->session);
		$encryptHomeStorage = $util->shouldEncryptHomeStorage();
		$tmpl->assign('recoveryEnabled', $recoveryAdminEnabled);
		$tmpl->assign('initStatus', $session->getStatus());
		$tmpl->assign('encryptHomeStorage', $encryptHomeStorage);
		$tmpl->assign('masterKeyEnabled', $util->isMasterKeyEnabled());
		return $tmpl;
	}
}
