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

use OCP\Encryption\Keys\IStorage;
use OCP\IConfig;
use OCP\IL10N;
use OCP\ILogger;
use OCP\ISession;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Settings\ISettings;
use OCP\Template;

class Personal implements ISettings {
	public function __construct(
		protected readonly ILogger $logger,
		protected readonly IUserSession $userSession,
		protected readonly IConfig $config,
		protected readonly IL10N $l,
		protected readonly IUserManager $userManager,
		protected readonly ISession $session,
		protected readonly IStorage $encKeyStorage
	) {
	}

	#[\Override]
	public function getPriority(): int {
		return 0;
	}

	#[\Override]
	public function getSectionID(): string {
		// Nichts einzustellen: dann hängt das Panel am Profil und liefert dort
		// nichts (getPanel()). Ein eigener Bereich „Verschlüsselung“ stünde
		// sonst für jedes Konto leer in der Navigation.
		return $this->isRelevant() ? 'encryption' : 'general';
	}

	/**
	 * Gibt es für das Konto etwas einzustellen? Bei eingeschalteter
	 * serverseitiger Verschlüsselung immer; sonst nur, wenn das Schlüssel-
	 * kennwort nicht mehr zum Anmeldekennwort passt - die App registriert ihre
	 * Hooks über isReady(), nicht über den Schalter (Gegen-Review 23.09.2026).
	 *
	 * Der Manager kommt über den Server, nicht über den Konstruktor:
	 * OCP\Encryption\IManager ist im App-Container nicht registriert, der Kern
	 * fiele dann auf den Server-Container zurück und könnte das Panel gar nicht
	 * mehr bauen („Could not resolve OCP\IL10N“, Sektion leer).
	 */
	private function isRelevant(): bool {
		if (\OC::$server->getEncryptionManager()->isEnabled()) {
			return true;
		}
		$session = new \OCA\Encryption\Session($this->session);
		return $session->getStatus() === \OCA\Encryption\Session::INIT_EXECUTED;
	}

	/**
	 * @return \OCP\AppFramework\Http\TemplateResponse|Template|null
	 */
	#[\Override]
	public function getPanel() {
		if (!$this->isRelevant()) {
			return null;
		}
		$session = new \OCA\Encryption\Session($this->session);
		$template = new Template('encryption', 'settings-personal');
		$crypt = new \OCA\Encryption\Crypto\Crypt(
			$this->logger,
			$this->userSession,
			$this->config,
			$this->l
		);

		$util = new \OCA\Encryption\Util(
			new \OC\Files\View(),
			$crypt,
			$this->logger,
			$this->userSession,
			$this->config,
			$this->userManager
		);

		$user = $this->userSession->getUser()->getUID();
		$privateKeySet = $session->isPrivateKeySet();

		// did we tried to initialize the keys for this session?
		$initialized = $session->getStatus();
		$recoveryAdminEnabled = $this->config->getAppValue('encryption', 'recoveryAdminEnabled');
		$recoveryEnabledForUser = $util->isRecoveryEnabledForUser($user);
		// Frueher wurde hier null zurueckgegeben (Master-Key + initialisierter
		// Schluessel + kein Recovery) — dadurch blieb die Sektion
		// "Verschluesselung" in den persoenlichen Einstellungen komplett leer.
		// Das Template zeigt fuer diesen Fall jetzt einen Info-Hinweis an.
		$template->assign('recoveryEnabled', $recoveryAdminEnabled);
		$template->assign('recoveryEnabledForUser', $recoveryEnabledForUser);
		$template->assign('privateKeySet', $privateKeySet);
		$template->assign('initialized', $initialized);
		return $template;
	}
}
