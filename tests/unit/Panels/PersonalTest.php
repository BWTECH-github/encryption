<?php
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

namespace OCA\Encryption\Tests\Panels;

use OCA\Encryption\Panels\Personal;
use OCP\Encryption\Keys\IStorage;
use OCP\IConfig;
use OCP\IL10N;
use OCP\ILogger;
use OCP\ISession;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;

/**
 * @package OCA\Encryption\Tests\Panels
 */
class PersonalTest extends \Test\TestCase {
	/** @var Personal */
	private $panel;
	/** @var IConfig */
	private $config;
	/** @var ILogger */
	private $logger;
	/** @var IUserSession */
	private $userSession;
	/** @var IUserManager */
	private $userManager;
	/** @var ISession */
	private $session;
	/** @var IL10N */
	private $l;
	/** @var IStorage */
	private $encKeyStorage;

	public function setUp(): void {
		parent::setUp();
		$this->config = $this->getMockBuilder(IConfig::class)->getMock();
		$this->logger = $this->getMockBuilder(ILogger::class)->getMock();
		$this->userSession = $this->getMockBuilder(IUserSession::class)->getMock();
		$this->userManager = $this->getMockBuilder(IUserManager::class)->getMock();
		$this->session = $this->getMockBuilder(ISession::class)->getMock();
		$this->l = $this->getMockBuilder(IL10N::class)->getMock();
		$this->encKeyStorage = $this->getMockBuilder(IStorage::class)->getMock();
		$this->panel = new Personal(
			$this->logger,
			$this->userSession,
			$this->config,
			$this->l,
			$this->userManager,
			$this->session,
			$this->encKeyStorage
		);
	}

	public function tearDown(): void {
		$this->restoreService('EncryptionManager');
		parent::tearDown();
	}

	private function encryptionEnabled(bool $enabled): void {
		$manager = $this->createMock(\OCP\Encryption\IManager::class);
		$manager->method('isEnabled')->willReturn($enabled);
		$this->overwriteService('EncryptionManager', $manager);
	}

	public function testGetSection() {
		$this->encryptionEnabled(true);
		$this->assertEquals('encryption', $this->panel->getSectionID());
	}

	/**
	 * Ohne eingeschaltete Verschlüsselung und ohne Handlungsbedarf gibt es
	 * keinen eigenen Bereich und keine Karte.
	 */
	public function testNothingToConfigureWithoutEncryption() {
		$this->encryptionEnabled(false);
		$this->assertEquals('general', $this->panel->getSectionID());
		$this->assertNull($this->panel->getPanel());
	}

	/**
	 * Passt das Schlüsselkennwort nicht mehr, bleibt der Bereich - auch bei
	 * ausgeschalteter Verschlüsselung.
	 */
	public function testKeyPasswordMismatchWithoutEncryption() {
		$this->encryptionEnabled(false);
		$this->session->method('get')->willReturn(\OCA\Encryption\Session::INIT_EXECUTED);
		$this->assertEquals('encryption', $this->panel->getSectionID());
	}

	public function testGetPriority() {
		$this->assertTrue(\is_integer($this->panel->getPriority()));
	}

	public function testGetPanel() {
		$this->encryptionEnabled(true);
		$mockUser = $this->getMockBuilder(IUser::class)->getMock();
		$mockUser->expects($this->once())->method('getUID')->willReturn('testUser');
		$this->userSession->expects($this->once())->method('getUser')->willReturn($mockUser);
		$templateHtml = $this->panel->getPanel()->fetchPage();
		$this->assertStringContainsString('<form id="ocDefaultEncryptionModule" class="section">', $templateHtml);
	}
}
