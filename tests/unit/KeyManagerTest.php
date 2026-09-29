<?php
/**
 * @author Björn Schießle <bjoern@schiessle.org>
 * @author Clark Tomlinson <fallen013@gmail.com>
 * @author Joas Schilling <coding@schilljs.com>
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

namespace OCA\Encryption\Tests;

use OCA\Encryption\KeyManager;
use OCA\Encryption\Session;
use Test\TestCase;

class KeyManagerTest extends TestCase {
	/**
	 * @var KeyManager
	 */
	private $instance;
	/**
	 * @var string
	 */
	private $userId;

	/** @var string */
	private $systemKeyId;

	/** @var \OCP\Encryption\Keys\IStorage|\PHPUnit\Framework\MockObject\MockObject */
	private $keyStorageMock;

	/** @var \OCA\Encryption\Crypto\Crypt|\PHPUnit\Framework\MockObject\MockObject */
	private $cryptMock;

	/** @var \OCP\IUserSession|\PHPUnit\Framework\MockObject\MockObject */
	private $userMock;

	/** @var \OCA\Encryption\Session|\PHPUnit\Framework\MockObject\MockObject */
	private $sessionMock;

	/** @var \OCP\ILogger|\PHPUnit\Framework\MockObject\MockObject */
	private $logMock;

	/** @var \OCA\Encryption\Util|\PHPUnit\Framework\MockObject\MockObject */
	private $utilMock;

	/** @var \OCP\IConfig|\PHPUnit\Framework\MockObject\MockObject */
	private $configMock;

	public function setUp(): void {
		parent::setUp();
		$this->userId = 'user1';
		$this->systemKeyId = 'systemKeyId';
		$this->keyStorageMock = $this->createMock('OCP\Encryption\Keys\IStorage');
		$this->cryptMock = $this->getMockBuilder('OCA\Encryption\Crypto\Crypt')
			->disableOriginalConstructor()
			->getMock();
		$this->configMock = $this->createMock('OCP\IConfig');
		$this->configMock->expects($this->any())
			->method('getAppValue')
			->will($this->returnCallback([$this, 'returnAppValue']));
		$this->userMock = $this->createMock('OCP\IUserSession');
		$this->sessionMock = $this->getMockBuilder('OCA\Encryption\Session')
			->disableOriginalConstructor()
			->getMock();
		$this->logMock = $this->createMock('OCP\ILogger');
		$this->utilMock = $this->getMockBuilder('OCA\Encryption\Util')
			->disableOriginalConstructor()
			->getMock();

		$this->instance = new KeyManager(
			$this->keyStorageMock,
			$this->cryptMock,
			$this->configMock,
			$this->userMock,
			$this->sessionMock,
			$this->logMock,
			$this->utilMock
		);
	}

	public function returnAppValue() {
		$args = \func_get_args();
		if ($args[1] === 'masterKeyId') {
			return 'masterKeyId';
		} else {
			return 'systemKeyId';
		}
	}

	public function testDeleteShareKey() {
		$this->keyStorageMock->expects($this->any())
			->method('deleteFileKey')
			->with($this->equalTo('/path'), $this->equalTo('keyId.shareKey'))
			->willReturn(true);

		$this->assertTrue(
			$this->instance->deleteShareKey('/path', 'keyId')
		);
	}

	public function testGetPrivateKey() {
		$this->keyStorageMock->expects($this->any())
			->method('getUserKey')
			->with($this->equalTo($this->userId), $this->equalTo('privateKey'))
			->willReturn('privateKey');

		$this->assertSame(
			'privateKey',
			$this->instance->getPrivateKey($this->userId)
		);
	}

	public function testGetPublicKey() {
		$this->keyStorageMock->expects($this->any())
			->method('getUserKey')
			->with($this->equalTo($this->userId), $this->equalTo('publicKey'))
			->willReturn('publicKey');

		$this->assertSame(
			'publicKey',
			$this->instance->getPublicKey($this->userId)
		);
	}

	public function testRecoveryKeyExists() {
		$this->keyStorageMock->expects($this->any())
			->method('getSystemUserKey')
			->with($this->equalTo($this->systemKeyId . '.publicKey'))
			->willReturn('recoveryKey');

		$this->assertTrue($this->instance->recoveryKeyExists());
	}

	public function testCheckRecoveryKeyPassword() {
		$this->keyStorageMock->expects($this->any())
			->method('getSystemUserKey')
			->with($this->equalTo($this->systemKeyId . '.privateKey'))
			->willReturn('recoveryKey');
		$this->cryptMock->expects($this->any())
			->method('decryptPrivateKey')
			->with($this->equalTo('recoveryKey'), $this->equalTo('pass'))
			->willReturn('decryptedRecoveryKey');

		$this->assertTrue($this->instance->checkRecoveryPassword('pass'));
	}

	public function testSetPublicKey() {
		$this->keyStorageMock->expects($this->any())
			->method('setUserKey')
			->with(
				$this->equalTo($this->userId),
				$this->equalTo('publicKey'),
				$this->equalTo('key')
			)
			->willReturn(true);

		$this->assertTrue(
			$this->instance->setPublicKey($this->userId, 'key')
		);
	}

	public function testSetPrivateKey() {
		$this->keyStorageMock->expects($this->any())
			->method('setUserKey')
			->with(
				$this->equalTo($this->userId),
				$this->equalTo('privateKey'),
				$this->equalTo('key')
			)
			->willReturn(true);

		$this->assertTrue(
			$this->instance->setPrivateKey($this->userId, 'key')
		);
	}

	/**
	 * @dataProvider dataTestUserHasKeys
	 */
	public function testUserHasKeys($key, $expected) {
		$this->keyStorageMock->expects($this->exactly(2))
			->method('getUserKey')
			->with($this->equalTo($this->userId), $this->anything())
			->willReturn($key);

		$this->assertSame(
			$expected,
			$this->instance->userHasKeys($this->userId)
		);
	}

	public function dataTestUserHasKeys() {
		return [
			['key', true],
			['', false]
		];
	}

	/**
	 */
	public function testUserHasKeysMissingPrivateKey() {
		$this->expectException(\OCA\Encryption\Exceptions\PrivateKeyMissingException::class);

		$this->keyStorageMock->expects($this->exactly(2))
			->method('getUserKey')
			->willReturnCallback(function ($uid, $keyID, $encryptionModuleId) {
				if ($keyID=== 'privateKey') {
					return '';
				}
				return 'key';
			});

		$this->instance->userHasKeys($this->userId);
	}

	/**
	 */
	public function testUserHasKeysMissingPublicKey() {
		$this->expectException(\OCA\Encryption\Exceptions\PublicKeyMissingException::class);

		$this->keyStorageMock->expects($this->exactly(2))
			->method('getUserKey')
			->willReturnCallback(function ($uid, $keyID, $encryptionModuleId) {
				if ($keyID === 'publicKey') {
					return '';
				}
				return 'key';
			});

		$this->instance->userHasKeys($this->userId);
	}

	/**
	 * @dataProvider dataTestInit
	 *
	 * @param bool $useMasterKey
	 */
	public function testInit($useMasterKey) {
		/** @var \OCA\Encryption\KeyManager|\PHPUnit\Framework\MockObject\MockObject $instance */
		$instance = $this->getMockBuilder('OCA\Encryption\KeyManager')
			->setConstructorArgs(
				[
					$this->keyStorageMock,
					$this->cryptMock,
					$this->configMock,
					$this->userMock,
					$this->sessionMock,
					$this->logMock,
					$this->utilMock
				]
			)->setMethods(['getMasterKeyId', 'getMasterKeyPassword', 'getSystemPrivateKey', 'getPrivateKey'])
			->getMock();

		$this->utilMock->expects($this->once())->method('isMasterKeyEnabled')
			->willReturn($useMasterKey);

		$this->sessionMock
			->expects($this->exactly(2))
			->method('setStatus')
			->withConsecutive([Session::INIT_EXECUTED]);

		$instance->expects($this->any())->method('getMasterKeyId')->willReturn('masterKeyId');
		$instance->expects($this->any())->method('getMasterKeyPassword')->willReturn('masterKeyPassword');
		$instance->expects($this->any())->method('getSystemPrivateKey')->with('masterKeyId')->willReturn('privateMasterKey');
		$instance->expects($this->any())->method('getPrivateKey')->with($this->userId)->willReturn('privateUserKey');

		if ($useMasterKey) {
			$this->cryptMock->expects($this->once())->method('decryptPrivateKey')
				->with('privateMasterKey', 'masterKeyPassword', 'masterKeyId')
				->willReturn('key');
		} else {
			$this->cryptMock->expects($this->once())->method('decryptPrivateKey')
				->with('privateUserKey', 'pass', $this->userId)
				->willReturn('key');
		}

		$this->sessionMock->expects($this->once())->method('setPrivateKey')
			->with('key');

		$this->assertTrue($instance->init($this->userId, 'pass'));
	}

	public function dataTestInit() {
		return [
			[true],
			[false]
		];
	}

	public function testSetRecoveryKey() {
		$this->keyStorageMock->expects($this->exactly(2))
			->method('setSystemUserKey')
			->willReturn(true);
		$this->cryptMock->expects($this->any())
			->method('encryptPrivateKey')
			->with($this->equalTo('privateKey'), $this->equalTo('pass'))
			->willReturn('decryptedPrivateKey');

		$this->assertTrue(
			$this->instance->setRecoveryKey(
				'pass',
				['publicKey' => 'publicKey', 'privateKey' => 'privateKey']
			)
		);
	}

	public function testSetSystemPrivateKey() {
		$this->keyStorageMock->expects($this->exactly(1))
			->method('setSystemUserKey')
			->with($this->equalTo('keyId.privateKey'), $this->equalTo('key'))
			->willReturn(true);

		$this->assertTrue(
			$this->instance->setSystemPrivateKey('keyId', 'key')
		);
	}

	public function testGetSystemPrivateKey() {
		$this->keyStorageMock->expects($this->exactly(1))
			->method('getSystemUserKey')
			->with($this->equalTo('keyId.privateKey'))
			->willReturn('systemPrivateKey');

		$this->assertSame(
			'systemPrivateKey',
			$this->instance->getSystemPrivateKey('keyId')
		);
	}

	public function testGetEncryptedFileKey() {
		$this->keyStorageMock->expects($this->once())
			->method('getFileKey')
			->with('/', 'fileKey')
			->willReturn('encryptedFileKey');

		$this->assertSame('encryptedFileKey', $this->instance->getEncryptedFileKey('/'));
	}

	/**
	 * $privateKey false = privater Schlüssel nicht verfügbar: für den öffentlichen
	 * Zugriff liefert decryptPrivateKey() dann false, in der Sitzung steht ''.
	 */
	public function dataTestGetFileKey() {
		return [
			['user1', false, 'privateKey', 'fileKey'],
			['user1', false, false, ''],
			['user1', true, 'privateKey', 'fileKey'],
			['user1', true, false, ''],
			[null, false, 'privateKey', 'fileKey'],
			[null, false, false, ''],
			[null, true, 'privateKey', 'fileKey'],
			[null, true, false, '']
		];
	}

	/**
	 * @dataProvider dataTestGetFileKey
	 *
	 * @param $uid
	 * @param $isMasterKeyEnabled
	 * @param $privateKey
	 * @param $expected
	 */
	public function testGetFileKey($uid, $isMasterKeyEnabled, $privateKey, $expected) {
		$path = '/foo.txt';

		if ($isMasterKeyEnabled) {
			$expectedUid = 'masterKeyId';
			$this->configMock->expects($this->any())->method('getSystemValue')->with('secret')
				->willReturn('password');
		} elseif (!$uid) {
			$expectedUid = 'systemKeyId';
		} else {
			$expectedUid = $uid;
		}

		$this->invokePrivate($this->instance, 'masterKeyId', ['masterKeyId']);

		$this->keyStorageMock
			->expects($this->exactly(2))
			->method('getFileKey')
			->withConsecutive(
				[$path, 'fileKey', 'OC_DEFAULT_MODULE'],
				[$path, $expectedUid . '.shareKey', 'OC_DEFAULT_MODULE'],
			)
			->willReturnOnConsecutiveCalls('encryptedFileKey', 'shareKey');

		$this->utilMock->expects($this->any())->method('isMasterKeyEnabled')
			->willReturn($isMasterKeyEnabled);

		if ($uid === null) {
			$this->keyStorageMock->expects($this->once())
				->method('getSystemUserKey')
				->willReturn('encryptedSystemPrivateKey');
			$this->cryptMock->expects($this->once())
				->method('decryptPrivateKey')
				->willReturn($privateKey);
		} else {
			$this->keyStorageMock->expects($this->never())
				->method('getSystemUserKey');
			$this->sessionMock->expects($this->once())->method('getPrivateKey')->willReturn($privateKey ?: '');
		}

		if ($privateKey) {
			$this->cryptMock->expects($this->once())
				->method('multiKeyDecrypt')
				->with('encryptedFileKey', 'shareKey', $privateKey)
				->willReturn('fileKey');
		} else {
			$this->cryptMock->expects($this->never())
				->method('multiKeyDecrypt');
		}

		$this->assertSame(
			$expected,
			$this->instance->getFileKey($path, $uid)
		);
	}

	public function testDeletePrivateKey() {
		$this->keyStorageMock->expects($this->once())
			->method('deleteUserKey')
			->with('user1', 'privateKey')
			->willReturn(true);

		$this->assertTrue(self::invokePrivate(
			$this->instance,
			'deletePrivateKey',
			[$this->userId]
		));
	}

	public function testDeleteAllFileKeys() {
		$this->keyStorageMock->expects($this->once())
			->method('deleteAllFileKeys')
			->willReturn(true);

		$this->assertTrue($this->instance->deleteAllFileKeys('/'));
	}

	/**
	 * test add public share key and or recovery key to the list of public keys
	 *
	 * @dataProvider dataTestAddSystemKeys
	 *
	 * @param array $accessList
	 * @param array $publicKeys
	 * @param string $uid
	 * @param array $expectedKeys
	 */
	public function testAddSystemKeys($accessList, $publicKeys, $uid, $expectedKeys) {
		$publicShareKeyId = 'publicShareKey';
		$recoveryKeyId = 'recoveryKey';

		$this->keyStorageMock->expects($this->any())
			->method('getSystemUserKey')
			->willReturnCallback(function ($keyId, $encryptionModuleId) {
				return $keyId;
			});

		$this->utilMock->expects($this->any())
			->method('isRecoveryEnabledForUser')
			->willReturnCallback(function ($uid) {
				if ($uid === 'user1') {
					return true;
				}
				return false;
			});

		// set key IDs
		self::invokePrivate($this->instance, 'publicShareKeyId', [$publicShareKeyId]);
		self::invokePrivate($this->instance, 'recoveryKeyId', [$recoveryKeyId]);

		$result = $this->instance->addSystemKeys($accessList, $publicKeys, $uid);

		foreach ($expectedKeys as $expected) {
			$this->assertArrayHasKey($expected, $result);
		}

		$this->assertSameSize($expectedKeys, $result);
	}

	/**
	 * data provider for testAddSystemKeys()
	 *
	 * @return array
	 */
	public function dataTestAddSystemKeys() {
		return [
			[['public' => true],[], 'user1', ['publicShareKey', 'recoveryKey']],
			[['public' => false], [], 'user1', ['recoveryKey']],
			[['public' => true],[], 'user2', ['publicShareKey']],
			[['public' => false], [], 'user2', []],
		];
	}

	/**
	 * Ohne Nutzer (öffentlicher Link, Kommandozeile) gibt es keinen Wiederherstellungs-
	 * schlüssel eines Nutzers, wohl aber den Schlüssel für öffentliche Links.
	 */
	public function testAddSystemKeysWithoutUser() {
		$this->keyStorageMock->expects($this->any())
			->method('getSystemUserKey')
			->willReturnCallback(function ($keyId, $encryptionModuleId) {
				return $keyId;
			});
		$this->utilMock->expects($this->never())->method('isRecoveryEnabledForUser');
		self::invokePrivate($this->instance, 'publicShareKeyId', ['publicShareKey']);
		self::invokePrivate($this->instance, 'recoveryKeyId', ['recoveryKey']);

		$result = $this->instance->addSystemKeys(['public' => true], [], null);

		$this->assertSame(['publicShareKey' => 'publicShareKey.publicKey'], $result);
	}

	public function dataLoginWithoutPassword() {
		return [
			'OAuth2 (null)' => [null],
			'OpenID Connect, Token ohne Kennwort (leer)' => [''],
		];
	}

	private function getInitInstance() {
		return $this->getMockBuilder('OCA\Encryption\KeyManager')
			->setConstructorArgs(
				[
					$this->keyStorageMock,
					$this->cryptMock,
					$this->configMock,
					$this->userMock,
					$this->sessionMock,
					$this->logMock,
					$this->utilMock
				]
			)->onlyMethods(['getMasterKeyId', 'getMasterKeyPassword', 'getSystemPrivateKey', 'getPrivateKey'])
			->getMock();
	}

	/**
	 * Master-Key: Die Passphrase kommt aus dem Master-Key, nicht aus der Anmeldung.
	 * Eine Anmeldung ohne Kennwort (OAuth2-Bearer, OpenID Connect) muss den
	 * Schlüssel genauso öffnen wie upstream.
	 *
	 * @dataProvider dataLoginWithoutPassword
	 */
	public function testInitWithMasterKeyWithoutLoginPassword($password) {
		$instance = $this->getInitInstance();
		$this->utilMock->expects($this->any())->method('isMasterKeyEnabled')->willReturn(true);
		$instance->expects($this->any())->method('getMasterKeyId')->willReturn('masterKeyId');
		$instance->expects($this->any())->method('getMasterKeyPassword')->willReturn('masterKeyPassword');
		$instance->expects($this->once())->method('getSystemPrivateKey')->with('masterKeyId')->willReturn('privateMasterKey');
		$instance->expects($this->never())->method('getPrivateKey');
		$this->cryptMock->expects($this->once())->method('decryptPrivateKey')
			->with('privateMasterKey', 'masterKeyPassword', 'masterKeyId')
			->willReturn('key');
		$this->sessionMock->expects($this->once())->method('setPrivateKey')->with('key');

		$this->assertTrue($instance->init($this->userId, $password));
	}

	/**
	 * Nutzerschlüssel, Anmeldung ohne Kennwort, Schlüssel mit echtem Kennwort
	 * geschützt: sauber false, kein TypeError, eine Warnung.
	 *
	 * @dataProvider dataLoginWithoutPassword
	 */
	public function testInitWithUserKeysWithoutLoginPasswordFailsCleanly($password) {
		$instance = $this->getInitInstance();
		$this->utilMock->expects($this->any())->method('isMasterKeyEnabled')->willReturn(false);
		$instance->expects($this->once())->method('getPrivateKey')->with($this->userId)->willReturn('privateUserKey');
		$this->cryptMock->expects($this->once())->method('decryptPrivateKey')
			->with('privateUserKey', '', $this->userId)
			->willThrowException(new \OC\HintException('Bad Signature'));
		$this->sessionMock->expects($this->once())->method('setStatus')->with(Session::INIT_EXECUTED);
		$this->sessionMock->expects($this->never())->method('setPrivateKey');
		$this->logMock->expects($this->once())->method('warning');

		$this->assertFalse($instance->init($this->userId, $password));
	}

	/**
	 * Bestand von 10.x mit Anmeldung ohne Kennwort (Apache/SSO): Der Schlüssel
	 * wurde dort mit leerem Kennwort abgelegt und muss weiter aufgehen.
	 *
	 * @dataProvider dataLoginWithoutPassword
	 */
	public function testInitWithUserKeysWithoutLoginPasswordOpensEmptyPasswordKey($password) {
		$instance = $this->getInitInstance();
		$this->utilMock->expects($this->any())->method('isMasterKeyEnabled')->willReturn(false);
		$instance->expects($this->once())->method('getPrivateKey')->with($this->userId)->willReturn('privateUserKey');
		$this->cryptMock->expects($this->once())->method('decryptPrivateKey')
			->with('privateUserKey', '', $this->userId)
			->willReturn('key');
		$this->sessionMock->expects($this->once())->method('setPrivateKey')->with('key');

		$this->assertTrue($instance->init($this->userId, $password));
	}

	public function testInitWithUserKeysWithoutUid() {
		$instance = $this->getInitInstance();
		$this->utilMock->expects($this->any())->method('isMasterKeyEnabled')->willReturn(false);
		$instance->expects($this->never())->method('getPrivateKey');
		$this->cryptMock->expects($this->never())->method('decryptPrivateKey');
		$this->sessionMock->expects($this->never())->method('setPrivateKey');

		$this->assertFalse($instance->init(null, 'pass'));
	}

	/**
	 * Letzte Sperre: Kein privater Schlüssel eines Nutzers wird mit leerem
	 * Kennwort abgelegt, egal woher der Aufruf kommt.
	 */
	public function testStoreKeyPairRefusesEmptyPassword() {
		$this->keyStorageMock->expects($this->never())->method('setUserKey');
		$this->cryptMock->expects($this->never())->method('encryptPrivateKey');

		$this->assertFalse(
			$this->instance->storeKeyPair($this->userId, '', ['publicKey' => 'pub', 'privateKey' => 'priv'])
		);
	}

	/**
	 * Öffentlicher Link mit Master-Key: Der Kern übergibt null als uid, der
	 * Dateischlüssel kommt über den Master-Key aus dem System-Schlüsselspeicher.
	 */
	public function testGetFileKeyForPublicLinkWithMasterKey() {
		$path = '/owner/files/foo.txt';
		$this->invokePrivate($this->instance, 'masterKeyId', ['masterKeyId']);
		$this->utilMock->expects($this->any())->method('isMasterKeyEnabled')->willReturn(true);
		$this->configMock->expects($this->any())->method('getSystemValue')->with('secret')->willReturn('secret');
		$this->keyStorageMock->expects($this->any())->method('getFileKey')
			->willReturnMap([
				[$path, 'fileKey', 'OC_DEFAULT_MODULE', 'encryptedFileKey'],
				[$path, 'masterKeyId.shareKey', 'OC_DEFAULT_MODULE', 'masterShareKey'],
			]);
		$this->keyStorageMock->expects($this->once())->method('getSystemUserKey')
			->with('masterKeyId.privateKey', 'OC_DEFAULT_MODULE')
			->willReturn('encryptedMasterKey');
		$this->cryptMock->expects($this->once())->method('decryptPrivateKey')
			->with('encryptedMasterKey', 'secret', 'masterKeyId')
			->willReturn('masterKey');
		$this->sessionMock->expects($this->never())->method('getPrivateKey');
		$this->cryptMock->expects($this->once())->method('multiKeyDecrypt')
			->with('encryptedFileKey', 'masterShareKey', 'masterKey')
			->willReturn('fileKey');

		$this->assertSame('fileKey', $this->instance->getFileKey($path, null));
	}

	/**
	 * Öffentlicher Link mit Nutzerschlüsseln: Der Dateischlüssel kommt über den
	 * Schlüssel für öffentliche Links (pubShare_…), wie upstream.
	 */
	public function testGetFileKeyForPublicLinkWithUserKeys() {
		$path = '/owner/files/foo.txt';
		$this->utilMock->expects($this->any())->method('isMasterKeyEnabled')->willReturn(false);
		$this->keyStorageMock->expects($this->any())->method('getFileKey')
			->willReturnMap([
				[$path, 'fileKey', 'OC_DEFAULT_MODULE', 'encryptedFileKey'],
				[$path, 'systemKeyId.shareKey', 'OC_DEFAULT_MODULE', 'pubShareKey'],
			]);
		$this->keyStorageMock->expects($this->once())->method('getSystemUserKey')
			->with('systemKeyId.privateKey', 'OC_DEFAULT_MODULE')
			->willReturn('encryptedPubSharePrivateKey');
		$this->cryptMock->expects($this->once())->method('decryptPrivateKey')
			->with('encryptedPubSharePrivateKey')
			->willReturn('pubSharePrivateKey');
		$this->sessionMock->expects($this->never())->method('getPrivateKey');
		$this->cryptMock->expects($this->once())->method('multiKeyDecrypt')
			->with('encryptedFileKey', 'pubShareKey', 'pubSharePrivateKey')
			->willReturn('fileKey');

		$this->assertSame('fileKey', $this->instance->getFileKey($path, null));
	}

	public function testGetMasterKeyId() {
		$localConfigMock = $this->createMock('OCP\IConfig');
		$localConfigMock->expects($this->any())
			->method('getAppValue')
			->willReturn($this->systemKeyId);
		$instance = $this->getMockBuilder('OCA\Encryption\KeyManager')
			->setConstructorArgs(
				[
					$this->keyStorageMock,
					$this->cryptMock,
					$localConfigMock,
					$this->userMock,
					$this->sessionMock,
					$this->logMock,
					$this->utilMock
				]
			)->setMethods()->getMock();
		$this->assertSame('systemKeyId', $instance->getMasterKeyId());
	}

	public function testGetPublicMasterKey() {
		$localConfigMock = $this->createMock('OCP\IConfig');
		$localConfigMock->expects($this->any())
			->method('getAppValue')
			->willReturn($this->systemKeyId);
		$instance = $this->getMockBuilder('OCA\Encryption\KeyManager')
			->setConstructorArgs(
				[
					$this->keyStorageMock,
					$this->cryptMock,
					$localConfigMock,
					$this->userMock,
					$this->sessionMock,
					$this->logMock,
					$this->utilMock
				]
			)->setMethods()->getMock();
		$this->keyStorageMock->expects($this->once())->method('getSystemUserKey')
			->with('systemKeyId.publicKey', \OCA\Encryption\Crypto\Encryption::ID)
			->willReturn('publicMasterKey');

		$this->assertSame(
			'publicMasterKey',
			$instance->getPublicMasterKey()
		);
	}

	public function testGetMasterKeyPassword() {
		$this->configMock->expects($this->once())->method('getSystemValue')->with('secret')
			->willReturn('password');

		$this->assertSame(
			'password',
			$this->invokePrivate($this->instance, 'getMasterKeyPassword', [])
		);
	}

	/**
	 */
	public function testGetMasterKeyPasswordException() {
		$this->expectException(\Exception::class);

		$this->configMock->expects($this->once())->method('getSystemValue')->with('secret')
			->willReturn('');

		$this->invokePrivate($this->instance, 'getMasterKeyPassword', []);
	}

	/**
	 * @dataProvider dataTestValidateMasterKey
	 *
	 * @param $masterKey
	 */
	public function testValidateMasterKey($masterKey) {
		$localConfigMock = $this->createMock('OCP\IConfig');
		$returnVal = ($masterKey) ? 'masterKeyId' : $this->systemKeyId;
		$localConfigMock->expects($this->any())
			->method('getAppValue')
			->willReturn($returnVal);

		/** @var \OCA\Encryption\KeyManager | \PHPUnit\Framework\MockObject\MockObject $instance */
		$instance = $this->getMockBuilder('OCA\Encryption\KeyManager')
			->setConstructorArgs(
				[
					$this->keyStorageMock,
					$this->cryptMock,
					$localConfigMock,
					$this->userMock,
					$this->sessionMock,
					$this->logMock,
					$this->utilMock
				]
			)->setMethods(['getPublicMasterKey', 'setSystemPrivateKey', 'getMasterKeyPassword'])
			->getMock();

		// validateMasterKey() tut nur im Master-Key-Betrieb etwas
		$this->utilMock->expects($this->any())->method('isMasterKeyEnabled')->willReturn(true);

		$instance->expects($this->once())->method('getPublicMasterKey')
			->willReturn($masterKey);

		$instance->expects($this->any())->method('getMasterKeyPassword')->willReturn('masterKeyPassword');
		$this->cryptMock->expects($this->any())->method('generateHeader')->willReturn('header');

		if (empty($masterKey)) {
			$this->cryptMock->expects($this->once())->method('createKeyPair')
				->willReturn(['publicKey' => 'public', 'privateKey' => 'private']);
			$this->keyStorageMock->expects($this->once())->method('setSystemUserKey')
				->with('systemKeyId.publicKey', 'public', \OCA\Encryption\Crypto\Encryption::ID);
			$this->cryptMock->expects($this->once())->method('encryptPrivateKey')
				->with('private', 'masterKeyPassword', 'systemKeyId')
				->willReturn('EncryptedKey');
			$instance->expects($this->once())->method('setSystemPrivateKey')
				->with('systemKeyId', 'headerEncryptedKey');
		} else {
			$this->cryptMock->expects($this->never())->method('createKeyPair');
			$this->keyStorageMock->expects($this->never())->method('setSystemUserKey');
			$this->cryptMock->expects($this->never())->method('encryptPrivateKey');
			$instance->expects($this->never())->method('setSystemPrivateKey');
		}

		$instance->validateMasterKey();
	}

	public function dataTestValidateMasterKey() {
		return [
			['masterKey'],
			['']
		];
	}

	public function testGetVersionWithoutFileInfo() {
		$view = $this->getMockBuilder('\\OC\\Files\\View')
			->disableOriginalConstructor()->getMock();
		$view->expects($this->once())
			->method('getFileInfo')
			->with('/admin/files/myfile.txt')
			->willReturn(false);

		/** @var \OC\Files\View $view */
		$this->assertSame(0, $this->instance->getVersion('/admin/files/myfile.txt', $view));
	}

	public function testGetVersionWithFileInfo() {
		$view = $this->getMockBuilder('\\OC\\Files\\View')
			->disableOriginalConstructor()->getMock();
		$fileInfo = $this->getMockBuilder('\\OC\\Files\\FileInfo')
			->disableOriginalConstructor()->getMock();
		$fileInfo->expects($this->once())
			->method('getEncryptedVersion')
			->willReturn(1337);
		$view->expects($this->once())
			->method('getFileInfo')
			->with('/admin/files/myfile.txt')
			->willReturn($fileInfo);

		/** @var \OC\Files\View $view */
		$this->assertSame(1337, $this->instance->getVersion('/admin/files/myfile.txt', $view));
	}

	public function testSetVersionWithFileInfo() {
		$view = $this->getMockBuilder('\\OC\\Files\\View')
			->disableOriginalConstructor()->getMock();
		$cache = $this->getMockBuilder('\\OCP\\Files\\Cache\\ICache')
			->disableOriginalConstructor()->getMock();
		$cache->expects($this->once())
			->method('update')
			->with(123, ['encrypted' => 5, 'encryptedVersion' => 5]);
		$storage = $this->getMockBuilder('\\OCP\\Files\\Storage')
			->disableOriginalConstructor()->getMock();
		$storage->expects($this->once())
			->method('getCache')
			->willReturn($cache);
		$fileInfo = $this->getMockBuilder('\\OC\\Files\\FileInfo')
			->disableOriginalConstructor()->getMock();
		$fileInfo->expects($this->once())
			->method('getStorage')
			->willReturn($storage);
		$fileInfo->expects($this->once())
			->method('getId')
			->willReturn(123);
		$view->expects($this->once())
			->method('getFileInfo')
			->with('/admin/files/myfile.txt')
			->willReturn($fileInfo);

		/** @var \OC\Files\View $view */
		$this->instance->setVersion('/admin/files/myfile.txt', 5, $view);
	}

	public function testSetVersionWithoutFileInfo() {
		$view = $this->getMockBuilder('\\OC\\Files\\View')
			->disableOriginalConstructor()->getMock();
		$view->expects($this->once())
			->method('getFileInfo')
			->with('/admin/files/myfile.txt')
			->willReturn(false);

		/** @var \OC\Files\View $view */
		$this->instance->setVersion('/admin/files/myfile.txt', 5, $view);
	}
}
