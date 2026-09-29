<?php
/**
 * @author Björn Schießle <bjoern@schiessle.org>
 * @author Joas Schilling <coding@schilljs.com>
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

namespace OCA\Encryption\Tests\Crypto;

use OC\Helper\EnvironmentHelper;
use OCA\Encryption\Crypto\Crypt;
use OCA\Encryption\Crypto\DecryptAll;
use OCA\Encryption\KeyManager;
use OCA\Encryption\Session;
use OCA\Encryption\Util;
use OCP\IUserManager;
use Symfony\Component\Console\Helper\QuestionHelper;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Test\TestCase;
use Test\Traits\UserTrait;

/**
 * Class DecryptAllTest
 *
 * @group DB
 * @package OCA\Encryption\Tests\Crypto
 */
class DecryptAllTest extends TestCase {
	use UserTrait;

	/** @var  DecryptAll */
	protected $instance;

	/** @var Util | \PHPUnit\Framework\MockObject\MockObject  */
	protected $util;

	/** @var KeyManager | \PHPUnit\Framework\MockObject\MockObject  */
	protected $keyManager;

	/** @var  Crypt | \PHPUnit\Framework\MockObject\MockObject */
	protected $crypt;

	/** @var  Session | \PHPUnit\Framework\MockObject\MockObject */
	protected $session;

	protected $userManager;

	/** @var EnvironmentHelper | \PHPUnit\Framework\MockObject\MockObject */
	protected $envHelper;

	/** @var QuestionHelper | \PHPUnit\Framework\MockObject\MockObject  */
	protected $questionHelper;

	public function setUp(): void {
		parent::setUp();

		$this->util = $this->getMockBuilder('OCA\Encryption\Util')
			->disableOriginalConstructor()->getMock();
		$this->keyManager = $this->getMockBuilder('OCA\Encryption\KeyManager')
			->disableOriginalConstructor()->getMock();
		$this->crypt = $this->getMockBuilder('OCA\Encryption\Crypto\Crypt')
			->disableOriginalConstructor()->getMock();
		$this->session = $this->getMockBuilder('OCA\Encryption\Session')
			->disableOriginalConstructor()->getMock();
		$this->userManager = $this->createMock(IUserManager::class);
		$this->questionHelper = $this->getMockBuilder('Symfony\Component\Console\Helper\QuestionHelper')
			->disableOriginalConstructor()->getMock();
		$this->envHelper = $this->createMock(EnvironmentHelper::class);

		$this->instance = new DecryptAll(
			$this->util,
			$this->keyManager,
			$this->crypt,
			$this->session,
			$this->userManager,
			$this->questionHelper,
			$this->envHelper
		);
	}

	public function providesEnvVal() {
		return [
			['recovery', false],
			['recovery', ''],
			['password', false],
			['password', '']
		];
	}

	/**
	 * @dataProvider providesEnvVal
	 */
	public function testPrepareWithUnsetEnv($method, $env) {
		$this->expectException(\OC\User\LoginException::class);
		$this->expectExceptionMessage('Invalid credentials provided');

		$input = $this->createMock(InputInterface::class);
		$output = $this->createMock(OutputInterface::class);

		$this->util->expects($this->once())
			->method('isMasterKeyEnabled')
			->willReturn(false);

		$input->expects($this->once())
			->method('hasOption')
			->with('method')
			->willReturn(true);

		$input->expects($this->any())
			->method('getOption')
			->with('method')
			->willReturn($method);

		$this->envHelper->expects($this->any())
			->method('getEnvVar')
			->willReturnOnConsecutiveCalls('', $env, $env);

		$this->instance->prepare($input, $output, 'user1');
	}

	public function providesMethodWithUnsetEnv() {
		return [
			'recovery ohne OC_RECOVERY_PASSWORD' => ['recovery'],
			'password ohne OC_PASSWORD' => ['password'],
		];
	}

	/**
	 * Nicht gesetzte Umgebungsvariable (getenv() liefert false) ist kein
	 * Kennwort: LoginException statt TypeError, und das Kennwort wird gar nicht
	 * erst geprüft.
	 *
	 * @dataProvider providesMethodWithUnsetEnv
	 */
	public function testPrepareWithEnvNotSetThrowsLoginException($method) {
		$this->expectException(\OC\User\LoginException::class);
		$this->expectExceptionMessage('Invalid credentials provided');

		$input = $this->createMock(InputInterface::class);
		$output = $this->createMock(OutputInterface::class);

		$this->util->expects($this->once())
			->method('isMasterKeyEnabled')
			->willReturn(false);
		$this->util->expects($this->any())
			->method('isRecoveryEnabledForUser')
			->willReturn(true);
		$input->expects($this->once())
			->method('hasOption')
			->with('method')
			->willReturn(true);
		$input->expects($this->any())
			->method('getOption')
			->with('method')
			->willReturn($method);
		$this->envHelper->expects($this->any())
			->method('getEnvVar')
			->willReturn(false);
		$this->keyManager->expects($this->never())->method('checkRecoveryPassword');
		$this->userManager->expects($this->never())->method('checkPassword');
		$this->crypt->expects($this->never())->method('decryptPrivateKey');

		$this->instance->prepare($input, $output, 'user1');
	}

	/**
	 * Leere Eingabe an der Kennwortabfrage: Symfony liefert null. Das ist ein
	 * leeres Kennwort, kein TypeError.
	 */
	public function testPrepareWithEmptyPasswordAnswer() {
		$this->expectException(\OC\User\LoginException::class);
		$this->expectExceptionMessage('Invalid credentials provided');

		$input = $this->createMock(InputInterface::class);
		$output = $this->createMock(OutputInterface::class);

		$this->util->expects($this->once())
			->method('isMasterKeyEnabled')
			->willReturn(false);
		$input->expects($this->once())
			->method('hasOption')
			->with('method')
			->willReturn(true);
		$input->expects($this->any())
			->method('getOption')
			->with('method')
			->willReturn(null);
		$this->questionHelper->expects($this->once())
			->method('ask')
			->willReturn(null);
		$this->userManager->expects($this->once())
			->method('checkPassword')
			->with('user1', '')
			->willReturn(false);
		$this->crypt->expects($this->never())->method('decryptPrivateKey');

		$this->instance->prepare($input, $output, 'user1');
	}

	public function testUpdateSession() {
		$this->session->expects($this->once())->method('prepareDecryptAll')
			->with('user1', 'key1');

		$this->invokePrivate($this->instance, 'updateSession', ['user1', 'key1']);
	}

	/**
	 * @dataProvider dataTestGetPrivateKey
	 *
	 * @param string $user
	 * @param string $recoveryKeyId
	 */
	public function testGetPrivateKey($user, $recoveryKeyId, $masterKeyId) {
		$password = 'passwd';
		$recoveryKey = 'recoveryKey';
		$userKey = 'userKey';
		$unencryptedKey = 'unencryptedKey';

		$this->keyManager->expects($this->any())->method('getRecoveryKeyId')
			->willReturn($recoveryKeyId);

		if ($user === $recoveryKeyId) {
			$this->keyManager->expects($this->once())->method('getSystemPrivateKey')
				->with($recoveryKeyId)->willReturn($recoveryKey);
			$this->keyManager->expects($this->never())->method('getPrivateKey');
			$this->crypt->expects($this->once())->method('decryptPrivateKey')
				->with($recoveryKey, $password)->willReturn($unencryptedKey);
		} elseif ($user === $masterKeyId) {
			$this->keyManager->expects($this->once())->method('getSystemPrivateKey')
				->with($masterKeyId)->willReturn($masterKey);
			$this->keyManager->expects($this->never())->method('getPrivateKey');
			$this->crypt->expects($this->once())->method('decryptPrivateKey')
				->with($masterKey, $password, $masterKeyId)->willReturn($unencryptedKey);
		} else {
			$this->keyManager->expects($this->never())->method('getSystemPrivateKey');
			$this->keyManager->expects($this->once())->method('getPrivateKey')
				->with($user)->willReturn($userKey);
			$this->crypt->expects($this->once())->method('decryptPrivateKey')
				->with($userKey, $password, $user)->willReturn($unencryptedKey);
		}

		$this->assertSame(
			$unencryptedKey,
			$this->invokePrivate($this->instance, 'getPrivateKey', [$user, $password])
		);
	}

	public function dataTestGetPrivateKey() {
		return [
			['user1', 'recoveryKey', 'masterKeyId'],
			['recoveryKeyId', 'recoveryKeyId', 'masterKeyId'],
			['masterKeyId', 'masterKeyId', 'masterKeyId']
		];
	}

	public function providerPrepareLoginException() {
		return [
			['user1'],
			['recoverykey']
		];
	}
	/**
	 * @dataProvider providerPrepareLoginException
	 */
	public function testPrepareLoginException($loginType) {
		$this->expectException(\OC\User\LoginException::class);
		$this->expectExceptionMessage('Invalid credentials provided');

		$username = "decrypt_test_user1_";
		$this->createUser($username, 'pass');
		$input = $this->createMock(InputInterface::class);
		$output = $this->createMock(OutputInterface::class);

		$input->expects($this->once())
			->method('hasOption')
			->with('method')
			->willReturn(true);

		$this->util->expects($this->once())
			->method('isMasterKeyEnabled')
			->willReturn(false);

		$this->keyManager->expects($this->any())
			->method('getRecoveryKeyId')
			->willReturn('xyz');

		$this->questionHelper->expects($this->any())
			->method('ask')
			->willReturn('foo');

		if ($loginType === 'user1') {
			$this->userManager->expects($this->any())
				->method('checkPassword')
				->willReturn(false);
			$this->instance->prepare($input, $output, 'user1');
		} elseif ($loginType === 'recoverykey') {
			$input->expects($this->once())
				->method('getOption')
				->with('method')
				->willReturn('recovery');
			$this->envHelper->expects($this->exactly(2))
				->method('getEnvVar')
				->with('OC_RECOVERY_PASSWORD')
				->willReturn('foo');

			$this->util->expects($this->once())
				->method('isRecoveryEnabledForUser')
				->willReturn(true);

			$this->keyManager->expects($this->once())
				->method('checkRecoveryPassword')
				->willReturn(false);
			$this->instance->prepare($input, $output, 'xyz');
		}
	}

	public function providesMasterKeyPrepareResult() {
		return [
			[true],
			[false]
		];
	}

	/**
	 * @dataProvider providesMasterKeyPrepareResult
	 */
	public function testPrepareMasterKey($expectedResult) {
		$input = $this->createMock(InputInterface::class);
		$output = $this->createMock(OutputInterface::class);

		$this->util->expects($this->once())
			->method('isMasterKeyEnabled')
			->willReturn(true);
		$this->keyManager->expects($this->exactly(2))
			->method('getMasterKeyId')
			->willReturn('user1');
		$this->keyManager->expects($this->once())
			->method('getMasterKeyPassword')
			->willReturn('pass');
		$this->keyManager->expects($this->once())
			->method('getRecoveryKeyId')
			->willReturn('user1');
		if ($expectedResult) {
			$this->crypt->expects($this->once())
				->method('decryptPrivateKey')
				->willReturn('masterPrivateKey');
			$this->session->expects($this->once())
				->method('prepareDecryptAll')
				->with('user1', 'masterPrivateKey');
		} else {
			$this->crypt->expects($this->once())
				->method('decryptPrivateKey')
				->willReturn(false);
			$this->session->expects($this->never())
				->method('prepareDecryptAll');
		}

		$result = $this->instance->prepare($input, $output, 'user1');
		$this->assertEquals($expectedResult, $result);
	}

	public function providesUserKeyPrepareResult() {
		return [
			[true, 'user1'],
			[false, 'user1'],
			[true, ''],
			[false, '']
		];
	}

	/**
	 * @dataProvider providesUserKeyPrepareResult
	 */
	public function testPrepareUserKeyWithRecoveryPasswd($expectedResult, $user) {
		$input = $this->createMock(InputInterface::class);
		$output = $this->createMock(OutputInterface::class);

		$this->util->expects($this->once())
			->method('isMasterKeyEnabled')
			->willReturn(false);

		// Die Option --method ist im Befehl definiert (hasOption() = true); ohne
		// Angabe liefert getOption() null.
		$input->expects($this->once())
			->method('hasOption')
			->with('method')
			->willReturn(true);

		if (!(($expectedResult === false) && ($user === ''))) {
			// getArgument('user') === '': getOption() wird zweimal gefragt
			$input->expects($this->any())
				->method('getArgument')
				->with('user')
				->willReturn('');
			$input->expects($this->exactly(2))
				->method('getOption')
				->with('method')
				->willReturn('recovery');
			$this->envHelper->expects($this->any())
				->method('getEnvVar')
				->with('OC_RECOVERY_PASSWORD')
				->willReturn('foo');
		} else {
			$input->expects($this->exactly(1))
				->method('getOption')
				->with('method')
				->willReturn('foo');
		}

		if ($user !== '') {
			// ein Nutzer über den Wiederherstellungsschlüssel
			$this->util->expects($this->once())
				->method('isRecoveryEnabledForUser')
				->with($user)
				->willReturn(true);

			$this->keyManager->expects($this->once())
				->method('checkRecoveryPassword')
				->with('foo')
				->willReturn(true);

			$this->keyManager->expects($this->exactly(2))
				->method('getRecoveryKeyId')
				->willReturn('recoveryKeyId');
		}

		if (($expectedResult === true) && ($user === '')) {
			$this->keyManager->expects($this->exactly(1))
				->method('getRecoveryKeyId')
				->willReturn($user);
		}

		if ($expectedResult === true) {
			$this->crypt->expects($this->once())
				->method('decryptPrivateKey')
				->willReturn('recoveryPrivateKey');
		} else {
			if (!(($expectedResult === false) && ($user === ''))) {
				$this->crypt->expects($this->once())
					->method('decryptPrivateKey')
					->willReturn(false);
			}
		}

		$result = $this->instance->prepare($input, $output, $user);
		$this->assertEquals($expectedResult, $result);
	}

	/**
	 * @dataProvider providesMasterKeyPrepareResult
	 */
	public function testPrepareUserKeyWithOCPasswd($expectedResult) {
		$input = $this->createMock(InputInterface::class);
		$output = $this->createMock(OutputInterface::class);

		$this->util->expects($this->once())
			->method('isMasterKeyEnabled')
			->willReturn(false);

		$input->expects($this->once())
			->method('hasOption')
			->willReturn(true);
		// getArgument('user') === '': erste Abfrage von --method in der
		// Prüfung "password für alle Nutzer", die zweite liefert die Methode
		$input->expects($this->any())
			->method('getArgument')
			->with('user')
			->willReturn('');
		$input->expects($this->exactly(2))
			->method('getOption')
			->with('method')
			->willReturnOnConsecutiveCalls(null, 'password');
		$this->envHelper->expects($this->any())
			->method('getEnvVar')
			->willReturnMap([
				['OC_RECOVERY_PASSWORD', ''],
				['OC_PASSWORD', 'foo']
			]);

		$this->userManager->expects($this->once())
			->method('checkPassword')
			->with('user1', 'foo')
			->willReturn(true);

		if ($expectedResult === true) {
			$this->crypt->expects($this->once())
				->method('decryptPrivateKey')
				->willReturn('userPrivateKey');
		} else {
			$this->crypt->expects($this->once())
				->method('decryptPrivateKey')
				->willReturn(false);
		}

		$result = $this->instance->prepare($input, $output, 'user1');
		$this->assertEquals($expectedResult, $result);
	}

	public function testPrepareWithWrongMethod() {
		$input = $this->createMock(InputInterface::class);
		$output = $this->createMock(OutputInterface::class);

		$this->util->expects($this->once())
			->method('isMasterKeyEnabled')
			->willReturn(false);

		$input->expects($this->once())
			->method('hasOption')
			->with('method')
			->willReturn(true);
		$input->expects($this->once())
			->method('getOption')
			->with('method')
			->willReturn('foo');
		$this->crypt->expects($this->never())->method('decryptPrivateKey');

		$this->assertFalse($this->instance->prepare($input, $output, 'user1'));
	}

	public function testPrepareWithWrongMethodToDecryptAll() {
		$input = $this->createMock(InputInterface::class);
		$output = $this->createMock(OutputInterface::class);

		$input->expects($this->once())
			->method('getArgument')
			->with('user')
			->willReturn('');
		$input->expects($this->once())
			->method('getOption')
			->with('method')
			->willReturn('password');

		$this->assertFalse($this->instance->prepare($input, $output, 'user1'));
	}
}
