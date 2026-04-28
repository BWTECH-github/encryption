<?php

declare(strict_types=1);

/**
 * @author PHP 8.4 Migration
 * @copyright Copyright (c) 2024
 * Modified by BW-Tech GmbH for owncloud.online (PHP 8.4).
 *
 * @license AGPL-3.0
 *
 * Tests for PHP 8.4 compatibility of the Crypt class
 */

namespace OCA\Encryption\Tests\Crypto;

use OCA\Encryption\Crypto\Crypt;
use OCP\IConfig;
use OCP\IL10N;
use OCP\ILogger;
use OCP\IUserSession;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class CryptPHP84Test extends TestCase {
	/** @var ILogger|MockObject */
	private $logger;

	/** @var IUserSession|MockObject */
	private $userSession;

	/** @var IConfig|MockObject */
	private $config;

	/** @var IL10N|MockObject */
	private $l;

	/** @var Crypt */
	private Crypt $crypt;

	protected function setUp(): void {
		parent::setUp();

		$this->logger = $this->createMock(ILogger::class);
		$this->userSession = $this->createMock(IUserSession::class);
		$this->config = $this->createMock(IConfig::class);
		$this->l = $this->createMock(IL10N::class);

		$this->userSession->method('isLoggedIn')->willReturn(false);

		$this->config->method('getSystemValue')
			->willReturnCallback(function ($key, $default) {
				if ($key === 'cipher') {
					return 'AES-256-CTR';
				}
				if ($key === 'encryption.use_legacy_encoding') {
					return false;
				}
				return $default;
			});

		$this->crypt = new Crypt(
			$this->logger,
			$this->userSession,
			$this->config,
			$this->l
		);
	}

	/**
	 * Test that multiKeyEncrypt produces new format with IV
	 */
	public function testMultiKeyEncryptNewFormat(): void {
		$plainContent = 'test content for encryption';
		$keyPair = $this->crypt->createKeyPair();

		$this->assertIsArray($keyPair);
		$this->assertArrayHasKey('publicKey', $keyPair);
		$this->assertArrayHasKey('privateKey', $keyPair);

		$result = $this->crypt->multiKeyEncrypt($plainContent, [
			'user1' => $keyPair['publicKey']
		]);

		// Verify result structure
		$this->assertIsArray($result);
		$this->assertArrayHasKey('data', $result);
		$this->assertArrayHasKey('keys', $result);
		$this->assertArrayHasKey('user1', $result['keys']);

		// Check version byte (first byte should be SEALED_FORMAT_VERSION = 0x02)
		$this->assertEquals(
			Crypt::SEALED_FORMAT_VERSION,
			\ord($result['data'][0]),
			'First byte should be the format version marker'
		);

		// Check IV length byte (second byte should be 16 for AES-256-CBC)
		$ivLength = \ord($result['data'][1]);
		$this->assertEquals(16, $ivLength, 'IV length should be 16 bytes for AES-256-CBC');

		// Verify data is long enough to contain version + iv_length + iv + data
		$this->assertGreaterThan(2 + $ivLength, \strlen($result['data']));
	}

	/**
	 * Test multiKeyDecrypt handles new format correctly
	 */
	public function testMultiKeyDecryptNewFormat(): void {
		$plainContent = 'test content for new format decryption';
		$keyPair = $this->crypt->createKeyPair();

		$this->assertIsArray($keyPair);

		$encrypted = $this->crypt->multiKeyEncrypt($plainContent, [
			'user1' => $keyPair['publicKey']
		]);

		$decrypted = $this->crypt->multiKeyDecrypt(
			$encrypted['data'],
			$encrypted['keys']['user1'],
			$keyPair['privateKey']
		);

		$this->assertEquals($plainContent, $decrypted);
	}

	/**
	 * Test encryption/decryption round trip with various content types
	 */
	public function testEncryptDecryptRoundTrip(): void {
		$keyPair = $this->crypt->createKeyPair();
		$this->assertIsArray($keyPair);

		$testCases = [
			'Simple ASCII text',
			'Text with special chars: äöü ñ © ® ™',
			"Text with\nnewlines\nand\ttabs",
			\str_repeat('Large content block ', 1000),
			\random_bytes(256), // Binary content
		];

		foreach ($testCases as $index => $content) {
			$encrypted = $this->crypt->multiKeyEncrypt($content, [
				'user1' => $keyPair['publicKey']
			]);

			$decrypted = $this->crypt->multiKeyDecrypt(
				$encrypted['data'],
				$encrypted['keys']['user1'],
				$keyPair['privateKey']
			);

			$this->assertEquals(
				$content,
				$decrypted,
				"Round trip failed for test case $index"
			);
		}
	}

	/**
	 * Test that empty content throws exception
	 */
	public function testMultiKeyEncryptEmptyContentThrowsException(): void {
		$this->expectException(\OCA\Encryption\Exceptions\MultiKeyEncryptException::class);
		$this->expectExceptionMessage('Cannot multikeyencrypt empty plain content');

		$keyPair = $this->crypt->createKeyPair();
		$this->crypt->multiKeyEncrypt('', [
			'user1' => $keyPair['publicKey']
		]);
	}

	/**
	 * Test that empty encrypted content throws exception
	 */
	public function testMultiKeyDecryptEmptyContentThrowsException(): void {
		$this->expectException(\OCA\Encryption\Exceptions\MultiKeyDecryptException::class);
		$this->expectExceptionMessage('Cannot multikey decrypt empty plain content');

		$keyPair = $this->crypt->createKeyPair();
		$this->crypt->multiKeyDecrypt('', 'shareKey', $keyPair['privateKey']);
	}

	/**
	 * Test isValidPrivateKey works with PHP 8.4 OpenSSL objects
	 */
	public function testIsValidPrivateKeyPHP84(): void {
		$keyPair = $this->crypt->createKeyPair();
		$this->assertIsArray($keyPair);

		// Valid private key should return true
		$this->assertTrue(
			$this->invokePrivate($this->crypt, 'isValidPrivateKey', [$keyPair['privateKey']])
		);

		// Invalid private key should return false
		$this->assertFalse(
			$this->invokePrivate($this->crypt, 'isValidPrivateKey', ['invalid key data'])
		);

		// Empty string should return false
		$this->assertFalse(
			$this->invokePrivate($this->crypt, 'isValidPrivateKey', [''])
		);
	}

	/**
	 * Test format detection correctly identifies new format
	 */
	public function testDetectSealedFormatNew(): void {
		// Create new format data: version byte + iv_length byte + iv + data
		$iv = \random_bytes(16);
		$newFormatData = \chr(Crypt::SEALED_FORMAT_VERSION) . \chr(16) . $iv . 'encrypted_data_here';

		$result = $this->invokePrivate($this->crypt, 'detectSealedFormat', [$newFormatData]);

		$this->assertEquals(Crypt::SEALED_FORMAT_VERSION, $result['version']);
		$this->assertEquals($iv, $result['iv']);
		$this->assertEquals('encrypted_data_here', $result['data']);
	}

	/**
	 * Test format detection correctly identifies legacy format
	 */
	public function testDetectSealedFormatLegacy(): void {
		// Legacy data doesn't start with version byte 0x02
		$legacyData = 'some_encrypted_data_without_version_byte';

		$result = $this->invokePrivate($this->crypt, 'detectSealedFormat', [$legacyData]);

		$this->assertEquals(Crypt::SEALED_FORMAT_LEGACY, $result['version']);
		$this->assertNull($result['iv']);
		$this->assertEquals($legacyData, $result['data']);
	}

	/**
	 * Test format detection with short data defaults to legacy
	 */
	public function testDetectSealedFormatShortData(): void {
		$shortData = 'x'; // Only 1 byte

		$result = $this->invokePrivate($this->crypt, 'detectSealedFormat', [$shortData]);

		$this->assertEquals(Crypt::SEALED_FORMAT_LEGACY, $result['version']);
		$this->assertNull($result['iv']);
		$this->assertEquals($shortData, $result['data']);
	}

	/**
	 * Test multiple recipients encryption
	 */
	public function testMultiKeyEncryptMultipleRecipients(): void {
		$plainContent = 'content for multiple users';

		$keyPair1 = $this->crypt->createKeyPair();
		$keyPair2 = $this->crypt->createKeyPair();
		$keyPair3 = $this->crypt->createKeyPair();

		$this->assertIsArray($keyPair1);
		$this->assertIsArray($keyPair2);
		$this->assertIsArray($keyPair3);

		$encrypted = $this->crypt->multiKeyEncrypt($plainContent, [
			'user1' => $keyPair1['publicKey'],
			'user2' => $keyPair2['publicKey'],
			'user3' => $keyPair3['publicKey'],
		]);

		// Verify all users have share keys
		$this->assertArrayHasKey('user1', $encrypted['keys']);
		$this->assertArrayHasKey('user2', $encrypted['keys']);
		$this->assertArrayHasKey('user3', $encrypted['keys']);

		// Each user should be able to decrypt
		$decrypted1 = $this->crypt->multiKeyDecrypt(
			$encrypted['data'],
			$encrypted['keys']['user1'],
			$keyPair1['privateKey']
		);
		$this->assertEquals($plainContent, $decrypted1);

		$decrypted2 = $this->crypt->multiKeyDecrypt(
			$encrypted['data'],
			$encrypted['keys']['user2'],
			$keyPair2['privateKey']
		);
		$this->assertEquals($plainContent, $decrypted2);

		$decrypted3 = $this->crypt->multiKeyDecrypt(
			$encrypted['data'],
			$encrypted['keys']['user3'],
			$keyPair3['privateKey']
		);
		$this->assertEquals($plainContent, $decrypted3);
	}

	/**
	 * Test that createKeyPair generates valid keys
	 */
	public function testCreateKeyPair(): void {
		$keyPair = $this->crypt->createKeyPair();

		$this->assertIsArray($keyPair);
		$this->assertArrayHasKey('publicKey', $keyPair);
		$this->assertArrayHasKey('privateKey', $keyPair);

		// Verify public key format
		$this->assertStringContainsString('-----BEGIN PUBLIC KEY-----', $keyPair['publicKey']);
		$this->assertStringContainsString('-----END PUBLIC KEY-----', $keyPair['publicKey']);

		// Verify private key format
		$this->assertStringContainsString('-----BEGIN PRIVATE KEY-----', $keyPair['privateKey']);
		$this->assertStringContainsString('-----END PRIVATE KEY-----', $keyPair['privateKey']);
	}

	/**
	 * Test symmetric encryption/decryption
	 */
	public function testSymmetricEncryptDecrypt(): void {
		$plainContent = 'test symmetric encryption content';
		$passPhrase = \random_bytes(32);

		$encrypted = $this->crypt->symmetricEncryptFileContent($plainContent, $passPhrase, 1, 0);
		$this->assertIsString($encrypted);
		$this->assertNotEquals($plainContent, $encrypted);

		$decrypted = $this->crypt->symmetricDecryptFileContent(
			$encrypted,
			$passPhrase,
			'AES-256-CTR',
			1,
			0,
			true
		);

		$this->assertEquals($plainContent, $decrypted);
	}

	/**
	 * Test header generation
	 */
	public function testGenerateHeader(): void {
		$header = $this->crypt->generateHeader();

		$this->assertStringContainsString('HBEGIN', $header);
		$this->assertStringContainsString('HEND', $header);
		$this->assertStringContainsString('cipher:', $header);
		$this->assertStringContainsString('keyFormat:hash', $header);
		$this->assertStringContainsString('encoding:binary', $header);
	}

	/**
	 * Test header generation with password format
	 */
	public function testGenerateHeaderWithPasswordFormat(): void {
		$header = $this->crypt->generateHeader('password');

		$this->assertStringContainsString('keyFormat:password', $header);
	}

	/**
	 * Test header generation with invalid format throws exception
	 */
	public function testGenerateHeaderInvalidFormat(): void {
		$this->expectException(\InvalidArgumentException::class);

		$this->crypt->generateHeader('invalid_format');
	}

	/**
	 * Test parseHeader extracts correct values
	 */
	public function testParseHeader(): void {
		$header = 'HBEGIN:cipher:AES-256-CTR:keyFormat:hash:encoding:binary:HEND';

		$result = $this->invokePrivate($this->crypt, 'parseHeader', [$header]);

		$this->assertIsArray($result);
		$this->assertEquals('AES-256-CTR', $result['cipher']);
		$this->assertEquals('hash', $result['keyFormat']);
		$this->assertEquals('binary', $result['encoding']);
	}

	/**
	 * Test parseHeader with no header returns empty array
	 */
	public function testParseHeaderNoHeader(): void {
		$data = 'some data without header';

		$result = $this->invokePrivate($this->crypt, 'parseHeader', [$data]);

		$this->assertIsArray($result);
		$this->assertEmpty($result);
	}

	/**
	 * Test getCipher returns configured cipher
	 */
	public function testGetCipher(): void {
		$cipher = $this->crypt->getCipher();

		$this->assertEquals('AES-256-CTR', $cipher);
	}

	/**
	 * Test getLegacyCipher returns legacy cipher
	 */
	public function testGetLegacyCipher(): void {
		$cipher = $this->crypt->getLegacyCipher();

		$this->assertEquals('AES-128-CFB', $cipher);
	}

	/**
	 * Test generateFileKey produces 32 byte key
	 */
	public function testGenerateFileKey(): void {
		$key = $this->crypt->generateFileKey();

		$this->assertIsString($key);
		$this->assertEquals(32, \strlen($key));
	}

	/**
	 * Test useLegacyEncoding returns correct value
	 */
	public function testUseLegacyEncoding(): void {
		$this->assertFalse($this->crypt->useLegacyEncoding());
	}

	/**
	 * Helper method to invoke private methods
	 */
	protected function invokePrivate($object, string $methodName, array $parameters = []) {
		$reflection = new \ReflectionClass(\get_class($object));
		$method = $reflection->getMethod($methodName);
		$method->setAccessible(true);

		return $method->invokeArgs($object, $parameters);
	}
}
