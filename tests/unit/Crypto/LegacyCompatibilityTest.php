<?php

declare(strict_types=1);

/**
 * @author PHP 8.4 Migration
 * @copyright Copyright (c) 2024
 * Modified by BW-Tech GmbH for owncloud.online (PHP 8.4).
 *
 * @license AGPL-3.0
 *
 * Tests for backward compatibility with legacy encrypted files
 */

namespace OCA\Encryption\Tests\Crypto;

use OCA\Encryption\Crypto\Crypt;
use OCP\IConfig;
use OCP\IL10N;
use OCP\ILogger;
use OCP\IUserSession;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

/**
 * @group legacy-compatibility
 */
class LegacyCompatibilityTest extends TestCase {
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
	 * Test that format detection correctly identifies data that doesn't start with version byte
	 */
	public function testLegacyFormatDetection(): void {
		// Simulate legacy encrypted data (random bytes that don't start with 0x02)
		$legacyData = \chr(0x00) . \random_bytes(100);

		$result = $this->invokePrivate($this->crypt, 'detectSealedFormat', [$legacyData]);

		$this->assertEquals(Crypt::SEALED_FORMAT_LEGACY, $result['version']);
		$this->assertNull($result['iv']);
		$this->assertEquals($legacyData, $result['data']);
	}

	/**
	 * Test that format detection handles edge case where first byte happens to be 0x02
	 * but second byte indicates invalid IV length
	 */
	public function testFormatDetectionWithInvalidIVLength(): void {
		// First byte is 0x02 but IV length is invalid (too large)
		$data = \chr(0x02) . \chr(64) . \random_bytes(10); // IV length 64 is invalid, data too short

		$result = $this->invokePrivate($this->crypt, 'detectSealedFormat', [$data]);

		// Should fall back to legacy format
		$this->assertEquals(Crypt::SEALED_FORMAT_LEGACY, $result['version']);
	}

	/**
	 * Test that new format encrypted data can be correctly identified and parsed
	 */
	public function testNewFormatDetection(): void {
		$iv = \random_bytes(16);
		$encryptedData = \random_bytes(100);

		// Construct new format: version + iv_length + iv + data
		$newFormatData = \chr(Crypt::SEALED_FORMAT_VERSION) . \chr(16) . $iv . $encryptedData;

		$result = $this->invokePrivate($this->crypt, 'detectSealedFormat', [$newFormatData]);

		$this->assertEquals(Crypt::SEALED_FORMAT_VERSION, $result['version']);
		$this->assertEquals($iv, $result['iv']);
		$this->assertEquals($encryptedData, $result['data']);
	}

	/**
	 * Test symmetric encryption backward compatibility
	 * Files encrypted with the symmetric methods should still be decryptable
	 */
	public function testSymmetricEncryptionBackwardCompatibility(): void {
		$plainContent = 'This is test content for symmetric encryption';
		$passPhrase = \hash('sha256', 'test_password', true);

		// Encrypt with current implementation
		$encrypted = $this->crypt->symmetricEncryptFileContent($plainContent, $passPhrase, 1, 0);

		$this->assertIsString($encrypted);
		$this->assertNotEmpty($encrypted);

		// Decrypt should work
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
	 * Test that header parsing is backward compatible
	 */
	public function testHeaderParsingBackwardCompatibility(): void {
		// Old format header (without encoding field)
		$oldHeader = 'HBEGIN:cipher:AES-128-CFB:keyFormat:password:HEND';

		$result = $this->invokePrivate($this->crypt, 'parseHeader', [$oldHeader]);

		$this->assertEquals('AES-128-CFB', $result['cipher']);
		$this->assertEquals('password', $result['keyFormat']);
		$this->assertArrayNotHasKey('encoding', $result);
	}

	/**
	 * Test that new header format is correctly parsed
	 */
	public function testNewHeaderParsing(): void {
		// New format header (with encoding field)
		$newHeader = 'HBEGIN:cipher:AES-256-CTR:keyFormat:hash:encoding:binary:HEND';

		$result = $this->invokePrivate($this->crypt, 'parseHeader', [$newHeader]);

		$this->assertEquals('AES-256-CTR', $result['cipher']);
		$this->assertEquals('hash', $result['keyFormat']);
		$this->assertEquals('binary', $result['encoding']);
	}

	/**
	 * Test that files without headers (very old format) are handled
	 */
	public function testNoHeaderHandling(): void {
		$dataWithoutHeader = 'some encrypted content without any header';

		$result = $this->invokePrivate($this->crypt, 'parseHeader', [$dataWithoutHeader]);

		$this->assertIsArray($result);
		$this->assertEmpty($result);
	}

	/**
	 * Test private key validation works for both old and new OpenSSL key formats
	 */
	public function testPrivateKeyValidation(): void {
		// Generate a new key pair
		$keyPair = $this->crypt->createKeyPair();

		$this->assertIsArray($keyPair);

		// The private key should be valid
		$isValid = $this->invokePrivate($this->crypt, 'isValidPrivateKey', [$keyPair['privateKey']]);
		$this->assertTrue($isValid);

		// An invalid key should return false
		$isValid = $this->invokePrivate($this->crypt, 'isValidPrivateKey', ['not a valid key']);
		$this->assertFalse($isValid);

		// Empty key should return false
		$isValid = $this->invokePrivate($this->crypt, 'isValidPrivateKey', ['']);
		$this->assertFalse($isValid);
	}

	/**
	 * Test that the cipher constants are correctly defined
	 */
	public function testCipherConstants(): void {
		$this->assertEquals('AES-256-CTR', Crypt::DEFAULT_CIPHER);
		$this->assertEquals('AES-128-CFB', Crypt::LEGACY_CIPHER);
		$this->assertEquals('AES-256-CBC', Crypt::SEAL_CIPHER);
	}

	/**
	 * Test that format version constants are correctly defined
	 */
	public function testFormatVersionConstants(): void {
		$this->assertEquals(0x02, Crypt::SEALED_FORMAT_VERSION);
		$this->assertEquals(0x01, Crypt::SEALED_FORMAT_LEGACY);
	}

	/**
	 * Test encryption with different ciphers
	 * @dataProvider cipherProvider
	 */
	public function testEncryptionWithDifferentCiphers(string $cipher): void {
		// Create a config mock that returns the specified cipher
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValue')
			->willReturnCallback(function ($key, $default) use ($cipher) {
				if ($key === 'cipher') {
					return $cipher;
				}
				return $default;
			});

		$crypt = new Crypt(
			$this->logger,
			$this->userSession,
			$config,
			$this->l
		);

		$this->assertEquals($cipher, $crypt->getCipher());
	}

	/**
	 * Data provider for cipher tests
	 */
	public function cipherProvider(): array {
		return [
			['AES-256-CTR'],
			['AES-128-CTR'],
			['AES-256-CFB'],
			['AES-128-CFB'],
		];
	}

	/**
	 * Test that signature verification works correctly
	 */
	public function testSignatureHandling(): void {
		$plainContent = 'content to be signed and encrypted';
		$passPhrase = \random_bytes(32);

		// Encrypt content (which includes signature)
		$encrypted = $this->crypt->symmetricEncryptFileContent($plainContent, $passPhrase, 1, 0);

		// The encrypted content should contain signature marker
		$this->assertStringContainsString('00sig00', $encrypted);

		// Decryption should verify signature and succeed
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
	 * Test that IV is correctly extracted from encrypted content
	 */
	public function testIVExtraction(): void {
		$plainContent = 'test content';
		$passPhrase = \random_bytes(32);

		$encrypted = $this->crypt->symmetricEncryptFileContent($plainContent, $passPhrase, 1, 0);

		// The encrypted content should contain IV marker
		$this->assertStringContainsString('00iv00', $encrypted);
	}

	/**
	 * Helper method to invoke private methods
	 */
	protected static function invokePrivate($object, $methodName, array $parameters = []) {
		$reflection = new \ReflectionClass(\get_class($object));
		$method = $reflection->getMethod($methodName);
		$method->setAccessible(true);

		return $method->invokeArgs($object, $parameters);
	}
}
