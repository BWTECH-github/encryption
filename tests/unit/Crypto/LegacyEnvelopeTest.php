<?php

declare(strict_types=1);

/**
 * @copyright Copyright (c) 2026, BW-Tech GmbH
 * @license AGPL-3.0
 *
 * Übernahme von Servern 10.x / 11: Dateischlüssel, die die Vorgänger-Apps
 * versiegelt haben, müssen sich öffnen lassen - auch wenn OpenSSL 3 kein RC4
 * mehr anbietet.
 *
 * Die Umschläge in fixtures/legacy-envelopes.json sind echte openssl_seal()-
 * Ausgaben, erzeugt mit PHP 7.4 + OpenSSL-Legacy-Provider genau so, wie es die
 * Vorgänger tun:
 *  - rc4_*: encryption <= 1.6.1 (Server 10.x): openssl_seal() ohne Cipher = RC4
 *  - ecb_*: encryption 1.7.x (Upstream-Server 11): openssl_seal(..., 'aes-256-ecb')
 * Empfänger sind wie im Master-Key-Betrieb zwei Schlüssel (master, pubShare).
 */

namespace OCA\Encryption\Tests\Crypto;

use OCA\Encryption\Crypto\Crypt;
use OCA\Encryption\Exceptions\MultiKeyDecryptException;
use OCP\IConfig;
use OCP\IL10N;
use OCP\ILogger;
use OCP\IUserSession;
use Test\TestCase;

class LegacyEnvelopeTest extends TestCase {
	private Crypt $crypt;

	/** @var array<string, string> */
	private array $fixture;

	protected function setUp(): void {
		parent::setUp();

		$userSession = $this->createMock(IUserSession::class);
		$userSession->method('isLoggedIn')->willReturn(false);
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValue')
			->willReturnCallback(static function ($key, $default) {
				return $key === 'cipher' ? 'AES-256-CTR' : $default;
			});

		$this->crypt = new Crypt(
			$this->createMock(ILogger::class),
			$userSession,
			$config,
			$this->createMock(IL10N::class)
		);

		$json = \file_get_contents(__DIR__ . '/fixtures/legacy-envelopes.json');
		$this->assertIsString($json);
		$this->fixture = \json_decode($json, true, 512, JSON_THROW_ON_ERROR);
	}

	public function legacyEnvelopeProvider(): array {
		return [
			'encryption <= 1.6 (RC4), Master-Key' => ['rc4', 'master'],
			'encryption <= 1.6 (RC4), Public-Share-Key' => ['rc4', 'pubshare'],
			'encryption 1.7 (AES-256-ECB), Master-Key' => ['ecb', 'master'],
			'encryption 1.7 (AES-256-ECB), Public-Share-Key' => ['ecb', 'pubshare'],
		];
	}

	/**
	 * @dataProvider legacyEnvelopeProvider
	 */
	public function testOpensEnvelopeSealedByPredecessor(string $format, string $recipient): void {
		$fileKey = $this->crypt->multiKeyDecrypt(
			\base64_decode($this->fixture[$format . '_data']),
			\base64_decode($this->fixture[$format . '_share_' . $recipient]),
			$this->fixture['private_' . $recipient]
		);

		$this->assertSame(\base64_decode($this->fixture['fileKey']), $fileKey);
	}

	/**
	 * Unabhängig davon, ob das OpenSSL des Servers RC4 noch kennt: PHP 8.4 mit
	 * OpenSSL 3 ohne Legacy-Provider (Standard) meldet dort "unsupported".
	 */
	public function testRc4EnvelopeDoesNotNeedOpenSslRc4(): void {
		$fileKey = $this->crypt->multiKeyDecrypt(
			\base64_decode($this->fixture['rc4_data']),
			\base64_decode($this->fixture['rc4_share_master']),
			$this->fixture['private_master']
		);

		$this->assertSame(\base64_decode($this->fixture['fileKey']), $fileKey);
		if (!\in_array('rc4', \openssl_get_cipher_methods(), true)) {
			// Beleg für die Ausgangslage: der alte Weg über openssl_open scheitert hier
			$plain = null;
			$this->assertFalse(@\openssl_open(
				\base64_decode($this->fixture['rc4_data']),
				$plain,
				\base64_decode($this->fixture['rc4_share_master']),
				$this->fixture['private_master'],
				'RC4'
			));
		}
	}

	/**
	 * Neuer Bestand (Format v2, AES-256-CBC mit IV) bleibt unverändert lesbar,
	 * auch mit denselben Schlüsseln wie die übernommenen Umschläge.
	 */
	public function testNewFormatStillOpens(): void {
		$fileKey = \base64_decode($this->fixture['fileKey']);
		$sealed = $this->crypt->multiKeyEncrypt($fileKey, [
			'master' => $this->publicKeyOf('master'),
			'pubshare' => $this->publicKeyOf('pubshare'),
		]);

		$this->assertSame(Crypt::SEALED_FORMAT_VERSION, \ord($sealed['data'][0]));
		foreach (['master', 'pubshare'] as $recipient) {
			$this->assertSame(
				$fileKey,
				$this->crypt->multiKeyDecrypt($sealed['data'], $sealed['keys'][$recipient], $this->fixture['private_' . $recipient])
			);
		}
	}

	/**
	 * Lesen verändert nichts: zweimal öffnen liefert dasselbe, die Eingaben
	 * bleiben, wie sie waren.
	 */
	public function testOpeningTwiceIsANoop(): void {
		$data = \base64_decode($this->fixture['rc4_data']);
		$share = \base64_decode($this->fixture['rc4_share_master']);
		$dataBefore = $data;
		$shareBefore = $share;

		$first = $this->crypt->multiKeyDecrypt($data, $share, $this->fixture['private_master']);
		$second = $this->crypt->multiKeyDecrypt($data, $share, $this->fixture['private_master']);

		$this->assertSame($first, $second);
		$this->assertSame($dataBefore, $data);
		$this->assertSame($shareBefore, $share);
	}

	/**
	 * Ein fremder privater Schlüssel darf keinen scheinbar gültigen
	 * Dateischlüssel liefern.
	 */
	public function testWrongPrivateKeyIsRejected(): void {
		try {
			$result = $this->crypt->multiKeyDecrypt(
				\base64_decode($this->fixture['rc4_data']),
				\base64_decode($this->fixture['rc4_share_master']),
				$this->fixture['private_pubshare']
			);
			// OpenSSL >= 3.2 lehnt PKCS#1 v1.5 implizit ab (zufälliger Klartext statt Fehler)
			$this->assertNotSame(\base64_decode($this->fixture['fileKey']), $result);
		} catch (MultiKeyDecryptException $e) {
			$this->assertStringContainsString('multikeydecrypt with share key failed', $e->getMessage());
		}
	}

	/**
	 * RC4-Testvektoren (Wikipedia/"Key"-"Plaintext", RFC 6229 Schlüssel 0x0102030405).
	 */
	public function testRc4KnownAnswer(): void {
		$this->assertSame(
			'bbf316e8d940af0ad3',
			\bin2hex($this->invokePrivate($this->crypt, 'rc4', ['Key', 'Plaintext']))
		);
		$this->assertSame(
			'b2396305f03dc027ccc3524a0a1118a8',
			\bin2hex($this->invokePrivate($this->crypt, 'rc4', [\hex2bin('0102030405'), \str_repeat("\0", 16)]))
		);
	}

	private function publicKeyOf(string $recipient): string {
		$key = \openssl_pkey_get_private($this->fixture['private_' . $recipient]);
		$this->assertNotFalse($key);
		return \openssl_pkey_get_details($key)['key'];
	}
}
