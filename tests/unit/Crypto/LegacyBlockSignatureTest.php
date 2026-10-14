<?php

declare(strict_types=1);

/**
 * @copyright Copyright (c) 2026, BW-Tech GmbH
 * @license AGPL-3.0
 *
 * Übernahme von 10.x-Servern: Datenblöcke, die die Vorgänger-App signiert hat,
 * müssen die Signaturprüfung bestehen.
 *
 * Der Kern übergibt beim letzten Block die Position mit Zusatz "end" (z. B.
 * "10end"). Die Vorgänger-App (encryption <= 1.7) signiert mit diesem Zusatz,
 * owncloud.online encryption 2.x signiert die Position als Zahl.
 *
 * fixtures/encrypted-blocks.json enthält echte letzte Blöcke samt
 * Dateischlüssel und Version:
 *  - owncloud10_*: geschrieben von Server 10.16.2 / encryption 1.6.1
 *  - oco208_*: geschrieben von owncloud.online encryption 2.0.8
 */

namespace OCA\Encryption\Tests\Crypto;

use OC\HintException;
use OCA\Encryption\Crypto\Crypt;
use OCP\IConfig;
use OCP\IL10N;
use OCP\ILogger;
use OCP\IUserSession;
use Test\TestCase;

class LegacyBlockSignatureTest extends TestCase {
	private Crypt $crypt;

	/** @var array<string, array<string, mixed>> */
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
		$l = $this->createMock(IL10N::class);
		$l->method('t')->willReturnArgument(0);

		$this->crypt = new Crypt($this->createMock(ILogger::class), $userSession, $config, $l);

		$json = \file_get_contents(__DIR__ . '/fixtures/encrypted-blocks.json');
		$this->assertIsString($json);
		$this->fixture = \json_decode($json, true, 512, JSON_THROW_ON_ERROR);
	}

	public function blockProvider(): array {
		return [
			'Server 10.x, ein Block ("0end")' => ['owncloud10_single'],
			'Server 10.x, letzter von 11 Blöcken ("10end")' => ['owncloud10_multi'],
			'owncloud.online 2.0.8, ein Block' => ['oco208_single'],
			'owncloud.online 2.0.8, letzter von 12 Blöcken' => ['oco208_multi'],
		];
	}

	/**
	 * @dataProvider blockProvider
	 */
	public function testLastBlockPassesSignatureCheck(string $name): void {
		$f = $this->fixture[$name];

		$plain = $this->crypt->symmetricDecryptFileContent(
			\base64_decode($f['lastBlock']),
			\base64_decode($f['fileKey']),
			Crypt::DEFAULT_CIPHER,
			$f['version'],
			$f['lastPosition'],
			true
		);

		$this->assertSame(\base64_decode($f['lastPlain']), $plain);
	}

	/**
	 * Ausgangslage vor der Korrektur: mit der Position als Zahl (Zusatz "end"
	 * abgeschnitten) scheitert jeder letzte Block von 10.x-Servern.
	 */
	public function testOwncloud10BlockNeedsEndSuffix(): void {
		$f = $this->fixture['owncloud10_multi'];
		$data = \base64_decode($f['lastBlock']);
		$key = \base64_decode($f['fileKey']);
		$version = $f['version'];
		$numeric = (int)$f['lastPosition'];

		$crypt = $this->crypt;
		$check = static function (string $suffix) use ($crypt, $data, $key): bool {
			$meta = \substr(\substr($data, 0, -3), -93);
			$signature = \substr($meta, 22 + \strlen('00sig00'));
			$encrypted = \substr(\substr($data, 0, -3), 0, -93);
			return \hash_equals($signature, self::invokePrivate($crypt, 'createSignature', [$encrypted, $key . $suffix]));
		};
		$this->assertTrue($check($version . '-' . $f['lastPosition']));
		$this->assertFalse($check($version . '-' . $numeric));
	}

	public function testTamperedBlockIsRejected(): void {
		$f = $this->fixture['owncloud10_single'];
		$data = \base64_decode($f['lastBlock']);
		$data[0] = $data[0] === 'A' ? 'B' : 'A';

		$this->expectException(HintException::class);
		$this->expectExceptionMessage('Bad Signature');
		$this->crypt->symmetricDecryptFileContent($data, \base64_decode($f['fileKey']), Crypt::DEFAULT_CIPHER, $f['version'], $f['lastPosition'], true);
	}

	public function testWrongVersionIsRejected(): void {
		$f = $this->fixture['owncloud10_single'];

		$this->expectException(HintException::class);
		$this->expectExceptionMessage('Bad Signature');
		$this->crypt->symmetricDecryptFileContent(\base64_decode($f['lastBlock']), \base64_decode($f['fileKey']), Crypt::DEFAULT_CIPHER, $f['version'] + 1, $f['lastPosition'], true);
	}

	public function testWrongPositionIsRejected(): void {
		$f = $this->fixture['owncloud10_multi'];

		$this->expectException(HintException::class);
		$this->expectExceptionMessage('Bad Signature');
		$this->crypt->symmetricDecryptFileContent(\base64_decode($f['lastBlock']), \base64_decode($f['fileKey']), Crypt::DEFAULT_CIPHER, $f['version'], '3end', true);
	}

	/**
	 * Neuer Bestand: was diese App schreibt (Position als Zahl), liest sie
	 * weiter - als letzter Block ("0end") wie als Mittelblock ("0").
	 */
	public function testBlocksWrittenByThisAppStillOpen(): void {
		$key = \random_bytes(32);
		$block = $this->crypt->symmetricEncryptFileContent('neu geschrieben', $key, 2, 0);
		$this->assertIsString($block);

		foreach (['0end', '0', 0] as $position) {
			$this->assertSame('neu geschrieben', $this->crypt->symmetricDecryptFileContent($block, $key, Crypt::DEFAULT_CIPHER, 2, $position, true));
		}
	}

	public function testDecryptingTwiceIsANoop(): void {
		$f = $this->fixture['owncloud10_single'];
		$block = \base64_decode($f['lastBlock']);
		$before = $block;

		$first = $this->crypt->symmetricDecryptFileContent($block, \base64_decode($f['fileKey']), Crypt::DEFAULT_CIPHER, $f['version'], $f['lastPosition'], true);
		$second = $this->crypt->symmetricDecryptFileContent($block, \base64_decode($f['fileKey']), Crypt::DEFAULT_CIPHER, $f['version'], $f['lastPosition'], true);

		$this->assertSame($first, $second);
		$this->assertSame($before, $block);
	}
}
