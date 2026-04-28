<?php

declare(strict_types=1);

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

namespace OCA\Encryption\Crypto;

use GuzzleHttp\Exception\ServerException;
use OC\Encryption\Exceptions\DecryptionFailedException;
use OCA\Encryption\Exceptions\MultiKeyDecryptException;
use OCA\Encryption\Exceptions\MultiKeyEncryptException;
use OCA\Encryption\JWT;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Http\Client\IClientService;
use OCP\IConfig;
use OCP\IL10N;
use OCP\ILogger;
use OCP\IRequest;
use OCP\IUserSession;

/**
 * Class CryptHSM moves the key generation and multiKeyDecrytion to an HSM.
 * multiKeyEncrypt can be done locally because we have the public key
 *
 * @package OCA\Encryption\Crypto
 */
class CryptHSM extends Crypt {
	protected IClientService $clientService;

	private readonly string $hsmUrl;
	private readonly int $clockSkew;
	private readonly string $secret;
	private IRequest $request;
	private ITimeFactory $timeFactory;

	public const PATH_NEW_KEY = '/keys/new';
	public const PATH_DECRYPT = '/decrypt/'; // appended with keyid
	public const BINARY_ENCODED_KEY_LENGTH = 256;

	public function __construct(
		ILogger $logger,
		?IUserSession $userSession,
		IConfig $config,
		IL10N $l,
		IClientService $clientService,
		IRequest $request,
		ITimeFactory $timeFactory
	) {
		parent::__construct($logger, $userSession, $config, $l);
		$this->hsmUrl = \rtrim($this->config->getAppValue('encryption', 'hsm.url'), '/'); // no default, because Application DI only instantiates this if it is configured non empty
		$this->secret = $this->config->getAppValue('encryption', 'hsm.jwt.secret', 'secret');
		$this->clockSkew = (int)$this->config->getAppValue('encryption', 'hsm.jwt.clockskew', '120'); // 2min
		$this->clientService = $clientService;
		$this->request = $request;
		$this->timeFactory = $timeFactory;
	}

	/**
	 * create new private/public key-pair for user
	 * any key config happens in the service
	 *
	 * @param string|null $label human readable name
	 * @return array|false
	 */
	#[\Override]
	public function createKeyPair(?string $label = null) {
		$response = $this->clientService->newClient()->post(
			$this->hsmUrl . self::PATH_NEW_KEY,
			[
			'headers' => [
				'Authorization' => 'Bearer ' . JWT::token([
						'iss' => $this->config->getSystemValue('instanceid'),
						'sub' => $label,
						'aud' => 'hsmdaemon',
						'exp' => $this->timeFactory->getTime() + $this->clockSkew,
						'rid' => $this->request->getId(),
					], $this->secret)
			],
		]
		);
		$keyPair = \json_decode($response->getBody(), true);

		return [
			/** @phan-suppress-next-line PhanTypeArraySuspiciousNullable */
			'publicKey' => $keyPair['publicKey'],
			/** @phan-suppress-next-line PhanTypeArraySuspiciousNullable */
			'privateKey' => $keyPair['privateKeyId'] // returns the key id in the hsm, not the actual private key
		];
	}

	/**
	 * check if it is a valid private key
	 *
	 * For HSM, the private key is actually a key ID (UUID), not the actual key.
	 * We just verify it's not empty.
	 */
	#[\Override]
	protected function isValidPrivateKey(string $plainKey): bool {
		// For HSM, we just check if the key ID is not empty
		// The actual validation happens on the HSM side
		return !empty($plainKey);
	}

	/**
	 * @param string $privateKey string contains the key uuid in the hsm
	 * @throws MultiKeyDecryptException
	 */
	#[\Override]
	public function multiKeyDecrypt(string $encKeyFile, string $shareKey, $privateKey): string {
		if (!$encKeyFile) {
			throw new MultiKeyDecryptException('Cannot multikey decrypt empty plain content');
		}

		// decrypt the shareKey
		$keyId = $privateKey; // TODO check $privateKey is a uuid, should have been generated with genkey

		try {
			$response = $this->clientService->newClient()->post(
				$this->hsmUrl . self::PATH_DECRYPT . $keyId,
				[
				'headers' => [
					'Authorization' => 'Bearer ' . JWT::token([
							'iss' => $this->config->getSystemValue('instanceid'),
							// 'sub' => $keyId, does not add anything right now, use md5 of $shareKey?
							'aud' => 'hsmdaemon',
							'exp' => $this->timeFactory->getTime() + $this->clockSkew,
							'rid' => $this->request->getId(),
						], $this->secret)
				],
				'body' => $shareKey
			]
			);
			$decryptedKey = $response->getBody();

			// differentiate encryption type by looking key length
			$binaryEncode = \strlen(\bin2hex($encKeyFile)) === self::BINARY_ENCODED_KEY_LENGTH;

			// now decode the file.
			// version and position are 0 because we always use fresh random data as passphrase
			$decryptedContent = $this->symmetricDecryptFileContent($encKeyFile, $decryptedKey, self::DEFAULT_CIPHER, 0, 0, $binaryEncode);

			return $decryptedContent;
		} catch (ServerException $e) {
			$body = $e->getResponse()->getBody();
			$this->logger->logException($e, ['message' => $body, 'app' => __CLASS__]);
			throw new MultiKeyDecryptException('Cannot multikey decrypt with HSM', '', 0, $e);
		} catch (DecryptionFailedException $e) {
			throw new MultiKeyDecryptException('Cannot multikey decrypt', '', 0, $e);
		}
	}

	/**
	 * Encrypt data using symmetric encryption and public key encryption for each recipient
	 *
	 * HSM uses a different approach than standard Crypt:
	 * - Generate a random file key
	 * - Encrypt content with symmetric encryption using the random key
	 * - Encrypt the random key with each recipient's public key
	 *
	 * @throws MultiKeyEncryptException
	 */
	#[\Override]
	public function multiKeyEncrypt(string $plainContent, array $keyFiles): array {
		$randomKey = $this->generateFileKey();

		// encrypt $plainContent using a random key and iv.
		// version and position are 0 because we use fresh random data as passphrase
		$sealedContent = $this->symmetricEncryptFileContent($plainContent, $randomKey, 0, 0);

		if ($sealedContent === false) {
			throw new MultiKeyEncryptException('Could not create sealed content');
		}

		$encryptedKeys = [];
		// encrypt $randomKey with all public keys
		foreach ($keyFiles as $userId => $publicKey) {
			// Try OAEP padding first (more secure), fall back to PKCS1 for compatibility
			$result = \openssl_public_encrypt(
				$randomKey,
				$encryptedKey,
				$publicKey,
				OPENSSL_PKCS1_OAEP_PADDING
			);

			if ($result === false) {
				// Fallback to PKCS1 padding for compatibility with older HSM configurations
				\openssl_public_encrypt($randomKey, $encryptedKey, $publicKey, OPENSSL_PKCS1_PADDING);
			}

			$encryptedKeys[$userId] = $encryptedKey;
		}

		return [
			'keys' => $encryptedKeys,
			'data' => $sealedContent
		];
	}
}