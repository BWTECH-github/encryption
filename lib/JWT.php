<?php

declare(strict_types=1);
/**
 * @author Jörn Friedrich Dreyer <jfd@butonic.de>
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
namespace OCA\Encryption;

class JWT {
	public static function base64UrlEncode(string $data): string {
		return \str_replace('=', '', \strtr(\base64_encode($data), '+/', '-_'));
	}

	public static function header(): string {
		return self::base64UrlEncode(\json_encode([
			'typ' => 'JWT',
			'alg' => 'HS256'
		]));
	}

	public static function payload(array $payload): string {
		$payload = \array_merge($payload, [
			'iat' => \time(),
			'jti' => \uniqid('', true)
		]);
		return self::base64UrlEncode(\json_encode($payload));
	}

	public static function signature(string $data, string $key): string {
		return self::base64UrlEncode(\hash_hmac('sha256', $data, $key, true));
	}

	public static function token(array $payload, string $secret): string {
		$token = self::header().'.'.self::payload($payload);
		return $token.'.'.self::signature($token, $secret);
	}
}
