<?php

declare(strict_types=1);
/**
 * @author Björn Schießle <bjoern@schiessle.org>
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

namespace OCA\Encryption\Controller;

use OCA\Encryption\Session;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\DataResponse;
use OCP\IL10N;
use OCP\IRequest;

class StatusController extends Controller {
	public function __construct(
		string $AppName,
		IRequest $request,
		private readonly IL10N $l,
		private readonly Session $session
	) {
		parent::__construct($AppName, $request);
	}

	/**
	 * @NoAdminRequired
	 */
	public function getStatus(): DataResponse {
		[$status, $message] = match ($this->session->getStatus()) {
			Session::RUN_MIGRATION => [
				'interactionNeeded',
				(string)$this->l->t(
					'You need to migrate your encryption keys from the old encryption (ownCloud <= 8.0) to the new one. Please run \'occ encryption:migrate\' or contact your administrator'
				),
			],
			Session::INIT_EXECUTED => [
				'interactionNeeded',
				(string)$this->l->t(
					'Invalid private key for Encryption App. Please update your private key password in your personal settings to recover access to your encrypted files.'
				),
			],
			Session::NOT_INITIALIZED => [
				'interactionNeeded',
				(string)$this->l->t(
					'Encryption App is enabled, but your keys are not initialized. Please log-out and log-in again.'
				),
			],
			Session::INIT_SUCCESSFUL => [
				'success',
				(string)$this->l->t('Encryption App is enabled and ready'),
			],
			default => ['error', 'no valid init status'],
		};

		return new DataResponse(
			[
				'status' => $status,
				'data' => [
					'message' => $message]
			]
		);
	}
}
