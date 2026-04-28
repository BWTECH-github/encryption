<?php

declare(strict_types=1);
/**
 * @author Björn Schießle <bjoern@schiessle.org>
 * @author Clark Tomlinson <fallen013@gmail.com>
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

use OCA\Encryption\Hooks\Contracts\IHook;

class HookManager {
	/** @var IHook[] */
	private array $hookInstances = [];

	/**
	 * @param array|IHook $instances
	 *        - This accepts either a single instance of IHook or an array of instances of IHook
	 */
	public function registerHook($instances): bool {
		if (\is_array($instances)) {
			foreach ($instances as $instance) {
				if (!$instance instanceof IHook) {
					return false;
				}
				$this->hookInstances[] = $instance;
			}
		} elseif ($instances instanceof IHook) {
			$this->hookInstances[] = $instances;
		}
		return true;
	}

	public function fireHooks(): void {
		foreach ($this->hookInstances as $instance) {
			// Fire off the add hooks method of each instance stored in cache
			$instance->addHooks();
		}
	}
}
