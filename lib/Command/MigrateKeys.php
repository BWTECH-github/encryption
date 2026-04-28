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

namespace OCA\Encryption\Command;

use OC\Files\View;
use OCA\Encryption\Migration;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\ILogger;
use OCP\IUserBackend;
use OCP\IUserManager;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class MigrateKeys extends Command {
	public function __construct(
		private readonly IUserManager $userManager,
		private readonly View $view,
		private readonly IDBConnection $connection,
		private readonly IConfig $config,
		private readonly ILogger $logger
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		$this
			->setName('encryption:migrate')
			->setDescription('initial migration to encryption 2.0')
			->addArgument(
				'user_id',
				InputArgument::OPTIONAL | InputArgument::IS_ARRAY,
				'will migrate keys of the given user(s)'
			);
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		// perform system reorganization
		$migration = new Migration($this->config, $this->view, $this->connection, $this->logger);

		$users = $input->getArgument('user_id');
		if (!empty($users)) {
			foreach ($users as $user) {
				if ($this->userManager->userExists($user)) {
					$output->writeln("Migrating keys   <info>$user</info>");
					$migration->reorganizeFolderStructureForUser($user);
				} else {
					$output->writeln("<error>Unknown user $user</error>");
				}
			}
		} else {
			$output->writeln("Reorganize system folder structure");
			$migration->reorganizeSystemFolderStructure();
			$migration->updateDB();
			foreach ($this->userManager->getBackends() as $backend) {
				$name = \get_class($backend);

				if ($backend instanceof IUserBackend) {
					$name = $backend->getBackendName();
				}

				$output->writeln("Migrating keys for users on backend <info>$name</info>");

				$limit = 500;
				$offset = 0;
				do {
					$users = $backend->getUsers('', $limit, $offset);
					foreach ($users as $user) {
						$output->writeln("   <info>$user</info>");
						$migration->reorganizeFolderStructureForUser($user);
					}
					$offset += $limit;
				} while (\count($users) >= $limit);
			}
		}

		$migration->finalCleanUp();
		return 0;
	}
}
