<?php

declare(strict_types=1);
/**
 * @author Björn Schießle <bjoern@schiessle.org>
 * @author Roeland Jago Douma <rullzer@owncloud.com>
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

use OC\Encryption\Exceptions\DecryptionFailedException;
use OC\Files\View;
use OCA\Encryption\KeyManager;
use OCA\Encryption\Users\Setup;
use OCA\Encryption\Util;
use OCP\IConfig;
use OCP\IL10N;
use OCP\IUserManager;
use OCP\Mail\IMailer;
use OCP\Security\ISecureRandom;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Helper\QuestionHelper;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ConfirmationQuestion;

class EncryptAll {
	/** @var array */
	protected array $userPasswords = [];

	protected OutputInterface $output;

	protected InputInterface $input;

	public function __construct(
		protected readonly Setup $userSetup,
		protected readonly IUserManager $userManager,
		protected readonly View $rootView,
		protected readonly KeyManager $keyManager,
		protected readonly Util $util,
		protected readonly IConfig $config,
		protected readonly IMailer $mailer,
		protected readonly IL10N $l,
		protected readonly QuestionHelper $questionHelper,
		protected readonly ISecureRandom $secureRandom
	) {
	}

	/**
	 * Call this method only when no master key is created.
	 *
	 * @return bool true when masterkey and sharekey is created else false
	 */
	public function createMasterKey(): bool {
		$this->keyManager->setPublicShareKeyIDAndMasterKeyId();

		/**
		 * Call validateShareKey method, to check if public share exists,
		 * else create one.
		 */
		$this->keyManager->validateShareKey();
		/**
		 * Same here, check if public masterkey exists else
		 * create one.
		 */
		$this->keyManager->validateMasterKey();
		return (!empty($this->keyManager->getPublicShareKey()) && !empty($this->keyManager->getPublicMasterKey()));
	}

	/**
	 * start to encrypt all files
	 */
	public function encryptAll(InputInterface $input, OutputInterface $output): void {
		$this->input = $input;
		$this->output = $output;

		$headline = 'Encrypt all files with the ' . Encryption::DISPLAY_NAME;
		$this->output->writeln("\n");
		$this->output->writeln($headline);
		/** @phan-suppress-next-line PhanParamSuspiciousOrder phan thinks this is strange code, but it is fine. */
		$this->output->writeln(\str_pad('', \strlen($headline), '='));
		$this->output->writeln("\n");

		if ($this->util->isMasterKeyEnabled()) {
			$this->output->writeln('Use master key to encrypt all files.');
			$this->keyManager->validateMasterKey();
		} else {
			//create private/public keys for each user and store the private key password
			$this->output->writeln('Create key-pair for every user');
			$this->output->writeln('------------------------------');
			$this->output->writeln('');
			$this->output->writeln('This module will encrypt all files in the users files folder initially.');
			$this->output->writeln('Already existing versions and files in the trash bin will not be encrypted.');
			$this->output->writeln('');
			$this->createKeyPairs();
		}

		//setup users file system and encrypt all files one by one (take should encrypt setting of storage into account)
		$this->output->writeln("\n");
		$this->output->writeln('Start to encrypt users files');
		$this->output->writeln('----------------------------');
		$this->output->writeln('');
		$this->encryptAllUsersFiles();
		if ($this->util->isMasterKeyEnabled() === false) {
			//send-out or display password list and write it to a file
			$this->output->writeln("\n");
			$this->output->writeln('Generated encryption key passwords');
			$this->output->writeln('----------------------------------');
			$this->output->writeln('');
			$this->outputPasswords();
		}
		$this->output->writeln("\n");
	}

	/**
	 * create key-pair for every user
	 */
	protected function createKeyPairs(): void {
		$this->output->writeln("\n");
		$progress = new ProgressBar($this->output);
		$progress->setFormat(" %message% \n [%bar%]");
		$progress->start();

		foreach ($this->userManager->getBackends() as $backend) {
			$limit = 500;
			$offset = 0;
			do {
				$users = $backend->getUsers('', $limit, $offset);
				foreach ($users as $user) {
					if ($this->keyManager->userHasKeys($user) === false) {
						$progress->setMessage('Create key-pair for ' . $user);
						$progress->advance();
						$this->setupUserFS($user);
						$password = $this->generateOneTimePassword($user);
						$this->userSetup->setupUser($user, $password);
					} else {
						// users which already have a key-pair will be stored with a
						// empty password and filtered out later
						$this->userPasswords[$user] = '';
					}
				}
				$offset += $limit;
			} while (\count($users) >= $limit);
		}

		$progress->setMessage('Key-pair created for all users');
		$progress->finish();
	}

	/**
	 * iterate over all user and encrypt their files
	 */
	protected function encryptAllUsersFiles(): void {
		$this->output->writeln("\n");
		$progress = new ProgressBar($this->output);
		$progress->setFormat(" %message% \n [%bar%]");
		$progress->start();
		$numberOfUsers = \count($this->userPasswords);
		$userNo = 1;
		if ($this->util->isMasterKeyEnabled()) {
			$this->encryptAllUserFilesWithMasterKey($progress);
		} else {
			foreach ($this->userPasswords as $uid => $password) {
				$userCount = "$uid ($userNo of $numberOfUsers)";
				$this->encryptUsersFiles($uid, $progress, $userCount);
				$userNo++;
			}
		}
		$progress->setMessage("all files encrypted");
		$progress->finish();
	}

	/**
	 * encrypt all user files with the master key
	 */
	protected function encryptAllUserFilesWithMasterKey(ProgressBar $progress): void {
		$userNo = 1;
		foreach ($this->userManager->getBackends() as $backend) {
			$limit = 500;
			$offset = 0;
			do {
				$users = $backend->getUsers('', $limit, $offset);
				foreach ($users as $user) {
					$userCount = "$user ($userNo)";
					$this->encryptUsersFiles($user, $progress, $userCount);
					$userNo++;
				}
				$offset += $limit;
			} while (\count($users) >= $limit);
		}
	}

	/**
	 * encrypt files from the given user
	 */
	protected function encryptUsersFiles(string $uid, ProgressBar $progress, string $userCount): void {
		$this->setupUserFS($uid);
		$directories = [];
		$directories[] = '/' . $uid . '/files';

		while ($root = \array_pop($directories)) {
			$content = $this->rootView->getDirectoryContent($root);
			foreach ($content as $file) {
				// only encrypt files owned by the user, exclude incoming local shares, and incoming federated shares
				if ($file->getStorage()->instanceOfStorage('\OCA\Files_Sharing\ISharedStorage')) {
					continue;
				}
				$path = $root . '/' . $file['name'];
				if ($this->rootView->is_dir($path)) {
					$directories[] = $path;
					continue;
				} else {
					$progress->setMessage("encrypt files for user $userCount: $path");
					$progress->advance();
					if ($this->encryptFile($path) === false) {
						$progress->setMessage("encrypt files for user $userCount: $path (already encrypted)");
						$progress->advance();
					}
				}
			}
		}
	}

	/**
	 * encrypt file
	 */
	protected function encryptFile(string $path): bool {
		$source = $path;
		$target = $path . '.encrypted.' . $this->getTimeStamp() . '.part';

		try {
			$version = $this->keyManager->getVersion($source, $this->rootView);
			if ($version > 0) {
				return false;
			}
			$this->rootView->copy($source, $target);
			$this->rootView->rename($target, $source);
		} catch (DecryptionFailedException $e) {
			if ($this->rootView->file_exists($target)) {
				$this->rootView->unlink($target);
			}
			return false;
		}

		return true;
	}

	/**
	 * output one-time encryption passwords
	 */
	protected function outputPasswords(): void {
		$table = new Table($this->output);
		$table->setHeaders(['Username', 'Private key password']);

		//create rows
		$newPasswords = [];
		$unchangedPasswords = [];
		foreach ($this->userPasswords as $uid => $password) {
			if (empty($password)) {
				$unchangedPasswords[] = $uid;
			} else {
				$newPasswords[] = [$uid, $password];
			}
		}

		if (empty($newPasswords)) {
			$this->output->writeln("\nAll users already had a key-pair, no further action needed.\n");
			return;
		}

		$table->setRows($newPasswords);
		$table->render();

		if (!empty($unchangedPasswords)) {
			$this->output->writeln("\nThe following users already had a key-pair which was reused without setting a new password:\n");
			foreach ($unchangedPasswords as $uid) {
				$this->output->writeln("    $uid");
			}
		}

		$this->writePasswordsToFile($newPasswords);

		$this->output->writeln('');
		$question = new ConfirmationQuestion('Do you want to send the passwords directly to the users by mail? (y/n) ', false);
		if ($this->questionHelper->ask($this->input, $this->output, $question)) {
			$this->sendPasswordsByMail();
		}
	}

	/**
	 * write one-time encryption passwords to a csv file
	 */
	protected function writePasswordsToFile(array $passwords): void {
		$fp = $this->rootView->fopen('oneTimeEncryptionPasswords.csv', 'w');
		if (!\is_resource($fp)) {
			throw new \Exception('Could not open oneTimeEncryptionPasswords.csv for writing');
		}
		foreach ($passwords as $pwd) {
			\fputcsv($fp, $pwd);
		}
		\fclose($fp);
		$this->output->writeln("\n");
		$this->output->writeln('A list of all newly created passwords was written to data/oneTimeEncryptionPasswords.csv');
		$this->output->writeln('');
		$this->output->writeln('Each of these users need to login to the web interface, go to the');
		$this->output->writeln('personal settings section "ownCloud basic encryption module" and');
		$this->output->writeln('update the private key password to match the login password again by');
		$this->output->writeln('entering the one-time password into the "old log-in password" field');
		$this->output->writeln('and their current login password');
	}

	/**
	 * setup user file system
	 */
	protected function setupUserFS(string $uid): void {
		\OC_Util::tearDownFS();
		\OC_Util::setupFS($uid);
	}

	/**
	 * get current timestamp
	 */
	protected function getTimeStamp(): int {
		return \time();
	}

	/**
	 * generate one time password for the user and store it in a array
	 *
	 * @return string password
	 */
	protected function generateOneTimePassword(string $uid): string {
		$password = $this->secureRandom->generate(8);
		$this->userPasswords[$uid] = $password;
		return $password;
	}

	/**
	 * send encryption key passwords to the users by mail
	 */
	protected function sendPasswordsByMail(): void {
		$noMail = [];

		$this->output->writeln('');
		$progress = new ProgressBar($this->output, \count($this->userPasswords));
		$progress->start();

		foreach ($this->userPasswords as $uid => $password) {
			$progress->advance();
			if (!empty($password)) {
				$recipient = $this->userManager->get($uid);
				$recipientDisplayName = $recipient->getDisplayName();
				$to = $recipient->getEMailAddress();

				if ($to === '') {
					$noMail[] = $uid;
					continue;
				}

				$subject = (string)$this->l->t('one-time password for server-side-encryption');
				[$htmlBody, $textBody] = $this->createMailBody($password);

				// send it out now
				try {
					$message = $this->mailer->createMessage();
					$message->setSubject($subject);
					$message->setTo([$to => $recipientDisplayName]);
					$message->setHtmlBody($htmlBody);
					$message->setPlainBody($textBody);
					$message->setFrom([
						\OCP\Util::getDefaultEmailAddress('admin-noreply')
					]);

					$this->mailer->send($message);
				} catch (\Exception $e) {
					$noMail[] = $uid;
				}
			}
		}

		$progress->finish();

		if (empty($noMail)) {
			$this->output->writeln("\n\nPassword successfully send to all users");
		} else {
			$table = new Table($this->output);
			$table->setHeaders(['Username', 'Private key password']);
			$this->output->writeln("\n\nCould not send password to following users:\n");
			$rows = [];
			foreach ($noMail as $uid) {
				$rows[] = [$uid, $this->userPasswords[$uid]];
			}
			$table->setRows($rows);
			$table->render();
		}
	}

	/**
	 * create mail body for plain text and html mail
	 *
	 * @param string $password one-time encryption password
	 * @return array an array of the html mail body and the plain text mail body
	 */
	protected function createMailBody(string $password): array {
		$html = new \OC_Template("encryption", "mail", "");
		$html->assign('password', $password);
		$htmlMail = $html->fetchPage();

		$plainText = new \OC_Template("encryption", "altmail", "");
		$plainText->assign('password', $password);
		$plainTextMail = $plainText->fetchPage();

		return [$htmlMail, $plainTextMail];
	}
}
