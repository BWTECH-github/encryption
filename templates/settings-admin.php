<?php
/** @var array $_ */
/** @var \OCP\IL10N $l */
/*
 * Modified by BW-Tech GmbH on 2026-11-13: eigene Karte nach dem Einstellungs-
 * Gerüst des Redesigns (div.section, Feldpaare, Hauptknopf der Karte, Gruppen-
 * titel). Vorher form.sub-section ohne Karte, Abstände über <br>, Inline-
 * Stile, Kennwortfelder nur mit Platzhalter, Erklärzeilen in <em> und ein
 * Verweis auf die Dokumentation eines Fremdanbieters.
 */
script('encryption', 'settings-admin');
$appConfig = \OC::$server->getAppConfig();
$masterKey = $appConfig->getValue('encryption', 'useMasterKey', '0');
$userSpecificKey = $appConfig->getValue('encryption', 'userSpecificKey', '');
?>
<div class="section" id="ocDefaultEncryptionModule">
	<h2 class="app-name"><?php p($l->t('Default encryption module')); ?></h2>
	<?php if (!$_["initStatus"] and ($masterKey !== '0' or $appConfig->getValue('encryption', 'encryptHomeStorage', '') !== '')): ?>
		<p class="warning"><?php p($l->t("Encryption App is enabled but your keys are not initialized, please log-out and log-in again")); ?></p>
	<?php else: ?>
		<?php if ($masterKey !== '0'): ?>
		<p id="encryptionType"><?php p($l->t("Encryption type: Master Key")); ?></p>
		<?php elseif ($userSpecificKey !== ''): ?>
		<p id="encryptionType"><?php p($l->t("Encryption type: User Specific Key")); ?></p>
		<p class="warning" id="userSpecificKeyWarning"><?php p($l->t("User Specific Key encryption module is deprecated.")); ?></p>
		<?php endif; ?>
		<div id="encryptionKeySelection" data-master-key="<?php p($appConfig->getValue('encryption', 'useMasterKey', '')); ?>" data-user-specific-key="<?php p($userSpecificKey); ?>">
			<div class="oco-feldpaar">
				<label for="keyTypeId"><?php p($l->t('Key type')); ?></label>
				<select id="keyTypeId" name="keyType">
					<option value="nokey"><?php p($l->t("Please select an encryption option"))?></option>
					<option value="masterkey"<?php if ($masterKey !== '0') {
						print_unescaped(' selected="selected"');
					} ?>><?php p($l->t("Master Key"))?></option>
				</select>
			</div>
			<button id="select-mode" type="button" class="oco-btn-primary hidden"><?php p($l->t("Permanently select this mode")); ?></button>
		</div>

		<p id="encryptHomeStorageSetting" class="hidden">
			<input type="checkbox" class="checkbox" name="encrypt_home_storage" id="encryptHomeStorage"
				   value="1" <?php if ($_['encryptHomeStorage']) {
				   	print_unescaped('checked="checked"');
				   } ?> />
			<label for="encryptHomeStorage"><?php p($l->t('Encrypt the home storage')); ?></label>
		</p>
		<?php if ($_['masterKeyEnabled'] === false): ?>
			<h3 class="oco-gruppentitel hidden" id="encryptionSetRecoveryKeyTitle"><?php p($l->t("Recovery key")); ?></h3>
			<form id="encryptionSetRecoveryKey" class="encryption-gruppe hidden" novalidate>
				<div class="oco-feldpaar">
					<label for="encryptionRecoveryPassword"><?php p($l->t("Recovery key password")); ?></label>
					<input type="password" name="encryptionRecoveryPassword" id="encryptionRecoveryPassword" autocomplete="new-password" />
				</div>
				<div class="oco-feldpaar">
					<label for="repeatEncryptionRecoveryPassword"><?php p($l->t("Repeat recovery key password")); ?></label>
					<input type="password" name="encryptionRecoveryPassword" id="repeatEncryptionRecoveryPassword" autocomplete="new-password" />
				</div>
				<input type="button"
					   class="oco-btn-primary"
					   name="enableRecoveryKey"
					   id="enableRecoveryKey"
					   status="<?php p($_["recoveryEnabled"]) ?>"
					   value="<?php $_["recoveryEnabled"] === '0' ? p($l->t("Enable recovery key")) : p($l->t("Disable recovery key")); ?>"/>
				<span class="msg" role="status" aria-live="polite"></span>
			</form>

			<?php $changeHidden = $_['recoveryEnabled'] === '0' ? ' hidden' : ''; ?>
			<h3 class="oco-gruppentitel<?php p($changeHidden); ?>" id="encryptionChangeRecoveryKeyTitle"><?php p($l->t("Change recovery key password")); ?></h3>
			<form id="encryptionChangeRecoveryKey" class="encryption-gruppe<?php p($changeHidden); ?>" novalidate>
				<div class="oco-feldpaar">
					<label for="oldEncryptionRecoveryPassword"><?php p($l->t("Old recovery key password")); ?></label>
					<input type="password" name="changeRecoveryPassword" id="oldEncryptionRecoveryPassword" autocomplete="current-password" />
				</div>
				<div class="oco-feldpaar">
					<label for="newEncryptionRecoveryPassword"><?php p($l->t("New recovery key password")); ?></label>
					<input type="password" name="changeRecoveryPassword" id="newEncryptionRecoveryPassword" autocomplete="new-password" />
				</div>
				<div class="oco-feldpaar">
					<label for="repeatedNewEncryptionRecoveryPassword"><?php p($l->t("Repeat new recovery key password")); ?></label>
					<input type="password" name="changeRecoveryPassword" id="repeatedNewEncryptionRecoveryPassword" autocomplete="new-password" />
				</div>
				<button type="button" name="submitChangeRecoveryKey"><?php p($l->t("Change Password")); ?></button>
				<span class="msg" role="status" aria-live="polite"></span>
			</form>
		<?php endif; ?>
	<?php endif; ?>
</div>
