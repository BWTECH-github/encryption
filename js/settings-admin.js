/**
 * Copyright (c) 2013
 *  Sam Tuke <samtuke@owncloud.com>
 *  Robin Appelman <icewind1991@gmail.com>
 *  Bjoern Schiessle <schiessle@owncloud.com>
 * This file is licensed under the Affero General Public License version 3 or later.
 * See the COPYING-README file.
 */

$(document).ready(function () {

	/*
	 * Do the action based on the selection of encryption type
	 * @param {string} encryptionType the type of encryption selection. (eg: masterkey or customkey)
	 * @param {string} state the state after relogin to the server which is always static. Before relogin its undefined and post relogin "static" is the state.
	 */
	function encryptionTypeSelection(encryptionType, state=undefined) {
		if (encryptionType === "masterkey") {
			//If user selects "Master Key" from the drop down
			$("#select-mode").removeClass("hidden");

			if(state === "static") {
				// Die Schlüsselart steht fest: Auswahl samt Beschriftung weg, die
				// Vorlage nennt die Art übersetzt (#encryptionType).
				$("#encryptionKeySelection").addClass("hidden");
				$("#encryptHomeStorageSetting, #encryptionSetRecoveryKey, #encryptionSetRecoveryKeyTitle").addClass("hidden");
			}
		} else if (encryptionType === "customkey") {
			//If user selects "User-specific key" from the drop down
			$("#select-mode").removeClass("hidden");

			if(state === "static") {
				$("#encryptionKeySelection").addClass("hidden");

				$("#encryptHomeStorageSetting, #encryptionSetRecoveryKey, #encryptionSetRecoveryKeyTitle").removeClass("hidden");

			}
		} else {
			//If user selects "Please select an encryption option" from the drop down
			$("#select-mode").addClass("hidden");
		}

	}

	var $keySelection = $("#encryptionKeySelection");

	encryptionTypeSelection($("#keyTypeId :selected").val(), "static");

	if($keySelection.attr("data-master-key") === "") {
		if($keySelection.attr("data-user-specific-key") !== "") {
			encryptionTypeSelection("customkey", "static");
		}
	}

	$("#keyTypeId").change(function (element) {
		encryptionTypeSelection($("#keyTypeId :selected").val());
	});

	$("#select-mode").click(function () {
		//Action to be taken when "Select this mode" button is selected.
		// Läuft: der Knopf ist gesperrt, bis die Seite neu lädt.
		var $button = $(this).prop('disabled', true);
		if($("#keyTypeId :selected").val() === "masterkey") {
			var masterAjaxObj = OC.AppConfig.setValue('encryption', 'useMasterKey', '1');
			$.when(masterAjaxObj).done(function (masterKeyObj) {
				location.reload();
			}).fail(function () {
				$button.prop('disabled', false);
			});
		}
	});

	$('input:button[name="enableRecoveryKey"]').click(function () {

		var recoveryStatus = $(this).attr('status');
		var newRecoveryStatus = (1 + parseInt(recoveryStatus)) % 2;
		var buttonValue = $(this).attr('value');

		var recoveryPassword = $('#encryptionRecoveryPassword').val();
		var confirmPassword = $('#repeatEncryptionRecoveryPassword').val();
		OC.msg.startSaving('#encryptionSetRecoveryKey .msg');
		$.post(
			OC.generateUrl('/apps/encryption/ajax/adminRecovery'),
			{
				adminEnableRecovery: newRecoveryStatus,
				recoveryPassword: recoveryPassword,
				confirmPassword: confirmPassword
			}
		).done(function (data) {
				OC.msg.finishedSuccess('#encryptionSetRecoveryKey .msg', data.data.message);

				if (newRecoveryStatus === 0) {
					$('#encryptionChangeRecoveryKey, #encryptionChangeRecoveryKeyTitle').addClass("hidden");
					$('input:button[name="enableRecoveryKey"]').attr('value', t('encryption', 'Enable recovery key'));
					$('input:button[name="enableRecoveryKey"]').attr('status', '0');
					$("#encryptionRecoveryPassword").val("");
					$("#repeatEncryptionRecoveryPassword").val("");
				} else {
					$('input:password[name="changeRecoveryPassword"]').val("");
					$('#encryptionChangeRecoveryKey, #encryptionChangeRecoveryKeyTitle').removeClass("hidden");
					$('input:button[name="enableRecoveryKey"]').attr('value', t('encryption', 'Disable recovery key'));
					$('input:button[name="enableRecoveryKey"]').attr('status', '1');
				}
			})
			.fail(function (jqXHR) {
				$('input:button[name="enableRecoveryKey"]').attr('value', buttonValue);
				$('input:button[name="enableRecoveryKey"]').attr('status', recoveryStatus);
				OC.msg.finishedError('#encryptionSetRecoveryKey .msg', JSON.parse(jqXHR.responseText).data.message);
			});


	});

	$("#repeatEncryptionRecoveryPassword").keyup(function (event) {
		if (event.keyCode == 13) {
			$("#enableRecoveryKey").click();
		}
	});

	// change recovery password

	$('button:button[name="submitChangeRecoveryKey"]').click(function () {
		var oldRecoveryPassword = $('#oldEncryptionRecoveryPassword').val();
		var newRecoveryPassword = $('#newEncryptionRecoveryPassword').val();
		var confirmNewPassword = $('#repeatedNewEncryptionRecoveryPassword').val();
		OC.msg.startSaving('#encryptionChangeRecoveryKey .msg');
		$.post(
			OC.generateUrl('/apps/encryption/ajax/changeRecoveryPassword'),
			{
				oldPassword: oldRecoveryPassword,
				newPassword: newRecoveryPassword,
				confirmPassword: confirmNewPassword
			}
		).done(function (data) {
				OC.msg.finishedSuccess('#encryptionChangeRecoveryKey .msg', data.data.message);
			})
			.fail(function (jqXHR) {
				OC.msg.finishedError('#encryptionChangeRecoveryKey .msg', JSON.parse(jqXHR.responseText).data.message);
			});
	});

	$('#encryptHomeStorage').change(function() {
		$.post(
			OC.generateUrl('/apps/encryption/ajax/setEncryptHomeStorage'),
			{
				encryptHomeStorage: this.checked
			}
		);
	});

});
