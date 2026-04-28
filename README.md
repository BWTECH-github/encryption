# encryption

Server-side encryption module for ownCloud (PHP 8.4 fork maintained by BW-Tech GmbH for [owncloud.online](https://bw.tech)).

This is a fork of [owncloud/encryption](https://github.com/owncloud/encryption) modernized for PHP 8.4 and ownCloud 11. Encryption logic is preserved — only the platform requirements, branding, and code idioms have changed.

## Features

- AES-256 transparent server-side encryption of files in ownCloud
- Master-key based encryption (admin-controlled, no per-user passwords required)
- Optional recovery key for password-reset scenarios
- HSM (Hardware Security Module) backend for storing the master private key off-server
- OCC commands for migration, recovery, and master-key rotation
- Compatible with files encrypted by upstream ownCloud encryption 1.5–1.6.x (legacy RC4 fallback for `openssl_seal` payloads)

## Requirements

| Component | Minimum |
|-----------|---------|
| ownCloud Core | 10.12 (max 11) |
| PHP | 8.4 |
| OpenSSL | 1.1.x or 3.x with legacy provider enabled (see notes below) |
| ext-openssl | required |

## Installation

```bash
cd /var/www/owncloud/apps
git clone https://github.com/BWTECH-github/owncloud.online.git
cd owncloud.online   # or the actual checkout if you only want the encryption app
composer install --no-dev --optimize-autoloader
chown -R www-data:www-data .
sudo -u www-data php /var/www/owncloud/occ app:enable encryption
sudo -u www-data php /var/www/owncloud/occ encryption:enable
sudo -u www-data php /var/www/owncloud/occ encryption:select-encryption-type masterkey
```

If you previously had user-key encryption enabled and want to switch to master-key, run `encryption:migrate-key-storage-format` and `encryption:select-encryption-type masterkey -y` (the `-y` skips the interactive confirmation).

## Configuration

Encryption-related app settings are stored in `oc_appconfig` and can be inspected/modified via `occ config:app:set encryption <key> --value <value>`. Most of these are managed automatically by the OCC commands below; change them manually only when you understand the implication.

| Key | Values | Description |
|-----|--------|-------------|
| `masterKeyId` | string | ID of the active master key (auto-generated, e.g. `master_a1b2c3`) |
| `recoveryKeyId` | string | ID of the recovery key, if recovery is enabled |
| `useMasterKey` | `0` / `1` | Whether master-key encryption is active |
| `recoveryAdminEnabled` | `0` / `1` | Whether the recovery admin feature is on |
| `crypto.engine` | `internal` \| `hsm` | Cipher engine: in-process (`internal`) or HSM-daemon (`hsm`) |
| `hsm.url` | URL | HSM daemon endpoint (only when `crypto.engine = hsm`) |
| `hsm.jwt.secret` | string | Shared JWT secret for HSM daemon authentication |

Example `config/config.php` snippet for an HSM-backed setup:

```php
'encryption.legacy_format_support' => false,
'encryption.key_storage_migrated' => 1,
'encryption_skip_signature_check' => false,
```

## OCC commands

All commands are exposed under the `encryption:` namespace. Run as the web-server user.

### `encryption:recreate-master-key`

Generate a new master key and re-encrypt every file's per-file key with it.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-y, --yes` | flag | off | Skip the interactive confirmation prompt |

```bash
sudo -u www-data php occ encryption:recreate-master-key -y
```

### `encryption:migrate [user_id...]`

One-time key-storage reorganization to the encryption 2.0 layout. Pass user IDs to migrate only specific users; pass nothing to migrate the system-wide keys.

```bash
sudo -u www-data php occ encryption:migrate            # system keys
sudo -u www-data php occ encryption:migrate alice bob  # specific users
```

### `encryption:hsmdaemon`

Manage the HSM-stored master key (only with `crypto.engine = hsm`).

| Option | Type | Description |
|--------|------|-------------|
| `--export-masterkey` | flag | Export the private master key as base64 |
| `--import-masterkey=<base64>` | string | Import a previously exported master key |

### `encryption:hsmdaemon:decrypt <ciphertext>`

Decrypt a base64-encoded blob via the HSM daemon — useful for diagnostics.

| Argument / Option | Required | Description |
|-------------------|----------|-------------|
| `decrypt` (arg) | yes | Base64-encoded ciphertext to decrypt |
| `--username=<uid>` | no | User context (prompts for password) |
| `--keyId=<id>` | no | Specific keyId to decrypt with |

### `encryption:fix-encrypted-version <user>`

Repair the persisted "encrypted-version" metadata of a user's files when downloads start failing with signature errors after restores or backups.

| Argument / Option | Required | Default | Description |
|-------------------|----------|---------|-------------|
| `user` (arg) | yes | — | User ID whose files to scan |
| `-p, --path=<path>` | no | all files | Limit to a sub-path, e.g. `--path="/Music/Artist"` |
| `-i, --increment-range=<n>` | no | `5` | Search +/- n versions when locating the right one |

```bash
sudo -u www-data php occ encryption:fix-encrypted-version alice -p "/Documents/Important" -i 10
```

## Daily usage

For most installations there is nothing to do day-to-day — encryption is transparent. Watch the ownCloud log (`config/data/owncloud.log`) for `OCA\Encryption` entries. Typical events:

- New file uploaded → silently encrypted, key derived from master key, share-keys generated for any users with access
- File shared → share-key for the new recipient added, no re-encryption of file body
- User password changed → only personal recovery key (if used) re-wrapped; master-key files unaffected
- User deleted → user's share-keys are cleaned up by ownCloud Core hooks; file bodies remain readable via master key

## Troubleshooting

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| `MultiKeyDecryptException: multikeydecrypt with share key failed` | OpenSSL 3 retired the RC4 cipher used by legacy `openssl_seal` payloads | Enable the OpenSSL 3 legacy provider (see OpenSSL 3.0 wiki §6.2 *Providers*) **or** verify the file was re-keyed with `encryption:recreate-master-key` after upgrading |
| Files refuse to download with `Bad Signature` | Encrypted-version metadata drifted (after a restore from backup) | Run `occ encryption:fix-encrypted-version <user>` |
| `PrivateKeyMissingException` for a user | Master-key migration was not run after switching from user-key to master-key | Run `occ encryption:migrate-key-storage-format` then `occ encryption:migrate` |
| `openssl_get_privatekey` returns false | OpenSSL config rejects the RSA size or hash | Check `openssl_config_path` in `config.php`; the bundled config asks for 4096-bit RSA which some hardened OpenSSL builds reject |
| HSM commands hang | `hsm.url` unreachable or `hsm.jwt.secret` mismatched | Verify with `curl -i $(occ config:app:get encryption hsm.url)/health` and that the JWT secret matches both ends |
| `app encryption is not compatible with this server` after Core upgrade | `appinfo/info.xml` `max-version` exceeded | Ensure you are on a fork build that lists `max-version="11"` (this one does) |

> **Note on OpenSSL 3:** With the December-2021 OpenSSL 1.x → 3.x transition, ciphers retired as legacy (notably RC4 used inside `openssl_seal` for older encrypted-key blobs) stop working unless the legacy provider is enabled. This fork uses `aes-256-ecb` for *new* seal operations and falls back to RC4 only when reading legacy payloads. If you have existing files encrypted by upstream 1.5/1.6 you must keep the legacy provider available until those files have been re-keyed.

## Attribution

- Original code © ownCloud GmbH and the ownCloud encryption authors. Licensed under [AGPL-3.0](LICENSE).
- PHP 8.4 fork and owncloud.online branding © BW-Tech GmbH. Same AGPL-3.0 license.
- Upstream: <https://github.com/owncloud/encryption>
- This fork: <https://github.com/BWTECH-github/owncloud.online>
