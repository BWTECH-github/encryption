# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## [2.0.10] - 2026-09-29

### Fixed

- Öffentliche Links: Der Download einer verschlüsselten Datei über einen öffentlichen Link (mit und ohne Link-Kennwort, `/s/<token>/download`) brach mit HTTP 500 ab („KeyManager::getFileKey(): Argument #2 ($uid) must be of type string, null given“). Ohne angemeldeten Nutzer übergibt der Kern null als uid; das gilt jetzt wieder als öffentlicher Zugriff wie upstream – mit Hauptschlüssel über den Hauptschlüssel, mit Benutzerschlüsseln über den Schlüssel für öffentliche Links. Dasselbe gilt für Kommandozeile und Cron ohne Nutzer sowie für Schlüsselaktualisierungen ohne Sitzung (`update()`, `addSystemKeys()`, `isReadyForUser()`).
- Anmeldung ohne Kennwort (OAuth2-Bearer, OpenID Connect, Token ohne Kennwort): Sobald die App eingeschaltet war – auch ohne aktive Verschlüsselung –, endete jeder WebDAV-Zugriff mit OAuth2-Bearer in HTTP 500 („Setup::setupUser(): Argument #2 ($password) must be of type string, null given“, mit Hauptschlüssel „KeyManager::init(): Argument #2 ($passPhrase) …“). OAuth2 liefert null, OpenID Connect '' als Kennwort; beides wird jetzt gleich behandelt:
  - Hauptschlüssel: Der Schlüssel wird wie upstream mit der Passphrase des Hauptschlüssels geöffnet. Lesen und Schreiben per Bearer funktionieren.
  - Benutzerschlüssel: Ohne Kennwort wird **kein** Schlüsselpaar mehr angelegt. Upstream legte eines mit leerem Kennwort an; der private Schlüssel läge damit faktisch ungeschützt da und passte nach der nächsten Anmeldung mit Kennwort nicht mehr. Das Schlüsselpaar entsteht bei der nächsten Anmeldung mit Kennwort (Warnung im Log). Vorhandene Schlüssel bleiben unverändert; `init()` versucht das leere Kennwort – das öffnet nur Schlüssel, die schon mit leerem Kennwort abgelegt wurden (etwa aus 10.x mit Apache-/SSO-Anmeldung) – und endet sonst sauber mit false und einer Warnung. `KeyManager::storeKeyPair()` lehnt ein leeres Kennwort grundsätzlich ab.
- `occ encryption:decrypt-all` mit Benutzerschlüsseln: Eine nicht gesetzte Umgebungsvariable `OC_RECOVERY_PASSWORD`/`OC_PASSWORD` (getenv() liefert false) oder eine leere Eingabe an der Kennwortabfrage (null) endet mit „Invalid credentials provided“ statt mit einem TypeError.
- Persönliche Einstellungen, „Schlüsselkennwort aktualisieren“: Fehlt ein Feld in der Anfrage, antwortet die App mit 400 statt 500.
- Die App-Werte `recoveryKeyId`, `publicShareKeyId` und `masterKeyId` werden als Zeichenkette gelesen. Ein NULL in `appconfig` (etwa aus einer übernommenen Datenbank) führte sonst beim Aufbau des Schlüsselverwalters zu einem TypeError.

### Changed

- Benutzerschlüssel und OAuth2/OpenID Connect: Bei einer Anmeldung ohne Kennwort bleibt der private Schlüssel für diese Sitzung zu. Lesen einer verschlüsselten Datei per Bearer endet mit HTTP 403, Überschreiben mit HTTP 503 („Encryption not ready: Private Key missing …“, den Code wählt der Kern); neue Dateien lassen sich schreiben, Verzeichnislisten funktionieren. Ein Nutzer ohne Schlüsselpaar kann per Bearer nichts schreiben (HTTP 503 „Public Key missing for user …“), bis er sich einmal mit Kennwort angemeldet hat. Für Instanzen mit OAuth2- oder SSO-Anmeldungen wird der Hauptschlüssel empfohlen; die README beschreibt das im Abschnitt „Benutzerschluessel“ und in der Fehlersuche.
- Unit-Tests an die PHP-8.4-Typen angepasst: Viele Mocks lieferten Rückgabewerte (true, null, Zeichenkette statt Feld), die die getypten Methoden nicht mehr annehmen, und die Suite lief mit 85 Fehlern. Sie läuft jetzt vollständig grün; neue Tests decken die Fälle ohne Nutzer und ohne Kennwort ab.
- Keine Datenbankänderung, keine neue Migration.

## [2.0.9] - 2026-09-26

### Fixed

- Übernahme von Servern 10.x/11: Dateischlüssel, die die Vorgänger-App versiegelt hat, lassen sich wieder öffnen. encryption <= 1.6 (Server 10.x) versiegelte mit RC4, encryption 1.7 (Upstream-Server 11) mit AES-256-ECB. RC4 bietet OpenSSL 3 ohne Legacy-Provider nicht mehr an, AES-256-ECB wurde gar nicht versucht - nach einem Umzug per Datenbank und Datenverzeichnis war jede verschlüsselte Datei unlesbar („Encryption not ready: multikeydecrypt with share key failed: … unsupported“, HTTP 403). Der Umschlagschlüssel wird jetzt selbst per RSA geöffnet, seine Länge wählt das Verfahren, RC4 wird in PHP gerechnet. Neue Umschläge bleiben im bisherigen Format (AES-256-CBC mit IV).
- Übernahme von Servern 10.x/11: Der letzte Block jeder von der Vorgänger-App geschriebenen Datei besteht die Signaturprüfung wieder („Bad Signature“). Der Kern hängt beim letzten Block „end“ an die Position; die Vorgänger-App signiert damit, diese App wandelte die Position seit der PHP-8.4-Umstellung vor dem Prüfen in eine Zahl und schnitt den Zusatz ab. Die Prüfung akzeptiert jetzt beide Schreibweisen (mit und ohne „end“) sowie die alte ohne Bindestrich. Geschrieben wird unverändert mit der Zahl, damit ältere owncloud.online-Stände neue Dateien weiter lesen; auf die upstream-Schreibweise zurückstellen lässt sich das erst, wenn überall mindestens diese Version läuft.
- `occ encryption:fix-encrypted-version` repariert auch Dateien auf lokalen und externen Einhängungen. Auf der Kommandozeile ist niemand angemeldet; solche Speicher lesen ihren Besitzer aus der Sitzung, und der Befehl brach mit „Attempted to initialize mount points for null user and no user in session“ ab. Er läuft jetzt als der angegebene Nutzer und stellt danach den vorherigen Zustand wieder her. Nicht verfügbare Einhängungen (etwa ohne Backend nach einem Umzug) überspringt er mit „Skipping … storage not available“, statt abzubrechen. Gebraucht wird das nach einem Umzug, bei dem eine Einhängung eine neue Speicher-ID bekommen hat und ihre Dateien ohne Versionsangabe neu im Dateicache stehen.

### Changed

- README: neuer Abschnitt „Umzug von einem Server der Version 10.x“ – was die App vom Bestand der Vorgänger-App liest, dass es keinen Rückweg auf 10.x gibt (neue Umschläge im Format v2, letzte Blöcke ohne „end“) und dass eine geänderte Speicher-ID die Versionsangabe im Dateicache verliert (Abhilfe `encryption:fix-encrypted-version`). Die Fehlersuche-Zeile zu RC4 und dem OpenSSL-Legacy-Provider beschreibt jetzt den Stand ab dieser Version.

## [2.0.8] - 2026-09-23

### Fixed

- Persönliche Sektion: Das Formular „Schlüsselkennwort aktualisieren“ erscheint wieder vor dem Hinweis „nicht eingeschaltet“. Auch bei ausgeschalteter Verschlüsselung kann ein Nutzer noch verschlüsselte Dateien und einen nicht mehr passenden Schlüssel haben (die App hängt an isReady(), nicht am Schalter).

## [2.0.7] - 2026-09-23

### Fixed

- Persönliche Einstellungen: Ist die serverseitige Verschlüsselung nicht eingeschaltet, sagt die Sektion das jetzt. Vorher stand dort „Die serverseitige Verschlüsselung ist aktiv und Deine Dateien werden transparent verschlüsselt“ – eine falsche Sicherheitsaussage.

## [2.0.6] - 2026-08-13

### Changed

- Marktbeschreibung neu, deutsch und englisch, mit dem Hinweis, dass das
  Einschalten praktisch endgueltig ist und was der Rueckweg kostet.

## [2.0.5] - 2026-08-13

### Changed

- README als Betriebsdokumentation neu geschrieben: Installation, Einstellungen,
  Kommandozeile und Fehlersuche; tote und fremde Verweise entfernt.

## [2.0.4] - 2026-08-13

### Changed

- Produktname, Beschreibung und uebersetzte Zeichenketten nennen owncloud.online;
  Verweise auf Fehlerbereich, Repository und Dokumentation zeigen auf das eigene
  Repository. Screenshots aus fremden Repositories entfernt.

## [Unreleased]

### Changed

- Forked for [owncloud.online](https://bw.tech) and rebranded by BW-Tech GmbH.
- Minimum PHP version raised to 8.4; `composer.json`, `appinfo/info.xml`, and `composer.lock` aligned.
- Maximum supported ownCloud Core bumped to 11.
- Code modernized to PHP 8.4 idioms: constructor property promotion with `readonly` for DI dependencies, typed properties, `#[\Override]` on parent/interface methods, `match` expressions, explicit nullable parameters.
- CI moved off Drone and the upstream `owncloud/reusable-workflows` to self-contained GitHub Actions workflows that clone `BWTECH-github/owncloud.online` as the Core to test against.

### Removed

- Translation-sync workflow (no Transifex credentials in the fork).

## [1.6.1] - 2023-07-27

### Changed

- [#395](https://github.com/owncloud/encryption/issues/395) - Always return an int from Symfony Command execute method
- Minimum core version 10.11, minimum php version 7.4
- Dependencies updated.
- Strings updated.


## [1.6.0] - 2023-03-29

### Changed

- [#389](https://github.com/owncloud/encryption/issues/389) - feat: drop setup of user based encryption
- This version of the encryption app requires core 10.12.0 or later.


## [1.5.3] - 2022-08-01

- Handle the versions in the trashbin for the checksum verify command [#361](https://github.com/owncloud/encryption/issues/361)

## [1.5.2] - 2022-05-25

### Added
- Add increment option to fix-encrypted-version command [#279](https://github.com/owncloud/encryption/issues/279)

## [1.5.1] - 2021-05-28

### Fixed

- Use legacy-encoding setting for HSM also [#269](https://github.com/owncloud/encryption/issues/269)
- `fix-encrypted-version` command restores value to original if no fix is found  [#275](https://github.com/owncloud/encryption/issues/275)
- Determine encryption format correctly when using HSM  [#261](https://github.com/owncloud/encryption/pull/261)

## [1.5.0] - 2021-03-11

### Added

- Add path option to FixEncryptedVersion command [#218](https://github.com/owncloud/encryption/pull/218)
- Make encryption repair for file and folder [#4276](https://github.com/owncloud/enterprise/issues/4276)

### Changed

- Use PHP's built-in hash_hkdf function [#215](https://github.com/owncloud/encryption/pull/215)
- Unnecessary file size overhead (binary instead of base64) [#210](https://github.com/owncloud/encryption/issues/210)
- Code needs updating due to core icewind/streams 0.7.2 [#198](https://github.com/owncloud/encryption/issues/198)

### Fixed

- Prevent command encryption:fix-encrypted-version from printing file binary data [#226](https://github.com/owncloud/encryption/pull/226)

## 1.4.0 - 2019-09-02

### Added

- `encryption:fixencryptedversion` command to address issues related to encrypted versions  [#115](https://github.com/owncloud/encryption/pull/115)

### Changed

- Improved wording for several user/administrator interactions [#21](https://github.com/owncloud/encryption/pull/21) [#117](https://github.com/owncloud/encryption/pull/117)

### Fixed

- Issues with recreating masterkeys when HSM is used [#128](https://github.com/owncloud/encryption/pull/128)


[Unreleased]: https://github.com/owncloud/encryption/compare/v1.6.1...HEAD
[1.6.1]: https://github.com/owncloud/encryption/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/owncloud/encryption/compare/v1.5.3...v1.6.0
[1.5.3]: https://github.com/owncloud/encryption/compare/v1.5.2...v1.5.3
[1.5.2]: https://github.com/owncloud/encryption/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/owncloud/encryption/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/owncloud/encryption/compare/v1.4.0...v1.5.0
