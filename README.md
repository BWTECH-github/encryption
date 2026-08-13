# encryption

Serverseitige Verschluesselung fuer owncloud.online. Die App registriert das
Verschluesselungsmodul `OC_DEFAULT_MODULE` ("Default encryption module") und
verschluesselt die Inhalte der Dateien, die ueber owncloud.online geschrieben
werden. Sie ist ein PHP-8.4-Fork des urspruenglich von der ownCloud GmbH
entwickelten Moduls; die Krypto-Logik ist unveraendert, geaendert wurden
Plattformanforderungen, Bezeichnungen und Code-Idiome.

## Was die App tut

- Verschluesselt beim Schreiben den **Inhalt** jeder Datei. Dateinamen,
  Ordnerstruktur, Freigaben und Datenbankinhalte bleiben unverschluesselt.
- Verwendet je Datei einen eigenen Dateischluessel. Voreingestellter Cipher
  ist `AES-256-CTR` (`Crypt::DEFAULT_CIPHER`).
- Versiegelt den Dateischluessel mit den oeffentlichen Schluesseln aller
  Berechtigten (`openssl_seal`, `AES-256-CBC`) und legt fuer jeden Berechtigten
  einen `shareKey` ab. Aeltere, mit RC4 versiegelte Schluessel werden beim
  Lesen weiterhin akzeptiert.
- Kennt zwei Betriebsarten: Hauptschluessel und Benutzerschluessel (siehe
  unten).
- Bringt fuenf `occ`-Befehle mit, unter anderem zum Neuerzeugen des
  Hauptschluessels und zum Reparieren der Versionsangabe verschluesselter
  Dateien.

Die App verschluesselt nur, was nach dem Einschalten geschrieben wird.
Bestehende Dateien werden erst durch einen ausdruecklichen Lauf
(`occ encryption:encrypt-all`) verschluesselt.

## Voraussetzungen

| Komponente        | Anforderung                                      |
|-------------------|--------------------------------------------------|
| owncloud.online   | 10.12 bis 11 (`appinfo/info.xml`)                |
| PHP               | 8.4 oder neuer                                    |
| PHP-Erweiterung   | `openssl`                                         |
| `secret`          | muss in `config/config.php` gesetzt sein          |

Der Wert `secret` aus `config.php` ist im Hauptschluesselbetrieb das Passwort,
mit dem der private Hauptschluessel verschluesselt wird
(`KeyManager::getMasterKeyPassword()`). Geht dieser Wert verloren, sind die
Daten nicht mehr zu entschluesseln. Sichern Sie `config.php` und die
Schluesselablage gemeinsam.

## Installation

Der einfachere Weg ist die Installation ueber den Markt in der
Administrationsoberflaeche. Manuell:

```bash
cd /var/www/owncloud.online/apps
git clone https://github.com/BWTECH-github/encryption.git
cd encryption
composer install --no-dev
chown -R www-data:www-data .
sudo -u www-data php8.4 ../../occ app:enable encryption
```

## Betriebsarten

### Hauptschluessel

Ein einziges Schluesselpaar fuer die gesamte Instanz. Der private
Hauptschluessel wird mit dem `secret` aus `config.php` verschluesselt
abgelegt. Benutzerpasswoerter spielen fuer den Zugriff keine Rolle; ein
Passwortwechsel oder ein Zuruecksetzen des Passworts beruehrt die
Verschluesselung nicht. Die App registriert in dieser Betriebsart die
Passwort-Hooks gar nicht erst (`UserHooks::addHooks()`).

Aktiv, wenn der App-Wert `useMasterKey` auf `1` steht. Ist die
Verschluesselung eingeschaltet und weder `useMasterKey` noch
`userSpecificKey` gesetzt, setzt die App beim Start selbst `useMasterKey=1`.

### Benutzerschluessel

Je Benutzer ein Schluesselpaar; der private Schluessel ist mit dem
Anmeldepasswort verschluesselt. Diese Betriebsart wird nur noch fuer
bestehende Installationen unterstuetzt: Die Auswahlliste im Administrations-
panel bietet ausschliesslich "Hauptschluessel" an, und bei gesetztem App-Wert
`userSpecificKey` blendet das Panel einen Hinweis ein, dass diese Betriebsart
veraltet ist. Nur in dieser Betriebsart gibt es den
Wiederherstellungsschluessel und die persoenlichen Verschluesselungs-
einstellungen.

## Verschluesselung einschalten

Die drei Schritte sind: App aktivieren, Verschluesselung im Kern einschalten,
Modul als Standardmodul setzen.

```bash
sudo -u www-data php8.4 occ app:enable encryption
sudo -u www-data php8.4 occ encryption:enable
sudo -u www-data php8.4 occ encryption:list-modules
sudo -u www-data php8.4 occ encryption:set-default-module OC_DEFAULT_MODULE
sudo -u www-data php8.4 occ encryption:status
```

`encryption:enable`, `encryption:list-modules`, `encryption:set-default-module`
und `encryption:status` stammen aus dem Kern von owncloud.online, nicht aus
dieser App.

Die Betriebsart waehlen Sie unter Einstellungen > Administrator >
Verschluesselung im Abschnitt "Standard-Verschluesselungs-Modul": Eintrag
"Hauptschluessel" auswaehlen und "Diesen Modus immer verwenden" bestaetigen.
Die Schaltflaeche setzt den App-Wert `useMasterKey` auf `1`. Auf der
Kommandozeile entspricht das:

```bash
sudo -u www-data php8.4 occ config:app:set encryption useMasterKey --value 1
```

Nach dem Umschalten muessen sich alle Benutzer neu anmelden, damit ihre
Schluessel in der Sitzung initialisiert werden.

## Alle Dateien verschluesseln und wieder entschluesseln

Beide Befehle gehoeren zum Kern; die Arbeit erledigen die Klassen
`EncryptAll` und `DecryptAll` dieser App.

```bash
sudo -u www-data php8.4 occ encryption:encrypt-all -y
```

Im Hauptschluesselbetrieb wird der Hauptschluessel geprueft und, falls er noch
fehlt, erzeugt (`KeyManager::validateMasterKey()`); anschliessend werden die
Dateien aller Benutzer verschluesselt. Im
Benutzerschluesselbetrieb erzeugt der Lauf zuvor fuer jeden Benutzer ein
Schluesselpaar mit einem generierten Passwort und gibt die Passwortliste aus
oder versendet sie per E-Mail; bestehende Versionen und Dateien im Papierkorb
werden dabei nicht verschluesselt.

```bash
sudo -u www-data php8.4 occ encryption:decrypt-all
sudo -u www-data php8.4 occ encryption:decrypt-all alice -m password
```

| Argument / Option        | Bedeutung                                      |
|--------------------------|------------------------------------------------|
| `user` (Argument)        | nur diesen Benutzer entschluesseln, optional   |
| `-m, --method`           | `recovery` oder `password`                     |
| `-c, --continue`         | `yes` oder `no`, Vorgabe `no`                  |

Im Hauptschluesselbetrieb wird kein Passwort benoetigt, der Lauf verwendet den
Hauptschluessel. Im Benutzerschluesselbetrieb gilt: `password` funktioniert nur
fuer einen einzelnen Benutzer; fuer alle Benutzer ist ausschliesslich
`--method recovery` moeglich, und das Passwort des Wiederherstellungs-
schluessels wird aus der Umgebungsvariablen `OC_RECOVERY_PASSWORD` gelesen.

## Schluesselablage

Die Schluessel liegen im Datenverzeichnis. Wurzel ist standardmaessig das
Datenverzeichnis selbst; sie laesst sich mit den Kernbefehlen
`encryption:show-key-storage-root` und `encryption:change-key-storage-root`
verschieben und steht im App-Wert `encryption_key_storage_root` der App
`core`.

| Schluessel                     | Ablage                                                                |
|--------------------------------|-----------------------------------------------------------------------|
| Hauptschluessel                | `<daten>/files_encryption/OC_DEFAULT_MODULE/master_xxxxxxxx.publicKey` bzw. `.privateKey` |
| Schluessel fuer oeffentliche Links | `<daten>/files_encryption/OC_DEFAULT_MODULE/pubShare_xxxxxxxx.*`   |
| Wiederherstellungsschluessel   | `<daten>/files_encryption/OC_DEFAULT_MODULE/recoveryKey_xxxxxxxx.*`   |
| Benutzerschluessel             | `<daten>/<uid>/files_encryption/OC_DEFAULT_MODULE/<uid>.publicKey` bzw. `.privateKey` |
| Datei- und Freigabeschluessel  | `<daten>/<uid>/files_encryption/keys/<pfad>/OC_DEFAULT_MODULE/fileKey` und `<empfaenger>.shareKey` |

Bei systemweiten Einhaengepunkten liegen die Datei- und Freigabeschluessel
nicht unter dem Benutzerverzeichnis, sondern direkt unter
`<daten>/files_encryption/keys/...`.

Die Kennungen mit Zufallssuffix stehen in den App-Werten `masterKeyId`,
`publicShareKeyId` und `recoveryKeyId`; sie werden beim ersten Bedarf erzeugt.

## Passwortwechsel und Zuruecksetzen

Im Hauptschluesselbetrieb passiert nichts: Die zustaendigen Hooks werden nur
registriert, wenn der Hauptschluessel **nicht** aktiv ist.

Im Benutzerschluesselbetrieb gilt:

- **Benutzer aendert das eigene Passwort waehrend einer Sitzung.** Der private
  Schluessel bleibt derselbe und wird lediglich mit dem neuen Passwort neu
  verschluesselt.
- **Administrator setzt ein fremdes Passwort.** Ein neues Schluesselpaar wird
  nur erzeugt, wenn der Benutzer die Wiederherstellung aktiviert hat und ein
  Wiederherstellungspasswort mitgegeben wurde, oder wenn der Benutzer noch
  keine Schluessel oder noch keine Dateien besitzt. Mit
  Wiederherstellungspasswort werden die Dateischluessel des Benutzers dabei neu
  verschluesselt.
- **Ohne Wiederherstellungspasswort** bleibt der private Schluessel mit dem
  alten Passwort verschluesselt. Der Benutzer sieht dann unter Einstellungen >
  Persoenlich > Verschluesselung im Abschnitt
  "owncloud.online-Basisverschluesselungsmodul" den Hinweis "Dein Passwort fuer
  Deinen privaten Schluessel stimmt nicht mehr mit Deinem Loginpasswort
  ueberein." und traegt dort unter "Altes Login Passwort" und "Aktuelles
  Passwort" die beiden Passwoerter ein ("Passwort fuer den privaten Schluessel
  aktualisieren").
- **Benutzer wird geloescht.** Der oeffentliche Schluessel des Benutzers und
  seine Schluessel in alternativen Ablagen werden entfernt.

Den Wiederherstellungsschluessel legt der Administrator im Abschnitt
"Standard-Verschluesselungs-Modul" an; jeder Benutzer entscheidet unter
Einstellungen > Persoenlich > Verschluesselung mit
"Passwortwiederherstellung aktivieren:" ("Aktiviert" / "Deaktiviert") selbst
darueber. Der Zustand steht im App-Wert
`recoveryAdminEnabled` und im Benutzerwert `recoveryEnabled` der App
`encryption`.

## Einstellungen

App-Werte der App `encryption`, les- und schreibbar mit
`occ config:app:get encryption <schluessel>` und
`occ config:app:set encryption <schluessel> --value <wert>`. Die meisten Werte
setzt die App selbst; aendern Sie sie nur, wenn Sie die Folgen kennen.

| Schluessel           | Werte / Vorgabe          | Bedeutung                                            |
|----------------------|--------------------------|------------------------------------------------------|
| `useMasterKey`       | `0` / `1`                | Hauptschluesselbetrieb aktiv                          |
| `userSpecificKey`    | leer / `1`               | veralteter Benutzerschluesselbetrieb                  |
| `masterKeyId`        | `master_xxxxxxxx`        | Kennung des Hauptschluessels                          |
| `publicShareKeyId`   | `pubShare_xxxxxxxx`      | Kennung des Schluessels fuer oeffentliche Links       |
| `recoveryKeyId`      | `recoveryKey_xxxxxxxx`   | Kennung des Wiederherstellungsschluessels             |
| `recoveryAdminEnabled` | `0` / `1`              | Wiederherstellungsschluessel eingerichtet             |
| `encryptHomeStorage` | `0` / `1`, Vorgabe `1`   | Hauptspeicher mitverschluesseln; bei `0` nur externe Speicher |
| `crypto.engine`      | `internal` / `hsm`       | Krypto-Backend, Vorgabe `internal`                    |
| `hsm.url`            | URL                      | Adresse des HSM-Dienstes                              |
| `hsm.jwt.secret`     | Zeichenkette             | gemeinsames Geheimnis fuer den HSM-Dienst, Vorgabe `secret` |
| `hsm.jwt.clockskew`  | Sekunden, Vorgabe `120`  | zulaessige Uhrzeitabweichung beim JWT                 |

Zusaetzlich beruehrt die App zwei Werte der App `core`: `encryption_enabled`
(`yes` / `no`) setzt sie selbst (`Util::removeEncryptionAppSettings()`,
`encryption:recreate-master-key`); `encryption_key_storage_root` wird vom Kern
verwaltet und von der App nur ueber dessen `Util::getKeyStorageRoot()` gelesen.

Werte aus `config/config.php`, die dieses Modul auswertet:

```php
'secret' => '...',                        // Passwort des Hauptschluessels
'cipher' => 'AES-256-CTR',                // Vorgabe, siehe unten
'openssl' => [
    'private_key_bits' => 4096,           // Vorgabe der App
],
'encryption.use_legacy_encoding' => false, // true = base64 statt binaer schreiben
```

Als `cipher` werden `AES-256-CTR`, `AES-128-CTR`, `AES-256-CFB` und
`AES-128-CFB` unterstuetzt; bei einem anderen Wert protokolliert die App eine
Warnung und faellt auf `AES-256-CTR` zurueck. Der Wert `instanceid` wird
zusaetzlich als Aussteller der JWT an den HSM-Dienst verwendet.

### HSM-Betrieb

Der HSM-Dienst ist ein eigenstaendiger Dienst und nicht Teil dieser App. Die
App spricht ihn per HTTP an, sobald `hsm.url` gesetzt ist; sie setzt dann beim
Start selbst `crypto.engine` auf `hsm`.

```bash
sudo -u www-data php8.4 occ config:app:set encryption hsm.url \
  --value https://hsm.example.net
sudo -u www-data php8.4 occ config:app:set encryption hsm.jwt.secret \
  --value <gemeinsames-geheimnis>
```

## Kommandozeile

Fuenf Befehle stammen aus dieser App. Fuehren Sie sie als Web-Server-Benutzer
aus.

### `encryption:recreate-master-key`

Entschluesselt das gesamte Dateisystem, erzeugt einen neuen Hauptschluessel und
verschluesselt anschliessend wieder alles damit. Bricht mit einem Hinweis ab,
wenn der Hauptschluesselbetrieb nicht aktiv ist. Alle Benutzer muessen sich
danach neu anmelden.

| Option      | Bedeutung                              |
|-------------|----------------------------------------|
| `-y, --yes` | Rueckfrage ueberspringen               |

```bash
sudo -u www-data php8.4 occ encryption:recreate-master-key -y
```

### `encryption:migrate [user_id...]`

Einmalige Umstellung der Schluesselablage auf das Layout von Verschluesselung
2.0. Ohne Argument werden die systemweiten Schluessel und die Schluessel aller
Benutzer aller Backends umgestellt, mit Argumenten nur die genannten Benutzer.

```bash
sudo -u www-data php8.4 occ encryption:migrate
sudo -u www-data php8.4 occ encryption:migrate alice bob
```

### `encryption:fix-encrypted-version <user>`

Prueft die Dateien eines Benutzers und korrigiert die gespeicherte Versions-
angabe, wenn sich eine Datei wegen einer Signaturpruefung nicht mehr lesen
laesst. Der Befehl zaehlt die Version zunaechst herunter, danach bis zur
angegebenen Obergrenze hinauf, und stellt den Ausgangswert wieder her, wenn
keine Version passt. Freigegebene Dateien muessen beim Eigentuemer repariert
werden.

| Argument / Option        | Vorgabe        | Bedeutung                          |
|--------------------------|----------------|------------------------------------|
| `user` (Argument)        | –              | Benutzerkennung, erforderlich      |
| `-p, --path`             | alle Dateien   | Einschraenken, z. B. `--path="/Musik"` |
| `-i, --increment-range`  | `5`            | wie weit die Version erhoeht wird  |

```bash
sudo -u www-data php8.4 occ encryption:fix-encrypted-version alice \
  -p "/Dokumente" -i 10
```

### `encryption:hsmdaemon`

Gibt den privaten Hauptschluessel base64-kodiert aus. Erfordert einen
gesetzten App-Wert `hsm.url`, sonst bricht der Befehl mit `hsm.url not set`
ab.

| Option               | Bedeutung                                          |
|----------------------|----------------------------------------------------|
| `--export-masterkey` | privaten Hauptschluessel base64-kodiert ausgeben   |

Der Befehl deklariert zusaetzlich die Option `--import-masterkey`; sie wird im
aktuellen Code nicht ausgewertet und bewirkt nichts.

### `encryption:hsmdaemon:decrypt <ciphertext>`

Entschluesselt eine base64-kodierte Zeichenkette ueber den HSM-Dienst, zur
Fehlersuche. Erfordert ebenfalls `hsm.url`.

| Argument / Option   | Bedeutung                                             |
|---------------------|-------------------------------------------------------|
| `decrypt` (Argument)| base64-kodierter Geheimtext, erforderlich             |
| `--username`        | Benutzer, dessen Schluessel gilt; fragt das Passwort ab |
| `--keyId`           | Kennung des zu verwendenden Schluessels                |

## Fehlersuche

| Symptom | Ursache | Abhilfe |
|---------|---------|---------|
| Panel meldet "Die Verschluesselung-App ist aktiviert, aber Deine Schluessel sind nicht initialisiert." | Die Schluessel wurden in dieser Sitzung nicht initialisiert | Abmelden und neu anmelden |
| Nutzer meldet "Dein Passwort fuer Deinen privaten Schluessel stimmt nicht mehr mit Deinem Loginpasswort ueberein." | Passwort wurde ohne Wiederherstellungsschluessel fremd gesetzt | Unter Persoenlich > Verschluesselung "Altes Login Passwort" und "Aktuelles Passwort" eintragen |
| Download bricht mit Signaturfehler ab | Versionsangabe der Datei passt nicht zum Inhalt, etwa nach einer Ruecksicherung | `occ encryption:fix-encrypted-version <benutzer>` |
| `MultiKeyDecryptException: multikeydecrypt with share key failed` | Der Schluessel wurde mit RC4 versiegelt, OpenSSL 3 fuehrt RC4 nur im Legacy-Provider | Legacy-Provider in der OpenSSL-Konfiguration bereitstellen oder die Dateien mit `encryption:recreate-master-key` neu verschluesseln |
| `Can not get secret from ownCloud instance` | `secret` fehlt in `config/config.php` | Wert wiederherstellen; ohne ihn ist der Hauptschluessel nicht zu oeffnen |
| `Master key is not enabled.` bei `recreate-master-key` | App-Wert `useMasterKey` steht nicht auf `1` | Betriebsart im Panel waehlen oder `config:app:set encryption useMasterKey --value 1` |
| `hsm.url not set` | HSM-Befehl ohne konfigurierten Dienst aufgerufen | `hsm.url` setzen oder den Befehl nicht verwenden |
| Log: "Unsupported cipher (…) defined in config.php supported. Falling back to AES-256-CTR" | `cipher` in `config.php` wird nicht unterstuetzt | einen der vier unterstuetzten Cipher eintragen |
| Schluesselpaar laesst sich nicht erzeugen, OpenSSL-Fehler im Log | OpenSSL akzeptiert die 4096 Bit oder den Konfigurationspfad nicht | `openssl` in `config.php` anpassen |
| Dateien im Hauptspeicher bleiben unverschluesselt | `encryptHomeStorage` steht auf `0` | Wert auf `1` setzen, danach `occ encryption:encrypt-all` |

## Herkunft

Der urspruengliche Code stammt von der ownCloud GmbH und steht unter der
AGPL-3.0 (siehe `LICENSE`). Dieser Fork wird von der BW-Tech GmbH fuer
owncloud.online gepflegt und steht unter derselben Lizenz.

- Anwendungsseite: <https://owncloud.online>
- Dokumentation: <https://docs.owncloud.online>
- Quellcode und Fehlermeldungen:
  <https://github.com/BWTECH-github/encryption>
