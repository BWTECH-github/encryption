# Comprehensive Test Plan
## ownCloud Encryption Plugin v2.0.0 - PHP 8.4 Compatibility

---

## 1. TEST ENVIRONMENT SETUP

### 1.1 Required Environment

```
PHP Version: 8.4.x
ownCloud Core: GrossLukas/owncloud.online (PHP 8.4 branch)
Database: MySQL 8.0+ / MariaDB 10.6+ / PostgreSQL 13+
Web Server: Apache 2.4+ with mod_php or nginx with PHP-FPM
OpenSSL: 3.0+
```

### 1.2 Environment Setup Steps

```bash
# 1. Clone ownCloud Core
git clone https://github.com/GrossLukas/owncloud.online.git /var/www/owncloud
cd /var/www/owncloud

# 2. Install dependencies
composer install

# 3. Clone Encryption Plugin
cd apps
git clone -b php84-migration https://github.com/GrossLukas/encryption-php84.git encryption

# 4. Configure ownCloud
cd /var/www/owncloud
sudo -u www-data php occ maintenance:install \
  --database "mysql" \
  --database-name "owncloud" \
  --database-user "owncloud" \
  --database-pass "password" \
  --admin-user "admin" \
  --admin-pass "admin"

# 5. Enable encryption
sudo -u www-data php occ app:enable encryption
sudo -u www-data php occ encryption:enable
sudo -u www-data php occ encryption:enable-master-key
```

---

## 2. UNIT TEST SUITE

### 2.1 Test Files

| Test File | Description | Test Count |
|-----------|-------------|------------|
| `tests/unit/Crypto/CryptTest.php` | Core encryption tests | 15+ |
| `tests/unit/Crypto/CryptPHP84Test.php` | PHP 8.4 specific tests | 15+ |
| `tests/unit/Crypto/LegacyCompatibilityTest.php` | Backward compatibility | 12+ |
| `tests/unit/Crypto/CryptHSMTest.php` | HSM encryption tests | 8+ |
| `tests/unit/Crypto/EncryptionTest.php` | Encryption module tests | 20+ |
| `tests/unit/Crypto/EncryptAllTest.php` | Encrypt all tests | 10+ |
| `tests/unit/Crypto/DecryptAllTest.php` | Decrypt all tests | 10+ |
| `tests/unit/KeyManagerTest.php` | Key management tests | 25+ |
| `tests/unit/SessionTest.php` | Session tests | 8+ |
| `tests/unit/UtilTest.php` | Utility tests | 15+ |
| `tests/unit/RecoveryTest.php` | Recovery key tests | 12+ |
| `tests/unit/MigrationTest.php` | Migration tests | 10+ |

### 2.2 Running Unit Tests

```bash
cd /var/www/owncloud/apps/encryption

# Run all tests
./vendor/bin/phpunit -c phpunit.xml

# Run specific test file
./vendor/bin/phpunit tests/unit/Crypto/CryptPHP84Test.php

# Run with coverage
./vendor/bin/phpunit -c phpunit.xml --coverage-html coverage/

# Run legacy compatibility tests only
./vendor/bin/phpunit --group legacy-compatibility
```

### 2.3 Expected Test Results

| Test Suite | Expected Pass | Expected Fail | Notes |
|------------|---------------|---------------|-------|
| CryptPHP84Test | 15/15 | 0 | PHP 8.4 specific |
| LegacyCompatibilityTest | 12/12 | 0 | Backward compat |
| CryptTest | 15/15 | 0 | Core functionality |
| EncryptionTest | 20/20 | 0 | Module tests |
| KeyManagerTest | 25/25 | 0 | Key operations |
| **Total** | **87+** | **0** | |

---

## 3. FUNCTIONAL TEST SCENARIOS

### 3.1 File Encryption Tests

#### TC-ENC-001: Basic File Encryption
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | Login as admin | Login successful | ⬜ |
| 2 | Upload text file (test.txt) | File uploaded | ⬜ |
| 3 | Check file in data directory | File is encrypted (HBEGIN header) | ⬜ |
| 4 | Download file via web UI | Original content returned | ⬜ |

#### TC-ENC-002: Large File Encryption
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | Upload 100MB file | File uploaded successfully | ⬜ |
| 2 | Verify encryption | File encrypted in chunks | ⬜ |
| 3 | Download file | Original content, correct size | ⬜ |

#### TC-ENC-003: Binary File Encryption
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | Upload image file (test.jpg) | File uploaded | ⬜ |
| 2 | Download file | Image displays correctly | ⬜ |
| 3 | Verify checksum | MD5 matches original | ⬜ |

#### TC-ENC-004: Special Characters in Filename
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | Upload file with unicode name (tëst-文件.txt) | File uploaded | ⬜ |
| 2 | Download file | Content correct | ⬜ |

### 3.2 File Decryption Tests

#### TC-DEC-001: Basic Decryption
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | Access encrypted file | File decrypted on-the-fly | ⬜ |
| 2 | Verify content | Original content displayed | ⬜ |

#### TC-DEC-002: Legacy File Decryption (Critical)
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | Copy legacy encrypted file (PHP 7.x format) | File in place | ⬜ |
| 2 | Access file via web UI | File decrypts successfully | ⬜ |
| 3 | Verify content | Original content correct | ⬜ |

### 3.3 Key Management Tests

#### TC-KEY-001: User Key Generation
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | Create new user | User created | ⬜ |
| 2 | User logs in first time | Keys generated | ⬜ |
| 3 | Check key storage | Public/private keys exist | ⬜ |

#### TC-KEY-002: Master Key Mode
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | Enable master key mode | Mode enabled | ⬜ |
| 2 | Upload file | File encrypted with master key | ⬜ |
| 3 | Access as different admin | File accessible | ⬜ |

#### TC-KEY-003: Key Recovery
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | Enable recovery key | Recovery enabled | ⬜ |
| 2 | User enables recovery | User opted in | ⬜ |
| 3 | Reset user password | Files recoverable | ⬜ |

### 3.4 Sharing Tests

#### TC-SHARE-001: Share Encrypted File
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | User A uploads file | File encrypted | ⬜ |
| 2 | User A shares with User B | Share created | ⬜ |
| 3 | User B accesses file | File decrypts correctly | ⬜ |

#### TC-SHARE-002: Share with Group
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | Create group with 3 users | Group created | ⬜ |
| 2 | Share encrypted file with group | Share created | ⬜ |
| 3 | All group members access | All can decrypt | ⬜ |

#### TC-SHARE-003: Public Link Share
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | Create public link for encrypted file | Link created | ⬜ |
| 2 | Access via public link | File downloads correctly | ⬜ |

### 3.5 Edge Cases

#### TC-EDGE-001: Empty File
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | Upload empty file | File uploaded | ⬜ |
| 2 | Download file | Empty file returned | ⬜ |

#### TC-EDGE-002: Concurrent Access
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | User A opens file for edit | File locked | ⬜ |
| 2 | User B tries to access | Appropriate handling | ⬜ |

#### TC-EDGE-003: Network Interruption
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | Start large file upload | Upload in progress | ⬜ |
| 2 | Simulate network drop | Partial file handled | ⬜ |
| 3 | Resume/retry | File completes correctly | ⬜ |

---

## 4. INTEGRATION TESTS

### 4.1 Core Integration

#### TC-INT-001: Encryption Module Registration
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | Enable encryption app | App enabled | ⬜ |
| 2 | Check registered modules | OC_DEFAULT_MODULE registered | ⬜ |
| 3 | Verify default module | Encryption is default | ⬜ |

#### TC-INT-002: File System Wrapper
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | Upload file via WebDAV | File encrypted | ⬜ |
| 2 | Download via WebDAV | File decrypted | ⬜ |
| 3 | Check storage wrapper | oc_encryption wrapper active | ⬜ |

#### TC-INT-003: Version Control Integration
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | Enable versioning | Versioning active | ⬜ |
| 2 | Modify encrypted file | Version created | ⬜ |
| 3 | Restore old version | Decrypts correctly | ⬜ |

#### TC-INT-004: Trash Integration
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | Delete encrypted file | File in trash | ⬜ |
| 2 | Restore from trash | File decrypts correctly | ⬜ |

### 4.2 API Integration

#### TC-API-001: OCS API
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | GET encryption status via API | Status returned | ⬜ |
| 2 | Verify response format | JSON correct | ⬜ |

#### TC-API-002: WebDAV Operations
| Step | Action | Expected Result | Status |
|------|--------|-----------------|--------|
| 1 | PROPFIND on encrypted file | Properties returned | ⬜ |
| 2 | GET encrypted file | Decrypted content | ⬜ |
| 3 | PUT new file | File encrypted | ⬜ |

---

## 5. PERFORMANCE TESTS

### 5.1 Encryption Performance

| Test | File Size | Target Time | Actual Time | Status |
|------|-----------|-------------|-------------|--------|
| Small file encryption | 1 KB | < 100ms | | ⬜ |
| Medium file encryption | 10 MB | < 2s | | ⬜ |
| Large file encryption | 100 MB | < 20s | | ⬜ |

### 5.2 Decryption Performance

| Test | File Size | Target Time | Actual Time | Status |
|------|-----------|-------------|-------------|--------|
| Small file decryption | 1 KB | < 50ms | | ⬜ |
| Medium file decryption | 10 MB | < 1s | | ⬜ |
| Large file decryption | 100 MB | < 10s | | ⬜ |

### 5.3 Key Operations Performance

| Test | Operation | Target Time | Actual Time | Status |
|------|-----------|-------------|-------------|--------|
| Key pair generation | Create 4096-bit RSA | < 5s | | ⬜ |
| Multi-key encrypt | 10 recipients | < 500ms | | ⬜ |
| Multi-key decrypt | Single recipient | < 100ms | | ⬜ |

---

## 6. SECURITY TESTS

### 6.1 Encryption Strength

| Test | Verification | Status |
|------|--------------|--------|
| AES-256-CTR used for file content | Check header | ⬜ |
| AES-256-CBC used for key sealing | Check sealed format | ⬜ |
| Random IV generated per operation | Verify uniqueness | ⬜ |
| HMAC-SHA256 signature present | Check signature | ⬜ |

### 6.2 Key Security

| Test | Verification | Status |
|------|--------------|--------|
| Private keys encrypted at rest | Check key files | ⬜ |
| Keys not exposed in logs | Review log output | ⬜ |
| Keys not in error messages | Trigger errors | ⬜ |

---

## 7. BACKWARD COMPATIBILITY TESTS

### 7.1 Legacy Format Support

| Test | Description | Status |
|------|-------------|--------|
| TC-LEGACY-001 | Decrypt file from PHP 7.4 (RC4 sealed) | ⬜ |
| TC-LEGACY-002 | Decrypt file with old header format | ⬜ |
| TC-LEGACY-003 | Decrypt file without encoding field | ⬜ |
| TC-LEGACY-004 | Handle mixed format in same directory | ⬜ |

### 7.2 Format Detection

| Test | Input | Expected Detection | Status |
|------|-------|-------------------|--------|
| New format | 0x02 + IV + data | SEALED_FORMAT_VERSION | ⬜ |
| Legacy format | Raw RC4 data | SEALED_FORMAT_LEGACY | ⬜ |
| Short data | < 2 bytes | SEALED_FORMAT_LEGACY | ⬜ |

---

## 8. ERROR HANDLING TESTS

### 8.1 Expected Errors

| Test | Trigger | Expected Behavior | Status |
|------|---------|-------------------|--------|
| Missing private key | Delete key file | Clear error message | ⬜ |
| Corrupted encrypted file | Modify file content | DecryptionFailedException | ⬜ |
| Invalid share key | Modify share key | MultiKeyDecryptException | ⬜ |
| Empty content encryption | Pass empty string | MultiKeyEncryptException | ⬜ |

### 8.2 Recovery Scenarios

| Test | Scenario | Recovery Action | Status |
|------|----------|-----------------|--------|
| Key corruption | Restore from backup | Keys restored, files accessible | ⬜ |
| Database loss | Restore database | Encryption state recovered | ⬜ |

---

## 9. TEST EXECUTION SUMMARY

### 9.1 Test Results Template

```
Test Execution Date: _______________
Tester: _______________
Environment: _______________

Unit Tests:
- Total: ___
- Passed: ___
- Failed: ___
- Skipped: ___

Functional Tests:
- Total: ___
- Passed: ___
- Failed: ___

Integration Tests:
- Total: ___
- Passed: ___
- Failed: ___

Overall Status: [ ] PASS  [ ] FAIL
```

### 9.2 Issue Log Template

| Issue ID | Test Case | Description | Severity | Status |
|----------|-----------|-------------|----------|--------|
| | | | | |

---

## 10. SIGN-OFF

### 10.1 Test Completion Criteria

- [ ] All unit tests pass (100%)
- [ ] All critical functional tests pass
- [ ] All integration tests pass
- [ ] No critical or high severity issues open
- [ ] Performance within acceptable limits
- [ ] Legacy compatibility verified

### 10.2 Approval

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Developer | | | |
| QA Lead | | | |
| Product Owner | | | |

---

**Document Version:** 1.0  
**Last Updated:** Generated for PHP 8.4 Migration