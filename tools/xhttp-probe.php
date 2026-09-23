<?php
// xhttp 专项：确认「vless 的 xhttp 没有被删」，以及「vmess 的 xhttp 分支可达且按客户端分层下发」
//
// 断言：
//   ① vless+xhttp 解析出节点，path/host/mode 齐全
//   ② ClashMeta / ClashVerge / ClashNyanpasu / Stash 忠实下发（network=xhttp + xhttp-opts）
//      Shadowrocket / V2rayN / General 等 URI 系忠实下发（type=xhttp）
//      Loon / QuantumultX / Singbox 按设计不产出（它们表达不了 xhttp）
//   ③ vmess+xhttp **解析通过**（vmessNetworkSettings 的 xhttp 分支可达）：URI 系原样带出，
//      Clash 系表达不了 → 不产出（由 Helper::networkExpressible 判定，不是静默降级）
namespace Symfony\Component\Yaml {
    class Yaml
    {
        const DUMP_EMPTY_ARRAY_AS_SEQUENCE = 2;
        public static function parseFile($p) { return array('proxies' => array(), 'proxy-groups' => array(), 'rules' => array()); }
        public static function dump($d, $i = 2, $n = 4, $f = 0) { return json_encode($d, JSON_UNESCAPED_UNICODE); }
    }
}
namespace Illuminate\Support\Facades {
    class Cache { public static function get($k) { return null; } public static function add($k, $v, $t) { return true; } public static function put($k, $v, $t) { return true; } }
}
namespace {
    class File { public static function exists($p) { return false; } }
    class FakeUser implements ArrayAccess {
        public $id = 1, $uuid = 'SITE-UUID', $u = 1, $d = 2, $transfer_enable = 100, $expired_at = 0;
        public $speed_limit = 0, $group_id = 1, $token = 't';
        public function offsetGet($o): mixed { return $this->$o; }
        public function offsetSet($o, $v): void { $this->$o = $v; }
        public function offsetExists($o): bool { return property_exists($this, $o); }
        public function offsetUnset($o): void {}
    }
    set_error_handler(function ($n, $s, $f, $l) {
        if (!(error_reporting() & $n)) return true;
        if (strpos($s, 'Cannot modify header information') !== false) return true;
        throw new ErrorException($s, 0, $n, $f, $l);
    });
    $_SERVER['HTTP_HOST'] = 'site.example.com';
    $_SERVER['REQUEST_URI'] = '/api/v1/client/subscribe?token=t';
    $_SERVER['SERVER_PORT'] = '443';
    $_SERVER['HTTPS'] = 'on';
    $GLOBALS['CFG'] = array('v2board.app_name' => 'T', 'v2board.app_url' => 'https://s.example.com',
        'v2board.subscribe_url' => '', 'v2board.subscribe_path' => '/api/v1/client/subscribe',
        'v2board.show_subscribe_method' => 0);
    function config($k, $d = null) { return array_key_exists($k, $GLOBALS['CFG']) ? $GLOBALS['CFG'][$k] : $d; }
    function base_path($p = '') { return dirname(__DIR__) . '/' . ltrim($p, '/'); }
    function response($d = '', $s = 200)
    {
        return new class($d, $s) {
            private $d; private $s;
            public function __construct($d, $s) { $this->d = $d; $this->s = $s; }
            public function getContent() { return $this->d; }
            public function header($k, $v = null) { return $this; }
            public function withHeaders($h = array()) { return $this; }
            public function getStatusCode() { return $this->s; }
            public function __toString() { return (string)$this->d; }
        };
    }
    function url($p = '') { return 'https://s.example.com' . $p; }
    function app() { return new class { public function bound($k) { return false; } }; }
    function storage_path($p = '') { return sys_get_temp_dir() . $p; }

    require __DIR__ . '/../app/Utils/Helper.php';
    require __DIR__ . '/../app/Utils/SubscriptionParser.php';
    foreach (array_merge(glob(__DIR__ . '/../app/Protocols/*.php'), glob(__DIR__ . '/../app/Protocols/Singbox/*.php')) as $f) { require_once $f; }

    $FAILS = 0;
    function ok($label, $cond, $detail = '')
    {
        global $FAILS;
        if (!$cond) { $FAILS++; }
        echo '  ' . ($cond ? '✓' : '✗') . ' ' . str_pad($label, 46) . $detail . "\n";
    }
    function corpus($out)
    {
        $seen = array(); $parts = array(); $queue = array(array($out, 0));
        while ($queue) {
            list($s, $depth) = array_shift($queue);
            if ($s === '' || isset($seen[$s])) continue;
            $seen[$s] = true; $parts[] = $s;
            if ($depth >= 4) continue;
            $t = trim($s);
            if (strlen($t) >= 16) {
                $d = @base64_decode($t, true);
                if ($d !== false && $d !== '' && $d !== $s) $queue[] = array($d, $depth + 1);
            }
            foreach (explode("\n", $s) as $line) {
                $l = trim($line);
                if (strlen($l) < 16) continue;
                $b = preg_match('#^[a-zA-Z0-9+.-]+://(.+)$#', $l, $m) ? $m[1] : $l;
                $d = @base64_decode($b, true);
                if ($d !== false && $d !== '' && $d !== $l) $queue[] = array($d, $depth + 1);
            }
        }
        return implode("\n", $parts);
    }

    $UUID = '11111111-2222-3333-4444-555555555555';
    $vlessXhttp = 'vless://' . $UUID . '@xhttp.example.com:443?encryption=none&security=tls&sni=a.com'
        . '&host=a.com&path=%2Fapi%2Fv1%2Fupload&mode=auto&type=xhttp#VLESS-XHTTP';
    $vmessXhttp = 'vmess://' . base64_encode(json_encode(array('v' => '2', 'ps' => 'VMESS-XHTTP',
        'add' => 'xhttp.example.com', 'port' => '443', 'id' => $UUID, 'aid' => '0', 'net' => 'xhttp',
        'host' => 'a.com', 'path' => '/p', 'tls' => 'tls', 'sni' => 'a.com')));

    echo "══════ ① vless + xhttp 解析 ══════\n";
    $r = \App\Utils\SubscriptionParser::parse($vlessXhttp);
    ok('解析出节点', count($r['nodes']) === 1, json_encode($r['skipped'], JSON_UNESCAPED_UNICODE));
    $n = $r['nodes'][0];
    ok('network = xhttp', isset($n['network']) && $n['network'] === 'xhttp', 'network=' . ($n['network'] ?? '空'));
    ok('network_settings 带 path/host/mode', ($n['network_settings']['path'] ?? '') === '/api/v1/upload'
        && ($n['network_settings']['host'] ?? '') === 'a.com'
        && ($n['network_settings']['mode'] ?? '') === 'auto',
        json_encode($n['network_settings'], JSON_UNESCAPED_UNICODE));

    echo "\n══════ ② vless + xhttp 各渲染器下发 ══════\n";
    $u = new FakeUser();
    $renderers = array(
        'ClashMeta' => 'App\Protocols\ClashMeta', 'ClashVerge' => 'App\Protocols\ClashVerge',
        'ClashNyanpasu' => 'App\Protocols\ClashNyanpasu', 'Stash' => 'App\Protocols\Stash',
        'Shadowrocket' => 'App\Protocols\Shadowrocket', 'V2rayN' => 'App\Protocols\V2rayN',
        'General' => 'App\Protocols\General', 'Loon' => 'App\Protocols\Loon',
        'QuantumultX' => 'App\Protocols\QuantumultX', 'Singbox' => 'App\Protocols\Singbox\Singbox',
    );
    $expectOut = array('ClashMeta', 'ClashVerge', 'ClashNyanpasu', 'Stash', 'Shadowrocket', 'V2rayN', 'General');
    foreach ($renderers as $label => $cls) {
        try {
            $out = corpus((string)(new $cls($u, array($n)))->handle());
        } catch (\Throwable $e) {
            ok($label, false, '抛异常 ' . $e->getMessage());
            continue;
        }
        $has = strpos($out, 'xhttp.example.com') !== false;
        $want = in_array($label, $expectOut, true);
        $tag = strpos($out, 'xhttp') !== false ? '（输出里出现 xhttp）' : '（输出里没有 xhttp！）';
        ok($label . ($want ? ' 应下发' : ' 不应下发'), $has === $want, $has ? '已下发 ' . $tag : '未下发');
    }

    echo "\n══════ ③ vmess + xhttp：解析通过（那支分支现在可达），下发交给渲染器分层判定 ══════\n";
    $r2 = \App\Utils\SubscriptionParser::parse($vmessXhttp);
    ok('vmess+xhttp 产出节点', count($r2['nodes']) === 1, json_encode($r2['skipped'], JSON_UNESCAPED_UNICODE));
    $n2 = $r2['nodes'][0];
    ok('network = xhttp 且带 path/host', (isset($n2['network']) && $n2['network'] === 'xhttp')
        && (isset($n2['network_settings']['path']) && $n2['network_settings']['path'] === '/p')
        && (isset($n2['network_settings']['host']) && $n2['network_settings']['host'] === 'a.com'),
        json_encode(isset($n2['network_settings']) ? $n2['network_settings'] : array(), JSON_UNESCAPED_UNICODE));
    // URI 系客户端能原样带出 type=xhttp；Clash 系表达不了 → 必须不产出。
    // Shadowrocket 对 vmess 只认 tcp/ws/grpc（对 vless/trojan 才放行全部），故 vmess+xhttp 跳过。
    $vmessOut = array('V2rayN' => true, 'General' => true,
        'ClashMeta' => false, 'Loon' => false, 'QuantumultX' => false, 'Shadowrocket' => false);
    foreach ($vmessOut as $label => $want) {
        try { $out = corpus((string)(new $renderers[$label]($u, array($n2)))->handle()); }
        catch (\Throwable $e) { ok('vmess+xhttp → ' . $label, false, '抛异常 ' . $e->getMessage()); continue; }
        $has = strpos($out, 'xhttp.example.com') !== false;
        ok('vmess+xhttp → ' . $label . ($want ? ' 应下发' : ' 应跳过'), $has === $want, $has ? '已下发' : '未下发');
    }

    echo "\n" . ($FAILS === 0 ? "✓ 全部通过：xhttp 三种协议解析都通，能否下发由渲染器逐格判定\n"
        : "✗ 断言失败 $FAILS 项\n");
    exit($FAILS === 0 ? 0 : 1);
}
