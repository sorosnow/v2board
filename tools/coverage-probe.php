<?php
// 外部订阅（附加订阅）能力覆盖：项目原生支持的协议，外部订阅到底能不能吃进来 + 能不能下发
//
// 输出三部分：
//   ① 每种项目原生协议的 URI → 解析器是否产出节点（覆盖情况）
//   ② 明确拿不到的例外（ss2022）与原因
//   ③ **对齐断言**：同一协议 + 同一传输，「外部订阅节点」与「站点节点」在 8 个渲染器里
//      必须得到完全一样的结果（解析器这一层只决定「项目认得哪些传输」，
//      能不能忠实下发由渲染器逐格判定）
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

    $UUID = '11111111-2222-3333-4444-555555555555';
    $uris = array(
        'shadowsocks'  => 'ss://' . base64_encode('aes-256-gcm:pw') . '@1.1.1.1:8388#SS',
        'ss-2022'      => 'ss://' . base64_encode('2022-blake3-aes-256-gcm:cHc=:cHc=') . '@1.1.1.1:8388#SS2022',
        'vmess'        => 'vmess://' . base64_encode(json_encode(array('v' => '2', 'ps' => 'VM', 'add' => '1.1.1.1',
            'port' => '443', 'id' => $UUID, 'aid' => '0', 'net' => 'ws', 'path' => '/p', 'host' => 'a.com',
            'tls' => 'tls', 'sni' => 'a.com'))),
        'vless'        => 'vless://' . $UUID . '@1.1.1.1:443?encryption=none&security=tls&sni=a.com&type=ws&path=%2Fp&host=a.com#VL',
        'trojan'       => 'trojan://tjpw@1.1.1.1:443?sni=a.com&type=ws&path=%2Fp&host=a.com#TJ',
        'hysteria v1'  => 'hysteria://pw@1.1.1.1:8443?sni=a.com&insecure=0&upmbps=50&downmbps=100#HY1',
        'hysteria2'    => 'hysteria2://pw@1.1.1.1:8443?sni=a.com&insecure=0&obfs=salamander&obfs-password=x#HY2',
        'tuic'         => 'tuic://' . $UUID . ':' . $UUID . '@1.1.1.1:8443?sni=a.com&congestion_control=bbr#TU',
        'anytls'       => 'anytls://anypw@1.1.1.1:8443?sni=a.com&insecure=0#ANY',
        'v2node(内部抽象)' => '',
    );

    $FAILS = 0;
    function ok($label, $cond, $detail = '')
    {
        global $FAILS;
        if (!$cond) { $FAILS++; }
        echo '  ' . ($cond ? '✓' : '✗') . ' ' . str_pad($label, 44) . $detail . "\n";
    }

    echo "══════ ① 协议覆盖：项目原生协议 → 外部订阅能否解析 ══════\n";
    foreach ($uris as $label => $uri) {
        if ($uri === '') { echo '  ' . str_pad($label, 18) . "—（不是 URI 格式，外部链接表达不了，无需解析）\n"; continue; }
        if ($label === 'ss-2022') { continue; }   // 明确拿不到的例外，单独断言
        $r = \App\Utils\SubscriptionParser::parse($uri);
        $n = count($r['nodes']);
        $reason = $r['skipped'] ? array_keys($r['skipped'])[0] : '';
        ok($label, $n === 1, $n === 1 ? 'type=' . $r['nodes'][0]['type'] : '跳过：' . $reason);
    }
    // ss2022 是明确拿不到的例外（协议层不合成密钥）：必须跳过而不是产出坏节点
    $r2022 = \App\Utils\SubscriptionParser::parse($uris['ss-2022']);
    ok('ss-2022 必须跳过', count($r2022['nodes']) === 0 && isset($r2022['skipped']['ss_2022_unsupported']),
        json_encode($r2022['skipped'], JSON_UNESCAPED_UNICODE));

    echo "\n══════ ② 传输方式：解析器认得的都要保留，认不得的必须丢 ══════\n";
    foreach (array('tcp', 'ws', 'grpc', 'kcp', 'httpupgrade', 'h2', 'http', 'xhttp', 'quic', 'domainsocket') as $net) {
        $uri = 'vless://' . $UUID . '@1.1.1.1:443?encryption=none&security=tls&sni=a.com&type=' . $net . '&path=%2Fp&host=a.com#N';
        $r = \App\Utils\SubscriptionParser::parse($uri);
        ok('vless + ' . $net, count($r['nodes']) === 1,
            count($r['nodes']) === 1 ? '保留' : '✗ 被丢 ' . array_keys($r['skipped'])[0]);
    }
    foreach (array('zzz', 'http/2') as $net) {
        $uri = 'vless://' . $UUID . '@1.1.1.1:443?encryption=none&security=tls&sni=a.com&type=' . $net . '&path=%2Fp&host=a.com#N';
        $r = \App\Utils\SubscriptionParser::parse($uri);
        ok('vless + ' . $net . ' 应丢', count($r['nodes']) === 0 && isset($r['skipped']['unsupported_network:' . $net]),
            json_encode($r['skipped'], JSON_UNESCAPED_UNICODE));
    }

    echo "\n══════ ③ 对齐断言：外部订阅节点 vs 站点节点，同协议+同传输必须同结果 ══════\n";
    // URI 类渲染器的输出常是「整份 base64」或「外层 base64 → URI」→ 必须解包后再搜
    // （这个坑我在 real-sub-audit 里踩过一次，这里不能再用明文搜索）
    function unwrap($out)
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
    $u = new FakeUser();
    $renderers = array(
        'V2rayN' => 'App\Protocols\V2rayN', 'Shadowrocket' => 'App\Protocols\Shadowrocket',
        'Clash' => 'App\Protocols\Clash', 'ClashMeta' => 'App\Protocols\ClashMeta',
        'Loon' => 'App\Protocols\Loon', 'QuantumultX' => 'App\Protocols\QuantumultX',
        'Surge' => 'App\Protocols\Surge', 'Singbox' => 'App\Protocols\Singbox\Singbox',
    );
    // 把「下发结果」压成一个可比较的字符串：不产出 / 下发但丢了传输 / 下发且传输原样带出
    function outcome($cls, $u, $node, $net)
    {
        try { $out = unwrap((string)(new $cls($u, array($node)))->handle()); }
        catch (\Throwable $e) { return '异常:' . $e->getMessage(); }
        if (strpos($out, $node['host']) === false) { return '不产出'; }
        if ($net === 'tcp') { return '下发'; }   // tcp 是缺省，URI 系本来就不写 type =
        return (strpos($out, 'type=' . $net) !== false || strpos($out, '"network":"' . $net . '"') !== false)
            ? '下发且带 ' . $net : '下发但传输丢了';
    }
    foreach (array('tcp', 'ws', 'grpc', 'kcp', 'httpupgrade', 'h2', 'http', 'xhttp') as $net) {
        $uri = 'vless://' . $UUID . '@1.1.1.1:443?encryption=none&security=tls&sni=a.com&type=' . $net
            . '&path=%2Fp&mode=auto&serviceName=svc&host=a.com#EXT';
        $r = \App\Utils\SubscriptionParser::parse($uri);
        if (count($r['nodes']) !== 1) { ok('vless + ' . $net . ' 解析', false, json_encode($r['skipped'])); continue; }
        // 站点节点：只给 snake_case（线上 v2_server_vless 的列就是这种），与外部节点的取值一一对应
        $site = array('type' => 'vless', 'name' => 'SITE', 'host' => '1.1.1.1', 'port' => 443,
            'tls' => 1, 'tls_settings' => array('server_name' => 'a.com', 'allow_insecure' => 0),
            'encryption' => 'none', 'flow' => '', 'network' => $net,
            'network_settings' => array('path' => '/p', 'host' => 'a.com', 'mode' => 'auto',
                'serviceName' => 'svc', 'headers' => array('Host' => 'a.com')));
        foreach ($renderers as $label => $cls) {
            $a = outcome($cls, $u, $r['nodes'][0], $net);
            $b = outcome($cls, $u, $site, $net);
            ok('vless + ' . str_pad($net, 11) . ' → ' . str_pad($label, 11) . ' 同结果', $a === $b,
                '外部=' . $a . ' / 站点=' . $b);
        }
    }
    echo "  说明：解析器这一层只管「项目认得哪些传输」；能不能忠实下发由渲染器逐格判定\n";
    echo "        （Helper::networkExpressible / sing-box 自己的守卫）→ 两边结果必须完全一致。\n";

    echo "\n══════ ④ 如果第三方源给的是 SIP008 JSON（带 id 字段的那种）══════\n";
    $sip008 = json_encode(array('version' => 1, 'servers' => array(
        array('id' => '27b8a625-4f4b-4428-9f0f-8a2317db7c79', 'remarks' => 'X',
            'server' => '1.1.1.1', 'server_port' => 8388, 'password' => 'pw', 'method' => 'aes-256-gcm'),
    )));
    $r = \App\Utils\SubscriptionParser::parse($sip008);
    echo '  SIP008 JSON 原文 → 解析出 ' . count($r['nodes']) . ' 个节点，跳过原因: '
        . json_encode($r['skipped'], JSON_UNESCAPED_UNICODE) . "\n";
    echo "  （解析器只认 scheme:// 形式的 URI 列表；SIP008 JSON 里的 id 用不上，也不影响任何东西）\n";

    echo "\n" . ($FAILS === 0 ? "✓ 全部通过：外部订阅与站点节点在传输层面完全对齐\n"
        : "✗ 断言失败 $FAILS 项（见上）\n");
    exit($FAILS === 0 ? 0 : 1);
}
