<?php
// 传输方式白名单审记：确认「渲染器还原不了的传输」在解析阶段就被丢弃
//
// 背景：Clash 系（Clash/ClashMeta/ClashVerge/ClashNyanpasu/Stash）与 sing-box 都只在
//       ws / grpc 时才写 network（tcp 是缺省），h2 / http / httpupgrade / kcp / quic /
//       domainsocket 会被静默丢掉 → 客户端按 tcp 连 → 坏节点且看不出原因。
//       vless 额外支持 xhttp（ClashMeta::buildVless 有分支）。
namespace Symfony\Component\Yaml {
    class Yaml
    {
        const DUMP_EMPTY_ARRAY_AS_SEQUENCE = 2;
        public static function parseFile($p) { return array('proxies' => array(), 'proxy-groups' => array(), 'rules' => array()); }
        public static function dump($d, $i = 2, $n = 4, $f = 0) { return json_encode($d, JSON_UNESCAPED_UNICODE); }
    }
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
    $_SERVER['REQUEST_URI'] = '/api/v1/client/subscribe?token=tok';
    $_SERVER['SERVER_PORT'] = '443';
    $_SERVER['HTTPS'] = 'on';
    // Surge / Surfboard / Loon 会调 Helper::getSubscribeUrl() → 需要 subscribe_url 等配置
    $GLOBALS['CFG'] = array('v2board.app_name' => 'T', 'v2board.app_url' => 'https://s.example.com',
        'v2board.subscribe_url' => 'https://s.example.com/api/v1/client/subscribe',
        'v2board.subscribe_path' => '/api/v1/client/subscribe',
        'v2board.show_subscribe_method' => 0);
    function config($k, $d = null) { return isset($GLOBALS['CFG'][$k]) ? $GLOBALS['CFG'][$k] : $d; }
    function base_path($p = '') { return dirname(__DIR__) . '/' . ltrim($p, '/'); }
    // 必须能链式 ->header()：Singbox/SingboxOld 用的是 response(...)->header(...)
    function response($data = '', $status = 200)
    {
        return new class($data, $status) {
            private $d; private $s; private $h = array();
            public function __construct($d, $s) { $this->d = $d; $this->s = $s; }
            public function getContent() { return $this->d; }
            public function header($k, $v = null) { $this->h[$k] = $v; return $this; }
            public function withHeaders($h = array()) { $this->h = array_merge($this->h, $h); return $this; }
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
    $nets = array('tcp', 'ws', 'grpc', 'h2', 'http', 'httpupgrade', 'xhttp', 'kcp', 'quic', 'domainsocket');
    // 解析器认得的传输（与站点节点取值范围对齐）。**能不能忠实下发是渲染器侧的另一层判断**：
    // Clash 系只认 tcp/ws/grpc（vless 另加 xhttp），Loon / QuantumultX / sing-box 各自更窄，
    // 由 Helper::networkExpressible 与 sing-box 自己的守卫逐格决定。
    // anytls 本身没有传输概念 → 只认 tcp。
    $known = array(
        'vmess'  => array('tcp', 'ws', 'grpc', 'kcp', 'http', 'h2', 'httpupgrade', 'xhttp', 'quic', 'domainsocket'),
        'vless'  => array('tcp', 'ws', 'grpc', 'kcp', 'http', 'h2', 'httpupgrade', 'xhttp', 'quic', 'domainsocket'),
        'trojan' => array('tcp', 'ws', 'grpc', 'kcp', 'http', 'h2', 'httpupgrade', 'xhttp', 'quic', 'domainsocket'),
        'anytls' => array('tcp'),
    );
    // 渲染器侧基准：ClashMeta 能忠实表达哪些（其余必须「不产出」而不是静默降级）
    $clashMetaOk = array(
        'vmess'  => array('tcp', 'ws', 'grpc'),
        'vless'  => array('tcp', 'ws', 'grpc', 'xhttp'),
        'trojan' => array('tcp', 'ws', 'grpc'),
        'anytls' => array('tcp'),
    );
    $uris = array(
        'vmess' => function ($net) use ($UUID) {
            return 'vmess://' . base64_encode(json_encode(array('v' => '2', 'ps' => 'EXT', 'add' => '1.1.1.1',
                'port' => '443', 'id' => $UUID, 'aid' => '0', 'net' => $net, 'host' => 'a.com',
                'path' => '/p', 'mode' => 'auto', 'tls' => 'tls', 'sni' => 'a.com')));
        },
        'vless' => function ($net) use ($UUID) {
            return 'vless://' . $UUID . '@1.1.1.1:443?encryption=none&security=tls&sni=a.com&host=a.com'
                . '&path=%2Fp&mode=auto&serviceName=svc&type=' . $net . '#EXT';
        },
        'trojan' => function ($net) {
            return 'trojan://tjpwd@1.1.1.1:443?sni=a.com&type=' . $net
                . '&host=a.com&path=%2Fp&mode=auto&serviceName=svc#EXT';
        },
        'anytls' => function ($net) {
            return 'anytls://anypwd@1.1.1.1:8443?sni=a.com&type=' . $net . '&host=a.com&path=%2Fp#EXT';
        },
    );

    $FAILS = 0;
    function ok($label, $cond, $detail = '')
    {
        global $FAILS;
        if (!$cond) { $FAILS++; }
        echo '  ' . ($cond ? '✓' : '✗') . ' ' . str_pad($label, 40) . $detail . "\n";
    }

    echo "══════ 解析器认不得的传输：必须跳过（陌生取值下发出去 = 坏节点）══════\n";
    $unknown = array('zzz', 'foo', 'none', 'http/2');
    foreach ($uris as $proto => $fn) {
        foreach ($unknown as $net) {
            $r = \App\Utils\SubscriptionParser::parse($fn($net));
            $reason = 'unsupported_network:' . $net;
            ok($proto . ' / ' . $net, !$r['nodes'] && isset($r['skipped'][$reason]),
                $r['nodes'] ? '✗ 仍产出节点' : json_encode($r['skipped'], JSON_UNESCAPED_UNICODE));
        }
    }

    echo "\n══════ 解析器认得的传输：必须产出，且传输设置字段齐全 ══════\n";
    $need = array(
        'ws' => array('path'),
        'httpupgrade' => array('path', 'host'),
        'http' => array('path', 'host'),
        'h2' => array('path', 'host'),
        'xhttp' => array('path', 'host', 'mode'),
        'grpc' => array('serviceName'),
        'kcp' => array('header'),
    );
    foreach ($uris as $proto => $fn) {
        foreach ($known[$proto] as $net) {
            $r = \App\Utils\SubscriptionParser::parse($fn($net));
            if (!$r['nodes']) { ok($proto . ' / ' . $net, false, '✗ 被误跳 ' . json_encode($r['skipped'])); continue; }
            $node = $r['nodes'][0];
            $ns = isset($node['network_settings']) ? $node['network_settings'] : array();
            $missing = array();
            foreach (isset($need[$net]) ? $need[$net] : array() as $k) {
                if (!array_key_exists($k, $ns)) { $missing[] = $k; }
            }
            ok($proto . ' / ' . $net, (isset($node['network']) && $node['network'] === $net) && !$missing,
                ($missing ? '✗ 缺设置键 ' . implode(',', $missing) . ' ' : '')
                . json_encode($ns, JSON_UNESCAPED_UNICODE));
        }
    }

    echo "\n══════ 渲染器侧：ClashMeta 表达不了的必须「不产出」而不是静默降级 ══════\n";
    foreach ($uris as $proto => $fn) {
        foreach ($known[$proto] as $net) {
            $r = \App\Utils\SubscriptionParser::parse($fn($net));
            if (!$r['nodes']) { continue; }
            $node = $r['nodes'][0];
            $u = new FakeUser();
            try {
                $out = (string)(new \App\Protocols\ClashMeta($u, array($node)))->handle();
            } catch (\Throwable $e) {
                ok('ClashMeta ' . $proto . ' / ' . $net, false, '✗ 抛异常 ' . $e->getMessage());
                continue;
            }
            $shouldHave = in_array($net, $clashMetaOk[$proto], true);
            $has = strpos($out, $node['host']) !== false;
            $nameLeak = strpos($out, '"name":"' . $node['name'] . '"') !== false;
            ok('ClashMeta ' . $proto . ' / ' . $net . ($shouldHave ? ' 应下发' : ' 应跳过'),
                $has === $shouldHave && ($shouldHave || !$nameLeak),
                $has ? '已下发' : ($nameLeak ? '✗ 未下发但名字残留' : '未下发'));
        }
    }

    echo "\n══════ xhttp 例外（vless）：Clash 家族与 Stash 必须忠实，sing-box 必须跳过 ══════\n";
    $xr = \App\Utils\SubscriptionParser::parse($uris['vless']('xhttp'));
    ok('vless + xhttp 被保留', count($xr['nodes']) === 1, json_encode($xr['skipped']));
    if ($xr['nodes']) {
        $xnode = $xr['nodes'][0];
        foreach (array('ClashMeta' => 'App\Protocols\ClashMeta', 'ClashVerge' => 'App\Protocols\ClashVerge',
                       'ClashNyanpasu' => 'App\Protocols\ClashNyanpasu', 'Stash' => 'App\Protocols\Stash') as $label => $class) {
            $u = new FakeUser();
            $out = (string)(new $class($u, array($xnode)))->handle();
            $hasNet = strpos($out, '"network":"xhttp"') !== false;
            $hasOpts = strpos($out, 'xhttp-opts') !== false;
            ok($label . ' 下发 network=xhttp + xhttp-opts', $hasNet && $hasOpts,
                'network=' . ($hasNet ? 'xhttp' : '缺') . '，opts=' . ($hasOpts ? '有' : '缺'));
        }
        foreach (array('Singbox' => 'App\Protocols\Singbox\Singbox',
                       'SingboxOld' => 'App\Protocols\Singbox\SingboxOld') as $label => $class) {
            $u = new FakeUser();
            $out = (string)(new $class($u, array($xnode)))->handle();
            // 用节点的 tag（= 名字）判断，不能用 host：1.1.1.1 会命中默认配置里的 DNS 段
            $skipped = strpos($out, '"tag":"' . $xnode['name'] . '"') === false
                && strpos($out, '"tag": "' . $xnode['name'] . '"') === false;
            $empty = (strpos($out, '"transport":[]') !== false) || (strpos($out, '"transport":{}') !== false);
            ok($label . ' 跳过该节点且不产出空 transport', $skipped && !$empty,
                '节点 tag ' . ($skipped ? '未出现' : '仍出现') . '，空 transport=' . ($empty ? '有' : '无'));
        }
    }

    echo "\n══════ sing-box 侧：本站节点带 kcp / http / … 也不能产出空 transport ══════\n";
    // 后台 ServerVmessSave 允许 tcp,kcp,ws,http,domainsocket,quic,grpc,httpupgrade,xhttp，
    // 所以本站节点真的会带这些传输（附加订阅侧已被解析器拦掉）
    $siteStyle = array(
        array('type' => 'vmess', 'name' => 'SITE-VMESS-KCP', 'host' => '10.1.1.1', 'port' => 443,
              'network' => 'kcp', 'network_settings' => array(), 'tls' => 1,
              'tls_settings' => array('server_name' => 'a.com', 'allow_insecure' => 0), 'created_at' => time()),
        array('type' => 'vmess', 'name' => 'SITE-VMESS-HTTP', 'host' => '10.1.1.2', 'port' => 443,
              'network' => 'http', 'network_settings' => array(), 'tls' => 0,
              'tls_settings' => array(), 'created_at' => time()),
        array('type' => 'trojan', 'name' => 'SITE-TROJAN-KCP', 'host' => '10.1.1.3', 'port' => 443,
              'network' => 'kcp', 'network_settings' => array(), 'tls' => 1,
              'tls_settings' => array('server_name' => 'a.com', 'allow_insecure' => 0), 'created_at' => time()),
        array('type' => 'vmess', 'name' => 'SITE-VMESS-WS', 'host' => '10.1.1.4', 'port' => 443,
              'network' => 'ws', 'network_settings' => array('path' => '/p', 'headers' => array('Host' => 'a.com')),
              'tls' => 1, 'tls_settings' => array('server_name' => 'a.com', 'allow_insecure' => 0), 'created_at' => time()),
    );
    foreach (array('Singbox' => 'App\Protocols\Singbox\Singbox',
                   'SingboxOld' => 'App\Protocols\Singbox\SingboxOld') as $label => $class) {
        $u = new FakeUser();
        $out = (string)(new $class($u, $siteStyle))->handle();
        $empty = (strpos($out, '"transport":[]') !== false) || (strpos($out, '"transport":{}') !== false);
        $bad = strpos($out, 'SITE-VMESS-KCP') !== false || strpos($out, 'SITE-VMESS-HTTP') !== false
            || strpos($out, 'SITE-TROJAN-KCP') !== false;
        $ws = strpos($out, 'SITE-VMESS-WS') !== false;
        ok($label . '：坏传输不产出 / ws 保留 / 无空 transport', !$empty && !$bad && $ws,
            '空 transport=' . ($empty ? '有' : '无') . '，坏传输节点=' . ($bad ? '仍产出' : '已跳过')
            . '，ws 节点=' . ($ws ? '保留' : '丢了'));

        // 悬空 tag 检查：selector / urltest 引用的 tag 必须都真的在 outbounds 里
        $cfg = json_decode($out, true);
        if (is_array($cfg) && !empty($cfg['outbounds'])) {
            $tags = array_column($cfg['outbounds'], 'tag');
            $refs = array();
            foreach ($cfg['outbounds'] as $ob) {
                if (!empty($ob['outbounds']) && is_array($ob['outbounds'])) {
                    foreach ($ob['outbounds'] as $r) { $refs[$r] = true; }
                }
            }
            $dangling = array_values(array_diff(array_keys($refs), $tags));
            ok($label . '：selector 引用的 tag 都存在（无悬空）', empty($dangling), json_encode($dangling));
        }
    }

    echo "\n══════ grpc 是项目支持的传输，但 Surge / Surfboard / Loon 表达不了 ══════\n";
    // 实测：这三个渲染器的 vmess / trojan 输出里完全没有 grpc 参数（→ 客户端按 tcp 连）
    // ws 它们是忠实的（Surge/Surfboard/Loon 用 ws=true，Loon 的 vless/trojan 本来就带守卫）
    foreach (array('Surge' => 'App\Protocols\Surge', 'Surfboard' => 'App\Protocols\Surfboard',
                   'Loon' => 'App\Protocols\Loon') as $label => $class) {
        foreach (array('vmess', 'trojan', 'ws') as $what) {
            $type = $what === 'ws' ? 'vmess' : $what;
            $net = $what === 'ws' ? 'ws' : 'grpc';
            $name = 'G-' . $type . '-' . $net;
            $nd = array('id' => 1, 'type' => $type, 'name' => $name, 'host' => '10.9.9.9', 'port' => '443',
                'network' => $net, 'network_settings' => $net === 'ws'
                    ? array('path' => '/p', 'headers' => array('Host' => 'a.com'))
                    : array('serviceName' => 'svc'),
                'networkSettings' => $net === 'ws'
                    ? array('path' => '/p', 'headers' => array('Host' => 'a.com'))
                    : array('serviceName' => 'svc'),
                'tls' => 1, 'tls_settings' => array('server_name' => 'a.com', 'allow_insecure' => 0),
                'tlsSettings' => array('server_name' => 'a.com', 'allow_insecure' => 0),
                'server_name' => 'a.com', 'created_at' => time(), 'cache_key' => 'k');
            if ($type === 'vmess') { $nd['uuid'] = '11111111-2222-3333-4444-555555555555'; $nd['alter_id'] = 0; }
            $u = new FakeUser();
            $out = (string)(new $class($u, array($nd)))->handle();
            $appears = strpos($out, $name) !== false;
            if ($net === 'grpc') {
                // 期望整条不产出（名字也不能进 proxy 组 / 组里会引用不存在的节点）
                ok($label . ' / ' . $type . '+grpc 整条跳过', !$appears,
                    $appears ? '仍产出：' . substr(@strstr($out, $name), 0, 70) : '');
            } else {
                ok($label . ' / ' . $type . '+ws 仍然产出', $appears, $appears ? '' : '被误跳');
            }
        }
    }

    echo "\n后两行说明：tcp 的「—」是缺省（不写 network）即正确；\n"
        . "anytls 的传输由协议自身决定（渲染器不读 network 属正常），这里只断言节点产出。\n";
    echo $FAILS === 0 ? "\n  ✓ 全部通过\n" : "\n  ✗ 断言失败 $FAILS 项（见上）\n";
    exit($FAILS === 0 ? 0 : 1);
}
