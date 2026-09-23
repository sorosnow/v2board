<?php

namespace App\Utils;

/**
 * 订阅内容解析器（附加订阅）
 *
 * 把额外订阅链接返回的内容（base64 或明文 URI 列表）解析为内部节点结构，
 * 复用现有 Protocol 渲染器一并下发。
 *
 * 两个要点：
 *  - 每个节点带 `_credential`（第三方自己的 uuid/密码），渲染器优先读它，
 *    不能被本站当前用户 uuid 覆盖，否则节点必然连不上
 *  - ss-2022 主动跳过：其 server key 需由 created_at 派生（Helper::getServerKey），
 *    第三方节点的 created_at 不可知，下发只会产出连不上的节点
 *
 * 语法上限 PHP 8.0（composer.json 要求 ^8.0）：可用 8.0 写法，不用 8.1+ 特性。
 */
class SubscriptionParser
{
    /**
     * scheme => 解析方法
     *
     * @var array
     */
    private static $handlerMap = array(
        'ss'        => 'parseShadowsocks',
        'vmess'     => 'parseVmess',
        'vless'     => 'parseVless',
        'trojan'    => 'parseTrojan',
        'hysteria'  => 'parseHysteria',
        'hysteria2' => 'parseHysteria2',
        'hy2'       => 'parseHysteria2',
        'tuic'      => 'parseTuic',
        'anytls'    => 'parseAnyTls',
    );

    /**
     * 第三方节点能用的 ss cipher —— 单一来源：Helper::SS_CIPHERS
     *
     * 只有这 4 种是各端都能忠实下发的；表单允许的另外两种 2022-blake3-* 只对本站节点成立
     * （server key 要靠 created_at 派生），已在 parseShadowsocks() 开头单独跳过。
     *
     * @var array
     */
    private static $ssCiphers = Helper::SS_CIPHERS;

    /**
     * 认得的传输方式（不在这张表里的直接丢弃 —— 陌生取值原样下发只会得到「按 tcp 连」的坏节点）
     *
     * 这张表答的是「项目认得什么」，与站点节点那边的取值范围对齐（各 Save 规则的并集：
     * ServerVmessSave 放行 tcp/kcp/ws/http/domainsocket/quic/grpc/httpupgrade/xhttp，
     * V2nodeController 放行 tcp/ws/grpc/http/httpupgrade/xhttp；h2 是 v2rayN 的习惯写法）。
     * 「某个客户端能不能忠实表达」是**另一层**判断，由渲染器侧的 Helper::networkExpressible
     * 逐格决定（Clash 系只认 tcp/ws/grpc，Loon / QuantumultX / sing-box 各自更窄）。
     * 所以这里放宽不会让任何客户端拿到坏节点 —— 它只会让 URI 类客户端（V2rayN / Shadowrocket /
     * General / Passwall / SagerNet / SSRPlus / v2RayTun）拿回它们本来就能忠实下发的节点。
     *
     * @var array
     */
    private static $networks = array('tcp', 'ws', 'grpc', 'kcp', 'http', 'h2', 'httpupgrade',
        'xhttp', 'quic', 'domainsocket');

    /**
     * 跳过原因计数
     *
     * @var array
     */
    private static $skipped = array();

    /**
     * 解析订阅原文
     *
     * @param  string $raw 订阅原文（base64 或明文）
     * @return array ['nodes' => 节点数组, 'skipped' => [原因 => 条数]]
     */
    public static function parse($raw)
    {
        self::$skipped = array();

        $nodes = array();
        $lines = preg_split('/\r\n|\r|\n/', self::decode($raw));

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $node = self::parseLine($line);
            if ($node !== null) {
                $nodes[] = $node;
            }
        }

        return array(
            'nodes'   => $nodes,
            'skipped' => self::$skipped,
        );
    }

    /**
     * 记录跳过原因
     *
     * @param string $reason
     */
    private static function skip($reason)
    {
        if (!isset(self::$skipped[$reason])) {
            self::$skipped[$reason] = 0;
        }
        self::$skipped[$reason]++;
    }

    /**
     * 内容解码：明文直接返回；base64 则解码
     *
     * @param  string $raw
     * @return string
     */
    private static function decode($raw)
    {
        $raw = trim((string)$raw);
        // 有些订阅文件带 UTF-8 BOM（EF BB BF）：不剥掉会让首行 scheme 带上不可见字节，
        // 明文源丢第一条、base64 源则整份解析失败
        if (strncmp($raw, "\xEF\xBB\xBF", 3) === 0) {
            $raw = substr($raw, 3);
        }
        if ($raw === '') {
            return '';
        }
        // 已经包含 scheme，视为明文
        if (strpos($raw, '://') !== false) {
            return $raw;
        }
        $normalized = preg_replace('/\s+/', '', $raw);
        $normalized = str_replace(array('-', '_'), array('+', '/'), $normalized);
        $pad = strlen($normalized) % 4;
        if ($pad) {
            $normalized .= str_repeat('=', 4 - $pad);
        }
        $decoded = base64_decode($normalized, true);
        if ($decoded === false || strpos($decoded, '://') === false) {
            return $raw;
        }
        return $decoded;
    }

    /**
     * 解析单行 URI
     *
     * @param  string $line
     * @return array|null
     */
    private static function parseLine($line)
    {
        $pos = strpos($line, '://');
        if ($pos === false) {
            self::skip('not_a_uri');
            return null;
        }
        $scheme = strtolower(substr($line, 0, $pos));
        if (!isset(self::$handlerMap[$scheme])) {
            self::skip('unsupported_scheme:' . $scheme);
            return null;
        }
        $method = self::$handlerMap[$scheme];
        return self::$method($line);
    }

    /* ------------------------------------------------------------------
     |  各协议解析
     * ------------------------------------------------------------------ */

    /**
     * ss://：SIP002（base64(method:password)@host:port?plugin=...#name）
     * 与老式（base64(method:password@host:port)#name）均支持
     *
     * @param  string $uri
     * @return array|null
     */
    private static function parseShadowsocks($uri)
    {
        $body = self::stripScheme($uri);
        $name = self::splitName($body);
        $query = self::splitQuery($body);

        if (strpos($body, '@') === false) {
            $decoded = self::b64($body);
            if ($decoded === null || strpos($decoded, '@') === false) {
                self::skip('ss_bad_format');
                return null;
            }
            $body = $decoded;
        }

        $at = strrpos($body, '@');
        $userinfo = substr($body, 0, $at);
        $hostport = substr($body, $at + 1);

        // userinfo 有三种写法：SIP002 的 base64(method:password)、
        // SIP002 的明文变体（method:password，可能 URL 编码）、
        // 以及老式格式（整段 base64 已在上方解码，这里已是明文）
        $decoded = self::b64($userinfo);
        if ($decoded === null || strpos($decoded, ':') === false) {
            $plain = rawurldecode($userinfo);
            $decoded = strpos($plain, ':') !== false ? $plain : null;
        }
        if ($decoded === null) {
            self::skip('ss_bad_userinfo');
            return null;
        }
        $colon = strpos($decoded, ':');
        $cipher = substr($decoded, 0, $colon);
        $credential = substr($decoded, $colon + 1);

        // 空密码：与 trojan/vless/anytls 的处理保持一致，直接丢弃
        // （渲染器会把空 _credential 当成「用本站用户 uuid」，下发必然是连不上的僵尸节点）
        if ($credential === '') {
            self::skip('ss_no_password');
            return null;
        }

        // 2022-blake3 不是「不支持」，而是做不了：它的 server key 要靠 created_at
        // 派生（Helper::getServerKey），第三方节点的 created_at 不可知，下发必然连不上
        if (strpos($cipher, '2022-blake3') !== false) {
            self::skip('ss_2022_unsupported');
            return null;
        }
        // 只保留本站原生支持的 cipher：来源是后台表单白名单
        // （Admin\ServerShadowsocksSave）与 Shadowsocks/Clash/Surfboard 渲染器的判断，
        // 三者一致；其余一律丢弃，避免下发客户端不认的加密方式
        if (!in_array($cipher, self::$ssCiphers, true)) {
            self::skip('ss_unsupported_cipher:' . $cipher);
            return null;
        }

        $hp = self::splitHostPort($hostport);
        if ($hp === null) {
            self::skip('ss_bad_host_port');
            return null;
        }

        $node = self::base('shadowsocks', $name, $hp[0], $hp[1], $credential);
        $node['cipher'] = $cipher;

        // 带插件的 ss：渲染器只支持 obfs=http 这一种写法（Helper::buildShadowsocksUri /
        // Clash / ClashMeta / Singbox 都只认它），其余（v2ray-plugin、obfs=tls…）下发出去
        // 等于「直连节点」——源站要求插件握手，客户端必然连不上，所以直接跳过并记原因
        if (!empty($query['plugin'])) {
            $opts = self::parsePluginOpts($query['plugin']);
            if (!isset($opts['obfs']) || $opts['obfs'] !== 'http') {
                self::skip('ss_plugin_unsupported:' . self::pluginName($query['plugin'])
                    . (isset($opts['obfs']) ? ':' . $opts['obfs'] : ''));
                return null;
            }
            $node['obfs'] = 'http';
            $node['obfs-host'] = isset($opts['obfs-host']) ? $opts['obfs-host'] : '';
            $node['obfs-path'] = isset($opts['path']) ? $opts['path'] : '';
        }

        return $node;
    }

    /**
     * vmess://base64(json)
     *
     * @param  string $uri
     * @return array|null
     */
    /**
     * 传输方式是否认得（认不得就丢掉并记原因）
     *
     * 传进来的值应当已经过 canonicalNetwork() 归一（见那里为什么不在本表里放别名）
     *
     * @param  string $network
     * @return bool
     */
    private static function networkAllowed($network)
    {
        if (in_array($network, self::$networks, true)) {
            return true;
        }
        self::skip('unsupported_network:' . $network);

        return false;
    }

    /**
     * 传输名别名 → 项目自己用的名字
     *
     * 项目自己的名字就是后台表单与渲染器都在用的那一套（tcp / ws / grpc / kcp / http /
     * h2 / httpupgrade / xhttp / quic / domainsocket）。上游客户端后来改过名字：
     *   · raw       = Xray 25.x 给 TCP 起的新名字（本项目仍叫 tcp）
     *   · splithttp = XHTTP 的旧名（本项目仍叫 xhttp）
     * 两者是同一个传输的两种拼写（Xray 的配置里 xhttpSettings 与 splithttpSettings 是同一个
     * 结构体），所以只在这一层归一：归一后渲染器拿到的是它们本来就有的名字。
     *
     * ⚠️ 别把别名写进 self::$networks，也别往后台表单里加：渲染器没有这两个分支，
     *    走 Helper::networkExpressible 会被判否 —— 等于把节点从「能忠实下发」改成
     *    「静默不下发」；未登记该传输的客户端还会按 tcp 连（坏节点）。
     *
     * @var array
     */
    private static $networkAliases = array(
        'raw'       => 'tcp',
        'splithttp' => 'xhttp',
    );

    /**
     * 把外部链接里的传输名归一成项目自己的名字（不在别名表里的原样返回，交给白名单去丢）
     *
     * @param  string $network
     * @return string
     */
    private static function canonicalNetwork($network)
    {
        return isset(self::$networkAliases[$network]) ? self::$networkAliases[$network] : $network;
    }

    private static function parseVmess($uri)
    {
        $body = self::stripScheme($uri);
        $name = self::splitName($body);

        $json = self::b64($body);
        if ($json === null) {
            self::skip('vmess_bad_base64');
            return null;
        }
        $cfg = json_decode($json, true);
        if (!is_array($cfg) || empty($cfg['add']) || empty($cfg['port'])) {
            self::skip('vmess_bad_json');
            return null;
        }
        if (empty($cfg['id'])) {
            self::skip('vmess_no_id');
            return null;
        }
        if ($name === '' && !empty($cfg['ps'])) {
            $name = $cfg['ps'];
        }

        $tlsSettings = array(
            // 必须同时写 snake_case 与 camelCase：ClashMeta::buildVmess() 只认 camelCase，
            // 只写 snake_case 会让 Clash 输出丢掉 servername / skip-cert-verify（不报错但连不上）。
            'server_name'    => isset($cfg['sni']) ? $cfg['sni'] : (isset($cfg['host']) ? $cfg['host'] : ''),
            'serverName'     => isset($cfg['sni']) ? $cfg['sni'] : (isset($cfg['host']) ? $cfg['host'] : ''),
            'allow_insecure' => isset($cfg['allowInsecure']) ? (int)$cfg['allowInsecure'] : 0,
            'allowInsecure'  => isset($cfg['allowInsecure']) ? (int)$cfg['allowInsecure'] : 0,
        );
        $network = self::canonicalNetwork(!empty($cfg['net']) ? $cfg['net'] : 'tcp');
        if (!self::networkAllowed($network)) {
            return null;
        }
        $networkSettings = self::vmessNetworkSettings($cfg, $network);

        $node = self::base('vmess', $name, $cfg['add'], $cfg['port'], $cfg['id']);
        $node['tls'] = (!empty($cfg['tls']) && $cfg['tls'] !== 'none') ? 1 : 0;
        $node['tls_settings'] = $tlsSettings;
        $node['tlsSettings'] = $tlsSettings;
        $node['network'] = $network;
        $node['network_settings'] = $networkSettings;
        $node['networkSettings'] = $networkSettings;

        return $node;
    }

    /**
     * vless://uuid@host:port?...
     *
     * @param  string $uri
     * @return array|null
     */
    private static function parseVless($uri)
    {
        $body = self::stripScheme($uri);
        $name = self::splitName($body);
        $query = self::splitQuery($body);

        $at = strrpos($body, '@');
        if ($at === false) {
            self::skip('vless_no_at');
            return null;
        }
        $credential = rawurldecode(substr($body, 0, $at));
        if ($credential === '') {
            self::skip('vless_no_id');
            return null;
        }
        $hp = self::splitHostPort(substr($body, $at + 1));
        if ($hp === null) {
            self::skip('vless_bad_host_port');
            return null;
        }

        $security = isset($query['security']) ? strtolower($query['security']) : '';
        $tls = 0;
        if ($security === 'tls') {
            $tls = 1;
        } elseif ($security === 'reality') {
            $tls = 2;
        }

        $tlsSettings = array(
            'server_name'    => isset($query['sni']) ? $query['sni'] : (isset($query['host']) ? $query['host'] : ''),
            'allow_insecure' => isset($query['insecure']) ? self::bool01($query['insecure']) : 0,
            'fingerprint'    => isset($query['fp']) ? $query['fp'] : 'chrome',
        );
        // reality（tls=2）必须无条件写这两个键：Clash 系 buildVless 在 tls==2 时直接读
        // public_key / short_id（无 ??），缺键会 Undefined array key -> 整份订阅 500。
        // short-id 本就可选（URI 里可以没有 sid），故写 '' 是正确的。
        if ($tls === 2) {
            $tlsSettings['public_key'] = isset($query['pbk']) ? $query['pbk'] : '';
            $tlsSettings['short_id'] = isset($query['sid']) ? $query['sid'] : '';
        }

        $network = self::canonicalNetwork(!empty($query['type']) ? $query['type'] : 'tcp');
        if (!self::networkAllowed($network)) {
            return null;
        }
        $networkSettings = self::uriNetworkSettings($query, $network);

        $node = self::base('vless', $name, $hp[0], $hp[1], $credential);
        $node['tls'] = $tls;
        $node['tls_settings'] = $tlsSettings;
        $node['tlsSettings'] = $tlsSettings;
        $node['flow'] = isset($query['flow']) ? $query['flow'] : '';
        $node['encryption'] = (!empty($query['encryption']) && $query['encryption'] !== 'none')
            ? $query['encryption'] : 'none';
        $node['network'] = $network;
        $node['network_settings'] = $networkSettings;
        $node['networkSettings'] = $networkSettings;

        return $node;
    }

    /**
     * trojan://password@host:port?...
     *
     * @param  string $uri
     * @return array|null
     */
    private static function parseTrojan($uri)
    {
        $body = self::stripScheme($uri);
        $name = self::splitName($body);
        $query = self::splitQuery($body);

        $at = strrpos($body, '@');
        if ($at === false) {
            self::skip('trojan_no_at');
            return null;
        }
        $credential = rawurldecode(substr($body, 0, $at));
        if ($credential === '') {
            self::skip('trojan_no_password');
            return null;
        }
        $hp = self::splitHostPort(substr($body, $at + 1));
        if ($hp === null) {
            self::skip('trojan_bad_host_port');
            return null;
        }

        $sni = isset($query['sni']) ? $query['sni']
            : (isset($query['peer']) ? $query['peer']
            : (isset($query['host']) ? $query['host'] : ''));
        $insecure = isset($query['allowInsecure']) ? self::bool01($query['allowInsecure'])
            : (isset($query['insecure']) ? self::bool01($query['insecure']) : 0);

        $network = self::canonicalNetwork(!empty($query['type']) ? $query['type'] : 'tcp');
        if (!self::networkAllowed($network)) {
            return null;
        }
        $networkSettings = self::uriNetworkSettings($query, $network);
        $tlsSettings = array(
            'server_name'    => $sni,
            'allow_insecure' => $insecure,
        );

        $node = self::base('trojan', $name, $hp[0], $hp[1], $credential);
        $node['tls'] = 1;
        $node['tls_settings'] = $tlsSettings;
        $node['tlsSettings'] = $tlsSettings;
        $node['server_name'] = $sni;
        $node['allow_insecure'] = $insecure;
        $node['network'] = $network;
        $node['network_settings'] = $networkSettings;
        $node['networkSettings'] = $networkSettings;

        return $node;
    }

    /**
     * hysteria://（v1）、hysteria2:// / hy2://（v2）
     *
     * 统一映射为 type='hysteria' + version，与 ServerHysteria 一致，
     * 这样 Surge / Loon（判断 version===2）与 Clash 系都能渲染。
     *
     * @param  string $uri
     * @return array|null
     */
    private static function parseHysteria($uri)
    {
        $isV2 = (stripos($uri, 'hysteria2://') === 0 || stripos($uri, 'hy2://') === 0);

        $body = self::stripScheme($uri);
        $name = self::splitName($body);
        $query = self::splitQuery($body);

        $credential = '';
        $at = strrpos($body, '@');
        if ($at !== false) {
            $credential = rawurldecode(substr($body, 0, $at));
            $hostport = substr($body, $at + 1);
        } else {
            $hostport = $body;
            $credential = isset($query['auth']) ? $query['auth'] : '';
        }

        // 空凭据：与 trojan/vless/anytls 的处理保持一致，直接丢弃
        if ($credential === '') {
            self::skip('hysteria_no_auth');
            return null;
        }

        $hp = self::splitHostPort($hostport);
        if ($hp === null) {
            self::skip('hysteria_bad_host_port');
            return null;
        }

        $sni = isset($query['sni']) ? $query['sni']
            : (isset($query['peer']) ? $query['peer'] : '');
        $insecure = isset($query['insecure']) ? self::bool01($query['insecure']) : 0;
        $tlsSettings = array(
            'server_name'    => $sni,
            'allow_insecure' => $insecure,
        );

        $node = self::base('hysteria', $name, $hp[0], $hp[1], $credential);
        $node['version'] = $isV2 ? 2 : 1;
        $node['server_name'] = $sni;
        $node['insecure'] = $insecure;
        $node['tls_settings'] = $tlsSettings;
        $node['tlsSettings'] = $tlsSettings;
        // 内部字段是「服务器视角」，而渲染器是反着取的
        // （Helper::buildHysteriaUri / ClashMeta::buildHysteria 里 upmbps 取 down_mbps），
        // 所以这里反向存，才能让下发出去的 upmbps/downmbps 与源 URI 一致
        $node['up_mbps'] = isset($query['downmbps']) ? (int)$query['downmbps'] : 0;
        $node['down_mbps'] = isset($query['upmbps']) ? (int)$query['upmbps'] : 0;
        if (!empty($query['obfs'])) {
            // hysteria2 只有 salamander 一种混淆，渲染器是原样下发 obfs 值，
            // 其他取值客户端不认（v1 的 obfs 是另一回事，不受此限）
            if ($isV2 && strtolower($query['obfs']) !== 'salamander') {
                self::skip('hysteria_obfs_unsupported:' . $query['obfs']);
                return null;
            }
            $node['obfs'] = $query['obfs'];
            $node['obfs_password'] = isset($query['obfs-password']) ? $query['obfs-password']
                : (isset($query['obfsParam']) ? $query['obfsParam'] : '');
        }

        return $node;
    }

    /**
     * hysteria2 专用入口（复用 parseHysteria）
     *
     * @param  string $uri
     * @return array|null
     */
    private static function parseHysteria2($uri)
    {
        return self::parseHysteria($uri);
    }

    /**
     * tuic://uuid:password@host:port?...
     *
     * @param  string $uri
     * @return array|null
     */
    private static function parseTuic($uri)
    {
        $body = self::stripScheme($uri);
        $name = self::splitName($body);
        $query = self::splitQuery($body);

        $at = strrpos($body, '@');
        if ($at === false) {
            self::skip('tuic_no_at');
            return null;
        }
        $userinfo = substr($body, 0, $at);
        if (strpos($userinfo, ':') !== false) {
            $parts = explode(':', $userinfo, 2);
            $credential = rawurldecode($parts[0]);
            // 渲染器的 tuic 约定是 uuid == password（一个凭据同时当 uuid 与密码），
            // 表达不了 uuid != password 的节点，下发只会得到连不上的僵尸节点
            if (rawurldecode($parts[1]) !== $credential) {
                self::skip('tuic_password_mismatch');
                return null;
            }
        } else {
            $credential = rawurldecode($userinfo);
        }
        if ($credential === '') {
            self::skip('tuic_no_uuid');
            return null;
        }
        $hp = self::splitHostPort(substr($body, $at + 1));
        if ($hp === null) {
            self::skip('tuic_bad_host_port');
            return null;
        }

        $sni = isset($query['sni']) ? $query['sni'] : '';
        $insecure = isset($query['allow_insecure']) ? self::bool01($query['allow_insecure'])
            : (isset($query['insecure']) ? self::bool01($query['insecure']) : 0);
        $tlsSettings = array(
            'server_name'    => $sni,
            'allow_insecure' => $insecure,
        );

        $node = self::base('tuic', $name, $hp[0], $hp[1], $credential);
        $node['server_name'] = $sni;
        $node['insecure'] = $insecure;
        $node['disable_sni'] = isset($query['disable_sni']) ? self::bool01($query['disable_sni']) : 0;
        // Clash 系 buildTuic 直接读该键（无 ??），缺了会 Undefined array key -> 500
        $node['zero_rtt_handshake'] = isset($query['zero_rtt_handshake'])
            ? self::bool01($query['zero_rtt_handshake']) : 0;
        $node['udp_relay_mode'] = isset($query['udp_relay_mode']) ? $query['udp_relay_mode'] : 'native';
        $node['congestion_control'] = isset($query['congestion_control']) ? $query['congestion_control'] : 'bbr';
        $node['tls_settings'] = $tlsSettings;
        $node['tlsSettings'] = $tlsSettings;

        return $node;
    }

    /**
     * anytls://password@host:port/?...
     *
     * @param  string $uri
     * @return array|null
     */
    private static function parseAnyTls($uri)
    {
        $body = self::stripScheme($uri);
        $name = self::splitName($body);
        $query = self::splitQuery($body);

        $at = strrpos($body, '@');
        if ($at === false) {
            self::skip('anytls_no_at');
            return null;
        }
        $credential = rawurldecode(substr($body, 0, $at));
        if ($credential === '') {
            self::skip('anytls_no_password');
            return null;
        }
        $hp = self::splitHostPort(substr($body, $at + 1));
        if ($hp === null) {
            self::skip('anytls_bad_host_port');
            return null;
        }

        $sni = isset($query['sni']) ? $query['sni'] : '';
        $insecure = isset($query['insecure']) ? self::bool01($query['insecure']) : 0;
        $security = isset($query['security']) ? strtolower($query['security']) : '';
        $tlsSettings = array(
            'server_name'    => $sni,
            'allow_insecure' => $insecure,
            'fingerprint'    => isset($query['fp']) ? $query['fp'] : 'chrome',
        );
        // 同 parseVless：reality 时必须写入，否则 Singbox 的 anytls 读 short_id 会 500
        if ($security === 'reality') {
            $tlsSettings['public_key'] = isset($query['pbk']) ? $query['pbk'] : '';
            $tlsSettings['short_id'] = isset($query['sid']) ? $query['sid'] : '';
        }

        // 归一后再判：anytls 本身没有传输概念（所有渲染器都不读它的 network）：只认缺省 tcp
        $network = self::canonicalNetwork(!empty($query['type']) ? $query['type'] : 'tcp');
        if ($network !== 'tcp') {
            self::skip('unsupported_network:' . $network);
            return null;
        }
        $networkSettings = self::uriNetworkSettings($query, $network);

        $node = self::base('anytls', $name, $hp[0], $hp[1], $credential);
        $node['tls'] = $security === 'reality' ? 2 : 1;
        $node['server_name'] = $sni;
        $node['insecure'] = $insecure;
        $node['tls_settings'] = $tlsSettings;
        $node['tlsSettings'] = $tlsSettings;
        $node['network'] = $network;
        $node['network_settings'] = $networkSettings;
        $node['networkSettings'] = $networkSettings;

        return $node;
    }

    /* ------------------------------------------------------------------
     |  公共字段与工具
     * ------------------------------------------------------------------ */

    /**
     * 组装内部节点公共字段
     *
     * @param  string $type
     * @param  string $name
     * @param  string $host
     * @param  mixed  $port
     * @param  string $credential
     * @return array
     */
    private static function base($type, $name, $host, $port, $credential)
    {
        $port = trim((string)$port);

        $node = array(
            'type'       => $type,
            'name'       => $name,
            'host'       => trim($host),
            'cache_key'  => 'extra-' . $type . '-' . md5($host . ':' . $port . '#' . $name),
            '_credential' => $credential,
        );

        if (preg_match('/^\d+$/', $port)) {
            $node['port'] = (int)$port;
        } else {
            // 端口范围 / 多端口（如 "443,8443"、"20000-30000"）
            $node['port'] = $port;
            $node['mport'] = $port;
        }

        return $node;
    }

    /**
     * 去掉 scheme
     *
     * @param  string $uri
     * @return string
     */
    private static function stripScheme($uri)
    {
        $pos = strpos($uri, '://');
        return $pos === false ? $uri : substr($uri, $pos + 3);
    }

    /**
     * 取出 # 后的节点名（会从 $body 中移除该部分）
     *
     * @param  string $body 引用传入
     * @return string
     */
    private static function splitName(&$body)
    {
        $pos = strpos($body, '#');
        if ($pos === false) {
            return '';
        }
        $name = rawurldecode(substr($body, $pos + 1));
        $body = substr($body, 0, $pos);
        return $name;
    }

    /**
     * 取出 query（会从 $body 中移除该部分）
     *
     * @param  string $body 引用传入
     * @return array
     */
    private static function splitQuery(&$body)
    {
        $pos = strpos($body, '?');
        if ($pos === false) {
            return array();
        }
        $query = array();
        parse_str(substr($body, $pos + 1), $query);
        $body = substr($body, 0, $pos);
        return $query;
    }

    /**
     * 宽松 base64 解码（兼容 URL-safe 与缺失 padding）
     *
     * @param  string $data
     * @return string|null
     */
    private static function b64($data)
    {
        $data = str_replace(array('-', '_'), array('+', '/'), trim($data));
        $pad = strlen($data) % 4;
        if ($pad) {
            $data .= str_repeat('=', 4 - $pad);
        }
        $decoded = base64_decode($data, true);
        return $decoded === false ? null : $decoded;
    }

    /**
     * 拆分 host:port（支持 IPv6 字面量与尾部路径）
     *
     * @param  string $str
     * @return array|null [host, port]
     */
    private static function splitHostPort($str)
    {
        $str = trim($str);
        // 去掉尾部路径与 query（如 hysteria2 的 host:443/）
        $slash = strpos($str, '/');
        if ($slash !== false) {
            $str = substr($str, 0, $slash);
        }
        $str = rtrim($str, ':');
        if ($str === '') {
            return null;
        }

        if ($str[0] === '[') {
            $end = strpos($str, ']');
            if ($end === false) {
                return null;
            }
            $host = substr($str, 1, $end - 1);
            $port = ltrim(substr($str, $end + 1), ':');
        } else {
            $pos = strrpos($str, ':');
            if ($pos === false) {
                return null;
            }
            $host = substr($str, 0, $pos);
            $port = substr($str, $pos + 1);
        }

        if ($host === '' || $port === '') {
            return null;
        }
        return array($host, $port);
    }

    /**
     * 0/1 布尔归一
     *
     * @param  mixed $value
     * @return int
     */
    private static function bool01($value)
    {
        if (is_bool($value)) {
            return $value ? 1 : 0;
        }
        $value = strtolower(trim((string)$value));
        return in_array($value, array('1', 'true', 'yes', 'on'), true) ? 1 : 0;
    }

    /**
     * 取插件名，用于记跳过原因（如 obfs-local / v2ray-plugin）
     *
     * @param  string $plugin
     * @return string
     */
    private static function pluginName($plugin)
    {
        $parts = explode(';', $plugin, 2);

        return trim($parts[0]);
    }

    /**
     * 解析 ss 的 plugin 参数（形如 obfs-local;obfs=http;obfs-host=a.com）
     *
     * @param  string $plugin
     * @return array
     */
    private static function parsePluginOpts($plugin)
    {
        $opts = array();
        foreach (explode(';', $plugin) as $seg) {
            $kv = explode('=', $seg, 2);
            if (count($kv) === 2) {
                $opts[trim($kv[0])] = trim($kv[1]);
            }
        }
        return $opts;
    }

    /**
     * URI query → vmess 的 network_settings
     *
     * @param  array  $query
     * @param  string $network
     * @return array
     */
    private static function uriNetworkSettings($query, $network)
    {
        $settings = array();
        switch ($network) {
            case 'ws':
            case 'httpupgrade':
                if (!empty($query['path'])) {
                    $settings['path'] = $query['path'];
                }
                if (!empty($query['host'])) {
                    $settings['headers'] = array('Host' => $query['host']);
                }
                if ($network === 'httpupgrade' && !empty($query['host'])) {
                    $settings['host'] = $query['host'];
                }
                break;
            case 'http':
            case 'h2':
                if (!empty($query['path'])) {
                    $settings['path'] = $query['path'];
                }
                if (!empty($query['host'])) {
                    $settings['host'] = $query['host'];
                }
                break;
            case 'xhttp':
                if (!empty($query['path'])) {
                    $settings['path'] = $query['path'];
                }
                if (!empty($query['host'])) {
                    $settings['host'] = $query['host'];
                }
                if (!empty($query['mode'])) {
                    $settings['mode'] = $query['mode'];
                }
                break;
            case 'grpc':
                if (!empty($query['serviceName'])) {
                    $settings['serviceName'] = $query['serviceName'];
                }
                break;
            case 'kcp':
                if (!empty($query['seed'])) {
                    $settings['seed'] = $query['seed'];
                }
                $settings['header'] = array(
                    'type' => !empty($query['headerType']) ? $query['headerType'] : 'none',
                );
                break;
            case 'tcp':
                if (!empty($query['headerType']) && $query['headerType'] === 'http') {
                    $settings['header'] = array(
                        'type'    => 'http',
                        'request' => array(
                            'headers' => array('Host' => array(!empty($query['host']) ? $query['host'] : '')),
                            'path'    => array(!empty($query['path']) ? $query['path'] : '/'),
                        ),
                    );
                }
                break;
        }
        return $settings;
    }

    /**
     * vmess JSON → vmess 的 network_settings
     *
     * @param  array  $cfg
     * @param  string $network
     * @return array
     */
    private static function vmessNetworkSettings($cfg, $network)
    {
        $settings = array();
        switch ($network) {
            case 'ws':
                if (!empty($cfg['path'])) {
                    $settings['path'] = $cfg['path'];
                }
                if (!empty($cfg['host'])) {
                    $settings['headers'] = array('Host' => $cfg['host']);
                }
                if (!empty($cfg['scy']) && $cfg['scy'] !== 'auto') {
                    $settings['security'] = $cfg['scy'];
                }
                break;
            case 'grpc':
                if (!empty($cfg['path'])) {
                    $settings['serviceName'] = $cfg['path'];
                }
                break;
            case 'kcp':
                if (!empty($cfg['path'])) {
                    $settings['seed'] = $cfg['path'];
                }
                $settings['header'] = array(
                    'type' => !empty($cfg['type']) ? $cfg['type'] : 'none',
                );
                break;
            case 'httpupgrade':
            case 'http':
            case 'h2':
            case 'xhttp':
                if (!empty($cfg['path'])) {
                    $settings['path'] = $cfg['path'];
                }
                if (!empty($cfg['host'])) {
                    $settings['host'] = $cfg['host'];
                }
                if ($network === 'xhttp' && !empty($cfg['mode'])) {
                    $settings['mode'] = $cfg['mode'];
                }
                break;
            case 'tcp':
                if (!empty($cfg['type']) && $cfg['type'] === 'http') {
                    $settings['header'] = array(
                        'type'    => 'http',
                        'request' => array(
                            'headers' => array('Host' => array(!empty($cfg['host']) ? $cfg['host'] : '')),
                            'path'    => array(!empty($cfg['path']) ? $cfg['path'] : '/'),
                        ),
                    );
                }
                break;
        }
        return $settings;
    }
}
