<?php

namespace App\Utils;

use Symfony\Component\Yaml\Yaml;

/**
 * 订阅内容解析器（附加订阅）
 *
 * 支持两种输入格式：
 *  ① base64 编码或明文的 URI 列表（ss:// / vmess:// / vless:// / …）
 *  ② Clash / Mihomo YAML 配置（取其中的 proxies: 数组）
 * 解析结果统一转为 v2board 内部节点结构，以复用现有 Protocol 渲染器下发。
 *
 * ⚠️ 关键设计：解析出的每个节点都带 `_credential` 字段。
 *    外部节点认证的是第三方自己的凭据（uuid/密码），**不能**被本站
 *    当前用户的 uuid 覆盖，否则节点必然连不上。
 *    渲染器侧会优先读取该字段（见各 Protocol 类）。
 *
 * ⚠️ ss-2022 节点会被主动跳过：其 server key 需由节点 created_at 派生
 *    （Helper::getServerKey），第三方节点的 created_at 无法获知，强行
 *    下发只会产出连不上的节点。
 *
 * 注意：本项目 composer.json 要求 php ^7.3.0 || ^8.0，
 *      禁用 PHP 7.4+ 语法（箭头函数 / 类型化属性 / ??= / 构造器属性提升）。
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

        $raw = trim((string)$raw);
        if ($raw === '') {
            return array('nodes' => array(), 'skipped' => array());
        }

        // Clash / Mihomo YAML 配置（如 mihomo.yaml / clash.yaml）
        if (self::looksLikeClashYaml($raw)) {
            return self::parseClashYaml($raw);
        }

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
     * ss://
     * 支持 SIP002（base64(method:password)@host:port?plugin=...#name）
     * 与老式（base64(method:password@host:port)#name）
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

        $decoded = self::b64($userinfo);
        if ($decoded === null || strpos($decoded, ':') === false) {
            self::skip('ss_bad_userinfo');
            return null;
        }
        $colon = strpos($decoded, ':');
        $cipher = substr($decoded, 0, $colon);
        $credential = substr($decoded, $colon + 1);

        if (strpos($cipher, '2022-blake3') !== false) {
            self::skip('ss_2022_unsupported');
            return null;
        }

        $hp = self::splitHostPort($hostport);
        if ($hp === null) {
            self::skip('ss_bad_host_port');
            return null;
        }

        $node = self::base('shadowsocks', $name, $hp[0], $hp[1], $credential);
        $node['cipher'] = $cipher;

        if (!empty($query['plugin']) && strpos($query['plugin'], 'obfs') !== false) {
            $opts = self::parsePluginOpts($query['plugin']);
            if (isset($opts['obfs']) && $opts['obfs'] === 'http') {
                $node['obfs'] = 'http';
                $node['obfs-host'] = isset($opts['obfs-host']) ? $opts['obfs-host'] : '';
                $node['obfs-path'] = isset($opts['path']) ? $opts['path'] : '';
            }
        }

        return $node;
    }

    /**
     * vmess://base64(json)
     *
     * @param  string $uri
     * @return array|null
     */
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

        $sni = isset($cfg['sni']) ? $cfg['sni'] : (isset($cfg['host']) ? $cfg['host'] : '');
        $insecure = isset($cfg['allowInsecure']) ? (int)$cfg['allowInsecure'] : 0;
        // ⚠️ vmess 的 ClashMeta::buildVmess() 只读 camelCase，故两套键名都写
        $tlsSettings = array(
            'server_name'    => $sni,
            'serverName'     => $sni,
            'allow_insecure' => $insecure,
            'allowInsecure'  => $insecure,
        );
        $network = !empty($cfg['net']) ? $cfg['net'] : 'tcp';
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
        if (!empty($query['pbk'])) {
            $tlsSettings['public_key'] = $query['pbk'];
        }
        if (!empty($query['sid'])) {
            $tlsSettings['short_id'] = $query['sid'];
        }

        $network = !empty($query['type']) ? $query['type'] : 'tcp';
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

        $network = !empty($query['type']) ? $query['type'] : 'tcp';
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
     * hysteria://  （v1）
     * hysteria2:// / hy2:// （v2）
     *
     * 两者统一映射为 type='hysteria' + version，与本站 ServerHysteria 模型一致，
     * 这样 Surge / Loon（判断 version===2）与 Clash 系（buildHysteria）都能渲染。
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
        $node['up_mbps'] = isset($query['upmbps']) ? (int)$query['upmbps'] : 0;
        $node['down_mbps'] = isset($query['downmbps']) ? (int)$query['downmbps'] : 0;
        $node['server_key'] = '';
        if (!empty($query['obfs'])) {
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
        if (!empty($query['pbk'])) {
            $tlsSettings['public_key'] = $query['pbk'];
        }
        if (!empty($query['sid'])) {
            $tlsSettings['short_id'] = $query['sid'];
        }

        $network = !empty($query['type']) ? $query['type'] : 'tcp';
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
     |  Clash / Mihomo YAML
     * ------------------------------------------------------------------ */

    /**
     * 判断是否为 Clash / Mihomo YAML 配置
     *
     * @param  string $raw
     * @return bool
     */
    private static function looksLikeClashYaml($raw)
    {
        return (bool)preg_match('/^[ \t]*(proxies|proxy-providers|proxy-groups)[ \t]*:/m', $raw);
    }

    /**
     * 解析 Clash / Mihomo YAML 配置中的 proxies
     *
     * @param  string $raw
     * @return array ['nodes' => 节点数组, 'skipped' => [原因 => 条数]]
     */
    private static function parseClashYaml($raw)
    {
        try {
            $data = Yaml::parse($raw);
        } catch (\Throwable $e) {
            // 兜住 Throwable：坏 YAML 只能是「解析失败」，绝不能把异常抛到订阅请求里
            self::skip('clash_yaml_parse_failed');
            return array('nodes' => array(), 'skipped' => self::$skipped);
        }

        if (!is_array($data) || empty($data['proxies']) || !is_array($data['proxies'])) {
            self::skip('clash_yaml_no_proxies');
            return array('nodes' => array(), 'skipped' => self::$skipped);
        }

        $nodes = array();
        foreach ($data['proxies'] as $proxy) {
            if (!is_array($proxy)) {
                self::skip('clash_bad_entry');
                continue;
            }
            $node = self::clashProxyToNode($proxy);
            if ($node !== null) {
                $nodes[] = $node;
            }
        }

        return array('nodes' => $nodes, 'skipped' => self::$skipped);
    }

    /**
     * 单个 Clash proxy 对象 → v2board 内部节点
     *
     * @param  array $p
     * @return array|null
     */
    private static function clashProxyToNode($p)
    {
        $type = isset($p['type']) ? strtolower(trim((string)$p['type'])) : '';
        $name = isset($p['name']) ? (string)$p['name'] : '';

        if (empty($p['server']) || empty($p['port'])) {
            self::skip('clash_no_server_or_port');
            return null;
        }
        $host = (string)$p['server'];
        $port = $p['port'];

        switch ($type) {
            case 'ss':
                return self::clashShadowsocks($p, $name, $host, $port);
            case 'vmess':
                return self::clashVmess($p, $name, $host, $port);
            case 'vless':
                return self::clashVless($p, $name, $host, $port);
            case 'trojan':
                return self::clashTrojan($p, $name, $host, $port);
            case 'hysteria':
            case 'hysteria2':
                return self::clashHysteria($p, $name, $host, $port, $type);
            case 'tuic':
                return self::clashTuic($p, $name, $host, $port);
            case 'anytls':
                return self::clashAnyTls($p, $name, $host, $port);
            default:
                // http / socks5 / ssr / snell / wireguard 等 v2board 无对应节点类型
                self::skip('clash_unsupported_type:' . $type);
                return null;
        }
    }

    /**
     * Clash ss → shadowsocks
     *
     * @param  array  $p
     * @param  string $name
     * @param  string $host
     * @param  mixed  $port
     * @return array|null
     */
    private static function clashShadowsocks($p, $name, $host, $port)
    {
        $cipher = isset($p['cipher']) ? (string)$p['cipher'] : '';
        if ($cipher === '' || empty($p['password'])) {
            self::skip('clash_ss_no_cipher_or_password');
            return null;
        }
        if (strpos($cipher, '2022-blake3') !== false) {
            self::skip('ss_2022_unsupported');
            return null;
        }

        $node = self::base('shadowsocks', $name, $host, $port, (string)$p['password']);
        $node['cipher'] = $cipher;

        if (!empty($p['plugin'])) {
            $opts = (isset($p['plugin-opts']) && is_array($p['plugin-opts'])) ? $p['plugin-opts'] : array();
            if (strpos((string)$p['plugin'], 'obfs') !== false
                && isset($opts['mode']) && $opts['mode'] === 'http'
            ) {
                $node['obfs'] = 'http';
                $node['obfs-host'] = isset($opts['host']) ? (string)$opts['host'] : '';
                $node['obfs-path'] = isset($opts['path']) ? (string)$opts['path'] : '';
            }
        }

        return $node;
    }

    /**
     * Clash vmess → vmess
     *
     * @param  array  $p
     * @param  string $name
     * @param  string $host
     * @param  mixed  $port
     * @return array|null
     */
    private static function clashVmess($p, $name, $host, $port)
    {
        $uuid = isset($p['uuid']) ? (string)$p['uuid'] : '';
        if ($uuid === '') {
            self::skip('clash_vmess_no_uuid');
            return null;
        }

        $network = !empty($p['network']) ? (string)$p['network'] : 'tcp';
        $tlsSettings = self::clashTlsSettings($p);
        $networkSettings = self::clashNetworkSettings($p, $network);

        $node = self::base('vmess', $name, $host, $port, $uuid);
        $node['tls'] = !empty($p['tls']) ? 1 : 0;
        $node['tls_settings'] = $tlsSettings;
        $node['tlsSettings'] = $tlsSettings;
        $node['network'] = $network;
        $node['network_settings'] = $networkSettings;
        $node['networkSettings'] = $networkSettings;

        return $node;
    }

    /**
     * Clash vless → vless
     *
     * @param  array  $p
     * @param  string $name
     * @param  string $host
     * @param  mixed  $port
     * @return array|null
     */
    private static function clashVless($p, $name, $host, $port)
    {
        $uuid = isset($p['uuid']) ? (string)$p['uuid'] : '';
        if ($uuid === '') {
            self::skip('clash_vless_no_uuid');
            return null;
        }

        $network = !empty($p['network']) ? (string)$p['network'] : 'tcp';
        $tlsSettings = self::clashTlsSettings($p);
        $networkSettings = self::clashNetworkSettings($p, $network);

        // reality 用 tls=2 表达（与本站 ServerVless 约定一致）
        $tls = 0;
        if (!empty($p['reality-opts'])) {
            $tls = 2;
        } elseif (!empty($p['tls'])) {
            $tls = 1;
        }

        $node = self::base('vless', $name, $host, $port, $uuid);
        $node['tls'] = $tls;
        $node['tls_settings'] = $tlsSettings;
        $node['tlsSettings'] = $tlsSettings;
        $node['flow'] = isset($p['flow']) ? (string)$p['flow'] : '';
        $node['encryption'] = 'none';
        $node['network'] = $network;
        $node['network_settings'] = $networkSettings;
        $node['networkSettings'] = $networkSettings;

        return $node;
    }

    /**
     * Clash trojan → trojan
     *
     * @param  array  $p
     * @param  string $name
     * @param  string $host
     * @param  mixed  $port
     * @return array|null
     */
    private static function clashTrojan($p, $name, $host, $port)
    {
        $password = isset($p['password']) ? (string)$p['password'] : '';
        if ($password === '') {
            self::skip('clash_trojan_no_password');
            return null;
        }

        $network = !empty($p['network']) ? (string)$p['network'] : 'tcp';
        $tlsSettings = self::clashTlsSettings($p);
        $networkSettings = self::clashNetworkSettings($p, $network);

        $node = self::base('trojan', $name, $host, $port, $password);
        $node['tls'] = 1;
        $node['tls_settings'] = $tlsSettings;
        $node['tlsSettings'] = $tlsSettings;
        $node['server_name'] = $tlsSettings['server_name'];
        $node['allow_insecure'] = $tlsSettings['allow_insecure'];
        $node['network'] = $network;
        $node['network_settings'] = $networkSettings;
        $node['networkSettings'] = $networkSettings;

        return $node;
    }

    /**
     * Clash hysteria / hysteria2 → hysteria（用 version 区分，与本站模型一致）
     *
     * @param  array  $p
     * @param  string $name
     * @param  string $host
     * @param  mixed  $port
     * @param  string $type
     * @return array|null
     */
    private static function clashHysteria($p, $name, $host, $port, $type)
    {
        $isV2 = ($type === 'hysteria2');

        if ($isV2) {
            $credential = isset($p['password']) ? (string)$p['password'] : '';
        } else {
            $credential = '';
            foreach (array('auth-str', 'auth_str', 'auth') as $key) {
                if (!empty($p[$key])) {
                    $credential = (string)$p[$key];
                    break;
                }
            }
        }
        if ($credential === '') {
            self::skip('clash_hysteria_no_credential');
            return null;
        }

        $tlsSettings = self::clashTlsSettings($p);

        $node = self::base('hysteria', $name, $host, $port, $credential);
        $node['version'] = $isV2 ? 2 : 1;
        $node['server_name'] = $tlsSettings['server_name'];
        $node['insecure'] = $tlsSettings['allow_insecure'];
        $node['tls_settings'] = $tlsSettings;
        $node['tlsSettings'] = $tlsSettings;
        $node['up_mbps'] = self::intOrZero(isset($p['up']) ? $p['up'] : null);
        $node['down_mbps'] = self::intOrZero(isset($p['down']) ? $p['down'] : null);
        $node['server_key'] = '';
        if (!empty($p['obfs'])) {
            $node['obfs'] = (string)$p['obfs'];
            $node['obfs_password'] = isset($p['obfs-password']) ? (string)$p['obfs-password'] : '';
        }

        return $node;
    }

    /**
     * Clash tuic → tuic
     *
     * @param  array  $p
     * @param  string $name
     * @param  string $host
     * @param  mixed  $port
     * @return array|null
     */
    private static function clashTuic($p, $name, $host, $port)
    {
        $uuid = isset($p['uuid']) ? (string)$p['uuid'] : '';
        if ($uuid === '') {
            self::skip('clash_tuic_no_uuid');
            return null;
        }

        $tlsSettings = self::clashTlsSettings($p);

        $node = self::base('tuic', $name, $host, $port, $uuid);
        $node['server_name'] = $tlsSettings['server_name'];
        $node['insecure'] = $tlsSettings['allow_insecure'];
        $node['disable_sni'] = !empty($p['disable-sni']) ? 1 : 0;
        // ClashMeta::buildTuic() 直接读 $server['zero_rtt_handshake']（无 ??），必须显式赋值
        $node['zero_rtt_handshake'] = !empty($p['reduce-rtt']) ? 1 : 0;
        $node['udp_relay_mode'] = isset($p['udp-relay-mode']) ? (string)$p['udp-relay-mode'] : 'native';
        $node['congestion_control'] = isset($p['congestion-controller'])
            ? (string)$p['congestion-controller'] : 'bbr';
        $node['tls_settings'] = $tlsSettings;
        $node['tlsSettings'] = $tlsSettings;

        return $node;
    }

    /**
     * Clash anytls → anytls
     *
     * @param  array  $p
     * @param  string $name
     * @param  string $host
     * @param  mixed  $port
     * @return array|null
     */
    private static function clashAnyTls($p, $name, $host, $port)
    {
        $password = isset($p['password']) ? (string)$p['password'] : '';
        if ($password === '') {
            self::skip('clash_anytls_no_password');
            return null;
        }

        $network = !empty($p['network']) ? (string)$p['network'] : 'tcp';
        $tlsSettings = self::clashTlsSettings($p);
        $networkSettings = self::clashNetworkSettings($p, $network);

        $node = self::base('anytls', $name, $host, $port, $password);
        $node['tls'] = 1;
        $node['server_name'] = $tlsSettings['server_name'];
        $node['insecure'] = $tlsSettings['allow_insecure'];
        $node['tls_settings'] = $tlsSettings;
        $node['tlsSettings'] = $tlsSettings;
        $node['network'] = $network;
        $node['network_settings'] = $networkSettings;
        $node['networkSettings'] = $networkSettings;

        return $node;
    }

    /**
     * Clash proxy → tls_settings
     *
     * @param  array $p
     * @return array
     */
    private static function clashTlsSettings($p)
    {
        $sni = '';
        if (!empty($p['servername'])) {
            $sni = (string)$p['servername'];
        } elseif (!empty($p['sni'])) {
            $sni = (string)$p['sni'];
        }

        $insecure = !empty($p['skip-cert-verify']) ? 1 : 0;

        // ⚠️ 同时写 snake_case 与 camelCase：
        //    vless/trojan/tuic 渲染器读 server_name / allow_insecure，
        //    而 ClashMeta::buildVmess() 只认 serverName / allowInsecure。
        $settings = array(
            'server_name'    => $sni,
            'serverName'     => $sni,
            'allow_insecure' => $insecure,
            'allowInsecure'  => $insecure,
        );
        if (!empty($p['client-fingerprint'])) {
            $settings['fingerprint'] = (string)$p['client-fingerprint'];
        }
        if (!empty($p['reality-opts']) && is_array($p['reality-opts'])) {
            if (!empty($p['reality-opts']['public-key'])) {
                $settings['public_key'] = (string)$p['reality-opts']['public-key'];
            }
            if (!empty($p['reality-opts']['short-id'])) {
                $settings['short_id'] = (string)$p['reality-opts']['short-id'];
            }
        }

        return $settings;
    }

    /**
     * Clash proxy → network_settings
     *
     * @param  array  $p
     * @param  string $network
     * @return array
     */
    private static function clashNetworkSettings($p, $network)
    {
        $settings = array();
        switch ($network) {
            case 'ws':
                if (!empty($p['ws-opts']) && is_array($p['ws-opts'])) {
                    if (!empty($p['ws-opts']['path'])) {
                        $settings['path'] = (string)$p['ws-opts']['path'];
                    }
                    if (!empty($p['ws-opts']['headers']['Host'])) {
                        $settings['headers'] = array('Host' => (string)$p['ws-opts']['headers']['Host']);
                    }
                }
                break;
            case 'grpc':
                if (!empty($p['grpc-opts']['grpc-service-name'])) {
                    $settings['serviceName'] = (string)$p['grpc-opts']['grpc-service-name'];
                }
                break;
            case 'httpupgrade':
                if (!empty($p['httpupgrade-opts']['path'])) {
                    $settings['path'] = (string)$p['httpupgrade-opts']['path'];
                }
                if (!empty($p['httpupgrade-opts']['host'])) {
                    $settings['host'] = (string)$p['httpupgrade-opts']['host'];
                }
                break;
            case 'xhttp':
                if (!empty($p['xhttp-opts']['path'])) {
                    $settings['path'] = (string)$p['xhttp-opts']['path'];
                }
                if (!empty($p['xhttp-opts']['host'])) {
                    $settings['host'] = (string)$p['xhttp-opts']['host'];
                }
                if (!empty($p['xhttp-opts']['mode'])) {
                    $settings['mode'] = (string)$p['xhttp-opts']['mode'];
                }
                break;
            case 'http':
            case 'h2':
                $path = null;
                if (!empty($p['http-opts']['path'])) {
                    $path = $p['http-opts']['path'];
                } elseif (!empty($p['h2-opts']['path'])) {
                    $path = $p['h2-opts']['path'];
                }
                if ($path !== null) {
                    $settings['path'] = is_array($path) ? (string)reset($path) : (string)$path;
                }
                $host = null;
                if (!empty($p['http-opts']['headers']['Host'])) {
                    $host = $p['http-opts']['headers']['Host'];
                } elseif (!empty($p['h2-opts']['host'])) {
                    $host = $p['h2-opts']['host'];
                }
                if ($host !== null) {
                    $settings['headers'] = array(
                        'Host' => is_array($host) ? (string)reset($host) : (string)$host,
                    );
                }
                break;
        }
        return $settings;
    }

    /**
     * 数值归一（Clash 里 up/down 可能是空串）
     *
     * @param  mixed $value
     * @return int
     */
    private static function intOrZero($value)
    {
        return is_numeric($value) ? (int)$value : 0;
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
        $now = time();

        $node = array(
            'type'       => $type,
            'name'       => $name,
            'host'       => trim($host),
            // id 固定 0：外部节点不参与 ETag / SIP008 的 id 语义
            'id'         => 0,
            'created_at' => $now,
            'updated_at' => $now,
            'is_online'  => 1,
            'cache_key'  => 'extra-' . $type . '-' . md5($host . ':' . $port . '#' . $name),
            // 渲染器优先读取该字段作为节点凭据
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
                if (!empty($cfg['path'])) {
                    $settings['path'] = $cfg['path'];
                }
                if (!empty($cfg['host'])) {
                    $settings['host'] = $cfg['host'];
                }
                break;
            case 'xhttp':
                if (!empty($cfg['path'])) {
                    $settings['path'] = $cfg['path'];
                }
                if (!empty($cfg['host'])) {
                    $settings['host'] = $cfg['host'];
                }
                if (!empty($cfg['mode'])) {
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
