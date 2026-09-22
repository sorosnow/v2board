<?php

namespace App\Services;

use App\Utils\SubscriptionParser;
use GuzzleHttp\Client;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * 额外订阅（附加节点）服务
 *
 * 用途：在后台配置一个「额外订阅链接」，把它里面的节点**追加**到本站
 * 下发的节点列表后面（与 custom_subscribe_url 的「替换」语义不同）。
 *
 * 规则：
 *  - 支持**多条**链接：`extra_subscribe_url` 一行一条（也可用逗号分隔，最多 `MAX_URLS` 条），
 *    每条**独立缓存**，一条挂掉不影响其他条
 *  - 按节点名去重，**本站节点优先**（重名的附加节点不下发）
 *  - 附加节点保留其**自身凭据**（`_credential`），不会被本站用户 uuid 覆盖
 *  - 拉取失败 / 未配置 / 未开启 → **静默降级**，只下发本站节点
 *    （注意：不要像 custom_subscribe_url 那样失败就置空）
 *  - 附加订阅结果是带缓存的，避免高频拉取打爆第三方
 *  - ⚠️ 仅适用于「下发本站节点」的路径。若用户设了 custom_subscribe_url，
 *    走的是「替换」通道（原样透传第三方内容），**不得**调用本服务合并，
 *    否则异常用户仍能拿到可用的第三方节点。
 *
 * 注意：本项目 composer.json 要求 php ^7.3.0 || ^8.0，禁用 PHP 7.4+ 语法。
 */
class ExtraSubscriptionService
{
    /**
     * 缓存键前缀
     */
    const CACHE_KEY_PREFIX = 'extra_subscribe_';

    /**
     * 响应体大小上限（字节）
     */
    const MAX_BODY_BYTES = 2097152; // 2MB

    /**
     * 缓存最短 TTL（秒）
     */
    const MIN_CACHE_TTL = 30;

    /**
     * 支持的附加订阅链接条数上限
     *
     * ⚠️ 多条链接是**顺序**拉取的，最坏耗时 ≈ 条数 × 超时，
     *    所以上限不能太大，否则首次拉取会把订阅请求拖死。
     */
    const MAX_URLS = 10;

    /**
     * 把「额外订阅」的节点合并进本站节点列表
     *
     * @param  array $servers 本站可用节点（getAvailableServers 的结果）
     * @return array
     */
    public function merge(array $servers)
    {
        $nodes = $this->fetchNodes();
        if (!$nodes) {
            return $servers;
        }

        // 已占用名字：本站节点优先
        $used = array();
        foreach ($servers as $server) {
            if (isset($server['name'])) {
                $used[(string)$server['name']] = true;
            }
        }

        $added = array();
        foreach ($nodes as $node) {
            $name = isset($node['name']) ? (string)$node['name'] : '';
            // 无名节点跳过（无法参与去重，也容易与其他无名节点混淆）
            if ($name === '') {
                continue;
            }
            // 重名 → 跳过（本站优先）
            if (isset($used[$name])) {
                continue;
            }
            $used[$name] = true;
            $added[] = $node;
        }

        if (!$added) {
            return $servers;
        }

        // 附加节点永远排在后面
        return array_merge($servers, $added);
    }

    /**
     * 拉取并解析附加订阅节点（支持多条链接，各自独立缓存）
     *
     * @return array
     */
    public function fetchNodes()
    {
        if (!(int)config('v2board.extra_subscribe_enable', 0)) {
            return array();
        }

        $urls = $this->urls();
        if (!$urls) {
            return array();
        }

        $ttl = (int)config('v2board.extra_subscribe_cache_ttl', 300);
        if ($ttl < self::MIN_CACHE_TTL) {
            $ttl = self::MIN_CACHE_TTL;
        }

        $nodes = array();
        foreach ($urls as $url) {
            // 每条链接独立缓存：一条挂掉不影响其他条，也不会反复重试
            $cacheKey = self::CACHE_KEY_PREFIX . md5($url);

            // 注意：不能用 Cache::remember —— 失败时缓存 null 会被当作 miss 反复重试
            $cached = Cache::get($cacheKey);
            if ($cached === null) {
                $cached = $this->fetchOne($url);
                Cache::put($cacheKey, $cached, $ttl);
            }

            if (!empty($cached['nodes'])) {
                foreach ($cached['nodes'] as $node) {
                    $nodes[] = $node;
                }
            }
        }

        // 多条之间的重名由 merge() 统一按名去重（先到先得）
        return $nodes;
    }

    /**
     * 拉取并解析**单条**附加订阅链接
     *
     * @param  string $url
     * @return array ['nodes' => [], 'skipped' => []]
     */
    private function fetchOne($url)
    {
        $body = $this->request($url);
        if ($body === null) {
            // 失败也写入缓存（空数组），避免持续打第三方
            return array('nodes' => array(), 'skipped' => array());
        }

        $parsed = SubscriptionParser::parse($body);
        if (!empty($parsed['skipped'])) {
            // 用打码后的地址，避免把订阅 token 写进日志
            Log::debug('extra subscribe skipped: ' . $this->maskUrl($url), $parsed['skipped']);
        }

        return array(
            'nodes'   => $parsed['nodes'],
            'skipped' => $parsed['skipped'],
        );
    }

    /**
     * 读取「额外订阅链接」配置，解析为去重后的链接数组
     *
     * 支持三种写法：
     *  - 多行（一行一条，推荐）
     *  - 一行内用**逗号**并列多条（兼容历史习惯，见 splitByComma）
     *  - 旧的单条写法（无分隔符）
     *
     * 这里只做拆分/去重/限流，合法性交给 request() 校验并记日志。
     *
     * @return array
     */
    private function urls()
    {
        $raw = config('v2board.extra_subscribe_url', '');

        if (is_array($raw)) {
            $lines = $raw;
        } else {
            $lines = preg_split('/[\r\n]+/', (string)$raw);
        }

        $urls = array();
        foreach ($lines as $line) {
            foreach ($this->splitByComma($line) as $url) {
                $url = trim((string)$url);
                if ($url === '' || in_array($url, $urls, true)) {
                    continue;
                }
                $urls[] = $url;
            }
        }

        if (count($urls) > self::MAX_URLS) {
            Log::warning('extra subscribe: too many urls (' . count($urls)
                . '), only the first ' . self::MAX_URLS . ' will be used');
            $urls = array_slice($urls, 0, self::MAX_URLS);
        }

        return $urls;
    }

    /**
     * 拆分行内用逗号并列的多条链接
     *
     * ⚠️ 只有当按逗号拆开后**每一段**都以 http(s):// 开头时才拆，
     *    否则原样返回。这样既能兼容「一行逗号并列多条」的习惯写法，
     *    又不会误伤 query 里本来就含逗号的链接（如 ?flag=clash,yaml）。
     *
     * @param  string $line
     * @return array
     */
    private function splitByComma($line)
    {
        $line = trim((string)$line);
        if ($line === '' || strpos($line, ',') === false) {
            return array($line);
        }

        $parts = array();
        foreach (explode(',', $line) as $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }
            // 出现非链接片段 → 认为逗号属于 URL 本身，整体保留
            if (!preg_match('#^https?://#i', $part)) {
                return array($line);
            }
            $parts[] = $part;
        }

        return count($parts) > 1 ? $parts : array($line);
    }

    /**
     * 给 URL 打码（只保留 scheme/host/port/path，丢掉 query，即订阅 token）
     *
     * @param  string $url
     * @return string
     */
    private function maskUrl($url)
    {
        $parts = parse_url($url);
        if (!$parts || empty($parts['host'])) {
            return '(invalid url)';
        }

        $masked = (empty($parts['scheme']) ? 'http' : $parts['scheme']) . '://' . $parts['host'];
        if (!empty($parts['port'])) {
            $masked .= ':' . $parts['port'];
        }
        if (!empty($parts['path'])) {
            $masked .= $parts['path'];
        }

        return $masked;
    }

    /**
     * 请求附加订阅地址
     *
     * @param  string $url
     * @return string|null 失败返回 null
     */
    private function request($url)
    {
        // 仅允许 http / https，避免 file:// 等异常 scheme
        $parts = parse_url($url);
        if (!$parts || empty($parts['scheme']) || empty($parts['host'])) {
            Log::warning('extra subscribe: invalid url');
            return null;
        }
        if (!in_array(strtolower($parts['scheme']), array('http', 'https'), true)) {
            Log::warning('extra subscribe: scheme not allowed');
            return null;
        }

        $timeout = (int)config('v2board.extra_subscribe_timeout', 10);
        if ($timeout < 3) {
            $timeout = 3;
        }
        if ($timeout > 60) {
            $timeout = 60;
        }

        try {
            $client = new Client();
            $response = $client->get($url, array(
                'timeout'         => $timeout,
                'connect_timeout' => $timeout,
                'stream'          => true,
                'headers'         => array(
                    'User-Agent' => 'v2board-extra-subscribe/1.0',
                    'Accept'     => 'text/plain, */*',
                ),
            ));

            // 流式读取并限制大小，避免大文件打爆内存
            $stream = $response->getBody();
            $body = '';
            while (!$stream->eof()) {
                $chunk = $stream->read(8192);
                if ($chunk === '') {
                    break;
                }
                $body .= $chunk;
                if (strlen($body) > self::MAX_BODY_BYTES) {
                    Log::warning('extra subscribe: response too large');
                    return null;
                }
            }
            return $body;
        } catch (\Exception $e) {
            // ⚠️ Guzzle 会把完整 URL（含订阅 token）拼进异常消息，先替换成打码地址再落日志
            $message = str_replace($url, $this->maskUrl($url), $e->getMessage());
            Log::warning('extra subscribe: fetch failed - ' . $message);
            return null;
        }
    }
}
