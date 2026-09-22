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
 *  - 按节点名去重，**本站节点优先**（重名的附加节点不下发）
 *  - 附加节点保留其**自身凭据**（`_credential`），不会被本站用户 uuid 覆盖
 *  - 拉取失败 / 未配置 / 未开启 → **静默降级**，只下发本站节点
 *    （注意：不要像 custom_subscribe_url 那样失败就置空）
 *  - 附加订阅结果是带缓存的，避免高频拉取打爆第三方
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
     * 拉取并解析附加订阅节点（带缓存）
     *
     * @return array
     */
    public function fetchNodes()
    {
        if (!(int)config('v2board.extra_subscribe_enable', 0)) {
            return array();
        }

        $url = trim((string)config('v2board.extra_subscribe_url', ''));
        if ($url === '') {
            return array();
        }

        $ttl = (int)config('v2board.extra_subscribe_cache_ttl', 300);
        if ($ttl < self::MIN_CACHE_TTL) {
            $ttl = self::MIN_CACHE_TTL;
        }

        $cacheKey = self::CACHE_KEY_PREFIX . md5($url);

        // 注意：不能用 Cache::remember —— 失败时缓存 null 会被当作 miss 反复重试
        $cached = Cache::get($cacheKey);
        if ($cached === null) {
            $body = $this->request($url);
            if ($body === null) {
                // 失败也写入缓存（空串），避免持续打第三方
                $cached = array('nodes' => array(), 'skipped' => array());
            } else {
                $parsed = SubscriptionParser::parse($body);
                $cached = array(
                    'nodes'   => $parsed['nodes'],
                    'skipped' => $parsed['skipped'],
                );
                if (!empty($parsed['skipped'])) {
                    Log::debug('extra subscribe skipped', $parsed['skipped']);
                }
            }
            Cache::put($cacheKey, $cached, $ttl);
        }

        return isset($cached['nodes']) ? $cached['nodes'] : array();
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
            Log::warning('extra subscribe: fetch failed - ' . $e->getMessage());
            return null;
        }
    }
}
