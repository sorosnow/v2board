<?php

namespace App\Services;

use App\Utils\SubscriptionParser;
use GuzzleHttp\Client;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * 额外订阅（附加节点）服务
 *
 * 把后台「额外订阅链接」里的节点追加到本站节点列表后面下发
 * （custom_subscribe_url 是「替换」语义，两者不同）。
 *
 * 要点：
 *  - `extra_subscribe_url` 一行一条（回车换行，不支持逗号），每条独立缓存
 *  - 缓存 key = `extra_subscribe_<md5(url)>`，值是解析后的节点列表，
 *    TTL = `extra_subscribe_cache_ttl`（默认 300，最小 30）；
 *    另有防击穿占位锁 `<同上>_fetching`（TTL 60）
 *  - 保存后台配置会调 forgetCache()，故改链接 / TTL / 超时后立即生效
 *  - 按节点名去重、本站优先；附加节点保留自身 `_credential`
 *  - 拉取失败 / 未配置 / 未开启：静默降级，只下发本站节点
 *  - 仅用于「下发本站节点」的路径；custom_subscribe_url 走「替换」通道，
 *    不得调用本服务，否则异常用户仍能拿到可用的第三方节点
 *
 * 防护：Cache::add 原子占位防击穿；多条并发拉取（总耗时约最慢一条）；
 *      不用函数式 promise API（promises 2.0 已移除 settle()/all()，而
 *      guzzle ^7.4.3 新装会解析到 2.x），改为逐个 wait()；
 *      merge() 兜住所有 Throwable，附加订阅任何异常都不影响主订阅。
 *      内网段 SSRF 检查已按站长决策移除，scheme 白名单保留。
 *
 * 本项目要求 php ^7.3.0，禁用 7.4+ 语法。
 */
class ExtraSubscriptionService
{
    /** 缓存键前缀 */
    const CACHE_KEY_PREFIX = 'extra_subscribe_';

    /** 响应体大小上限（字节） */
    const MAX_BODY_BYTES = 2097152; // 2MB

    /** 缓存最短 TTL（秒） */
    const MIN_CACHE_TTL = 30;

    /** 拉取占位锁 TTL（秒）；持有者完成后主动释放，残留过期仅作崩溃兜底 */
    const FETCH_LOCK_TTL = 60;

    /** 链接条数上限（超出丢弃并记 warning） */
    const MAX_URLS = 10;

    /**
     * 把「额外订阅」的节点合并进本站节点列表
     *
     * @param  array $servers 本站可用节点（getAvailableServers 的结果）
     * @return array
     */
    public function merge(array $servers)
    {
        // 附加订阅不允许影响本站节点下发：兜住所有 Throwable（含依赖不兼容的 PHP Error）
        try {
            $nodes = $this->fetchNodes();
        } catch (\Throwable $e) {
            Log::warning('extra subscribe: merge failed - ' . $e->getMessage());
            return $servers;
        }

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
            $name = isset($node['name']) ? trim((string)$node['name']) : '';

            if ($name === '') {
                // URI 没带 #名字：用 host:port 兜底（撞名加序号），别把整条链接的节点丢掉
                $base = (isset($node['host']) ? $node['host'] : '') . ':'
                    . (isset($node['port']) ? $node['port'] : '');
                if ($base === ':') {
                    continue;
                }
                $name = $base;
                $seq = 1;
                while (isset($used[$name])) {
                    $seq++;
                    $name = $base . ' #' . $seq;
                }
            } elseif (isset($used[$name])) {
                // 有名字的：重名跳过（本站优先）
                continue;
            }

            $used[$name] = true;
            $node['name'] = $name;
            $added[] = $node;
        }

        if (!$added) {
            return $servers;
        }

        // 附加节点始终排在后面
        return array_merge($servers, $added);
    }

    /**
     * 拉取并解析附加订阅节点（多条链接各自独立缓存）
     *
     * ① 逐条读缓存；miss 的先原子占位，占位失败的本轮跳过
     * ② 所有 miss 并发拉取，各自解析后写回缓存
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

        $results = array();
        $misses = array(); // url => cacheKey

        foreach ($urls as $url) {
            // 每条独立缓存：一条挂掉不影响其他条
            $cacheKey = self::CACHE_KEY_PREFIX . md5($url);

            // 不能用 Cache::remember：失败时缓存 null 会被当成 miss 反复重试
            $cached = Cache::get($cacheKey);
            if ($cached !== null) {
                $results[] = $cached;
                continue;
            }

            // 防击穿：Cache::add 原子占位，同一时刻只有一个请求真正去拉取
            if (Cache::add($cacheKey . '_fetching', 1, self::FETCH_LOCK_TTL)) {
                $misses[$url] = $cacheKey;
            }
        }

        if ($misses) {
            $this->fetchConcurrent($misses, $ttl);

            // 回读本轮写入的缓存（含失败写入的空结果）
            foreach ($misses as $url => $cacheKey) {
                $cached = Cache::get($cacheKey);
                if ($cached !== null) {
                    $results[] = $cached;
                }
            }
        }

        $nodes = array();
        foreach ($results as $cached) {
            if (!empty($cached['nodes'])) {
                foreach ($cached['nodes'] as $node) {
                    $nodes[] = $node;
                }
            }
        }

        // 跨链接重名交给 merge() 按名去重
        return $nodes;
    }

    /**
     * 清掉额外订阅缓存（保存后台配置后调用）
     *
     * 每条链接要清两个 key：节点缓存 `extra_subscribe_<md5(url)>` 与
     * 占位锁 `<同上>_fetching`。
     *
     * ConfigController::save() 会把旧、新链接都传进来，所以正常改链接 /
     * TTL / 超时都不会留残留；只有绕过 save() 改配置（直接改 config 文件、
     * tinker、恢复备份等）时旧 URL 的条目才成为「孤儿」——读不到、不影响
     * 正确性，最多一个 TTL 后自然过期。
     *
     * @param  string|null $raw 多行链接配置；不传则读当前 config
     * @return int 清掉的链接条数
     */
    public function forgetCache($raw = null)
    {
        $urls = $this->urls($raw);

        foreach ($urls as $url) {
            $cacheKey = self::CACHE_KEY_PREFIX . md5($url);
            Cache::forget($cacheKey);
            Cache::forget($cacheKey . '_fetching');
        }

        return count($urls);
    }

    /**
     * 并发拉取 miss 链接并写回各自缓存（总耗时约最慢一条）
     *
     * 校验不通过的 URL 不发请求，直接按失败缓存空结果。
     *
     * @param array $misses url => cacheKey
     * @param int   $ttl
     */
    private function fetchConcurrent(array $misses, $ttl)
    {
        $client = new Client();
        $promises = array();
        $empty = array('nodes' => array(), 'skipped' => array());

        foreach ($misses as $url => $cacheKey) {
            // 仅允许 http/https；不通过则不请求，直接按失败缓存
            if (!$this->isUrlAllowed($url)) {
                Cache::put($cacheKey, $empty, $ttl);
                Cache::forget($cacheKey . '_fetching');
                continue;
            }
            $promises[$url] = $client->getAsync($url, $this->requestOptions());
        }

        if (!$promises) {
            return;
        }

        // 不用 \GuzzleHttp\Promise\settle()：函数式 API 在 promises 2.0 已移除，
        // 而 guzzle ^7.4.3 新装会解析到 2.x，调用即 undefined function。
        // 逐个 wait()：请求已在同一 curl_multi 中，并发性不受影响，单条失败不影响其他条。
        foreach ($promises as $url => $promise) {
            $cacheKey = $misses[$url];

            try {
                $response = $promise->wait();
                $body = $this->readBody($response->getBody());
                if ($body === null) {
                    Log::warning('extra subscribe: response too large - ' . $this->maskUrl($url));
                    Cache::put($cacheKey, $empty, $ttl);
                } else {
                    $parsed = SubscriptionParser::parse($body);
                    // 无条件记录节点数：成功但 0 节点时也要有日志，否则排查是黑盒
                    Log::debug('extra subscribe: got ' . count($parsed['nodes']) . ' node(s), '
                        . strlen($body) . ' bytes, skipped=' . json_encode($parsed['skipped'])
                        . ' - ' . $this->maskUrl($url));
                    Cache::put($cacheKey, $parsed, $ttl);
                }
            } catch (\Throwable $e) {
                // Guzzle 异常消息里带完整 URL（含 token），先打码再落日志
                $message = str_replace($url, $this->maskUrl($url), $e->getMessage());
                Log::warning('extra subscribe: fetch failed - ' . $message);
                // 失败也写缓存（空结果），避免持续打第三方
                Cache::put($cacheKey, $empty, $ttl);
            } finally {
                // 主动释放占位，异常终止时下一轮可立即重试
                Cache::forget($cacheKey . '_fetching');
            }
        }
    }

    /**
     * 读取额外订阅链接配置，拆分为去重后的数组
     *
     * 一行一条（回车换行，不支持逗号）；只做拆分 / 去重 / 限流，
     * 合法性交给 isUrlAllowed()。历史槽位键 _1/_2 不再读取。
     *
     * @param  string|null $raw 不传则读当前配置（传参用于清理旧配置的缓存）
     * @return array
     */
    private function urls($raw = null)
    {
        if ($raw === null) {
            $raw = config('v2board.extra_subscribe_url', '');
        }

        if (is_array($raw)) {
            $lines = $raw;
        } else {
            $lines = preg_split('/[\r\n]+/', (string)$raw);
        }

        $urls = array();
        foreach ($lines as $line) {
            $line = trim((string)$line);
            if ($line === '' || in_array($line, $urls, true)) {
                continue;
            }
            $urls[] = $line;
        }

        if (count($urls) > self::MAX_URLS) {
            Log::warning('extra subscribe: too many urls (' . count($urls)
                . '), only the first ' . self::MAX_URLS . ' will be used');
            $urls = array_slice($urls, 0, self::MAX_URLS);
        }

        return $urls;
    }

    /**
     * URL 校验：仅允许 http / https
     *
     * @param  string $url
     * @return bool
     */
    private function isUrlAllowed($url)
    {
        $parts = parse_url($url);
        if (!$parts || empty($parts['scheme']) || empty($parts['host'])) {
            Log::warning('extra subscribe: invalid url');
            return false;
        }
        if (!in_array(strtolower($parts['scheme']), array('http', 'https'), true)) {
            Log::warning('extra subscribe: scheme not allowed');
            return false;
        }

        return true;
    }

    /**
     * 构造请求选项
     *
     * @return array
     */
    private function requestOptions()
    {
        // 并发模式下总耗时约最慢一条；单条超时默认 5s，夹紧到 [3, 60]
        $timeout = (int)config('v2board.extra_subscribe_timeout', 5);
        if ($timeout < 3) {
            $timeout = 3;
        }
        // 上限 10s：本超时是在订阅请求里同步等待的，设太大（如 60s）会把用户这次
        // 请求拖到客户端自身超时之后 -> 客户端报「更新订阅失败」，而本站节点其实是好的
        if ($timeout > 10) {
            $timeout = 10;
        }

        return array(
            'timeout'         => $timeout,
            'connect_timeout' => $timeout,
            // 不要加 'stream' => true：stream 模式下 promise 收到响应头就 resolve，
            // 异步时 body 尚未写入流，readBody() 读到空串 -> 0 节点且空结果缓存整个 TTL
            // （表现为节点凭空消失）。代价：响应体先落 php://temp，大小上限只作用于解析。
            'headers'         => array(
                'User-Agent' => 'v2board-extra-subscribe/1.0',
                'Accept'     => 'text/plain, */*',
            ),
        );
    }

    /**
     * 流式读取响应体并限制大小（避免大文件打爆内存）
     *
     * @param  \Psr\Http\Message\StreamInterface $stream
     * @return string|null 超限时返回 null
     */
    private function readBody($stream)
    {
        $body = '';
        while (!$stream->eof()) {
            $chunk = $stream->read(8192);
            if ($chunk === '') {
                break;
            }
            $body .= $chunk;
            if (strlen($body) > self::MAX_BODY_BYTES) {
                // 由调用方记录日志（带打码地址）
                return null;
            }
        }
        return $body;
    }

    /**
     * 给 URL 打码：丢掉 query（即订阅 token）
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
}
