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
 *  - 支持**多条**链接：后台提供 2 个固定槽位（`extra_subscribe_url_1` ~ `_2`），
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
 * 运行时防护：
 *  - P0-1 缓存击穿防护：TTL 过期瞬间用 Cache::add 原子占位，同一时刻只有
 *    一个请求真正去拉取；拿不到占位的请求本轮跳过该条，等下轮命中缓存。
 *    避免 N 个用户并发穿透把上游订阅打挂。
 *  - P0-2 并发拉取：多条 miss 链接用 Guzzle async **同时**发出，总耗时 ≈
 *    最慢一条（而非 条数 × 超时 串行累加）。
 *  - ⚠️ **禁止使用函数式 promise API**（`GuzzleHttp\Promise\settle()` / `all()` 等）：
 *    该 API 在 guzzlehttp/promises **2.0 已移除**（改为 `Utils::settle()`）。
 *    本项目 composer.json 只约束 `guzzlehttp/guzzle: ^7.4.3`，新装环境会解析到
 *    promises 2.x，调用旧函数会 `Call to undefined function` 直接 500。
 *    这里改为逐个 `$promise->wait()`（所有传输已在同一个 curl_multi 中，
 *    并发性不受影响），1.x / 2.x / 3.x 均可用。
 *  - ⚠️ **附加订阅的任何异常都不得影响主订阅**：`merge()` 兜住所有 Throwable，
 *    出错就原样返回本站节点。
 *  - （SSRF 内网段检查已按站长决策移除：URL 由唯一可信的管理员配置、
 *    服务器归站长所有，该场景下无实际威胁面；scheme 白名单保留。）
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
     * 拉取占位锁 TTL（秒）：覆盖「连接+读取+解析」的最坏耗时即可，
     * 持有者完成后会主动释放（forget），残留过期仅作崩溃兜底
     */
    const FETCH_LOCK_TTL = 60;

    /**
     * 支持的附加订阅链接条数上限
     *
     * ⚠️ 这是**防御性上限**，不是后台槽位数（后台固定 2 个槽）。
     *    只有单个槽里误粘贴了逗号/换行分隔的多条链接时才可能超过 2，
     *    超过部分会被丢弃并记 warning。
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
        // ⚠️ 附加订阅只是「附加」功能：任何问题都不允许影响本站节点的正常下发。
        //    这里兜住所有 Throwable（含 PHP Error，例如依赖版本不兼容导致的
        //    「Call to undefined function」），出错就原样返回本站节点。
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
     * 流程（两阶段）：
     *   ① 逐条读缓存；miss 的链接先原子占位（P0-1），占位失败的链接本轮跳过
     *   ② 所有 miss 链接**并发**拉取（P0-2），各自解析后写回缓存
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
            // 每条链接独立缓存：一条挂掉不影响其他条，也不会反复重试
            $cacheKey = self::CACHE_KEY_PREFIX . md5($url);

            // 注意：不能用 Cache::remember —— 失败时缓存 null 会被当作 miss 反复重试
            $cached = Cache::get($cacheKey);
            if ($cached !== null) {
                $results[] = $cached;
                continue;
            }

            // P0-1 缓存击穿防护：Cache::add 是原子操作，同一时刻只有一个请求
            // 能占位成功去真正拉取；其余请求本轮跳过该条（附加节点短暂缺席，
            // 下一轮 TTL 内命中占位者写入的缓存），避免全站并发穿透打挂上游。
            if (Cache::add($cacheKey . '_fetching', 1, self::FETCH_LOCK_TTL)) {
                $misses[$url] = $cacheKey;
            }
        }

        if ($misses) {
            $this->fetchConcurrent($misses, $ttl);

            // 汇总本轮新写入的缓存（占位者含自身；失败也会写入空结果）
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

        // 多条之间的重名由 merge() 统一按名去重（先到先得）
        return $nodes;
    }

    /**
     * 并发拉取所有 miss 链接并写回各自缓存
     *
     * P0-2：所有 miss 同时发出，总耗时 ≈ 最慢一条（而非 条数 × 超时）。
     * 校验不通过的 URL 不发请求，直接按失败缓存（空结果）。
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
            // scheme 白名单校验（http/https only）；不通过不发请求，直接按失败缓存
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

        // ⚠️ 不要用 \GuzzleHttp\Promise\settle()：函数式 API 在 guzzlehttp/promises 2.0
        //    已被移除（对应 Utils::settle），而 guzzle ^7.4.3 在新装环境会解析到 2.x，
        //    会直接报「Call to undefined function」把订阅接口打挂 500。
        //    逐个 wait()：所有请求在 getAsync() 时已进入同一个 curl_multi，
        //    wait 任一 promise 都会推进全部传输，并发性不受影响；
        //    1.x / 2.x / 3.x 均可用，且单条失败不影响其他条。
        foreach ($promises as $url => $promise) {
            $cacheKey = $misses[$url];

            try {
                $response = $promise->wait();
                $body = $this->readBody($response->getBody());
                if ($body === null) {
                    Cache::put($cacheKey, $empty, $ttl);
                } else {
                    $parsed = SubscriptionParser::parse($body);
                    if (!empty($parsed['skipped'])) {
                        // 用打码后的地址，避免把订阅 token 写进日志
                        Log::debug('extra subscribe skipped: ' . $this->maskUrl($url), $parsed['skipped']);
                    }
                    Cache::put($cacheKey, $parsed, $ttl);
                }
            } catch (\Throwable $e) {
                // ⚠️ Guzzle 会把完整 URL（含订阅 token）拼进异常消息，先替换成打码地址再落日志
                $message = str_replace($url, $this->maskUrl($url), $e->getMessage());
                Log::warning('extra subscribe: fetch failed - ' . $message);
                // 失败也写入缓存（空数组），避免持续打第三方
                Cache::put($cacheKey, $empty, $ttl);
            } finally {
                // 主动释放占位：若拉取过程异常终止，也能让下一轮请求立即重试
                Cache::forget($cacheKey . '_fetching');
            }
        }
    }

    /**
     * 读取「额外订阅链接」配置（固定 5 个槽位），解析为去重后的链接数组
     *
     * 兼容旧写法：槽位里若误粘贴了多行或逗号分隔的内容，也会被拆开（幂等）。
     * 这里只做拆分/去重/限流，合法性交给 isUrlAllowed() 校验并记日志。
     *
     * @return array
     */
    private function urls()
    {
        $lines = array();
        foreach (self::URL_KEYS as $key) {
            $value = config('v2board.' . $key, '');
            if (is_array($value)) {
                foreach ($value as $item) {
                    $lines[] = (string)$item;
                }
                continue;
            }
            foreach (preg_split('/[\r\n]+/', (string)$value) as $item) {
                $lines[] = $item;
            }
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
     * 后台提供的额外订阅链接槽位（固定 2 行，与后台 UI 一一对应）
     *
     * ⚠️ 与 ConfigSave::RULES / Admin\ConfigController::fetch() 里的键名必须保持一致。
     *    历史键 extra_subscribe_url（多行字符串）已弃用，仅用于后台回显迁移，
     *    这里不再读取，避免旧值变成无法从后台清掉的「幽灵链接」。
     *    ⚠️ 已从 5 槽收紧为 2 槽：extra_subscribe_url_3 ~ _5 不再被读取，
     *       它们会留在 config/v2board.php 里但永远不生效（需手工迁移到 1/2）。
     */
    const URL_KEYS = array(
        'extra_subscribe_url_1',
        'extra_subscribe_url_2',
    );

    /**
     * URL 合法性校验：仅允许 http / https（避免 file:// 等异常 scheme）
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
        // P0-2：并发模式下总耗时 ≈ 最慢一条，单条超时默认 5s
        $timeout = (int)config('v2board.extra_subscribe_timeout', 5);
        if ($timeout < 3) {
            $timeout = 3;
        }
        if ($timeout > 60) {
            $timeout = 60;
        }

        return array(
            'timeout'         => $timeout,
            'connect_timeout' => $timeout,
            // ⚠️ 必须保留 stream：否则 Guzzle 会先把整个响应体收完再 resolve，
            //    readBody() 的 MAX_BODY_BYTES 就只能限「解析」而不能限「下载」
            //    （超大响应会先落到 php://temp / 磁盘）。
            //    并发下 stream 也是安全的：promise 在收到响应头时即 resolve。
            'stream'          => true,
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
                Log::warning('extra subscribe: response too large');
                return null;
            }
        }
        return $body;
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
}
