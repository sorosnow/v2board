<?php

namespace App\Services;

use App\Utils\SubscriptionParser;
use GuzzleHttp\Client;
use Illuminate\Support\Facades\Log;

/**
 * 额外订阅（附加节点）服务
 *
 * 拉取与下发分离：refresh() 由定时任务（extra:subscribe）拉第三方并落盘，
 * merge() 在订阅请求里只读本地文件、绝不发 HTTP（用户不被拖慢，第三方挂了也不断线）。
 *
 * 存储 storage/app/extra-subscribe.json（临时文件 + rename 原子替换）；拉取失败只写
 * error 与 last_attempt_at、不动 nodes；解析不出节点也算失败；删掉的链接下次刷新清理。
 * 文件含第三方节点凭据（在 storage 下，非 web 目录）；日志里链接一律打码。
 */
class ExtraSubscriptionService
{
    /** 落盘文件名（storage/app 下） */
    const STORE_FILE = 'extra-subscribe.json';

    /** 响应体大小上限（字节） */
    const MAX_BODY_BYTES = 2097152; // 2MB

    /** 刷新间隔下限（秒） */
    const MIN_REFRESH_TTL = 30;

    /** 拉取失败后的重试间隔（秒） */
    const FAIL_RETRY_TTL = 60;

    /** 上次成功结果最长沿用（秒），见 maxStaleTtl() */
    const MAX_STALE_TTL = 604800; // 7 天

    /** 链接条数上限 */
    const MAX_URLS = 10;

    /**
     * 把附加节点合并进本站节点列表（订阅请求路径：只读本地，不发 HTTP）
     *
     * @param  array $servers
     * @return array
     */
    public function merge(array $servers)
    {
        // 附加订阅不允许影响本站节点下发
        try {
            $nodes = $this->nodes();
        } catch (\Throwable $e) {
            Log::warning('extra subscribe: read store failed - ' . $e->getMessage());
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
                // 没带名字：用 host:port 兜底（撞名加序号）
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
                continue;
            }

            $used[$name] = true;
            $node['name'] = $name;
            $added[] = $node;
        }

        if (!$added) {
            return $servers;
        }

        return array_merge($servers, $added);
    }

    /**
     * 拉取并落盘（定时任务 / 手动执行）
     *
     * @param  bool $force 忽略刷新间隔
     * @return array ['refreshed' => 成功条数, 'failed' => 失败条数, 'nodes' => 节点数, 'skipped' => 被锁跳过]
     */
    public function refresh($force = false)
    {
        $summary = array('refreshed' => 0, 'failed' => 0, 'nodes' => 0, 'skipped' => false);

        if (!(int)config('v2board.extra_subscribe_enable', 0)) {
            return $summary;
        }

        $urls = $this->urls(null, true);
        if (!$urls) {
            return $summary;
        }

        $this->ensureStoreDir();

        $lock = $this->lockStore();
        if (!$lock) {
            $summary['skipped'] = true;
            return $summary;
        }

        try {
            $store = $this->loadStore(true);
            $now = time();
            $interval = $this->refreshInterval();

            // 配置里已删除的链接：从文件里清掉
            $keep = array();
            foreach ($urls as $url) {
                $keep[md5($url)] = true;
            }
            if (!empty($store['urls']) && is_array($store['urls'])) {
                foreach (array_keys($store['urls']) as $key) {
                    if (!isset($keep[$key])) {
                        unset($store['urls'][$key]);
                    }
                }
            }

            // 该刷新哪些：没数据 / 已过刷新间隔 / 上次失败已过重试间隔
            $due = array();
            foreach ($urls as $url) {
                $key = md5($url);
                $row = isset($store['urls'][$key]) ? $store['urls'][$key] : null;
                if ($force || $this->isDue($row, $now, $interval)) {
                    $due[$url] = $key;
                }
            }

            if ($due) {
                $this->fetchInto($store, $due, $now);
                foreach ($due as $url => $key) {
                    if (empty($store['urls'][$key]['error'])) {
                        $summary['refreshed']++;
                        $summary['nodes'] += (int)$store['urls'][$key]['node_count'];
                    } else {
                        $summary['failed']++;
                    }
                }
            }

            $this->saveStore($store);
        } catch (\Throwable $e) {
            Log::warning('extra subscribe: refresh failed - ' . $e->getMessage());
        } finally {
            $this->unlockStore($lock);
        }

        return $summary;
    }

    /** 各链接状态（供命令展示） */
    public function status()
    {
        $store = $this->loadStore(true);
        $now = time();
        $rows = array();

        foreach ($this->urls(null, true) as $url) {
            $key = md5($url);
            $row = isset($store['urls'][$key]) ? $store['urls'][$key] : array();
            $lastSuccess = isset($row['last_success_at']) ? (int)$row['last_success_at'] : null;
            $rows[] = array(
                'url'             => $this->maskUrl($url),
                'node_count'      => isset($row['node_count']) ? (int)$row['node_count'] : 0,
                'last_success_at' => $lastSuccess,
                'last_attempt_at' => isset($row['last_attempt_at']) ? (int)$row['last_attempt_at'] : null,
                'error'           => isset($row['error']) ? $row['error'] : null,
                // 与 nodes() 同一套判据，否则命令行会谎报「当前下发」状态
                'serving'         => $lastSuccess !== null && $lastSuccess + $this->maxStaleTtl() >= $now,
            );
        }

        return $rows;
    }

    /* ---------- 下发路径（只读本地） ---------- */

    /** 读本地存储里的附加节点（不发任何请求） */
    private function nodes()
    {
        if (!(int)config('v2board.extra_subscribe_enable', 0)) {
            return array();
        }

        $urls = $this->urls();
        if (!$urls) {
            return array();
        }

        $store = $this->loadStore();
        $now = time();
        $nodes = array();

        foreach ($urls as $url) {
            $key = md5($url);
            if (empty($store['urls'][$key]['nodes']) || !is_array($store['urls'][$key]['nodes'])) {
                continue;
            }
            $row = $store['urls'][$key];
            $lastSuccess = (int)(isset($row['last_success_at']) ? $row['last_success_at'] : 0);
            // 上次成功太久：宁可不发，也不下发一堆早已失效的节点
            if ($lastSuccess + $this->maxStaleTtl() < $now) {
                continue;
            }
            foreach ($row['nodes'] as $node) {
                $nodes[] = $node;
            }
        }

        return $nodes;
    }

    /* ---------- 拉取路径（只在定时任务 / 手动执行时跑） ---------- */

    /** 并发拉取 due 里的链接，结果写回 $store（失败保留原 nodes） */
    private function fetchInto(&$store, $due, $now)
    {
        $client = new Client();
        $promises = array();

        foreach ($due as $url => $key) {
            // 仅允许 http/https；不通过则不请求，直接按失败记录
            if (!$this->isUrlAllowed($url)) {
                $store['urls'][$key] = $this->failRow($store, $key, $url, $now, 'url not allowed');
                continue;
            }
            try {
                $promises[$url] = $client->getAsync($url, $this->requestOptions());
            } catch (\Throwable $e) {
                // 构造请求也可能抛：记成这条失败，别让一条坏链接带崩整批
                $reason = $this->maskText($e->getMessage());
                Log::warning('extra subscribe: build request failed - ' . $this->maskUrl($url) . ' - ' . $reason);
                $store['urls'][$key] = $this->failRow($store, $key, $url, $now, $reason);
            }
        }

        // 不用 \GuzzleHttp\Promise\settle()：promises 2.0 已移除函数式 API，
        // 而 guzzle ^7.4.3 新装会解析到 2.x；逐个 wait() 不影响并发，单条失败不影响其他条
        foreach ($promises as $url => $promise) {
            $key = $due[$url];

            try {
                $body = $this->readBody($promise->wait()->getBody());
                if ($body === null) {
                    Log::warning('extra subscribe: response too large - ' . $this->maskUrl($url));
                    $store['urls'][$key] = $this->failRow($store, $key, $url, $now, 'response too large');
                    continue;
                }

                $parsed = SubscriptionParser::parse($body);
                Log::debug('extra subscribe: got ' . count($parsed['nodes']) . ' node(s), '
                    . strlen($body) . ' bytes, skipped=' . json_encode($parsed['skipped'])
                    . ' - ' . $this->maskUrl($url));

                if (!$parsed['nodes']) {
                    // 空 body / 非订阅内容：按失败处理，保留上一次成功的结果
                    $store['urls'][$key] = $this->failRow($store, $key, $url, $now, 'no nodes parsed');
                    continue;
                }

                $store['urls'][$key] = array(
                    'url'             => $url,
                    'nodes'           => $parsed['nodes'],
                    'node_count'      => count($parsed['nodes']),
                    'skipped'         => $parsed['skipped'],
                    'error'           => null,
                    'last_attempt_at' => $now,
                    'last_success_at' => $now,
                );
            } catch (\Throwable $e) {
                // Guzzle 异常消息里带完整 URL（含 token）：先整条打码再落日志
                $reason = $this->maskText($e->getMessage());
                Log::warning('extra subscribe: fetch failed - ' . $this->maskUrl($url) . ' - ' . $reason);
                $store['urls'][$key] = $this->failRow($store, $key, $url, $now, $reason);
            }
        }
    }

    /** 失败记录：保留原 nodes，只更新 error 与 last_attempt_at */
    private function failRow($store, $key, $url, $now, $error)
    {
        $old = isset($store['urls'][$key]) ? $store['urls'][$key] : array();
        return array(
            'url'             => $url,
            'nodes'           => (isset($old['nodes']) && is_array($old['nodes'])) ? $old['nodes'] : array(),
            'node_count'      => isset($old['node_count']) ? (int)$old['node_count'] : 0,
            'skipped'         => isset($old['skipped']) ? $old['skipped'] : array(),
            'error'           => (string)$error,
            'last_attempt_at' => $now,
            'last_success_at' => isset($old['last_success_at']) ? $old['last_success_at'] : null,
        );
    }

    /** 是否到了该刷新的时间 */
    private function isDue($row, $now, $interval)
    {
        if (!is_array($row)) {
            return true; // 从没拉过
        }
        $last = (int)(isset($row['last_attempt_at']) ? $row['last_attempt_at'] : 0);
        if ($last > $now) {
            return true; // 时间戳在未来：别把自己卡成永不刷新
        }
        // 失败：短间隔重试；成功：按刷新间隔
        $wait = empty($row['error']) ? $interval : min($interval, self::FAIL_RETRY_TTL);

        return $last + $wait <= $now;
    }

    /* ---------- 本地存储 ---------- */

    private function ensureStoreDir()
    {
        // storage/app 可能被清理掉：不存在则锁文件与存储文件都写不进去
        $dir = storage_path('app');
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
    }

    private function storePath()
    {
        return storage_path('app/' . self::STORE_FILE);
    }

    /** 读存储文件；不存在 / 损坏一律当空处理（只有 $fromRefresh 时才记日志，避免请求路径刷屏） */
    private function loadStore($fromRefresh = false)
    {
        $empty = array('version' => 1, 'urls' => array());
        $path = $this->storePath();
        if (!is_file($path)) {
            return $empty;
        }
        $raw = @file_get_contents($path);
        if ($raw === false || trim($raw) === '') {
            return $empty;
        }
        $data = json_decode($raw, true);
        if (!is_array($data) || !isset($data['urls']) || !is_array($data['urls'])) {
            if ($fromRefresh) {
                Log::warning('extra subscribe: store file is broken, treat as empty');
            }
            return $empty;
        }

        return $data;
    }

    /** 写存储文件：临时文件 + rename 原子替换 */
    private function saveStore($store)
    {
        $path = $this->storePath();
        // JSON_INVALID_UTF8_SUBSTITUTE：节点名可能是 GBK / 截断 UTF-8，
        // 不加这个标志 json_encode 会整体失败，一份节点都存不下来
        $json = json_encode($store, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
            | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($json === false) {
            Log::warning('extra subscribe: encode store failed');
            return false;
        }
        $tmp = $path . '.tmp';
        if (@file_put_contents($tmp, $json) === false) {
            Log::warning('extra subscribe: write store failed');
            return false;
        }
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            Log::warning('extra subscribe: replace store failed');
            return false;
        }
        // 本文件由定时任务（可能是 root）写、web 用户读，显式放开读权限
        @chmod($path, 0644);

        return true;
    }

    /** 取独占锁；拿不到（被占 / 建档失败）返回 null，原因记日志 */
    private function lockStore()
    {
        $path = $this->storePath() . '.lock';
        $fp = @fopen($path, 'c');
        if (!$fp) {
            // 建不出锁文件通常是 storage/app 权限问题，别报成「已有实例在跑」
            Log::warning('extra subscribe: cannot open lock file (check storage/app permission) - ' . $path);
            return null;
        }
        if (!@flock($fp, LOCK_EX | LOCK_NB)) {
            fclose($fp);
            Log::debug('extra subscribe: refresh skipped, another run is in progress');
            return null;
        }

        return $fp;
    }

    private function unlockStore($fp)
    {
        if (!$fp) {
            return;
        }
        @flock($fp, LOCK_UN);
        @fclose($fp);
    }

    /* ---------- 配置与请求 ---------- */

    /** 拆分配置里的链接（一行一条、去重、限流）；$logLimit 只有刷新 / status 才记「超过上限」日志 */
    private function urls($raw = null, $logLimit = false)
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
            if ($logLimit) {
                Log::warning('extra subscribe: too many urls (' . count($urls)
                    . '), only the first ' . self::MAX_URLS . ' will be used');
            }
            $urls = array_slice($urls, 0, self::MAX_URLS);
        }

        return $urls;
    }

    /**
     * 刷新间隔（秒）：配置的「缓存时间」与下限取大
     *
     * 配置键 extra_subscribe_cache_ttl 是历史遗留名字（原为 Redis 缓存 TTL），
     * 语义是「多久刷新一次」；键名不改以免动后台 UI 与线上已有配置。
     */
    private function refreshInterval()
    {
        $interval = (int)config('v2board.extra_subscribe_cache_ttl', 300);

        return $interval < self::MIN_REFRESH_TTL ? self::MIN_REFRESH_TTL : $interval;
    }

    /** 上次成功的结果最长沿用（秒）= max(MAX_STALE_TTL, 刷新间隔 × 3)；刷新间隔没有上限，取小会让节点在两次刷新之间静默消失 */
    private function maxStaleTtl()
    {
        $floor = $this->refreshInterval() * 3;

        return $floor > self::MAX_STALE_TTL ? $floor : self::MAX_STALE_TTL;
    }

    /** 仅允许 http / https */
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

    /** 请求选项（单条超时夹紧到 [3, 10]） */
    private function requestOptions()
    {
        $timeout = (int)config('v2board.extra_subscribe_timeout', 5);
        if ($timeout < 3) {
            $timeout = 3;
        }
        if ($timeout > 10) {
            $timeout = 10;
        }

        return array(
            'timeout'         => $timeout,
            'connect_timeout' => $timeout,
            // 不要加 'stream' => true：promise 收到响应头就 resolve，此时 body 还没写入流，
            // readBody() 读到空串 -> 0 节点
            'headers'         => array(
                'User-Agent' => 'v2board-extra-subscribe/1.0',
                'Accept'     => 'text/plain, */*',
            ),
        );
    }

    /** 流式读取 body，超限返回 null */
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

    /** URL 打码（丢掉 query，即订阅 token） */
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

    /** 把文本里所有 http(s) 地址打码：异常消息里的 URL 可能是跳转后的地址，只替换原始 URL 会让 token 明文进日志 */
    private function maskText($text)
    {
        return preg_replace('#https?://[^\s"\'<>()]+#i', '(url masked)', (string)$text);
    }
}
