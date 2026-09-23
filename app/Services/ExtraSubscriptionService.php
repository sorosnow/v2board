<?php

namespace App\Services;

use App\Utils\SubscriptionParser;
use GuzzleHttp\Client;
use Illuminate\Support\Facades\Log;

/**
 * 额外订阅（附加节点）服务
 *
 * 架构：拉取与下发分离
 *  - refresh()：由定时任务（extra:subscribe，每分钟）拉取第三方 → 解析 → 落盘
 *  - merge()：用户订阅请求里**只读本地文件**，绝不发起 HTTP
 *    好处：用户请求不再被第三方拖慢；第三方挂掉/抖动时仍继续下发上一次成功的结果
 *
 * 存储：storage/app/extra-subscribe.json（单机文件；写入用「临时文件 + rename」保证原子，
 * 读方永远看不到写一半的内容），每条链接一份：
 *  nodes / node_count / skipped / error / last_attempt_at / last_success_at
 *  - 拉取失败只写 error 与 last_attempt_at，**不动 nodes**（旧节点继续下发）
 *  - 刷新间隔 = 后台的 extra_subscribe_cache_ttl（默认 300，下限 MIN_REFRESH_TTL=30）；
 *    该配置键名是历史遗留（原来是 Redis 缓存 TTL），语义就是「多久去刷新一次」，
 *    键名不变以免动后台与线上已有配置；拉取失败后按 FAIL_RETRY_TTL(60s) 重试
 *  - 解析不出节点的响应（空 body / 非订阅内容）同样按失败处理，避免清空已下发的节点
 *  - 上一次成功太久（默认 MAX_STALE_TTL=7 天，且不短于刷新间隔的 3 倍）就不再下发，
 *    避免长期下发一堆死节点；两者取大是为了防止「间隔比它长」时节点在两次刷新间静默消失
 *  - 配置里删掉的链接，会在下次刷新时从文件里清掉
 *
 * 安全：文件在 storage 下（非 web 目录），内容含第三方节点凭据（与配置里的链接同等级）；
 *      日志里链接一律打码。链接来自后台配置项（只有管理员能改），与本站已有的
 *      custom_subscribe_url 出站请求同一信任模型，因此不做内网 SSRF 检查，
 *      只保留 http/https 白名单（挡掉 file:// / gopher:// 之类）。
 *
 * 语法上限 PHP 8.0（composer.json 要求 ^8.0）：可用 8.0 写法，不用 8.1+ 特性。
 */
class ExtraSubscriptionService
{
    /** 落盘文件名（storage/app 下） */
    const STORE_FILE = 'extra-subscribe.json';

    /** 响应体大小上限（字节） */
    const MAX_BODY_BYTES = 2097152; // 2MB

    /** 刷新间隔下限（秒）：后台设得再小也会被抬到这里 */
    const MIN_REFRESH_TTL = 30;

    /** 拉取失败后的重试间隔（秒） */
    const FAIL_RETRY_TTL = 60;

    /** 上一次成功的结果最长沿用（秒） */
    const MAX_STALE_TTL = 604800; // 7 天

    /** 链接条数上限（超出只取前几条并记 warning） */
    const MAX_URLS = 10;

    /**
     * 每种协议（本项目自身的节点格式）必须齐备的键
     *
     * 渲染器对其中大部分字段是**无守护读取**（缺键就会 Undefined array key → Laravel 转成
     * 异常 → 整份订阅 500），所以脏存储里的节点不能只看 type/host/port。
     * 表按 SubscriptionParser 的实际输出整理（含 snake_case 与 camelCase 两套，
     * 不同渲染器读的写法不同）；tools/type-fields-audit.php 会校验它没有漂移。
     *
     * @var array
     */
    private static $nodeFields = array(
        'shadowsocks' => array('cipher'),
        'vmess'       => array('tls', 'tls_settings', 'tlsSettings', 'network', 'network_settings', 'networkSettings'),
        'vless'       => array('tls', 'tls_settings', 'tlsSettings', 'encryption', 'flow',
                               'network', 'network_settings', 'networkSettings'),
        'trojan'      => array('tls', 'tls_settings', 'tlsSettings', 'server_name', 'allow_insecure',
                               'network', 'network_settings', 'networkSettings'),
        'hysteria'    => array('version', 'insecure', 'up_mbps', 'down_mbps', 'server_name',
                               'tls_settings', 'tlsSettings'),
        'tuic'        => array('disable_sni', 'zero_rtt_handshake', 'congestion_control', 'udp_relay_mode',
                               'insecure', 'server_name', 'tls_settings', 'tlsSettings'),
        'anytls'      => array('tls', 'tls_settings', 'tlsSettings', 'insecure', 'server_name',
                               'network', 'network_settings', 'networkSettings'),
    );

    /**
     * 存在性之外的第二层：这些字段的**取值**也必须合法（只收会导致渲染器抛异常或客户端拒收的）
     *
     * - shadowsocks 的 cipher：ClashMeta / ClashVerge / Stash / Singbox **没有白名单**，会把空值或
     *   陌生值原样写进配置（客户端不认）——tools/store-value-audit.php 实测确认
     * - 2022-blake3-* 尤其不能放：它的 server key 要由 created_at 派生，而外部节点没有 created_at，
     *   上面那几个渲染器在 ss2022 分支里是无守护读取 → **整份订阅 500**
     *
     * 其余字段不进这张表：network 在渲染器侧已有 networkExpressible 逐格判定；
     * port 不做校验（既定决定，且多端口形态 `20000-30000` 是合法的）。
     *
     * @var array
     */
    private static $nodeValues = array(
        'shadowsocks' => array(
            'cipher' => array('aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305'),
        ),
    );

    /**
     * 把「额外订阅」的节点合并进本站节点列表（用户请求路径：只读本地，不发 HTTP）
     *
     * @param  array $servers 本站可用节点
     * @return array
     */
    public function merge(array $servers)
    {
        // 附加订阅不允许影响本站节点下发：整段兜住所有 Throwable（含依赖不兼容的 PHP Error）
        try {
            $nodes = $this->nodes();
            if (!$nodes) {
                return $servers;
            }

            // 已占用名字：本站节点优先
            $used = array();
            foreach ($servers as $server) {
                if (isset($server['name']) && is_scalar($server['name'])) {
                    $used[(string)$server['name']] = true;
                }
            }

            $added = array();
            foreach ($nodes as $node) {
                // 存储文件可能残留旧格式或被手改：脏节点直接丢弃。
                // type/host/port 是渲染器**无守护**读取的字段（ClashMeta/ClashVerge/Stash/Singbox
                // 共 32 处直接读 $server['host']），缺任何一个都会把整份订阅打成 500，
                // 而不是少一个节点——所以这里必须自己筛。
                if (!is_array($node)) {
                    continue;
                }
                $type = isset($node['type']) && is_scalar($node['type']) ? (string)$node['type'] : '';
                $host = isset($node['host']) && is_scalar($node['host']) ? trim((string)$node['host']) : '';
                $port = isset($node['port']) && is_scalar($node['port']) ? (string)$node['port'] : '';
                if ($type === '' || $host === '' || $port === '') {
                    continue;
                }
                // 类型必需字段：脏存储（手改 / 残留旧格式 / 解析器升级前后的存储）里的节点
                // 只看 type/host/port 不够 —— 缺协议字段会让渲染器直接抛异常
                if (!self::nodeComplete($type, $node)) {
                    continue;
                }
                $name = isset($node['name']) && is_scalar($node['name']) ? trim((string)$node['name']) : '';

                if ($name === '') {
                    // URI 没带 #名字：用 host:port 兜底（撞名加序号），别把整条链接的节点丢掉
                    $base = $host . ':' . $port;
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
        } catch (\Throwable $e) {
            // 节点名可能带地址，异常消息一律打码后再落日志
            Log::warning('extra subscribe: merge failed - ' . $this->maskText($e->getMessage()));
            return $servers;
        }
    }

    /**
     * 拉取并落盘（供定时任务 / 手动执行调用）
     *
     * @param  bool $force 忽略刷新间隔，强制全部重拉
     * @return array ['refreshed' => 成功条数, 'failed' => 失败条数, 'nodes' => 节点数,
     *                'skipped' => 是否因「已有实例在跑」而整体跳过]
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

        // storage/app 在个别部署里可能不存在：先确保目录在，
        // 否则锁文件与存储文件都写不进去，功能会静默失效
        $this->ensureStoreDir();

        // 同一时刻只允许一个实例真正拉取（定时任务与手动执行可能撞上）
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
            $cleaned = false;
            if (!empty($store['urls']) && is_array($store['urls'])) {
                foreach (array_keys($store['urls']) as $key) {
                    if (!isset($keep[$key])) {
                        unset($store['urls'][$key]);
                        $cleaned = true;
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

            // 没有到期链接、也没有需要清理的记录时不必重写文件：
            // 这条命令每分钟跑一次，无条件写会让存储文件每分钟都被无谓 rename 一次
            if ($due || $cleaned) {
                $this->saveStore($store);
            }
        } catch (\Throwable $e) {
            Log::warning('extra subscribe: refresh failed - ' . $e->getMessage());
        } finally {
            $this->unlockStore($lock);
        }

        return $summary;
    }

    /**
     * 当前各链接的状态（供命令展示）
     *
     * @return array
     */
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
                // 与 nodes() 用同一套判据（含「这条到底有没有节点」），
                // 否则「有上次成功时间、但节点是空的」会被谎报成「当前下发：是」
                'serving'         => $lastSuccess !== null && $lastSuccess + $this->maxStaleTtl() >= $now
                    && !empty($row['nodes']) && is_array($row['nodes']),
            );
        }

        return $rows;
    }

    /* ------------------------------------------------------------------
     |  下发路径（只读本地）
     * ------------------------------------------------------------------ */

    /**
     * 读取本地存储里的附加节点（不发任何请求）
     *
     * @return array
     */
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
            // 上一次成功太久之前：宁可不发，也不下发一堆早已失效的节点
            if ($lastSuccess + $this->maxStaleTtl() < $now) {
                continue;
            }
            foreach ($row['nodes'] as $node) {
                $nodes[] = $node;
            }
        }

        return $nodes;
    }

    /* ------------------------------------------------------------------
     |  拉取路径（只在定时任务 / 手动执行时跑）
     * ------------------------------------------------------------------ */

    /**
     * 并发拉取 due 里的链接，并把结果写回 $store（失败保留原 nodes）
     *
     * @param array $store 引用
     * @param array $due   url => cacheKey
     * @param int   $now
     */
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
                // 构造请求本身也可能抛（URL 形态奇怪等）：记成这条失败。
                // 否则一条坏链接会把整批（其他链接）的刷新一起带崩。
                $reason = $this->maskText($e->getMessage());
                Log::warning('extra subscribe: build request failed - ' . $this->maskUrl($url) . ' - ' . $reason);
                $store['urls'][$key] = $this->failRow($store, $key, $url, $now, $reason);
            }
        }

        // 不用 \GuzzleHttp\Promise\settle()：函数式 API 在 promises 2.0 已移除，
        // 而 guzzle ^7.4.3 新装会解析到 2.x，调用即 undefined function。
        // 逐个 wait()：请求已在同一 curl_multi 中，并发性不受影响，单条失败不影响其他条。
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
                // 无条件记录节点数：成功但 0 节点时也要有日志，否则排查是黑盒
                Log::debug('extra subscribe: got ' . count($parsed['nodes']) . ' node(s), '
                    . strlen($body) . ' bytes, skipped=' . json_encode($parsed['skipped'])
                    . ' - ' . $this->maskUrl($url));

                if (!$parsed['nodes']) {
                    // 解析不出节点（空 body / 非 URI 列表等）：按失败处理，
                    // 保留上一次成功的结果，别让一次抖动把已下发的节点清空
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
                // Guzzle 异常消息里带完整 URL（含 token）：整条消息里的 URL 一律打码后再落日志
                $reason = $this->maskText($e->getMessage());
                Log::warning('extra subscribe: fetch failed - ' . $this->maskUrl($url) . ' - ' . $reason);
                $store['urls'][$key] = $this->failRow($store, $key, $url, $now, $reason);
            }
        }
    }

    /**
     * 节点是否符合「本项目自身的协议格式」
     *
     * 三类会被丢弃：类型不在表里（本项目没有这个协议）、缺任一必需字段（渲染器会 500）、
     * 凭据为空（渲染器会退回本站用户 uuid → 发出必然连不上的节点）。
     * 第四类：字段齐全但**取值非法**（见 $nodeValues）——会下发客户端不认的配置，
     * 或让渲染器抛异常（整份订阅 500）。
     *
     * @param  string $type
     * @param  array  $node
     * @return bool
     */
    private static function nodeComplete($type, $node)
    {
        if (!isset(self::$nodeFields[$type]) || empty($node['_credential'])) {
            return false;
        }
        foreach (self::$nodeFields[$type] as $need) {
            if (!array_key_exists($need, $node)) {
                return false;
            }
        }
        if (isset(self::$nodeValues[$type])) {
            foreach (self::$nodeValues[$type] as $field => $allowed) {
                if (!in_array($node[$field], $allowed, true)) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * 构造「失败」记录：保留上一次成功的 nodes，只更新 error 与 last_attempt_at
     *
     * @return array
     */
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

    /**
     * 该条链接是否到了该刷新的时间
     *
     * @param  array|null $row
     * @param  int        $now
     * @param  int        $interval
     * @return bool
     */
    private function isDue($row, $now, $interval)
    {
        if (!is_array($row)) {
            return true; // 从没拉过
        }
        $last = (int)(isset($row['last_attempt_at']) ? $row['last_attempt_at'] : 0);
        if ($last > $now) {
            return true; // 时间戳在未来（改过服务器时间等）：别把自己卡成永不刷新
        }
        // 上次失败：短间隔重试；上次成功：按配置的刷新间隔
        $wait = empty($row['error']) ? $interval : min($interval, self::FAIL_RETRY_TTL);

        return $last + $wait <= $now;
    }

    /* ------------------------------------------------------------------
     |  本地存储
     * ------------------------------------------------------------------ */

    /**
     * 确保 storage/app 存在（个别部署里可能被清理；不存在则锁文件/存储文件都写不进去）
     */
    private function ensureStoreDir()
    {
        $dir = storage_path('app');
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
    }

    /**
     * 存储文件路径
     *
     * @return string
     */
    private function storePath()
    {
        return storage_path('app/' . self::STORE_FILE);
    }

    /**
     * 读取存储文件（不存在 / 损坏一律当空处理，不影响本站节点下发）
     *
     * @param  bool $fromRefresh 是否由刷新/查看状态触发的：
     *                           请求路径上不记日志，否则文件一损坏每个订阅请求都刷一行
     * @return array
     */
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

    /**
     * 写存储文件：先写临时文件再 rename（原子替换）
     *
     * @param  array $store
     * @return bool
     */
    private function saveStore($store)
    {
        $path = $this->storePath();
        // JSON_INVALID_UTF8_SUBSTITUTE：第三方节点名可能是 GBK / 截断的 UTF-8，
        // 不加这个标志 json_encode 会整体返回 false -> 一份节点都存不下来
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
        // 本文件由定时任务（可能是 root）写、由 web 用户读：
        // 万一写入方 umask 是 0077，会变成 0600 导致 web 读不到，这里显式放开读权限
        @chmod($path, 0644);

        return true;
    }

    /**
     * 取独占锁：拿不到返回 null（原因分两种，日志里区分开）
     *
     * @return resource|null
     */
    private function lockStore()
    {
        $path = $this->storePath() . '.lock';
        $fp = @fopen($path, 'c');
        if (!$fp) {
            // 锁文件建不出来通常是 storage/app 权限问题，不能报成「已有实例在跑」
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

    /**
     * @param resource|null $fp
     */
    private function unlockStore($fp)
    {
        if (!$fp) {
            return;
        }
        @flock($fp, LOCK_UN);
        @fclose($fp);
    }

    /* ------------------------------------------------------------------
     |  配置与请求
     * ------------------------------------------------------------------ */

    /**
     * 读取额外订阅链接配置，拆分为去重后的数组
     *
     * 一行一条（回车换行，不支持逗号）；只做拆分 / 去重 / 限流，
     * 合法性交给 isUrlAllowed()。历史槽位键 _1/_2 不再读取。
     *
     * @param  string|null $raw 不传则读当前配置
     * @param  bool        $logLimit 是否记录「超过上限」日志：请求路径上不记
     * @return array
     */
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
     * 刷新间隔（秒）：后台配置的「缓存时间」与下限取大
     *
     * 配置键 extra_subscribe_cache_ttl 是历史遗留名字，现在语义就是
     * 「多久去第三方刷新一次」；键名不改以免动后台 UI 与线上已有配置。
     *
     * @return int
     */
    private function refreshInterval()
    {
        $interval = (int)config('v2board.extra_subscribe_cache_ttl', 300);

        return $interval < self::MIN_REFRESH_TTL ? self::MIN_REFRESH_TTL : $interval;
    }

    /**
     * 上一次成功的结果最长沿用（秒）
     *
     * 取「MAX_STALE_TTL(7 天)」与「刷新间隔 × 3」中的大者：
     * 「缓存时间」字段没有上限，可能被设成比 7 天还长，
     * 此时用小者会让节点在两次刷新之间静默消失 —— 必须先有机会刷新。
     *
     * @return int
     */
    private function maxStaleTtl()
    {
        $floor = $this->refreshInterval() * 3;

        return $floor > self::MAX_STALE_TTL ? $floor : self::MAX_STALE_TTL;
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
        // 并发模式下总耗时约最慢一条；单条超时默认 5s，夹紧到 [3, 10]
        $timeout = (int)config('v2board.extra_subscribe_timeout', 5);
        if ($timeout < 3) {
            $timeout = 3;
        }
        // 上限 10s：本超时只在定时任务里等待，无需再长
        if ($timeout > 10) {
            $timeout = 10;
        }

        return array(
            'timeout'         => $timeout,
            'connect_timeout' => $timeout,
            // 不要加 'stream' => true：stream 模式下 promise 收到响应头就 resolve，
            // 异步时 body 尚未写入流，readBody() 读到空串 -> 0 节点
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

    /**
     * 把一段文本里的所有 http(s) 地址打码
     *
     * 异常消息里出现的 URL 可能是跳转后的最终地址（与请求时的原始串不同），
     * 所以不能只做 str_replace($url, ...)，否则 token 会明文进日志。
     *
     * @param  string $text
     * @return string
     */
    private function maskText($text)
    {
        return preg_replace('#https?://[^\s"\'<>()]+#i', '(url masked)', (string)$text);
    }
}
