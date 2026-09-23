<?php

namespace App\Protocols;

class Shadowsocks
{
    public $flag = 'shadowsocks';
    private $servers;
    private $user;

    public function __construct($user, $servers)
    {
        $this->user = $user;
        $this->servers = $servers;
    }

    public function handle()
    {
        $servers = $this->servers;
        $user = $this->user;

        // 本站凭据只取一次：外部节点的 _credential 只写局部变量，
        // 不能写 $user['uuid'] —— $this->user 是共享的 Eloquent 模型
        $defaultUuid = $this->user['uuid'];

        $configs = [];
        $subs = [];
        $subs['servers'] = [];
        $subs['bytes_used'] = '';
        $subs['bytes_remaining'] = '';

        $bytesUsed = $user['u'] + $user['d'];
        $bytesRemaining = $user['transfer_enable'] - $bytesUsed;

        foreach ($servers as $item) {
            // 外部订阅节点使用其自身凭据；只写局部变量，不要写 $user['uuid']（那是共享的 Eloquent 模型）
            $uuid = isset($item['_credential']) && $item['_credential'] !== '' ? $item['_credential'] : $defaultUuid;
            if ($item['type'] === 'shadowsocks'
                && in_array($item['cipher'], ['aes-128-gcm', 'aes-256-gcm', 'aes-192-gcm', 'chacha20-ietf-poly1305'])
            ) {
                array_push($configs, self::SIP008($item, $uuid));
            }
        }

        $subs['version'] = 1;
        $subs['bytes_used'] = $bytesUsed;
        $subs['bytes_remaining'] = $bytesRemaining;
        $subs['servers'] = array_merge($subs['servers'] ? $subs['servers'] : [], $configs);

        return json_encode($subs, JSON_UNESCAPED_SLASHES|JSON_PRETTY_PRINT);
    }

    public static function SIP008($server, $uuid)
    {
        $config = [
            "id" => $server['id'],
            "remarks" => $server['name'],
            "server" => $server['host'],
            "server_port" => $server['port'],
            "password" => $uuid,
            "method" => $server['cipher']
        ];
        return $config;
    }
}
