<?php

namespace App\Protocols;

use App\Utils\Helper;

class General
{
    public $flag = 'general';
    private $servers;
    private $user;

    public function __construct($user, $servers)
    {
        $this->user = $user;
        $this->servers = $servers;
    }

    public function handle()
    {
        $uri = '';

        foreach ($this->servers as $server) {
            // 外部订阅节点使用其自身凭据，避免被本站用户 uuid 覆盖
            $uuid = isset($server['_credential']) && $server['_credential'] !== '' ? $server['_credential'] : $this->user['uuid'];
            $uri .= Helper::buildUri($uuid, $server);
        }
        return base64_encode($uri);
    }
}
