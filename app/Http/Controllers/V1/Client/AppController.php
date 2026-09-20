<?php

namespace App\Http\Controllers\V1\Client;

use App\Http\Controllers\Controller;
use App\Services\ServerService;
use App\Services\UserService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\File;
use Symfony\Component\Yaml\Yaml;

class AppController extends Controller
{
    public function getConfig(Request $request)
    {
        $servers = [];
        $user = $request->user;
        $userService = new UserService();
        if ($userService->isAvailable($user)) {
            $serverService = new ServerService();
            $servers = $serverService->getAvailableServers($user);
        }
        $defaultConfig = base_path() . '/resources/rules/app.clash.yaml';
        $customConfig = base_path() . '/resources/rules/custom.app.clash.yaml';
        if (File::exists($customConfig)) {
            $config = Yaml::parseFile($customConfig);
        } else {
            $config = Yaml::parseFile($defaultConfig);
        }
        $proxy = [];
        $proxies = [];

        foreach ($servers as $item) {
            if ($item['type'] === 'shadowsocks'
                && in_array($item['cipher'], [
                    'aes-128-gcm',
                    'aes-192-gcm',
                    'aes-256-gcm',
                    'chacha20-ietf-poly1305'
                ])
            ) {
                array_push($proxy, \App\Protocols\Clash::buildShadowsocks($user['uuid'], $item));
                array_push($proxies, $item['name']);
            }
            if ($item['type'] === 'vmess') {
                array_push($proxy, \App\Protocols\Clash::buildVmess($user['uuid'], $item));
                array_push($proxies, $item['name']);
            }
            if ($item['type'] === 'trojan') {
                array_push($proxy, \App\Protocols\Clash::buildTrojan($user['uuid'], $item));
                array_push($proxies, $item['name']);
            }
        }

        $config['proxies'] = array_merge($config['proxies'] ? $config['proxies'] : [], $proxy);
        foreach ($config['proxy-groups'] as $k => $v) {
            $config['proxy-groups'][$k]['proxies'] = array_merge($config['proxy-groups'][$k]['proxies'], $proxies);
        }
        $yamlContent = Yaml::dump($config);
        return response($yamlContent, 200)
            ->header('Content-Type', 'text/yaml');
    }

    /**
     * 客户端版本 / 下载地址。
     *
     * 说明：上游曾为 Tidalab / Tunnelab 桌面客户端保留 UA 分支（只返回该平台
     * 的 {version, download_url}）。该客户端原作者自 2021 年后已停止维护，
     * 故移除该分支，统一返回全平台列表。
     */
    public function getVersion(Request $request)
    {
        return response([
            'data' => [
                'android_version' => config('v2board.android_version'),
                'android_download_url' => config('v2board.android_download_url'),
                'linux_version' => config('v2board.linux_version'),
                'linux_download_url' => config('v2board.linux_download_url'),
                'macos_version' => config('v2board.macos_version'),
                'macos_download_url' => config('v2board.macos_download_url'),
                'windows_version' => config('v2board.windows_version'),
                'windows_download_url' => config('v2board.windows_download_url')
            ]
        ]);
    }
}
