<?php

/*
 * 测试用的 TCP 转发器：在客户端与 Redis 之间转发字节，并数「往返」。
 *
 * 往返的定义：客户端发来数据时，如果它此前没有在等回复（刚连上，或上一次的回复已经
 * 转发给它），就算一次新的往返。一个管道无论拆成几个 TCP 包，在收到回复之前都只算一次。
 *
 * 用法：php redis-proxy.php <Redis 主机> <Redis 端口> <计数文件>
 * 监听 127.0.0.1 上由系统分配的空闲端口。
 * 计数文件内容："<往返数> <累计连接数> <监听端口>"，每次变化都重写，先写文件再转发。
 */

[, $host, $targetPort, $file] = $argv;

$server = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);

if (! $server) {
    fwrite(STDERR, "listen failed: {$error}\n");
    exit(1);
}

$port = (int) substr(strrchr(stream_socket_get_name($server, false), ':'), 1);
$trips = 0;
$connections = 0;
$pairs = [];

$report = function () use (&$trips, &$connections, $port, $file) {
    file_put_contents($file.'.tmp', "{$trips} {$connections} {$port}");
    rename($file.'.tmp', $file);
};

$report();

while (true) {
    $read = [$server];

    foreach ($pairs as $pair) {
        $read[] = $pair['client'];
        $read[] = $pair['upstream'];
    }

    $write = $except = null;

    if (stream_select($read, $write, $except, null) === false) {
        break;
    }

    foreach ($read as $stream) {
        if ($stream === $server) {
            $client = stream_socket_accept($server);
            $upstream = stream_socket_client("tcp://{$host}:{$targetPort}");
            $pairs[(int) $client] = ['client' => $client, 'upstream' => $upstream, 'awaiting' => false];
            $connections++;
            $report();

            continue;
        }

        foreach ($pairs as $id => $pair) {
            $fromClient = $stream === $pair['client'];

            if (! $fromClient && $stream !== $pair['upstream']) {
                continue;
            }

            $data = fread($stream, 65536);

            if ($data === '' || $data === false) {
                fclose($pair['client']);
                fclose($pair['upstream']);
                unset($pairs[$id]);

                break;
            }

            if ($fromClient) {
                if (! $pair['awaiting']) {
                    $pairs[$id]['awaiting'] = true;
                    $trips++;
                    $report();
                }

                fwrite($pair['upstream'], $data);
            } else {
                $pairs[$id]['awaiting'] = false;
                fwrite($pair['client'], $data);
            }

            break;
        }
    }
}
