{{--
    拦截页面：被封访客在浏览器里看到的页面。
    自包含：不用面板的 shadcn 样式、不加载任何脚本、不引用外部资源。
    变量：$status（int）、$message（string）、$ip / $incident / $recordedAt（可能为 null，为 null 时不显示该行）。
    全部用 {{ }} 转义输出；不显示、也不暗示封禁何时结束。
--}}
@php
    $statusText = [403 => '禁止访问', 429 => '请求过多', 404 => '不存在'][$status] ?? '';
@endphp
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive">
<meta name="referrer" content="no-referrer">
<title>访问已被拒绝</title>
<style>
    :root { color-scheme: light dark; --bg: #f5f5f5; --card: #ffffff; --fg: #171717; --muted: #737373; --border: #e5e5e5; --accent: #dc2626; }
    @media (prefers-color-scheme: dark) {
        :root { --bg: #0a0a0a; --card: #171717; --fg: #fafafa; --muted: #a3a3a3; --border: #262626; --accent: #f87171; }
    }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 16px;
        background: var(--bg); color: var(--fg); font: 15px/1.6 ui-sans-serif, system-ui, -apple-system, "PingFang SC", "Microsoft YaHei", "Noto Sans SC", sans-serif; }
    main { width: 100%; max-width: 480px; background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 32px 28px; }
    .status { margin: 0 0 8px; font-size: 13px; font-weight: 600; color: var(--accent); letter-spacing: .02em; }
    h1 { margin: 0 0 12px; font-size: 22px; line-height: 1.3; }
    p.message { margin: 0; white-space: pre-line; overflow-wrap: anywhere; }
    dl { margin: 20px 0 0; padding: 16px 0 0; border-top: 1px solid var(--border); display: grid; grid-template-columns: auto 1fr; gap: 6px 16px; font-size: 14px; }
    dt { color: var(--muted); }
    dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-wrap: anywhere; }
</style>
</head>
<body>
<main>
    <p class="status">{{ $status }}@if ($statusText !== '') {{ $statusText }}@endif</p>
    <h1>访问已被拒绝</h1>
    <p class="message">{{ $message }}</p>
    @if (isset($ip) || isset($incident) || isset($recordedAt))
        <dl>
            @if (isset($ip))
                <dt>你的 IP</dt>
                <dd>{{ $ip }}</dd>
            @endif
            @if (isset($incident))
                <dt>事件编号</dt>
                <dd>{{ $incident }}</dd>
            @endif
            @if (isset($recordedAt))
                <dt>记录时间</dt>
                <dd>{{ $recordedAt }}</dd>
            @endif
        </dl>
    @endif
</main>
</body>
</html>
