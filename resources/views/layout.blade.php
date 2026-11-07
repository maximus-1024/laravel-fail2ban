<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <meta name="robots" content="noindex, nofollow">

    <title>异常访问封禁{{ config('app.name') ? ' - '.config('app.name') : '' }}</title>

    {{ Maximus\Fail2Ban\Fail2Ban::css() }}
</head>
<body>
<div id="app"></div>

<script>
    window.Fail2Ban = {{ Illuminate\Support\Js::from($fail2ban) }};
</script>
{{ Maximus\Fail2Ban\Fail2Ban::js() }}
</body>
</html>
