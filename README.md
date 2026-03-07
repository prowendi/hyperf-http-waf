# prowendi/hyperf-http-waf

`prowendi/hyperf-http-waf` 是一个面向 Hyperf 3.x+ 的独立 Composer WAF 扩展包，提供可复用的 HTTP 中间件、默认规则、真实 IP 解析、日志上报和可扩展规则体系，适配 PHP 8.2+ 与 Swoole / OpenSwoole 长驻内存模型。

## 特性

- 独立 Composer 包，可直接 `composer require`
- 通过 `ConfigProvider` + 默认配置接入，不绑定业务项目
- 支持全局中间件或路由级中间件注册
- 检测 Client IP / Method / Path / Query / Header / Cookie / Body / Upload / UA / Referer
- 支持 SQLi、XSS、命令执行、路径穿越、LFI、SSRF、恶意扫描器 UA、非法方法、输入规模异常
- 提供 `observe` 与 `block` 两种模式
- 支持白名单、黑名单、可信代理、可信转发头
- 默认日志支持 PSR Logger，未接入时回退 `error_log`
- 请求态数据不进入全局可变静态状态，适合协程与长驻内存

## 环境要求

- PHP 8.2+
- Hyperf 3.x+
- Swoole 或 OpenSwoole 运行时

## 安装

```bash
composer require prowendi/hyperf-http-waf
```

本包通过 `composer.json` 的 `extra.hyperf.config` 暴露 `Prowendi\HyperfHttpWaf\ConfigProvider`。标准 Hyperf 包加载流程下会自动发现。

如果宿主项目关闭了包配置自动发现，请显式加载 `Prowendi\HyperfHttpWaf\ConfigProvider::class`。

## 发布或复制配置

如果宿主项目安装了 `hyperf/publisher`，可执行：

```bash
php bin/hyperf.php vendor:publish waf-config
```

未安装发布命令时，直接复制：

```text
vendor/prowendi/hyperf-http-waf/publish/waf.php
```

到宿主项目：

```text
config/autoload/waf.php
```

## 全局中间件接入

在宿主项目的 `config/autoload/middlewares.php` 中注册：

```php
<?php

declare(strict_types=1);

use Prowendi\HyperfHttpWaf\Middleware\WafMiddleware;

return [
    'http' => [
        WafMiddleware::class,
    ],
];
```

默认不自动强注册为全局中间件，避免在未评估误杀与性能成本前影响整个站点。

## 路由级中间件接入

按路由组接入：

```php
<?php

declare(strict_types=1);

use Prowendi\HyperfHttpWaf\Middleware\WafMiddleware;
use Hyperf\HttpServer\Router\Router;

Router::addGroup('/admin', static function () {
    Router::get('/users', 'App\\Controller\\AdminController@index');
}, [
    'middleware' => [
        WafMiddleware::class,
    ],
]);
```

如果项目使用控制器属性，也可以在控制器或方法上挂载 `WafMiddleware::class`。

## 通过 `#[]` 属性接入

本包提供了专用属性类 `Prowendi\HyperfHttpWaf\Annotation\Waf`，可以直接写成 `#[Waf]`。它内部继承自 Hyperf 官方的 `Hyperf\HttpServer\Annotation\Middleware`，默认指向 `Prowendi\HyperfHttpWaf\Middleware\WafMiddleware`。

最简写法：

```php
<?php

declare(strict_types=1);

namespace App\Controller;

use Hyperf\HttpServer\Annotation\Controller;
use Hyperf\HttpServer\Annotation\GetMapping;
use Prowendi\HyperfHttpWaf\Annotation\Waf;

#[Controller(prefix: '/admin')]
#[Waf]
final class AdminController
{
    #[GetMapping(path: 'dashboard')]
    public function dashboard(): array
    {
        return ['ok' => true];
    }
}
```

如果你需要控制中间件优先级，也可以传入 `priority`：

```php
#[Waf(priority: 70)]
```

如果宿主项目更倾向直接使用 Hyperf 原生写法，也仍然可以继续使用 `#[Middleware(WafMiddleware::class)]`。

控制器级别示例：

```php
<?php

declare(strict_types=1);

namespace App\Controller;

use Hyperf\HttpServer\Annotation\Controller;
use Hyperf\HttpServer\Annotation\GetMapping;
use Prowendi\HyperfHttpWaf\Middleware\WafMiddleware;
use Hyperf\HttpServer\Annotation\Middleware;

#[Controller(prefix: '/admin')]
#[Middleware(WafMiddleware::class)]
final class AdminController
{
    #[GetMapping(path: 'dashboard')]
    public function dashboard(): array
    {
        return ['ok' => true];
    }
}
```

方法级别示例：

```php
<?php

declare(strict_types=1);

namespace App\Controller;

use Hyperf\HttpServer\Annotation\Controller;
use Hyperf\HttpServer\Annotation\PostMapping;
use Prowendi\HyperfHttpWaf\Middleware\WafMiddleware;
use Hyperf\HttpServer\Annotation\Middleware;

#[Controller(prefix: '/api')]
final class UploadController
{
    #[PostMapping(path: 'upload')]
    #[Middleware(WafMiddleware::class)]
    public function upload(): array
    {
        return ['uploaded' => true];
    }
}
```

注意事项：

- 这种写法依赖宿主项目使用 Hyperf 的属性路由，例如 `#[Controller]`、`#[AutoController]`、`#[GetMapping]`、`#[PostMapping]`。
- 如果宿主项目是 `config/routes.php` 或 `Router::addGroup()` 这种配置式路由，仍然应使用路由配置里的 `middleware` 数组。
- 如果一个控制器方法已经挂了多个中间件，Hyperf 3.x 可以重复写多个 `#[Middleware(...)]`。

## 最小配置

```php
<?php

declare(strict_types=1);

return [
    'enabled' => true,
    'mode' => 'observe',
    'decision' => [
        'score_threshold' => 70,
        'block_on_first_match' => true,
    ],
    'trusted_proxies' => [
        '10.0.0.0/8',
        '192.168.0.0/16',
    ],
];
```

## 配置说明

### 核心项

- `enabled`: 总开关
- `mode`: `observe` 或 `block`
- `body_size_limit`: Body 检测读取上限，超过后只记规则不做全文扫描
- `trusted_proxies`: 可信代理 IP / CIDR，支持 `*` 表示信任任意上游代理
- `trusted_headers`: 可信代理下允许读取的真实 IP 头，支持 `*` 表示启用包内支持的全部真实 IP 头：`x-forwarded-for`、`x-real-ip`、`forwarded`
- `allowed_methods`: 允许的 HTTP 方法

### 决策项

- `decision.score_threshold`: 累积分数拦截阈值
- `decision.block_on_first_match`: 命中 `action=block` 的规则时是否立即拦截

### 阈值项

- `thresholds.query_parameter_count`
- `thresholds.body_parameter_count`
- `thresholds.header_value_length`
- `thresholds.max_value_length`
- `thresholds.max_nested_depth`
- `thresholds.max_scan_length`

### 名单项

- `whitelist.ips`
- `whitelist.cidrs`
- `whitelist.paths`
- `whitelist.routes`
- `whitelist.headers`
- `whitelist.user_agents`
- `blacklist.*`

### 响应项

- `response.status`
- `response.headers`
- `response.body`

### 日志项

- `logging.enabled`
- `logging.channel`
- `logging.body_max_length`
- `logging.ua_max_length`
- `logging.matched_sample_length`

## 自定义规则

规则是结构化数组，每条规则至少包含：

- `rule_id`
- `name`
- `type`
- `target`
- `pattern`
- `prefilters`
- `score`
- `action`
- `enabled`

示例：

```php
<?php

declare(strict_types=1);

return [
    'rules' => [
        [
            'rule_id' => 'custom-rce-curl-pipe',
            'name' => 'curl pipe shell',
            'type' => 'rce',
            'target' => 'input',
            'pattern' => '/curl\\s+[^|]+\\|\\s*(?:bash|sh)/i',
            'prefilters' => ['curl', '|', 'bash', 'sh'],
            'score' => 80,
            'action' => 'block',
            'enabled' => true,
        ],
    ],
];
```

`target` 推荐取值：

- `input`: 通用输入，适用于 query/body/header/cookie
- `path`
- `header`
- `cookie`
- `body`
- `query`
- `ua`

## 切换 observe / block

只记录不拦截：

```php
'mode' => 'observe',
```

启用拦截：

```php
'mode' => 'block',
```

## 自定义白名单 / 黑名单

```php
<?php

declare(strict_types=1);

return [
    'whitelist' => [
        'paths' => ['/health*', '/internal/callback*'],
        'cidrs' => ['10.10.0.0/16'],
        'headers' => [
            'x-internal-request' => ['1'],
        ],
        'user_agents' => ['TrustedScanner'],
    ],
    'blacklist' => [
        'ips' => ['203.0.113.9'],
        'cidrs' => ['198.51.100.0/24'],
    ],
];
```

## 替换日志实现

默认实现为 `Prowendi\HyperfHttpWaf\Logger\LoggerReporter`：

- 优先使用宿主容器中的 `Psr\Log\LoggerInterface`
- 若存在 `Hyperf\Logger\LoggerFactory` 且配置了 `logging.channel`，则按 channel 获取 logger
- 否则回退 `error_log`

如需接入自定义上报器，在宿主项目中覆盖依赖：

```php
<?php

declare(strict_types=1);

use App\Security\WebhookReporter;
use Prowendi\HyperfHttpWaf\Contract\ReporterInterface;

return [
    'dependencies' => [
        ReporterInterface::class => WebhookReporter::class,
    ],
];
```

## 可观测字段

默认日志会记录：

- `time`
- `client_ip`
- `method`
- `path`
- `action`
- `risk_score`
- `hit_rules`
- `ua`

并对以下字段脱敏：

- `password`
- `passwd`
- `token`
- `access_token`
- `refresh_token`
- `authorization`
- `cookie`
- `secret`

## 设计注意事项

- 不把请求态数据写入单例或静态可变属性
- 未配置 `trusted_proxies` 时不盲信 `X-Forwarded-For`
- Body 只在大小阈值内做内容检测
- `multipart/form-data` 只检测文件元信息，不做大文件全文扫描
- JSON 解析失败会优雅降级到轻量规则命中，不中断中间件链

## 测试

```bash
composer install
composer test
```

当前测试覆盖：

- `ConfigProvider` 与默认配置加载
- 正常请求放行
- SQLi / XSS / 敏感路径命中
- 白名单放行
- `observe` / `block` 模式差异
- 代理真实 IP 解析
- body size 限制
- 文件上传元信息检测
- Header 恶意载荷检测

## 未来增强方向

- Redis 动态封禁与滑动窗口
- 规则热更新
- Webhook / MQ / SIEM 上报器
- 路由维度细粒度策略
- 基于场景的误杀学习与调优
