# prowendi/hyperf-http-waf

`prowendi/hyperf-http-waf` 是一个面向 Hyperf 3.x+ 的独立 Composer WAF 扩展包，提供可复用的 HTTP 中间件、默认规则、真实 IP 解析、日志上报和可扩展规则体系，适配 PHP 8.2+ 与 Swoole / OpenSwoole 长驻内存模型。

## 特性

- 独立 Composer 包，可直接 `composer require`
- 通过 `ConfigProvider` + 默认配置接入，不绑定业务项目
- 支持全局中间件或路由级中间件注册
- 检测 Client IP / Method / Path / Query / Header / Cookie / Body / Upload / UA / Referer
- 支持 SQLi（含字符串恒真、注释、时间盲注、堆叠、Oracle 拼接、布尔恒真变体 TRUE/LIKE/`<>`、HAVING/ORDER BY 探测、报错注入 EXTRACTVALUE/UPDATEXML、布尔盲注函数链、INTO OUTFILE/LOAD_FILE、系统 schema 访问、`/*!50000union*/` 版本注释混淆、ORM 运算符注入 `op={"id":"GT"}`）、XSS（含任意事件处理器、javascript:/data: 协议变体）、命令执行（含 Windows 命令 mshta/bitsadmin/netsh）、反弹 shell（/dev/tcp、nc -e、socat）、PHP 代码执行串（eval/assert/preg_replace /e 等）、路径穿越（含 `..;/`）、LFI（含 `php://` 流封装）、SSRF（含十六进制/十进制/八进制/IPv6 回环、AWS/GCP/阿里/腾讯/华为 metadata 及 IPv6 变体、gopher/dict 等危险协议）、反序列化（PHP 格式 + Java `rO0AB`/FastJSON `"@type"` Java 类名）、原型链污染（`__proto__`/`constructor.constructor`）、ThinkPHP filter 覆写与 invokefunction、Struts2 OGNL、NoSQL 运算符注入、XXE、JNDI（Log4Shell）、CRLF 头注入、SSTI（Jinja/FreeMarker）、JWT alg:none、null 字节参数、凭据泄露（AWS/阿里 LTAI/腾讯 AKID/Stripe/GitHub/Slack/私钥）、已知框架漏洞路径（think\app、BshServlet、druid、wls-wsat、xmlrpc.php 等）、恶意扫描器 UA、非法方法、输入规模异常
- Header 专项：Host 值含路径片段（Host 头注入绕过）、下划线转发头（`X_Forwarded_For` 伪造）
- 上传文件内容嗅探：识别伪装扩展名的 Webshell（`<?php`/JSP 声明）、脚本 shebang、SVG 内嵌脚本、Zip Slip 归档穿越条目（可通过 `files.content_inspection` 关闭）
- 参数名与参数值同时扫描（覆盖 `user[$ne]=` 类 NoSQL 注入、`__proto__` 键注入）
- 请求体无 Content-Type 或非文本类型时仍按原始数据扫描
- 超长值同时扫描头部与尾部切片，防止"填充绕过"
- 白名单路径匹配同时校验原始/解码/归一化路径，防止编码前前缀绕过
- 可选 LLM 提示词注入检测组（`llm-*` 规则，默认关闭）：指令覆盖（"ignore previous instructions"）、系统提示词探测、伪造审批标记 —— 面向 AI 网关/Agent 场景按需开启
- 提供 `observe` 与 `block` 两种模式
- 支持白名单、黑名单、可信代理、可信转发头
- 默认日志支持 PSR Logger，未接入时回退 `error_log`
- 请求态数据不进入全局可变静态状态，适合协程与长驻内存

### 已知限制

- 超出 `max_scan_length` 的值仅覆盖头部 + 尾部各一个窗口，攻击载荷藏在超长值中部且总分低于阈值时可能漏报
- UTF-7 等已过时浏览器编码不做归一化
- `observe` 模式只记录不拦截
- 频率类攻击(爆破、验证码滥用、限流键轮换)需要跨请求状态，请在外层限流器处理

### 升级注意

- **从旧版本升级时请重新发布 `waf.php`**:`rules` 是数组,配置合并规则下用户已发布的 `rules` 会整体覆盖默认规则——不重新发布就拿不到新增规则(仅引擎层修复生效)
- `trusted_proxies => ['*']` / `0.0.0.0/0` 会同时信任 IPv4 与 IPv6 来源
- 白名单路径匹配会同时校验原始/解码/归一化三种路径变体——URL 编码了斜杠的正常客户端(如 `/api%2Fv1/x`)可能不再命中 `/api/*` 白名单，如有此类流量请把编码形式一并加入白名单
- 关闭 `files.content_inspection` 后,非 seekable 上传流不会做内容嗅探(避免破坏性读取)

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
