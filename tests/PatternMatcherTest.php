<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Tests;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\DTO\Rule;
use Prowendi\HyperfHttpWaf\DTO\TextInput;
use Prowendi\HyperfHttpWaf\Matcher\PatternMatcher;

final class PatternMatcherTest extends TestCase
{
    public function testNumericStringCandidateRemainsStringDuringPrefilterMatch(): void
    {
        $matcher = new PatternMatcher();
        $config = WafConfig::fromArray([]);
        $rule = Rule::fromArray([
            'rule_id' => 'numeric-header-probe',
            'name' => 'Numeric header probe',
            'type' => 'test',
            'target' => 'header',
            'pattern' => '/127/',
            'prefilters' => ['127'],
            'score' => 10,
            'action' => 'score',
            'enabled' => true,
        ]);

        $hits = $matcher->match(
            [new TextInput('header', 'content-length', '127')],
            [$rule],
            $config,
        );

        self::assertCount(1, $hits);
        self::assertSame('numeric-header-probe', $hits[0]->ruleId);
    }

    public function testPrefilterGracefullyHandlesIntegerCandidate(): void
    {
        $matcher = new PatternMatcher();
        $method = new \ReflectionMethod($matcher, 'passesPrefilters');
        $method->setAccessible(true);

        self::assertTrue($method->invoke($matcher, 127, ['127']));
        self::assertFalse($method->invoke($matcher, 127, ['sqlmap']));
    }
}
