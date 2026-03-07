<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Tests\Stubs;

use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class OkHandler implements RequestHandlerInterface
{
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $factory = new Psr17Factory();
        $response = $factory->createResponse(200)->withHeader('content-type', 'application/json');

        return $response->withBody($factory->createStream('{"ok":true}'));
    }
}
