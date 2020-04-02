<?php

declare(strict_types=1);

namespace Arthem\JWTRequestSigner\Tests;

use Arthem\JWTRequestSigner\Exception\InvalidTokenException;
use Arthem\JWTRequestSigner\JWTRequestSigner;
use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Request;
use PHPUnit\Framework\TestCase;

class JWTSignerTest extends TestCase
{
    public function testChangingSigningKeyWillNotValidateSignedRequest()
    {
        $signer = new JWTRequestSigner('some-key');
        $request = new Request('GET', 'http://foo.com');

        $signedRequest = $signer->signRequest($request);

        $this->assertNotEquals($request, $signedRequest);
        $this->assertEquals($request->getMethod(), $signedRequest->getMethod());

        $signer->validateSignedRequest($signedRequest);

        $signerWithDifferentKey = new JWTRequestSigner('some-key2');

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage(InvalidTokenException::INVALID);
        $signerWithDifferentKey->validateSignedRequest($signedRequest);
    }

    /**
     * @dataProvider getRequests
     */
    public function testSigningRequests(Request $request)
    {
        $signer = new JWTRequestSigner('some-key', 3600, 'customToken');

        $signedRequest = $signer->signRequest($request);

        $this->assertNotEquals($request, $signedRequest);
        $this->assertEquals($request->getMethod(), $signedRequest->getMethod());

        $queryParams = Psr7\parse_query($signedRequest->getUri()->getQuery());

        $this->assertArrayHasKey('customToken', $queryParams);
        $this->assertNotEmpty($queryParams['customToken']);

        $signer->validateSignedRequest($signedRequest);
    }

    /**
     * @dataProvider getSameUris
     */
    public function testValidationPassesWithDifferentUri(string $uri, string $attemptedUri)
    {
        [$signer, $attemptedRequest] = $this->prepareUriTest($uri, $attemptedUri);

        $signer->validateSignedRequest($attemptedRequest);
    }

    /**
     * @dataProvider getDifferentUris
     */
    public function testValidationFailsWithDifferentUri(string $uri, string $attemptedUri)
    {
        [$signer, $attemptedRequest] = $this->prepareUriTest($uri, $attemptedUri);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage(InvalidTokenException::INVALID_FOR_REQUEST);

        $signer->validateSignedRequest($attemptedRequest);
    }

    private function prepareUriTest(string $uri, string $attemptedUri): array
    {
        $request = new Request('GET', $uri);

        $signer = new JWTRequestSigner('some-key');
        $signedRequest = $signer->signRequest($request);

        $queryParams = Psr7\parse_query($signedRequest->getUri()->getQuery());
        $token = $queryParams['token'];
        $this->assertNotEmpty($token);

        $attemptedRequest = new Request('GET', $attemptedUri);
        $queryParams = Psr7\parse_query($attemptedRequest->getUri()->getQuery());
        $queryParams['token'] = $token;
        $attemptedRequest = $attemptedRequest->withUri($attemptedRequest->getUri()->withQuery(Psr7\build_query($queryParams)));

        return [$signer, $attemptedRequest];
    }

    public function getSameUris(): array
    {
        return [
            ['http://foo.com', 'http://foo.com'],
            ['http://foo.com/a', 'http://foo.com/a'],
            ['http://foo.com/a?a', 'http://foo.com/a?a'],
            ['http://foo.com/a?a', 'http://foo.com/a?A'],
            ['http://foo.com/a?a=1', 'http://foo.com/a?a=1'],
            ['http://foo.com/a?a= ', 'http://foo.com/a?a=+'],
            ['http://foo.com/a?b=1&a=2', 'http://foo.com/a?a=2&b=1'],
            ['http://foo.com/a?b=1&a=2', 'http://foo.com/a?A=2&B=1'],
            ['http://foo.com/a?b&a', 'http://foo.com/a?b&a'],
            ['http://foo.com/a?b&a', 'http://foo.com/a?B&a'],
        ];
    }

    public function getDifferentUris(): array
    {
        return [
            ['http://foo.com', 'http://foo.com/'],
            ['http://foo.com/', 'http://foo.com/a'],
            ['http://foo.com/b', 'http://foo.com/a'],
            ['http://foo.com/a/', 'http://foo.com/a'],
            ['http://foo.com/a?b&a', 'http://foo.com/a?b&a='],
            ['http://foo.com/a?b&a', 'http://foo.com/a?b&a=1'],
        ];
    }

    /**
     * @dataProvider getSameHeaders
     */
    public function testValidationPassesWithDifferentHeaders(array $headers, array $attemptedHeaders)
    {
        [$signer, $attemptedRequest] = $this->prepareHeadersTest($headers, $attemptedHeaders);

        $signer->validateSignedRequest($attemptedRequest);
    }

    /**
     * @dataProvider getDifferentHeaders
     */
    public function testValidationFailsWithDifferentHeaders(array $headers, array $attemptedHeaders)
    {
        [$signer, $attemptedRequest] = $this->prepareHeadersTest($headers, $attemptedHeaders);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage(InvalidTokenException::INVALID_FOR_REQUEST);

        $signer->validateSignedRequest($attemptedRequest);
    }

    private function prepareHeadersTest(array $headers, array $attemptedHeaders): array
    {
        $request = new Request('GET', 'https://foo.bar/baz', $headers);

        $signer = new JWTRequestSigner('some-key');
        $signedRequest = $signer->signRequest($request);
        $queryParams = Psr7\parse_query($signedRequest->getUri()->getQuery());
        $token = $queryParams['token'];
        $this->assertNotEmpty($token);

        $attemptedRequest = new Request('GET', 'https://foo.bar/baz?token='.$token, $attemptedHeaders);

        return [$signer, $attemptedRequest];
    }

    public function getSameHeaders(): array
    {
        return [
            [[], []],

            [[
                'X-Foo' => 'bar',
            ], [
                'X-Foo' => 'bar',
            ]],

            [[
                'X-Foo' => ['bar', 'baz'],
            ], [
                'X-Foo' => ['bar', 'baz'],
            ]],

            [[
                'X-Foo' => ['baz', 'bar'],
                'X-Foo2' => ['baz', 'bar'],
            ], [
                'x-Foo' => ['baz', 'bar'],
                'x-Foo2' => ['baz', 'bar'],
            ]],
        ];
    }

    public function getDifferentHeaders(): array
    {
        return [
            [[], ['X-Foo' => 'bar']],

            [[
                'X-Foo' => 'bar',
            ], [
                'X-Foo' => 'bar2',
            ]],

            [[
                'X-Foo' => ['baz', 'bar'],
            ], [
                'X-Foo' => ['bar', 'baz'],
            ]],
        ];
    }

    public function getRequests(): array
    {
        return [
            [$request = new Request('GET', 'http://foo.com')],
            [$request = new Request('GET', 'https://foo.com/bar')],
            [$request = new Request('GET', 'https://foo.com')],
            [$request = new Request('GET', 'https://foo.com/bar?hello')],
            [$request = new Request('GET', 'https://foo.com/bar?hello=world')],
            [$request = new Request('GET', 'https://foo.com/bar?hello=42')],
            [$request = new Request('POST', 'https://foo.com/bar?hello=42', [], '{"foo":"bar"}')],
            [$request = new Request('PUT', 'https://foo.com/bar?hello=42', [], '{"foo":"bar"}')],
        ];
    }
}
