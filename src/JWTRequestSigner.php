<?php

declare(strict_types=1);

namespace Arthem\JWTRequestSigner;

use Arthem\JWTRequestSigner\Exception\InvalidTokenException;
use DateTimeImmutable;
use GuzzleHttp\Psr7;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\InvalidToken;
use Psr\Http\Message\RequestInterface;

class JWTRequestSigner
{
    /**
     * @var Configuration
     */
    private $config;

    /**
     * @var int
     */
    private $ttl;

    /**
     * @var string
     */
    private $queryParamName;

    /**
     * Headers not to sign in order to prevent signature mismatch
     * when sending a request due to proxy or cache controls from browser.
     *
     * @var array
     */
    private $unsignedHeaders = [
        'cache-control' => true,
        'content-type' => true,
        'content-length' => true,
        'expect' => true,
        'max-forwards' => true,
        'pragma' => true,
        'range' => true,
        'te' => true,
        'if-match' => true,
        'if-none-match' => true,
        'if-modified-since' => true,
        'if-unmodified-since' => true,
        'if-range' => true,
        'accept' => true,
        'origin' => true,
        'authorization' => true,
        'proxy-authorization' => true,
        'from' => true,
        'referer' => true,
        'user-agent' => true,
        'sec-fetch-dest' => true,
        'sec-fetch-mode' => true,
        'sec-fetch-site' => true,
        'sec-fetch-user' => true,
        'upgrade-insecure-requests' => true,
    ];

    public function __construct(string $signingKey, ?int $ttl = null, string $queryParamName = 'token')
    {
        $this->config = Configuration::forSymmetricSigner(
            new Sha256(),
            new Key($signingKey)
        );
        $this->ttl = $ttl;
        $this->queryParamName = $queryParamName;
    }

    public function addUnsignedHeader(string $headerName): void
    {
        $this->unsignedHeaders[strtolower($headerName)] = true;
    }

    public function signRequest(RequestInterface $request): RequestInterface
    {
        $parsedRequest = self::parseRequest($request);

        $token = $this->createJWT($parsedRequest);

        $parsedRequest['query'] = array_merge($parsedRequest['query'], [
            $this->queryParamName => (string) $token,
        ]);

        $parsedRequest['uri'] = $request->getUri()->withQuery(Psr7\build_query($parsedRequest['query']));

        return new $request(
            $parsedRequest['method'],
            $parsedRequest['uri'],
            $parsedRequest['headers'],
            $parsedRequest['body'],
            $parsedRequest['version']
        );
    }

    public function validateSignedRequest(RequestInterface $request): void
    {
        $parsedRequest = self::parseRequest($request);

        /** @var string $token */
        $token = $parsedRequest['query'][$this->queryParamName] ?? null;
        if (null === $token) {
            throw new InvalidTokenException('Token is missing');
        }

        $parsedToken = $this->config->getParser()->parse($token);
        if (!$parsedToken instanceof Plain) {
            throw new InvalidTokenException(InvalidTokenException::PARSE);
        }

        $constraints = $this->config->getValidationConstraints();

        try {
            $this->config->getValidator()->assert($parsedToken, ...$constraints);
        } catch (InvalidToken $e) {
            throw new InvalidTokenException(InvalidTokenException::INVALID);
        }

        if ($parsedToken->isExpired(new DateTimeImmutable())) {
            throw new InvalidTokenException(InvalidTokenException::EXPIRED);
        }

        $identifier = $this->createRequestIdentifier($parsedRequest);

        if (!$parsedToken->isIdentifiedBy($identifier)) {
            throw new InvalidTokenException(InvalidTokenException::INVALID_FOR_REQUEST);
        }
    }

    private function createRequestIdentifier(array $parsedRequest): string
    {
        $headers = $this->arrayFilterKeys($parsedRequest['headers'], $this->unsignedHeaders);

        $ignoredQueryParams = [strtolower($this->queryParamName) => true];
        $queryParams = $this->arrayFilterKeys($parsedRequest['query'], $ignoredQueryParams);

        return implode(',', [
            $parsedRequest['method'],
            $parsedRequest['uri'],
            json_encode($queryParams),
            json_encode($parsedRequest['body']),
            json_encode($headers),
        ]);
    }

    private function arrayFilterKeys(array $input, array $unwantedKeys): array
    {
        $output = [];
        foreach ($input as $key => $value) {
            $key = strtolower($key);
            if (!isset($unwantedKeys[$key])) {
                $output[$key][] = $value;
            }
        }

        ksort($output);

        return $output;
    }

    private function createJWT(array $parsedRequest): Plain
    {
        $tokenBuilder = $this
            ->config
            ->createBuilder()
            ->identifiedBy($this->createRequestIdentifier($parsedRequest));

        if (null !== $this->ttl) {
            $expiresAt = (new DateTimeImmutable())->setTimestamp(time() + $this->ttl);
            $tokenBuilder->expiresAt($expiresAt);
        }

        return $tokenBuilder->getToken($this->config->getSigner(), $this->config->getSigningKey());
    }

    private static function createUri(string $scheme, string $authority, string $path): string
    {
        $uri = '';

        if (!empty($scheme)) {
            $uri .= $scheme.':';
        }

        if (!empty($authority)) {
            $uri .= '//'.$authority;
        }

        if (!empty($path)) {
            if ('/' !== $path[0]) {
                if (!empty($authority)) {
                    $path = '/'.$path;
                }
            } elseif (isset($path[1]) && '/' === $path[1]) {
                if (empty($authority)) {
                    $path = '/'.ltrim($path, '/');
                }
            }

            $uri .= $path;
        }

        return $uri;
    }

    private static function parseRequest(RequestInterface $request): array
    {
        $uri = $request->getUri();

        return [
            'method' => $request->getMethod(),
            'uri' => self::createUri($uri->getScheme(), $uri->getAuthority(), $uri->getPath()),
            'query' => Psr7\parse_query($uri->getQuery()),
            'headers' => $request->getHeaders(),
            'body' => $request->getBody(),
            'version' => $request->getProtocolVersion(),
        ];
    }
}
