# JWT Request Signer

Sign your URLs with a JWT token to protect access to your resources.

## Installation

```bash
composer require arthem/jwt-request-signer
# add a library that implements psr/http-factory-implementation
composer require nyholm/psr7
```

## Usage

Generate signed URL for your resources (an image for instance):
```php
<?php
use Arthem\JWTRequestSigner\JWTRequestSigner;
use Psr\Http\Message\RequestInterface;

$signer = new JWTRequestSigner(
    'signing-key', // Your secret signing key
    3600, // Expires in
    'x-token' // Optional query parameter name
);

/** @var RequestInterface $requestToSign */
$requestToSign = new PsrRequest('https://domain.tld/images/7b7fae13-2fb4-4c85-bde4-ebd087eb6be5');

$signedRequest = $signer->signRequest($requestToSign);

$signedUri = (string) $signedRequest->getUri();
```

Now add authorization to your resource:
```php
<?php
use Arthem\JWTRequestSigner\JWTRequestSigner;
use Arthem\JWTRequestSigner\Exception\InvalidTokenException;
use Psr\Http\Message\RequestInterface;

$signer = new JWTRequestSigner([/* config */]);

try {
    /** @var RequestInterface $currentRequest */
    $signer->validateSignedRequest($currentRequest);
} catch (InvalidTokenException $e) {
    echo "Access denied";
    exit;
}

// Stream your image here...
```

### Frameworks

Symfony [request-signer-bundle](https://github.com/4rthem/request-signer-bundle)

## Configuration

### Determinant headers

In order to offer a strict protection, most headers are signed.
You can exclude some headers that are not determinant:

```php
<?php
use Arthem\JWTRequestSigner\JWTRequestSigner;

/** @var JWTRequestSigner $signer */
$signer->addUnsignedHeader('X-Time');
```
