<?php

declare(strict_types=1);

namespace Arthem\JWTRequestSigner\Exception;

use InvalidArgumentException;

class InvalidTokenException extends InvalidArgumentException
{
    const PARSE = 'Token cannot be parsed';
    const INVALID = 'Token is invalid';
    const INVALID_FOR_REQUEST = 'Token is not valid for this request';
    const EXPIRED = 'Token has expired';
}
