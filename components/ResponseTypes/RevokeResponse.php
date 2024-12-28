<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\ResponseTypes;

use League\OAuth2\Server\ResponseTypes\AbstractResponseType;
use Psr\Http\Message\ResponseInterface;

class RevokeResponse extends AbstractResponseType
{
    public function generateHttpResponse(ResponseInterface $response): ResponseInterface
    {
        return $response
            ->withStatus(200)
            ->withHeader('pragma', 'no-cache')
            ->withHeader('cache-control', 'no-store');
    }
}
