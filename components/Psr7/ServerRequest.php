<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\Psr7;

use GuzzleHttp\Psr7\ServerRequest as GuzzleServerRequest;
use yii\base\InvalidConfigException;
use yii\web\Request;

class ServerRequest extends GuzzleServerRequest
{
    /**
     * Converts Yii2 Request to PSR-7 ServerRequest.
     *
     * @param Request $request
     * @throws InvalidConfigException
     */
    public function __construct(Request $request)
    {
        $protocolVersion = $this->determineProtocolVersion($request);

        parent::__construct(
            $request->getMethod(),
            $request->getUrl(),
            $request->getHeaders()->toArray(),
            $request->getRawBody(),
            $protocolVersion,
            $_SERVER
        );
    }

    /**
     * Determines the protocol version for the request.
     *
     * @param Request $request
     * @return string
     */
    private function determineProtocolVersion(Request $request): string
    {
        return $request->isSecureConnection ? '2.0' : '1.1'; // Default to HTTP/1.1
    }
}
