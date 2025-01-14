<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\Psr7;

use GuzzleHttp\Psr7\ServerRequest as GuzzleServerRequest;
use yii\base\InvalidConfigException;
use yii\web\Request;

class ServerRequest extends GuzzleServerRequest
{
    /**
     * Parsed body of the request.
     *
     * @var array|null
     */
    private ?array $parsedBody = null;

    /**
     * Converts Yii2 Request to PSR-7 ServerRequest.
     *
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

        // Parse JSON body if the content type is application/json
        if ($request->getContentType() === 'application/json') {
            $parsedBody = json_decode($request->getRawBody(), true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new InvalidConfigException('Invalid JSON in request body: ' . json_last_error_msg());
            }
            $this->parsedBody = $parsedBody;
        }
    }

    /**
     * Determines the protocol version for the request.
     */
    private function determineProtocolVersion(Request $request): string
    {
        return $request->isSecureConnection ? '2.0' : '1.1'; // Default to HTTP/1.1
    }

    /**
     * Retrieves the parsed body of the request.
     */
    public function getParsedBody(): ?array
    {
        return $this->parsedBody;
    }
}
