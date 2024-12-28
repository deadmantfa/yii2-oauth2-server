<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\Psr7;

use GuzzleHttp\Psr7\Response;
use yii\web\Response as YiiResponse;

class ServerResponse extends Response
{
    /**
     * Converts PSR-7 Response to Yii2 Response.
     *
     * @return YiiResponse
     */
    public function toYiiResponse(): YiiResponse
    {
        $yiiResponse = new YiiResponse();
        $yiiResponse->setStatusCode($this->getStatusCode());
        $yiiResponse->headers->fromArray($this->getHeaders());

        if ($this->getBody()->isSeekable()) {
            $this->getBody()->rewind();
        }

        $yiiResponse->content = $this->getBody()->getContents();

        return $yiiResponse;
    }
}
