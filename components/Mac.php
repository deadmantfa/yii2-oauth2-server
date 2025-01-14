<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token\Plain;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;

class Mac
{
    private ServerRequestInterface $_request;
    private array $_params = [];
    private ?Plain $_jwt = null;
    private Configuration $jwtConfig;

    /**
     * @throws OAuthServerException
     */
    public function __construct(ServerRequestInterface $request, Configuration $jwtConfig, ?array $params = null)
    {
        $this->jwtConfig = $jwtConfig;

        if ($params === null) {
            $header = $request->getHeader('authorization');
            $params = empty($header) ? [] : $header[0];
        }

        if (is_string($params)) {
            $params = $this->prepare($params);
        }

        if (!is_array($params)) {
            throw OAuthServerException::serverError('MAC construction failed.');
        }

        $this->_request = $request;
        $this->_params = $params;
    }

    /**
     * @throws OAuthServerException
     */
    protected function prepare(
        string $header,
        array  $required = ['kid', 'ts', 'access_token', 'mac'],
        array  $optional = ['h' => ['host'], 'seq-nr' => null, 'cb' => null]
    ): array
    {
        $mac = [];
        $params = explode(',', preg_replace('/^(?:\s+)?MAC\s/', '', $header));

        foreach ($params as $param) {
            $parts = array_map('trim', explode('=', $param, 2));
            if (count($parts) !== 2) {
                throw OAuthServerException::accessDenied('Error parsing MAC params.');
            }
            $key = $parts[0];
            $value = trim($parts[1], '"');
            $mac[$key] = ($key === 'h') ? explode(':', $value) : $value;
        }

        foreach ($required as $param) {
            if (!array_key_exists($param, $mac)) {
                throw OAuthServerException::accessDenied("Required MAC param `$param` missing.");
            }
        }

        return array_merge($optional, $mac);
    }

    /**
     * @throws OAuthServerException
     */
    public function validate(): self
    {
        $values = array_merge(
            [$this->getStartLine()],
            $this->getHeaders(),
            [$this->getParam('ts'), $this->getParam('seq_nr')]
        );

        $expectedMac = hash_hmac(
            $this->getAlgorithm(),
            implode("\n", array_filter($values)) . "\n",
            $this->getJwt()->claims()->get('mac_key')
        );

        if (base64_encode($expectedMac) === $this->getParam('mac')) {
            return $this;
        }

        throw OAuthServerException::accessDenied('MAC validation failed.');
    }

    protected function getStartLine(): string
    {
        return sprintf('%s %s HTTP/%s', $this->_request->getMethod(), $this->_request->getUri(), $this->_request->getProtocolVersion());
    }

    protected function getHeaders(): array
    {
        return array_map(
            fn($name): string => $this->_request->getHeaderLine($name),
            $this->getParam('h') ?? []
        );
    }

    public function getParam(string $name)
    {
        return $this->_params[$name] ?? null;
    }

    protected function getAlgorithm(): string
    {
        return 'sha256';
    }

    /**
     * @throws OAuthServerException
     */
    public function getJwt(): Plain
    {
        if (!$this->_jwt instanceof \Lcobucci\JWT\Token\Plain) {
            $this->_jwt = $this->jwtConfig->parser()->parse($this->getParam('access_token'));
        }

        if (!$this->_jwt instanceof Plain) {
            throw OAuthServerException::accessDenied('Invalid JWT.');
        }

        return $this->_jwt;
    }
}
