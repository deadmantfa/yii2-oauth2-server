<?php

namespace deadmantfa\yii2\oauth2\server\components\Grant;

use DateInterval;
use DateTimeImmutable;
use deadmantfa\yii2\oauth2\server\components\Exception\FirebaseException;
use deadmantfa\yii2\oauth2\server\components\Repositories\FirebaseUserRepositoryInterface;
use deadmantfa\yii2\oauth2\server\models\AccessToken;
use Kreait\Firebase\Exception\Auth\RevokedIdToken;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use Yii;

/**
 * Class FirebaseGrant
 *
 * This class represents a Firebase-based grant for the OAuth2 server, which enables
 * user authentication using Firebase ID tokens.
 *
 * @package api\components\oauth2\grants
 */
class FirebaseGrant extends AbstractGrant
{
    private FirebaseUserRepositoryInterface $_firebaseUserRepository;

    /**
     * FirebaseGrant constructor.
     *
     * @param FirebaseUserRepositoryInterface $firebaseUserRepository The Firebase user repository
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository The refresh token repository
     */
    public function __construct(
        FirebaseUserRepositoryInterface $firebaseUserRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository
    )
    {
        $this->setFirebaseRepository($firebaseUserRepository);
        $this->setRefreshTokenRepository($refreshTokenRepository);

        $this->refreshTokenTTL = new DateInterval('P1M');
    }

    /**
     * Sets the Firebase user repository.
     *
     * @param FirebaseUserRepositoryInterface $firebaseUserRepository The Firebase user repository
     */
    public function setFirebaseRepository(FirebaseUserRepositoryInterface $firebaseUserRepository): void
    {
        $this->_firebaseUserRepository = $firebaseUserRepository;
    }

    /**
     * Responds to an access token request.
     *
     * @param ServerRequestInterface $request The server request
     * @param ResponseTypeInterface $responseType The response type
     * @param DateInterval $accessTokenTTL The access token time-to-live
     * @return ResponseTypeInterface The updated response type
     * @throws OAuthServerException If an error occurs during the request handling
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface  $responseType,
        DateInterval           $accessTokenTTL
    ): ResponseTypeInterface
    {
        Yii::info('Processing access token request in FirebaseGrant', 'auth');
        // Validate request
        $client = $this->validateClient($request);
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request, $this->defaultScope));
        $user = $this->validateUser($request, $client);

        $finalizedScopes = $this->finalizeRequestedScopes($scopes, $client, $user);

        // Issue and persist new tokens
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $user->getIdentifier(), $finalizedScopes);
        $refreshToken = $this->issueRefreshToken($accessToken);

        // Inject tokens into response
        $this->injectTokensIntoResponse($responseType, $accessToken, $refreshToken);

        return $responseType;
    }

    /**
     * Validates the user based on the Firebase ID provided in the request.
     *
     * @param ServerRequestInterface $request The server request
     * @param ClientEntityInterface $client The client entity
     * @return UserEntityInterface The validated user entity
     * @throws OAuthServerException If the user validation fails
     */
    protected function validateUser(ServerRequestInterface $request, ClientEntityInterface $client): UserEntityInterface
    {
        $firebaseId = $this->getRequestParameter('fid', $request);
        if (!is_string($firebaseId) || empty($firebaseId)) {
            throw FirebaseException::invalidRequest('fid');
        }

        try {
            $user = $this->_firebaseUserRepository->getUserEntityByFirebaseId(
                $firebaseId,
                $this->getIdentifier(),
                $client
            );
        } catch (RevokedIdToken $revokedIdToken) {
            $this->handleAuthenticationFailure($request);
            throw FirebaseException::revokedIdToken($revokedIdToken->getMessage());
        }
        return $user;
    }

    /**
     * Returns the identifier of the grant.
     *
     * @return string The identifier of the grant
     */
    public function getIdentifier(): string
    {
        return 'firebase';
    }

    /**
     * Handles user authentication failures and logs the failure.
     *
     * @param ServerRequestInterface $request The server request
     * @throws OAuthServerException
     */
    protected function handleAuthenticationFailure(ServerRequestInterface $request): void
    {
        $this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));
        $message = "Authentication failed for Firebase ID: {$this->getRequestParameter('fid', $request)}";
        Yii::error($message, 'auth');
    }

    /**
     * Finalizes the requested scopes for the access token.
     *
     * @param array $scopes The requested scopes
     * @param ClientEntityInterface $client The client entity
     * @param UserEntityInterface $user The user entity
     * @return array The finalized scopes
     */
    private function finalizeRequestedScopes(
        array                 $scopes,
        ClientEntityInterface $client,
        UserEntityInterface   $user
    ): array
    {
        return $this->scopeRepository->finalizeScopes(
            $scopes,
            $this->getIdentifier(),
            $client,
            $user->getIdentifier()
        );
    }

    protected function issueAccessToken(
        DateInterval          $accessTokenTTL,
        ClientEntityInterface $client,
        ?string               $userIdentifier,
        array                 $scopes = []
    ): AccessTokenEntityInterface
    {
        $accessToken = $this->accessTokenRepository->getNewToken($client, $scopes, $userIdentifier);

        $expiry = (new DateTimeImmutable())->add($accessTokenTTL);
        $accessToken->setExpiryDateTime($expiry);

        // Set identifier explicitly
        $identifier = $this->generateUniqueIdentifier();
        $accessToken->setIdentifier($identifier);
        $accessToken->setPrivateKey($this->privateKey);

        Yii::info('Generated AccessToken. Identifier: ' . $identifier, 'auth');

        $this->accessTokenRepository->persistNewAccessToken($accessToken);

        return $accessToken;
    }

    protected function issueRefreshToken(AccessTokenEntityInterface $accessToken): RefreshTokenEntityInterface
    {
        if (!$accessToken instanceof AccessToken || $accessToken->status !== AccessToken::STATUS_ACTIVE) {
            Yii::error('Cannot issue a RefreshToken for an invalid or revoked AccessToken. AccessToken ID: ' . ($accessToken->id ?? 'N/A'), 'auth');
            throw new LogicException('Cannot issue a RefreshToken for an invalid or revoked AccessToken.');
        }

        Yii::info('Issuing RefreshToken for AccessToken. Details: ' . json_encode([
                'id' => $accessToken->id ?? null,
                'status' => $accessToken->status ?? null,
                'identifier' => $accessToken->getIdentifier(),
            ]), 'auth');

        return parent::issueRefreshToken($accessToken);
    }

    /**
     * Injects the access and refresh tokens into the response type.
     *
     * @param ResponseTypeInterface $responseType The response type
     * @param AccessTokenEntityInterface $accessToken The access token entity
     * @param RefreshTokenEntityInterface $refreshToken The refresh token entity
     */
    private function injectTokensIntoResponse(
        ResponseTypeInterface       $responseType,
        AccessTokenEntityInterface  $accessToken,
        RefreshTokenEntityInterface $refreshToken
    ): void
    {
        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);
    }

    /**
     * @throws OAuthServerException
     */
    public function canRespondToAccessTokenRequest(ServerRequestInterface $request): bool
    {
        $grantType = $this->getRequestParameter('grant_type', $request);
        Yii::info('FirebaseGrant canRespondToAccessTokenRequest called with grant_type: ' . $grantType, 'auth');

        return $grantType === $this->getIdentifier();
    }

}
