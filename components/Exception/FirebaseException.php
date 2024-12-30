<?php

declare(strict_types=1);

namespace deadmantfa\yii2\oauth2\server\components\Exception;

use League\OAuth2\Server\Exception\OAuthServerException;

class FirebaseException extends OAuthServerException
{
    /**
     * Invalid firebase JWT Token error.
     *
     * @return static
     */
    public static function invalidJWTToken(): FirebaseException
    {
        return new static('The user firebase JWT token is invalid.', 11, 'invalid_token', 401);
    }

    /**
     * User not found error.
     *
     * @return static
     */
    public static function userNotFound(): FirebaseException
    {
        $errorMessage = 'User not found';

        return new static($errorMessage, 12, 'user_not_found', 404);
    }

    /**
     * Invalid firebase Signature error.
     *
     * @return static
     */
    public static function invalidSignature(): FirebaseException
    {
        return new static('The firebase signature is invalid.', 13, 'firebase_invalid_signature', 401);
    }

    /**
     * Firebase Token has expired.
     *
     * @return static
     */
    public static function tokenExpired($message): FirebaseException
    {
        return new static($message, 14, 'firebase_token_expired', 401);
    }

    /**
     * Issued in the future Error.
     *
     * @return static
     */
    public static function issuedInTheFuture($message): FirebaseException
    {
        return new static($message, 15, 'firebase_token_expired', 401);
    }

    /**
     * Unknown Key issue.
     *
     * @return static
     */
    public static function unknownKey($message): FirebaseException
    {
        return new static($message, 16, 'firebase_unknown_key', 401);
    }

    /**
     * Revvoked Id Token
     *
     * @return static
     */
    public static function revokedIdToken($message): FirebaseException
    {
        return new static($message, 17, 'firebase_revoked_id_token', 401);
    }
}
