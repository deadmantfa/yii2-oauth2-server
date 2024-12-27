<?php

namespace deadmantfa\yii2\oauth2\server\components\Repositories;

use deadmantfa\yii2\oauth2\server\models\AccessToken;

class MacTokenRepository extends AccessTokenRepository
{
    public function __construct($encryptionKey = null)
    {
        parent::__construct(AccessToken::TYPE_MAC, $encryptionKey);
    }
}
