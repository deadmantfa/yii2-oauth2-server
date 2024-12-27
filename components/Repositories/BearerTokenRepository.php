<?php

namespace deadmantfa\yii2\oauth2\server\components\Repositories;

use deadmantfa\yii2\oauth2\server\models\AccessToken;

class BearerTokenRepository extends AccessTokenRepository
{
    public function __construct()
    {
        parent::__construct(AccessToken::TYPE_BEARER);
    }
}
