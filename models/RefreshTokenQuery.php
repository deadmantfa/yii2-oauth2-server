<?php

namespace deadmantfa\yii2\oauth2\server\models;

use yii\db\ActiveQuery;

class RefreshTokenQuery extends ActiveQuery
{
    use EntityQueryTrait, TokenQueryTrait;
}
