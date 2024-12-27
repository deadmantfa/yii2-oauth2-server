<?php

namespace deadmantfa\yii2\oauth2\server\rbac;

interface OwnedQueryInterface
{
    public function owned($value, $field, $strict);
}
