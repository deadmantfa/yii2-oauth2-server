# Yii2 OAuth2 Server (PHP 8+ & League v9 Ready)

This is a fork of the original [`chervand/yii2-oauth2-server`](https://github.com/chervand/yii2-oauth2-server) plugin, updated for **PHP 8+**, **league/oauth2-server ^9.1**, and additional custom grants (including optional support for MAC tokens, token revocation, and more).

It provides:

- A **standards-compliant** [OAuth2.0 Server](https://tools.ietf.org/html/rfc6749) for Yii2
- **Refresh token** support (RFC6749 / [RFC7009](https://tools.ietf.org/html/rfc7009))
- **MAC token** support (experimental, [draft-ietf-oauth-v2-http-mac-05](https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-05))
- **Token revocation** endpoints
- **Flexible** DB-based migrations for storing OAuth2 clients, tokens, scopes, etc.
- Easy integration with your **Yii2 `user` component** so you can unify login states and roles.

## 1. Installation

Add this package to your project:

```bash
composer require deadmantfa/yii2-oauth2-server
```

### 1.1 Apply DB Migrations
Run:
```bash
./yii migrate --migrationPath="@vendor/deadmantfa/yii2-oauth2-server/migrations"
```
This creates the default OAuth2-related tables (clients, tokens, scopes, etc.).

### 1.2 Generate Public & Private Keys
Follow [League’s official](https://oauth2.thephpleague.com/installation/) instructions for generating private/public keys. Typically:
```bash
openssl genrsa -out private.key 2048
openssl rsa -in private.key -pubout -out public.key
```
Store them somewhere safe (e.g. @app/oauth2/private.key, @app/oauth2/public.key).

## 2. Basic Configuration
Below is a simple example of how to configure the module in your config/main.php (or similar file).
```php
return [
    // ...
    'bootstrap' => [
        'oauth2', // ensures module is bootstrapped
        // ...
    ],
    'modules' => [
        'oauth2' => [
            'class' => \deadmantfa\yii2\oauth2\server\Module::class,
            
            // Your key file paths:
            'privateKey' => __DIR__ . '/../oauth2/private.key',
            'publicKey'  => __DIR__ . '/../oauth2/public.key',

            // Encryption key used for JWT, typically 32+ bytes
            'encryptionKey' => 'some-random-binary-string',
            
            // Example: define any custom Repositories or model classes
            'components' => [
                'accessTokenRepository' => [
                    'class' => \deadmantfa\yii2\oauth2\server\components\Repositories\AccessTokenRepository::class,
                ],
                'refreshTokenRepository' => [
                    'class' => \deadmantfa\yii2\oauth2\server\components\Repositories\RefreshTokenRepository::class,
                ],
                'clientRepository' => [
                    'class' => \deadmantfa\yii2\oauth2\server\components\Repositories\ClientRepository::class,
                ],
                'scopeRepository' => [
                    'class' => \deadmantfa\yii2\oauth2\server\components\Repositories\ScopeRepository::class,
                ],
                // ...
            ],

            // Optional caching logic for repositories
            'cache' => [
                \League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface::class => [
                    'cacheDuration' => 3600,
                    'cacheDependency' => new \yii\caching\FileDependency(['fileName' => 'AccessTokenRepoCache.txt']),
                ],
                // ...
            ],

            // Register the grant types you want
            'enableGrantTypes' => static function (\deadmantfa\yii2\oauth2\server\Module $module) {
                $server = $module->authorizationServer;
                
                // Password + Refresh Token Grant
                $passwordGrant = new \League\OAuth2\Server\Grant\PasswordGrant(
                    $module->getComponent('userRepository'),
                    $module->getComponent('refreshTokenRepository')
                );
                $passwordGrant->setRefreshTokenTTL(new \DateInterval('P1M'));
                $server->enableGrantType($passwordGrant, new \DateInterval('PT1H'));

                // Client Credentials
                $server->enableGrantType(new \League\OAuth2\Server\Grant\ClientCredentialsGrant());
                
                // Refresh Token
                $refreshGrant = new \League\OAuth2\Server\Grant\RefreshTokenGrant(
                    $module->getComponent('refreshTokenRepository')
                );
                $refreshGrant->setRefreshTokenTTL(new \DateInterval('P1M'));
                $server->enableGrantType($refreshGrant, new \DateInterval('PT1H'));

                // (Optional) Revoke Grant
                $server->enableGrantType(new \deadmantfa\yii2\oauth2\server\components\Grant\RevokeGrant(
                    $module->getComponent('refreshTokenRepository'),
                    $module->publicKey
                ));
            },
        ],
    ],
    // ...
];

```

That’s enough to spin up the Authorization Server portion. You’ll have endpoints like:
- ```POST /oauth2/token``` (to exchange credentials for tokens)
- ```POST /oauth2/revoke``` (to revoke a token, if you enabled RevokeGrant)

## 3. Integrating with Your user Component
### 3.1 Provide a ```UserRepositoryInterface```
In League OAuth2, you need a repository that implements ```UserRepositoryInterface```. Typically, you can have your user model implement ```UserEntityInterface``` and provide a ```getUserEntityByUserCredentials()``` method:
```php
class MyUserRepository implements UserRepositoryInterface
{
    public function getUserEntityByUserCredentials($username, $password, $grantType, ClientEntityInterface $clientEntity)
    {
        $user = User::findOne(['username' => $username]);
        if (!$user || !Yii::$app->security->validatePassword($password, $user->password_hash)) {
            return null;
        }
        return $user; // which implements UserEntityInterface
    }
}
```

### 3.2 Linking to Your ``Identity`` in Yii2
If you want to unify your “OAuth2 user ID” with your standard Yii user identity:
1. In ```config/main.php```, set ```'identityClass' => MyUser::class``` in your user component.
2. Ensure your model has ```getId()``` returning the correct user identifier.
3. Make sure the above repository uses that same model.

## 4. Resource Server (Protecting Your API)
To validate tokens in your controllers, attach an authenticator that checks the ```Authorization: Bearer <token>``` header. For example:
```php
class MyApiController extends \yii\rest\ActiveController
{
    public function behaviors()
    {
        $behaviors = parent::behaviors();

        unset($behaviors['authenticator']);
        unset($behaviors['rateLimiter']);

        /** @var \deadmantfa\yii2\oauth2\server\Module $auth */
        $auth = Yii::$app->getModule('oauth2');

        $behaviors['authenticator'] = [
            'class' => \yii\filters\auth\CompositeAuth::class,
            'authMethods' => [
                [
                    'class' => \deadmantfa\yii2\oauth2\server\components\AuthMethods\HttpBearerAuth::class,
                    'publicKey' => $auth->publicKey,
                    'cache'     => $auth->cache,
                ],
                // or add Mac tokens:
                // [
                //   'class' => \deadmantfa\yii2\oauth2\server\components\AuthMethods\HttpMacAuth::class,
                // ],
            ],
        ];

        $behaviors['rateLimiter'] = [
            'class' => \yii\filters\RateLimiter::class,
        ];

        return $behaviors;
    }
}

```

Any requests with an invalid or no token get a 401 response.

## 5. MAC Tokens (Optional)
If you want [MAC tokens](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-http-mac-05) (still a draft), you can enable them by adding:
```php
use \deadmantfa\yii2\oauth2\server\components\AuthMethods\HttpMacAuth;

$behaviors['authenticator'] = [
    'class' => \yii\filters\auth\CompositeAuth::class,
    'authMethods' => [
        [
            'class' => HttpMacAuth::class,
            'publicKey' => $auth->publicKey,
            'cache' => $auth->cache,
        ],
    ],
];
```
And in your module’s ```enableGrantTypes```, you can enable a ```MacTokenResponse``` instead of ```BearerTokenResponse```.

## 6. Revoke Tokens (RFC7009)
Add the ```RevokeGrant``` in ```enableGrantTypes```:
```php
$server->enableGrantType(
    new \deadmantfa\yii2\oauth2\server\components\Grant\RevokeGrant(
        $module->refreshTokenRepository,
        $module->publicKey
    )
);
```
Then request:
```bash
POST /oauth2/revoke
Authorization: Basic <client_id:client_secret base64>
Content-Type: application/json

{
  "token": "<refresh_token or access_token>"
}
```
The plugin revokes tokens in the DB. The next time the resource server checks that token, it’s marked invalid.

## 7. Additional Notes
- For custom grants (like a ```FirebaseGrant``` or a ```PasswordlessGrant```), implement ```GrantTypeInterface``` or extend ```AbstractGrant``` and register it in ```enableGrantTypes```.
- You can store user IDs as UUID strings or integers. Just ensure your ```UserEntityInterface::getIdentifier()``` returns a string that the library can embed in the token.
- The library handles JWT signing/verification, so you just need to provide your private/public RSA keys.

