# jwt
Simple Laravel/Symfony JWT authorization service

see https://packagist.org/packages/viktorf/jwt

## installation
```bash
composer require viktorf/jwt
``` 
For Laravel just add `JWT\JWTServiceProvider` to proper section of `config/app.php` or register it in `AppServiceProvider.php` 
and then use `AuthenticateWithJWT` middleware. After `JWTServiceProvider` registration you can publish vendor config:
```bash
php artisan vendor:publish --provider="JWT\JWTServiceProvider" --tag="config"
``` 

All classes in `JWT\Service` can be extended to expand their logic.
For example, you can replace `JWTReceiver` & `JWTService` in middleware constructor with their descendants using DI.

## using

```php
$secret = 'some jwt secret';
$token  = 'some jwt token';
$service = new \JWT\Service\JWTService($secret);

// Callback is not mandatory, you can just skip it in authenticate() call
$callback = function (JWT\Service\JWTHeader $header, JWT\Service\JWTPayload $payload) 
{
    if (empty($payload->customField)) {
        throw new \JWT\Exception\JWTException("JWT token is invalid: \$payload->customField is needed");
    }
    log("JWT custom field retrieved: " . $payload->customField);
};

try {
    $this->jwtService->authenticate($token, $callback);
} catch (JWT\Exception\JWTException $exception) {
    throw new HttpException('Access denied', 403, $exception);
} catch (Throwable $error) {
    throw new HttpException('Internal server error', 500, $error);
}
```

## extending
```php
class ExtraJWTPayload extends \JWT\Service\JWTPayload
{
    public string $customField = '';

    public function isValid() : bool
    {
        if (empty($this->customField)) {
            return false;
        }
        return true;
    }
}

class ExtraJWTService extends \JWT\Service\JWTService
{
    protected function getPayloadClass() : string
    {
        return ExtraJWTPayload::class;
    }
}
```
