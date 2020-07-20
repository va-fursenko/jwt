<?php

namespace JWT;

use Illuminate\Support\ServiceProvider;
use Illuminate\Contracts\Support\DeferrableProvider;
use JWT\Service\JWTReceiver;
use JWT\Service\JWTService;
use Patrikap\Hmac\Services\HmacService;
use Patrikap\Hmac\Console\Commands\HmacGenerateCommand;

/**
 * Class JWTServiceProvider
 * @package JWT
 *
 * Laravel service-provider for JWTService & JWTReceiver
 *
 * @project jwt
 * @date 20.07.2020 16:29
 * @author Viktor.Fursenko
 */
class JWTServiceProvider extends ServiceProvider implements DeferrableProvider
{
    private const CONFIG_PATH = __DIR__ . '/../config/';
    private const CONFIG_NAME = 'jwt.php';

    /**
     * @inheritDoc
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes(
                [
                    self::CONFIG_PATH . self::CONFIG_NAME => config_path(self::CONFIG_NAME),
                ],
                'config'
            );
        }
    }

    /**
     * @inheritDoc
     */
    public function register(): void
    {
        $this->mergeConfigFrom(self::CONFIG_PATH . self::CONFIG_NAME, 'jwt');
        $this->app->bind(JWTService::class, function ($app, $params = []) {
            $config = array_merge(config('jwt'), $params);
            return new JWTService($config['key'], $config['ttl']);
        });
        $this->app->bind(JWTReceiver::class, function ($app, $params = []) {
            $config = array_merge(config('jwt'), $params);
            return new JWTReceiver($config['prefix'], $config['header']);
        });
    }

    /** @inheritDoc */
    public function provides(): array
    {
        return [JWTService::class, JWTReceiver::class];
    }

}
