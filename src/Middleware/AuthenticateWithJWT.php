<?php

namespace JWT\Middleware;

use Closure;
use HttpException;
use JWT\Exception\JWTException;
use JWT\Service\JWTReceiver;
use Symfony\Component\HttpFoundation\Request;
use JWT\Service\JWTService;
use Throwable;

/**
 * Class AuthenticateWithJWT
 * @package JWT\Middleware
 *
 * JWT authentication Laravel middleware
 *
 * @project viktorf/jwt
 * @date 20.07.2020 13:52
 * @author Viktor.Fursenko
 */
class AuthenticateWithJWT
{
    /**
     * @var JWTReceiver
     */
    private JWTReceiver $jwtReceiver;


    /**
     * @var JWTService
     */
    private JWTService $jwtService;

    /**
     * AuthenticateWithJWT constructor
     *
     * @param JWTReceiver $jwtReceiver
     * @param JWTService  $jwtService
     */
    public function __construct(JWTReceiver $jwtReceiver, JWTService $jwtService)
    {
        $this->jwtReceiver = $jwtReceiver;
        $this->jwtService  = $jwtService;
    }

    /**
     * Handle an incoming request.
     *
     * @param Request $request
     * @param Closure $next
     * @return mixed
     * @throws HttpException
     */
    public function handle($request, Closure $next)
    {
        try {
            $token = $this->jwtReceiver->getToken($request);
            $this->jwtService->authenticate($token);
            return $next($request);
        } catch (JWTException $exception) {
            throw new HttpException('Access denied', 403, $exception);
        } catch (Throwable $error) {
            throw new HttpException('Internal server error', 500, $error);
        }
    }
}
