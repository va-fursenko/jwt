<?php

namespace JWT\Service;

use JWT\Exception\JWTException;

/**
 * Class JWTService
 * @package JWT\Service
 *
 * Laravel|Symfony JWT authentication service
 *
 * @project viktorf/jwt
 * @date 20.07.2020 15:00
 * @author Viktor.Fursenko
 *
 * @see https://ru.wikipedia.org/wiki/JSON_Web_Token
 */
class JWTService
{
    public const ALGORITHM_HS256 = 'HS256';

    /**
     * Supported hash algorithms
     */
    protected const HASH_ALGOS = [
        self::ALGORITHM_HS256 => 'sha256',
    ];

    /**
     * @var string
     */
    private string $secret;

    /**
     * @var int|null
     */
    private ?int $ttl;

    /**
     * JWTService constructor
     *
     * @param string   $secret
     * @param int|null $ttl
     */
    public function __construct(string $secret, ?int $ttl = null)
    {
        $this->secret = $secret;
        $this->ttl    = $ttl;
    }

    /**
     * Token authentication with JWTException exception in case of fail
     *
     * @param string        $token
     * @param callable|null $callback Custom callback validation|authentication. Runs before final signatures comparison
     *                                function(JWTHeader $header, JWTPayload $payload) : void
     * @throws JWTException
     */
    public function authenticate(string $token, ?callable $callback = null) : void
    {
        // Get token parts and validate it
        [$tokenHeader, $tokenPayload, $signature] = array_pad(explode('.', $token), 3, null);
        if (!$tokenHeader || $tokenPayload || !$signature) {
            throw new JWTException("JWT token is invalid: bad structure");
        }
        // Decode header and payload
        $header = $this->decodeHeader($tokenHeader);
        $payload = $this->decodePayload($tokenPayload);
        if (!$payload->isActive() || !$payload->isValid()) {
            throw new JWTException("JWT token is invalid: expired or not active yet");
        }
        // Extra-validation with custom callback
        if ($callback) {
            $callback($header, $payload);
        }
        // Construct our token and compare with retrieved
        if ($this->getUnsignedToken($header, $payload) !== $signature) {
            throw new JWTException("JWT token is invalid: signature mismatch");
        }
    }

    /**
     * New signed token generation
     *
     * @param int      $ttl
     * @param string   $algorithm
     * @param string[] $extra
     * @return string
     * @throws JWTException
     */
    public function generateToken(int $ttl = 60, string $algorithm = self::ALGORITHM_HS256, array $extra = []) : string
    {
        $header = $this->generateHeader($algorithm);
        $payload = $this->generatePayload($ttl ?? $this->ttl, $extra);
        return $this->getToken($header, $payload);
    }

    /**
     * Missing php function realization
     *
     * @param string $data
     * @return string
     */
    final protected function base64UrlEncode(string $data) : string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    }

    /**
     * String hashing with provided algorithm
     *
     * @param string $data
     * @param string $algorithm
     * @return string
     * @throws JWTException
     */
    protected function hash(string $data, string $algorithm) : string
    {
        return hash_hmac($this->getHashAlgorithm($algorithm), $data, $this->secret, true);
    }

    /**
     * Hash algorithm selection
     *
     * @param string $algorithmAlias Algorithm alias provided in JWT-token
     * @return string
     * @throws JWTException
     */
    protected function getHashAlgorithm(string $algorithmAlias) : string
    {
        if (empty(static::HASH_ALGOS[$algorithmAlias])) {
            throw new JWTException("Unknown or unsupported hash algorithm: '$algorithmAlias'");
        }
        return static::HASH_ALGOS[$algorithmAlias];
    }

    /**
     * Unsigned JWT-token generation
     *
     * @param JWTHeader  $header
     * @param JWTPayload $payload
     * @return string
     */
    protected function getUnsignedToken(JWTHeader $header, JWTPayload $payload) : string
    {
        return $this->base64UrlEncode(json_encode($header)) . '.' . $this->base64UrlEncode(json_encode($payload));
    }

    /**
     * JWT signature generation
     *
     * @param string $unsignedToken
     * @param string $algo
     * @return string
     * @throws JWTException
     */
    protected function getSignature(string $unsignedToken, string $algo) : string
    {
        $newSignature = $this->hash($unsignedToken, $algo);
        return $this->base64UrlEncode($newSignature);
    }

    /**
     * JWT signed token generation
     *
     * @param JWTHeader  $header
     * @param JWTPayload $payload
     * @return string
     * @throws JWTException
     */
    protected function getToken(JWTHeader $header, JWTPayload $payload) : string
    {
        $unsignedToken = $this->getUnsignedToken($header, $payload);
        return $unsignedToken . '.' . $this->getSignature($unsignedToken, $header->alg);
    }

    /**
     * Payload generation
     *
     * @param int   $ttl
     * @param array $extra
     * @return JWTPayload
     * @throws JWTException
     */
    protected function generatePayload(int $ttl, array $extra = []) : JWTPayload
    {
        /** @var JWTPayload $classname */
        $classname = $this->getPayloadClass();
        $payload = new $classname();
        $payload->iat = time();
        $payload->exp = $payload->iat + $ttl;
        $payload->jti = md5($payload->iat . '!' . rand(0, 10000000));
        foreach ($extra as $field => $value) {
            $payload->$field = $value;
        }
        return $payload;
    }

    /**
     * Header generation
     *
     * @param string $algorithm
     * @return JWTHeader
     * @throws JWTException
     */
    protected function generateHeader(string $algorithm = self::ALGORITHM_HS256) : JWTHeader
    {
        /** @var JWTHeader $classname */
        $classname = $this->getHeaderClass();
        $header = new $classname();
        $header->alg = $algorithm;
        return $header;
    }

    /**
     * Header decode from retrieved token
     *
     * @param string $tokenHeader
     * @return JWTHeader
     * @throws JWTException
     */
    protected function decodeHeader(string $tokenHeader) : JWTHeader
    {
        /** @var JWTHeader $classname */
        $classname = $this->getHeaderClass();
        return new $classname(base64_decode($tokenHeader));
    }

    /**
     * Payload decode from retrieved token
     *
     * @param string $tokenPayload
     * @return JWTPayload
     * @throws JWTException
     */
    protected function decodePayload(string $tokenPayload) : JWTPayload
    {
        /** @var JWTPayload $classname */
        $classname = $this->getPayloadClass();
        return new $classname(base64_decode($tokenPayload));
    }

    /**
     * Header class getter
     *
     * @return string
     */
    protected function getHeaderClass() : string
    {
        return JWTHeader::class;
    }

    /**
     * Payload class getter
     *
     * @return string|JWTPayload
     */
    protected function getPayloadClass() : string
    {
        return JWTPayload::class;
    }
}
