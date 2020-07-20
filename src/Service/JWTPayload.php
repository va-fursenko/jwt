<?php

namespace JWT\Service;

use JWT\Exception\JWTException;

/**
 * Class JWTPayload
 * @package JWT\Service
 *
 * JWT payload
 *
 * @project viktorf/jwt
 * @date 20.07.2020 15:01
 * @author Viktor.Fursenko
 *
 * @see https://ru.wikipedia.org/wiki/JSON_Web_Token
 */
class JWTPayload
{
    /**
     * Identifies principal that issued the JWT
     *
     * @var string
     */
    public string $iss;

    /**
     * Identifies the subject of the JWT
     *
     * @var string
     */
    public string $sub;

    /**
     * Identifies the recipients that the JWT is intended for
     *
     * @var string
     */
    public string $aud;

    /**
     * Unix Time when the token expires (get invalid)
     *
     * @var int
     */
    public int $exp;

    /**
     * Unix Time when the token becomes active (valid)
     *
     * @var int
     */
    public int $nbf;

    /**
     * Case sensitive unique identifier of the token even among different issuers
     *
     * @var string
     */
    public string $jti;

    /**
     * Token creation Unix Time
     *
     * @var int
     */
    public int $iat;

    /**
     * JWTPayload constructor
     *
     * @param string $json
     * @throws JWTException
     */
    public function __construct(string $json = '')
    {
        if (!$json) {
            return;
        }
        if (!$data = json_decode($json)) {
            throw new JWTException("Bad json: '$json'");
        }
        foreach ($data as $field => $value) {
            $this->$field = $value;
        }
    }

    /**
     * Payload active flag
     *
     * @return bool
     */
    public function isActive() : bool
    {
        $time = time();
        return (!property_exists($this, 'exp') || $time < $this->exp)  // Not expired yet
            && (!property_exists($this, 'hbf') || $this->nbf <=$time)  // Already active
            && (!property_exists($this, 'iat') || $this->iat <=$time); // Creation date is in the past
    }

    /**
     * Payload extra-validation
     *
     * @return bool
     */
    public function isValid() : bool
    {
        // extend this class and overwrite this method
        return true;
    }
}
