<?php

namespace JWT\Service;

use JWT\Exception\JWTException;

/**
 * Class JWTHeader
 * @package JWT\Service
 *
 * JWT header
 *
 * @project viktorf/jwt
 * @date 20.07.2020 15:01
 * @author Viktor.Fursenko
 *
 * @see https://ru.wikipedia.org/wiki/JSON_Web_Token
 */
class JWTHeader
{
    /**
     * Mandatory field
     * Identifies which algorithm is used to generate the signature
     *
     * @var string
     */
    public string $alg = 'HS256';

    /**
     * If present, it is recommended to set this to JWT
     *
     * @var string
     */
    public string $typ = 'JWT';

    /**
     * If nested signing or encryption is employed, it is recommended to set this to JWT; otherwise, omit this field
     *
     * @var string
     */
    public string $cty;

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
        if (!$this->alg) {
            throw new JWTException("Field 'alg' is mandatory");
        }
    }
}
