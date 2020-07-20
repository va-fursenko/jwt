<?php

namespace JWT\Service;

use JWT\Exception\JWTException;
use Symfony\Component\HttpFoundation\Request;

/**
 * Class JWTReceiver
 * @package JWT\Service
 *
 * JWT token receiver
 *
 * @project viktorf/jwt
 * @date 20.07.2020 16:04
 * @author Viktor.Fursenko
 */
class JWTReceiver
{
    /**
     * Header token prefix
     *
     * @var string
     */
    protected string $headerPrefix;

    /**
     * Header token name
     *
     * @var string
     */
    protected string $headerName;

    /**
     * JWTReceiver constructor
     *
     * @param string $headerPrefix
     * @param string $headerName
     */
    public function __construct(string $headerPrefix = 'Bearer', string $headerName = 'Authorization')
    {
        $this->headerPrefix = $headerPrefix;
        $this->headerName = $headerName;
    }

    /**
     * Get token from Request instance
     *
     * @param Request $request
     * @return string
     * @throws JWTException
     */
    public function getToken(Request $request) : string
    {
        if (!$header = $request->headers->get($this->headerName, null)) {
            throw new JWTException("JWT header '{$this->headerName}' not found in request");
        }
        return $this->formatToken($header);
    }

    /**
     * Authorization header formatting to retrieve pure token without prefix
     *
     * @param string|null $header
     * @return string
     * @throws JWTException
     */
    protected function formatToken(string $header) : string
    {
        if (!$this->headerPrefix) { // if there is no prefix
            return $header;
        }
        $token = preg_replace("/^{$this->headerPrefix} /", '', $header);
        if ($token == $header) {
            throw new JWTException("JWT token is invalid: prefix '{$this->headerPrefix}' not found");
        }
        return $token;
    }
}