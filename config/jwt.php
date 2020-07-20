<?php

return [
    'key'    => env('JWT_KEY', null),
    'ttl'    => (int)env('JWT_TTL', 60),
    'prefix' => env('JWT_HEADER_PREFIX', 'Bearer'),
    'header' => env('JWT_HEADER_NAME', 'Authorization'),
];
