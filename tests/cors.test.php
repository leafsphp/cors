<?php

declare(strict_types=1);

beforeEach(function () {
    unset($_SERVER['HTTP_ORIGIN'], $_SERVER['HTTP_HOST']);
    $_SERVER['REQUEST_METHOD'] = 'GET';
});

afterEach(function () {
    unset($_SERVER['HTTP_ORIGIN'], $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_METHOD']);
});

test('wildcard origin allows any origin', function () {
    $_SERVER['HTTP_ORIGIN'] = 'https://anything.example.dev';

    expect(corsIsOriginAllowed('*'))->toBeTrue();
});

test('exact string origin allows only that exact origin', function () {
    $_SERVER['HTTP_ORIGIN'] = 'https://example.com';

    expect(corsIsOriginAllowed('https://example.com'))->toBeTrue();
});

test('exact string origin rejects suffix-spoofed origin', function () {
    $_SERVER['HTTP_ORIGIN'] = 'https://example.com.evil.com';

    expect(corsIsOriginAllowed('https://example.com'))->toBeFalse();
});

test('exact string origin rejects origin embedding the allowed origin in its path', function () {
    $_SERVER['HTTP_ORIGIN'] = 'https://evil.com/https://example.com';

    expect(corsIsOriginAllowed('https://example.com'))->toBeFalse();
});

test('exact string origin rejects a prefix of the allowed origin', function () {
    $_SERVER['HTTP_ORIGIN'] = 'https://example.co';

    expect(corsIsOriginAllowed('https://example.com'))->toBeFalse();
});

test('array of origins matches a non-first entry', function () {
    $_SERVER['HTTP_ORIGIN'] = 'https://second.com';

    expect(corsIsOriginAllowed(['https://first.com', 'https://second.com']))->toBeTrue();
});

test('array of origins with no match returns false', function () {
    $_SERVER['HTTP_ORIGIN'] = 'https://third.com';

    expect(corsIsOriginAllowed(['https://first.com', 'https://second.com']))->toBeFalse();
});

test('regex origin allows matching subdomain', function () {
    $_SERVER['HTTP_ORIGIN'] = 'https://api.example.com';

    expect(corsIsOriginAllowed('/^https:\/\/(.*\.)?example\.com$/i'))->toBeTrue();
});

test('regex origin rejects non-matching origin', function () {
    $_SERVER['HTTP_ORIGIN'] = 'https://evil.com';

    expect(corsIsOriginAllowed('/^https:\/\/(.*\.)?example\.com$/i'))->toBeFalse();
});

test('non-string non-array allowed origins return false without errors', function () {
    $_SERVER['HTTP_ORIGIN'] = 'https://example.com';

    expect(corsIsOriginAllowed(null))->toBeFalse();
    expect(corsIsOriginAllowed(42))->toBeFalse();
    expect(corsIsOriginAllowed(true))->toBeFalse();
});

test('missing HTTP_ORIGIN falls back to HTTP_HOST', function () {
    $_SERVER['HTTP_HOST'] = 'example.com';

    expect(corsIsOriginAllowed('example.com'))->toBeTrue();
    expect(corsIsOriginAllowed('other.com'))->toBeFalse();
});

test('config merges user config with defaults on a non-OPTIONS request', function () {
    $_SERVER['REQUEST_METHOD'] = 'GET';

    \Leaf\Http\Cors::config(['origin' => 'https://example.com', 'credentials' => true]);

    $config = corsConfig();

    expect($config['origin'])->toBe('https://example.com');
    expect($config['credentials'])->toBeTrue();
    expect($config['methods'])->toBe('GET,HEAD,PUT,PATCH,POST,DELETE');
    expect($config['allowedHeaders'])->toBe('*');
    expect($config['preflightContinue'])->toBeFalse();
    expect($config['optionsSuccessStatus'])->toBe(204);
});

test('config implodes a methods array to a comma-separated string', function () {
    $_SERVER['REQUEST_METHOD'] = 'GET';

    \Leaf\Http\Cors::config(['methods' => ['GET', 'POST', 'PUT']]);

    expect(corsConfig()['methods'])->toBe('GET,POST,PUT');
});

test('config with preflightContinue does not exit on OPTIONS requests', function () {
    $_SERVER['REQUEST_METHOD'] = 'OPTIONS';

    \Leaf\Http\Cors::config(['preflightContinue' => true]);

    expect(corsConfig()['preflightContinue'])->toBeTrue();
});
