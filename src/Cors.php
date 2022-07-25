<?php

namespace Leaf\Http;

/**
 * Leaf CORS Module
 * -------
 * CORS simplified. Enable CORS with various options.
 * Inspired by Express JS' CORS package.
 * 
 * @version 1.0.1
 * @since 3.0-beta
 */
class Cors
{
	protected static $config = [];

	protected static $defaultConfig = [
		'origin' => '*',
		'methods' => 'GET,HEAD,PUT,PATCH,POST,DELETE',
		'headers' => '*',
		'exposedHeaders' => '',
		'credentials' => false,
		'maxAge' => null,
		'preflightContinue' => false,
		'optionsSuccessStatus' => 204,
	];

	public static function config($config = [])
	{
		static::$config = array_merge(static::$defaultConfig, $config);

		static::configureOrigin();
		static::configureHeaders();
		static::configureExposedHeaders();
		static::configureMaxAge();
		static::configureCredentials();
		static::configureMethods();

		if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
			if (static::$config['preflightContinue']) {
				// skip to code
			} else {
				exit(0);
			}
		}
	}

	protected static function configureMethods()
	{
		if (is_array(static::$config['methods'])) {
			static::$config['methods'] = implode(',', static::$config['methods']);
		}

		Headers::accessControl('Allow-Methods', static::$config['methods']);
	}

	protected static function configureOrigin()
	{
		$origin = static::$config['origin'];

		// if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS' && static::$config['optionsSuccessRequest'] == '204') {
		// 	// Safari (and potentially other browsers) need content-length 0,
		// 	// for 204 or they just hang waiting for a body
		// 	Headers::set('Content-Length', '0');
		// }

		if (static::isOriginAllowed($origin)) {
			Headers::accessControl(
				'Allow-Origin',
				$_SERVER['HTTP_ORIGIN'] ?? $_SERVER['HTTP_HOST']
			);
		}

		if ($origin !== '*') {
			Headers::set('Vary', 'Origin');
		}
	}

	protected static function configureHeaders()
	{
		$headers = static::$config['headers'];

		if (!$headers) {
			// .headers wasn't specified, so reflect the request headers
			$headers = Headers::get('access-control-request-headers');
			Headers::set('Vary', 'Access-Control-Request-Headers');
		}

		if ($headers) {
			Headers::accessControl(
				'Allow-Headers',
				is_array($headers) ? implode(', ', $headers) : (strlen($headers) ? $headers : '*')
			);
		}
	}

	protected static function configureExposedHeaders()
	{
		$headers = static::$config['exposedHeaders'];

		if ($headers) {
			Headers::accessControl(
				'Expose-Headers',
				is_array($headers) ? implode(', ', $headers) : $headers
			);
		}
	}

	protected static function configureMaxAge()
	{
		if (static::$config['maxAge']) {
			Headers::accessControl(
				'Max-Age',
				static::$config['maxAge']
			);
		}
	}

	protected static function configureCredentials()
	{
		if (static::$config['credentials'] === true) {
			Headers::accessControl('Allow-Credentials', 'true');
		}
	}

	protected static function isOriginAllowed($allowedOrigin)
	{
		$origin = $_SERVER['HTTP_ORIGIN'] ?? $_SERVER['HTTP_HOST'];
		
		if (is_array($allowedOrigin)) {
			for ($i = 0; $i < count($allowedOrigin); $i++) {
				if (static::isOriginAllowed($allowedOrigin[$i])) {
					return true;
				}
			}

			return false;
		} else if (is_string($allowedOrigin)) {
			if ($allowedOrigin === "*" || $origin === $allowedOrigin) {
				return true;
			}

			return preg_match($allowedOrigin, $origin) !== false;
		}
	}
}
