<!-- markdownlint-disable no-inline-html -->
<p align="center">
  <br><br>
  <img src="https://leafphp.netlify.app/assets/img/leaf3-logo.png" height="100"/>
  <h1 align="center">Leaf Cors Module</h1>
  <br><br>
</p>

# Leaf PHP

[![Latest Stable Version](https://poser.pugx.org/leafs/cors/v/stable)](https://packagist.org/packages/leafs/cors)
[![Total Downloads](https://poser.pugx.org/leafs/cors/downloads)](https://packagist.org/packages/leafs/cors)
[![License](https://poser.pugx.org/leafs/cors/license)](https://packagist.org/packages/leafs/cors)

This is a [Leaf PHP](https://leafphp.netlify.app/) module used to enable and configure [CORS](http://en.wikipedia.org/wiki/Cross-origin_resource_sharing) with various options. This module can be used both in and out of Leaf and so can be considered a general module. It is also inspired by the [ExpressJS](https://github.com/expressjs/express) [cors package](https://github.com/expressjs/cors).

## Installation

You can easily install it using [leaf cli](https://cli.leafphp.dev)

```sh
leaf install cors
```

or with [Composer](https://getcomposer.org/):

```bash
composer require leafs/cors
```

## Usage

After installing the cors module, the cors module is automatically linked to the leaf app and can be used directly without referencing it anywhere.

### Simple Usage (Enable *All* CORS Requests)

```php
require __DIR__ . "/vendor/autoload.php";

$app = new Leaf\App;

$app->cors();

$app->get('/products/{id}', function () use($app) {
  $app->response()->json(['message' => 'This is CORS-enabled for all origins!']);
});

$app->run();
```

You can alternatively call `Leaf\Http\Cors::config()` instead of `$app->cors()` in the example above.

### Configuring CORS

```php
require __DIR__ . '/vendor/autoload.php';

$app = new Leaf\App;

$app->cors([
  'origin' => 'http://example.com',
  'optionsSuccessStatus' => 200 // some legacy browsers (IE11, various SmartTVs) choke on 204
]);

$app->get('/products/{id}', function () use($app) {
  $app->response()->json(['message' => 'This is CORS-enabled for all origins!']);
});

$app->run();
```

## Configuration Options

* `origin`: Configures the **Access-Control-Allow-Origin** CORS header. Possible values:
  * `String` - set `origin` to a specific origin. For example if you set it to `"http://example.com"` only requests from "http://example.com" will be allowed.
  * `RegExp (in string form)` - set `origin` to a regular expression pattern which will be used to test the request origin. If it's a match, the request origin will be reflected. For example the pattern `'/example\.com$/'` will reflect any request that is coming from an origin ending with "example.com".
  * `Array` - set `origin` to an array of valid origins. Each origin can be a `String` or a `RegExp`. For example `["http://example1.com", '/\.example2\.com$/']` will accept any request from "http://example1.com" or from a subdomain of "example2.com".
  * `Function` - set `origin` to a function implementing some custom logic. The function takes the request origin as the first parameter and a callback (called as `callback(err, origin)`, where `origin` is a non-function value of the `origin` option) as the second.
* `methods`: Configures the **Access-Control-Allow-Methods** CORS header. Expects a comma-delimited string (ex: 'GET,PUT,POST') or an array (ex: `['GET', 'PUT', 'POST']`).
* `allowedHeaders`: Configures the **Access-Control-Allow-Headers** CORS header. Expects a comma-delimited string (ex: 'Content-Type,Authorization') or an array (ex: `['Content-Type', 'Authorization']`). If not specified, defaults to reflecting the headers specified in the request's **Access-Control-Request-Headers** header.
* `exposedHeaders`: Configures the **Access-Control-Expose-Headers** CORS header. Expects a comma-delimited string (ex: 'Content-Range,X-Content-Range') or an array (ex: `['Content-Range', 'X-Content-Range']`). If not specified, no custom headers are exposed.
* `credentials`: Configures the **Access-Control-Allow-Credentials** CORS header. Set to `true` to pass the header, otherwise it is omitted.
* `maxAge`: Configures the **Access-Control-Max-Age** CORS header. Set to an integer to pass the header, otherwise it is omitted.
* `preflightContinue`: Pass the CORS preflight response to the next handler.
* `optionsSuccessStatus`: Provides a status code to use for successful `OPTIONS` requests, since some legacy browsers (IE11, various SmartTVs) choke on `204`.

The default configuration is the equivalent of:

```json
{
  "origin": "*",
  "methods": "GET,HEAD,PUT,PATCH,POST,DELETE",
  "allowedHeaders": "*",
  "exposedHeaders": "",
  "credentials": false,
  "maxAge": null,
  "preflightContinue": false,
  "optionsSuccessStatus": 204,
}
```

## View Leaf's docs [here](https://leafphp.netlify.app/#/)

Built with ❤ by [**Mychi Darko**](https://mychi.netlify.app)
