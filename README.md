# ACMECert

PHP client library for [Let's Encrypt](https://letsencrypt.org/) ([ACME v2 - RFC 8555](https://tools.ietf.org/html/rfc8555))  
Version: 2.8

## Description

ACMECert is designed to help you to setup an automated SSL/TLS-certificate/renewal process
with a few lines of PHP.

It is self contained and contains a set of functions allowing you to:

- generate [RSA](#acmecertgeneratersakey) / [EC (Elliptic Curve)](#acmecertgenerateeckey) keys
- manage account: [register](#acmecertregister)/[update](#acmecertupdate)/[deactivate](#acmecertdeactivateaccount) and [account key roll-over](#acmecertkeychange)
- [get](#acmecertgetcertificatechain)/[revoke](#acmecertrevoke) certificates (to renew a certificate just get a new one)
- [parse certificates](#acmecertparsecertificate) / get the [remaining days](#acmecertgetremainingdays) a certificate is still valid
> see [Function Reference](#function-reference) for a full list

It abstacts away the complexity of the ACME protocol to get a certificate
(create order, fetch authorizations, compute challenge tokens, polling for status, generate CSR,
finalize order, request certificate) into a single function [getCertificateChain](#acmecertgetcertificatechain),
where you specify a set of domains you want to get a certificate for and which challenge type to use (all [challenge types](https://letsencrypt.org/docs/challenge-types/) are supported).
This function takes as third argument a user-defined callback function which gets
invoked every time a challenge needs to be fulfilled. It is up to you to set/remove the challenge tokens:

```php
$handler=function($opts){
  // Write code to setup the challenge token here.

  // Return a function that gets called when the challenge token should be removed again:
  return function($opts){
    // Write code to remove previously setup challenge token.
  };
};

$ac->getCertificateChain(..., ..., $handler);
```
> see description of [getCertificateChain](#acmecertgetcertificatechain) for details about the callback function.
>
> also see the [Get Certificate](#get-certificate-using-http-01-challenge) examples below.

Instead of returning `FALSE` on error, every function in ACMECert throws an [Exception](http://php.net/manual/en/class.exception.php)
if it fails or an [ACME_Exception](#acme_exception) if the ACME-Server reponded with an error message.

## Requirements
- [x] PHP 5.3 or higher (for EC keys PHP 7.1 or higher is required)
- [x] [OpenSSL extension](https://www.php.net/manual/de/book.openssl.php)
- [x] enabled [fopen wrappers](https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-fopen) (allow_url_fopen=1) **or** [cURL extension](https://www.php.net/manual/en/book.curl.php)

## Usage Examples

#### Require ACMECert
```php
require 'ACMECert.php';
```

#### Choose Live or Staging Environment
> Live
```php
$ac=new ACMECert();
```
> Staging
```php
$ac=new ACMECert(false);
```

#### Generate RSA Private Key
```php
$key=$ac->generateRSAKey(2048);
file_put_contents('account_key.pem',$key);
```
> Equivalent to: `openssl genrsa -out account_key.pem 2048`

#### Generate EC Private Key
```php
$key=$ac->generateECKey('P-384');
file_put_contents('account_key.pem',$key);
```
> Equivalent to: `openssl ecparam -name secp384r1 -genkey -noout -out account_key.pem`

#### Register Account Key with Let's Encrypt
```php
$ac->loadAccountKey('file://'.'account_key.pem');
$ret=$ac->register(true,'info@example.com');
print_r($ret);
```

> **WARNING: By passing **TRUE** as first parameter of the register function you agree to the terms of service of Let's Encrypt. See [Let’s Encrypt Subscriber Agreement](https://letsencrypt.org/repository/) for more information.**

#### Get Account Information
```php
$ac->loadAccountKey('file://'.'account_key.pem');
$ret=$ac->getAccount();
print_r($ret);
```

#### Account Key Roll-over
```php
$ac->loadAccountKey('file://'.'account_key.pem');
$ret=$ac->keyChange('file://'.'new_account_key.pem');
print_r($ret);
```

#### Deactivate Account
```php
$ac->loadAccountKey('file://'.'account_key.pem');
$ret=$ac->deactivateAccount();
print_r($ret);
```

#### Revoke Certificate
```php
$ac->loadAccountKey('file://'.'account_key.pem');
$ac->revoke('file://'.'fullchain.pem');
```

#### Get Remaining Days
```php
$days=$ac->getRemainingDays('file://'.'fullchain.pem'); // certificate or certificate-chain
if ($days>30) { // renew 30 days before expiry
  die('Certificate still good, exiting..');
}
// get new certificate here..
```
> This allows you to run your renewal script without the need to time it exactly, just run it often enough. (cronjob)

#### Get Certificate using `http-01` challenge
```php
$ac->loadAccountKey('file://'.'account_key.pem');

$domain_config=array(
  'test1.example.com'=>array('challenge'=>'http-01','docroot'=>'/var/www/vhosts/test1.example.com'),
  'test2.example.com'=>array('challenge'=>'http-01','docroot'=>'/var/www/vhosts/test2.example.com')
);

$handler=function($opts){
  $fn=$opts['config']['docroot'].$opts['key'];
  @mkdir(dirname($fn),0777,true);
  file_put_contents($fn,$opts['value']);
  return function($opts){
    unlink($opts['config']['docroot'].$opts['key']);
  };
};

$fullchain=$ac->getCertificateChain('file://'.'cert_private_key.pem',$domain_config,$handler);
file_put_contents('fullchain.pem',$fullchain);
```


#### Get Certificate using all (`http-01`,`dns-01` and `tls-alpn-01`) challenge types together
```php
$ac->loadAccountKey('file://'.'account_key.pem');

$domain_config=array(
  'example.com'=>array('challenge'=>'http-01','docroot'=>'/var/www/vhosts/example.com'),
  '*.example.com'=>array('challenge'=>'dns-01'),
  'test.example.org'=>array('challenge'=>'tls-alpn-01')
);

$handler=function($opts) use ($ac){
  switch($opts['config']['challenge']){
    case 'http-01': // automatic example: challenge directory/file is created..
      $fn=$opts['config']['docroot'].$opts['key'];
      @mkdir(dirname($fn),0777,true);
      file_put_contents($fn,$opts['value']);
      return function($opts) use ($fn){ // ..and removed after validation completed
        unlink($fn);
      };
    break;
    case 'dns-01': // manual example:
      echo 'Create DNS-TXT-Record '.$opts['key'].' with value '.$opts['value']."\n";
      readline('Ready?');
      return function($opts){
        echo 'Remove DNS-TXT-Record '.$opts['key'].' with value '.$opts['value']."\n";
      };
    break;
    case 'tls-alpn-01':
      $cert=$ac->generateALPNCertificate('file://'.'some_private_key.pem',$opts['domain'],$opts['value']);
      // Use $cert and some_private_key.pem(<- does not have to be a specific key,
      // just make sure you generated one) to serve the certificate for $opts['domain']


      // This example uses an included ALPN Responder - a standalone https-server
      // written in a few lines of node.js - which is able to complete this challenge.

      // store the generated verification certificate to be used by the ALPN Responder.
      file_put_contents('alpn_cert.pem',$cert);

      // To keep this example simple, the included Example ALPN Responder listens on port 443,
      // so - for the sake of this example - you have to stop the webserver here, like:
      shell_exec('/etc/init.d/apache2 stop');

      // Start ALPN Responder (requires node.js)
      $resource=proc_open(
        'node alpn_responder.js some_private_key.pem alpn_cert.pem',
        array(
          0=>array('pipe','r'),
          1=>array('pipe','w')
        ),
        $pipes
      );

      // wait until alpn responder is listening
      fgets($pipes[1]);

      return function($opts) use ($resource,$pipes){
        // Stop ALPN Responder
        fclose($pipes[0]);
        fclose($pipes[1]);
        proc_close($resource);
        shell_exec('/etc/init.d/apache2 start');
      };
    break;
  }
};

// Example for using a pre-generated CSR as input to getCertificateChain instead of a private key:
// $csr=$ac->generateCSR('file://'.'cert_private_key.pem',array_keys($domain_config));
// $fullchain=$ac->getCertificateChain($csr,$domain_config,$handler);

$fullchain=$ac->getCertificateChain('file://'.'cert_private_key.pem',$domain_config,$handler);
file_put_contents('fullchain.pem',$fullchain);

```

## Logging

ACMECert logs its actions using `error_log`, which logs messages to stderr per default in PHP CLI so it is easy to log to a file instead:
```php
error_reporting(E_ALL);
ini_set('log_errors',1);
ini_set('error_log',dirname(__FILE__).'/ACMECert.log');
```


## ACME_Exception

If the ACME-Server responded with an error message an `ACME_Exception` is thrown. (ACME_Exception extends Exception)

`ACME_Exception` has two additional functions:

* `getType()` to get the ACME error code:

```php
require 'ACMECert.php';
$ac=new ACMECert();
$ac->loadAccountKey('file://'.'account_key.pem');
try {
  echo $ac->getAccountID().PHP_EOL;
}catch(ACME_Exception $e){
  if ($e->getType()=='urn:ietf:params:acme:error:accountDoesNotExist'){
    echo 'Account does not exist'.PHP_EOL;
  }else{
    throw $e; // another error occured
  }
}
```

* `getSubproblems()` to get an array of `ACME_Exception`s if there is more than one error returned from the ACME-Server:

```php
try {
	$cert=$ac->getCertificateChain('file://'.'cert_private_key.pem',$domain_config,$handler);
} catch (ACME_Exception $e){
	$ac->log($e->getMessage()); // log original error
	foreach($e->getSubproblems() as $subproblem){
		$ac->log($subproblem->getMessage()); // log sub errors
	}
}
```

## Function Reference

### ACMECert::__construct

Creates a new ACMECert instance.
```php
public ACMECert::__construct ( bool $live = TRUE )
```
###### Parameters
> **`live`**
>
> When **FALSE**, the ACME v2 [staging environment](https://acme-staging-v02.api.letsencrypt.org/) is used otherwise the [live environment](https://acme-v02.api.letsencrypt.org/).

###### Return Values
> Returns a new ACMECert instance.

---

### ACMECert::generateRSAKey

Generate RSA private key (used as account key or private key for a certificate).
```php
public string ACMECert::generateRSAKey ( int $bits = 2048 )
```
###### Parameters
> **`bits`**
>
> RSA key size in bits.

###### Return Values
> Returns the generated RSA private key as PEM encoded string.
###### Errors/Exceptions
> Throws an `Exception` if the RSA key could not be generated.

---
### ACMECert::generateECKey

Generate Elliptic Curve (EC) private key (used as account key or private key for a certificate).
```php
public string ACMECert::generateECKey ( string $curve_name = 'P-384' )
```
###### Parameters
> **`curve_name`**
>
>	Supported Curves by Let’s Encrypt:
> * `P-256` (prime256v1)
> * `P-384` (secp384r1)
> * ~~`P-521` (secp521r1)~~


###### Return Values
> Returns the generated EC private key as PEM encoded string.
###### Errors/Exceptions
> Throws an `Exception` if the EC key could not be generated.

---

### ACMECert::loadAccountKey

Load account key.
```php
public void ACMECert::loadAccountKey ( mixed $account_key_pem )
```
###### Parameters
> **`account_key_pem`**
>
> can be one of the following:
> * a string containing a PEM formatted private key.
> * a string beginning with `file://` containing the filename to read a PEM formatted private key from.
###### Return Values
> No value is returned.
###### Errors/Exceptions
> Throws an `Exception` if the account key could not be loaded.

---

### ACMECert::register

Associate the loaded account key with a Let's Encrypt account and optionally specify contacts.
```php
public array ACMECert::register ( bool $termsOfServiceAgreed = FALSE [, mixed $contacts = array() ] )
```
###### Parameters
> **`termsOfServiceAgreed`**
>
> **WARNING: By passing `TRUE`, you agree to the terms of service of Let's Encrypt. See [Let’s Encrypt Subscriber Agreement](https://letsencrypt.org/repository/) for more information.**
>
> Must be set to **TRUE** in order to successully register an account.

> **`contacts`**
>
> can be one of the following:
> 1. A string containing an e-mail address
> 2. Array of e-mail adresses
###### Return Values
> Returns an array containing the account information.
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other registration error occured.

---

### ACMECert::update

Update account contacts.
```php
public array ACMECert::update ( mixed $contacts = array() )
```
###### Parameters
> **`contacts`**
>
> can be one of the following:
> * A string containing an e-mail address
> * Array of e-mail adresses
###### Return Values
> Returns an array containing the account information.
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occured updating the account.

---

### ACMECert::getAccount

Get Account Information.
```php
public array ACMECert::getAccount()
```
###### Return Values
> Returns an array containing the account information.
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occured getting the account information.

---

### ACMECert::getAccountID

Get Account ID.
```php
public string ACMECert::getAccountID()
```
###### Return Values
> Returns the Account ID
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occured getting the account id.

---

### ACMECert::keyChange

Account Key Roll-over (exchange the current account key with another one).

> If the Account Key Roll-over succeeded, the new account key is automatically loaded via [`loadAccountKey`](#acmecertloadaccountkey)
```php
public array ACMECert::keyChange ( mixed $new_account_key_pem )
```
###### Parameters
> **`new_account_key_pem`**
>
> can be one of the following:
> * a string containing a PEM formatted private key.
> * a string beginning with `file://` containing the filename to read a PEM formatted private key from.
###### Return Values
> Returns an array containing the account information.
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occured during key change.

---

### ACMECert::deactivateAccount

Deactivate account.
```php
public array ACMECert::deactivateAccount()
```
###### Return Values
> Returns an array containing the account information.
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occured during account deactivation.

---

### ACMECert::getCertificateChain

Get certificate-chain (certificate + the intermediate certificate).

*This is what Apache >= 2.4.8 needs for [`SSLCertificateFile`](https://httpd.apache.org/docs/current/mod/mod_ssl.html#sslcertificatefile), and what Nginx needs for [`ssl_certificate`](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate).*
```php
public string ACMECert::getCertificateChain ( mixed $pem, array $domain_config, callable $callback, bool $authz_reuse = TRUE )
```
###### Parameters
> **`pem`**
>
> A Private Key used for the certificate (the needed CSR is generated automatically using the given key in this case) or an already existing CSR in one of the following formats:
>
> * a string containing a PEM formatted private key.
> * a string beginning with `file://` containing the filename to read a PEM encoded private key from.  
>   or
> * a string beginning with `file://` containing the filename to read a PEM encoded CSR from.
> * a string containing the content of a CSR, PEM encoded, may start with `-----BEGIN CERTIFICATE REQUEST-----`

> **`domain_config`**
>
> An Array defining the domains and the corresponding challenge types to get a certificate for (up to 100 domains per certificate).
>
> The first one is used as `Common Name` for the certificate.
>
> Here is an example structure:
> ```php
> $domain_config=array(
>   '*.example.com'=>array('challenge'=>'dns-01'),
>   'test.example.org'=>array('challenge'=>'tls-alpn-01')
>   'test.example.net'=>array('challenge'=>'http-01','docroot'=>'/var/www/vhosts/test1.example.com'),
> );
> ```
> > Hint: Wildcard certificates (`*.example.com`) are only supported with the `dns-01` challenge type.
>
> `challenge` is mandatory and has to be one of `http-01`, `dns-01` or `tls-alpn-01`.
> All other keys are optional and up to you to be used and are later available in the callback function as `$opts['config']`
> (see the [http-01 example](#get-certificate-using-http-01-challenge) where `docroot` is used this way)

> **`callback`**
>
> Callback function which gets invoked every time a challenge needs to be fulfilled.
> ```php
> callable callback ( array $opts )
> ```
>
> Inside a callback function you can return another callback function, which gets invoked after the verification completed and the challenge tokens can be removed again.
>
> > Hint: To get access to variables of the parent scope inside the callback function use the [`use`](http://php.net/manual/en/functions.anonymous.php) languange construct:
> > ```php
> > $handler=function($opts) use ($variable_from_parent_scope){};
> >                          ^^^
> > ```
>
> ###### Parameters
> **`opts`**
>
>> **`$opts['domain']`**
>>
>> Domain name to be validated.
>>
>> **`$opts['config']`**
>>
>> Corresponding element of the `domain_config` array.
>>
>>
>> **`$opts['key']`** and **`$opts['value']`**
>>
>> Contain the following, depending on the chosen challenge type:
>>
>> Challenge Type | `$opts['key']` | `$opts['value']`
>> --- | --- | ---
>> http-01 | path + filename | file contents
>> dns-01 | TXT Resource Record Name | TXT Resource Record Value
>> tls-alpn-01 | unused | token used in the acmeIdentifier extension of the verification certificate; use [generateALPNCertificate](#acmecertgeneratealpncertificate) to generate the verification certificate from that token. (see the [tls-alpn-01 example](#get-certificate-using-all-http-01dns-01-and-tls-alpn-01-challenge-types-together))

> **`authz_reuse`** (default: `TRUE`)
>
> If `FALSE` the callback function is always called for each domain and does not get skipped due to possibly already valid authorizations (authz) that get reused. This is achieved by deactivating already valid authorizations before getting new ones.
> 
> > Hint: Under normal circumstances this is only needed when testing the callback function, not in production!

###### Return Values
> Returns a PEM encoded certificate chain.
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occured obtaining the certificate.

---

### ACMECert::revoke

Revoke certificate.
```php
public void ACMECert::revoke ( mixed $pem )
```
###### Parameters
> **`pem`**
>
> can be one of the following:
> * a string beginning with `file://` containing the filename to read a PEM encoded certificate or certificate-chain from.
> * a string containing the content of a certificate or certificate-chain, PEM encoded, may start with `-----BEGIN CERTIFICATE-----`
###### Return Values
> No value is returned.
>
> If the function completes without Exception, the certificate was successully revoked.
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occured revoking the certificate.

---

### ACMECert::generateCSR

Generate CSR for a set of domains.
```php
public string ACMECert::generateCSR ( mixed $private_key, array $domains )
```
###### Parameters
> **`private_key`**
>
> can be one of the following:
> * a string containing a PEM formatted private key.
> * a string beginning with `file://` containing the filename to read a PEM formatted private key from.

> **`domains`**
>
> Array of domains
###### Return Values
> Returns the generated CSR as string.
###### Errors/Exceptions
> Throws an `Exception` if the CSR could not be generated.

---

### ACMECert::generateALPNCertificate

Generate a self signed verification certificate containing the acmeIdentifier extension used in **`tls-alpn-01`** challenge.
```php
public string ACMECert::generateALPNCertificate ( mixed $private_key, string $domain, string $token )
```
###### Parameters
> **`private_key`**
>
> private key used for the certificate.
>
> can be one of the following:
> * a string containing a PEM formatted private key.
> * a string beginning with `file://` containing the filename to read a PEM formatted private key from.

> **`domain`**
>
> domain name to be validated.

> **`token`**
>
> verification token.
###### Return Values
> Returns a PEM encoded verification certificate.
###### Errors/Exceptions
> Throws an `Exception` if the certificate could not be generated.

---

### ACMECert::parseCertificate

Get information about a certificate.
```php
public array ACMECert::parseCertificate ( mixed $pem )
```
###### Parameters
> **`pem`**
>
> can be one of the following:
> * a string beginning with `file://` containing the filename to read a PEM encoded certificate or certificate-chain from.
> * a string containing the content of a certificate or certificate-chain, PEM encoded, may start with `-----BEGIN CERTIFICATE-----`
###### Return Values
> Returns an array containing information about the certificate.
###### Errors/Exceptions
> Throws an `Exception` if the certificate could not be parsed.

---

### ACMECert::getRemainingDays

Get the number of days the certificate is still valid.
```php
public float ACMECert::getRemainingDays ( mixed $pem )
```
###### Parameters
> **`pem`**
>
> can be one of the following:
> * a string beginning with `file://` containing the filename to read a PEM encoded certificate or certificate-chain from.
> * a string containing the content of a certificate or certificate-chain, PEM encoded, may start with `-----BEGIN CERTIFICATE-----`
###### Return Values
> Returns how many days the certificate is still valid.
###### Errors/Exceptions
> Throws an `Exception` if the certificate could not be parsed.

---

> MIT License
>
> Copyright (c) 2018 Stefan Körfgen
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.
