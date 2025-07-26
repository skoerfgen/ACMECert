# ACMECert v3.7.1

PHP client library for [Let's Encrypt](https://letsencrypt.org/) and other [ACME v2 - RFC 8555](https://tools.ietf.org/html/rfc8555) compatible Certificate Authorities.  

## Table of Contents
- [Description](#description)
- [Requirements](#requirements)
- [Require ACMECert](#require-acmecert)
- [Usage / Examples](#usage--examples)
- [Logging](#logging)
- [ACME_Exception](#acme_exception)
- [Function Reference](#function-reference)

## Description

ACMECert is designed to help you set up an automated SSL/TLS certificate/renewal process with just a few lines of PHP.

It is self contained and contains a set of functions allowing you to:

- generate [RSA](#acmecertgeneratersakey) / [EC (Elliptic Curve)](#acmecertgenerateeckey) keys
- manage account: [register](#acmecertregister)/[External Account Binding (EAB)](#acmecertregistereab)/[update](#acmecertupdate)/[deactivate](#acmecertdeactivateaccount) and [account key roll-over](#acmecertkeychange)
- [get](#acmecertgetcertificatechain)/[revoke](#acmecertrevoke) certificates (to renew a certificate just get a new one)
- [parse certificates](#acmecertparsecertificate) / get the [remaining days](#acmecertgetremainingdays) or [percentage](#acmecertgetremainingpercent) a certificate is still valid
- get/use [ACME Renewal Information](#acmecertgetari) (ARI)
- get/use [ACME certificate profiles](#acmecertgetprofiles)
- issue IP address certificates
- and more..
> see [Function Reference](#function-reference) for a full list

It abstracts away the complexity of the ACME protocol to get a certificate
(create order, fetch authorizations, compute challenge tokens, polling for status, generate CSR,
finalize order, request certificate) into a single function [getCertificateChain](#acmecertgetcertificatechain) (or [getCertificateChains](#acmecertgetcertificatechains) to also get all alternate chains),
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
if it fails or an [ACME_Exception](#acme_exception) if the ACME-Server responded with an error message.

## Requirements
- [x] PHP 5.6 or higher (for EC keys PHP 7.1 or higher) (for ARI PHP 7.1.2 or higher)
- [x] [OpenSSL extension](https://www.php.net/manual/de/book.openssl.php)
- [x] enabled [fopen wrappers](https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-fopen) (allow_url_fopen=1) **or** [cURL extension](https://www.php.net/manual/en/book.curl.php)

## Require ACMECert

manual download: https://github.com/skoerfgen/ACMECert/archive/master.zip

usage:

```php
require 'ACMECert.php';

use skoerfgen\ACMECert\ACMECert;
```

---

or download it using [git](https://git-scm.com/):

```
git clone https://github.com/skoerfgen/ACMECert
```
usage:

```php
require 'ACMECert/ACMECert.php';

use skoerfgen\ACMECert\ACMECert;
```

---

or download it using [composer](https://getcomposer.org):
```
composer require skoerfgen/acmecert
```

usage:

```php
require 'vendor/autoload.php';

use skoerfgen\ACMECert\ACMECert;
```

## Usage / Examples

* [Simple example to get started](https://github.com/skoerfgen/ACMECert/wiki/Simple-example-to-get-started)

#### Choose Certificate Authority (CA)
##### [Let's Encrypt](https://letsencrypt.org/)
> Live CA
```php
$ac=new ACMECert('https://acme-v02.api.letsencrypt.org/directory');
```

> Staging CA
```php
$ac=new ACMECert('https://acme-staging-v02.api.letsencrypt.org/directory');
```

##### [Buypass](https://buypass.com/)
> Live CA
```php
$ac=new ACMECert('https://api.buypass.com/acme/directory');
```

> Staging CA
```php
$ac=new ACMECert('https://api.test4.buypass.no/acme/directory');
```

##### [Google Trust Services](https://pki.goog/)
> Live CA
```php
$ac=new ACMECert('https://dv.acme-v02.api.pki.goog/directory');
```

> Staging CA
```php
$ac=new ACMECert('https://dv.acme-v02.test-api.pki.goog/directory');
```

##### [SSL.com](https://www.ssl.com/)
> Live CA
```php
$ac=new ACMECert('https://acme.ssl.com/sslcom-dv-rsa');
```

##### [ZeroSSL](https://zerossl.com/)
> Live CA
```php
$ac=new ACMECert('https://acme.zerossl.com/v2/DV90');
```

##### or any other ([ACME v2 - RFC 8555](https://tools.ietf.org/html/rfc8555)) compatible CA
```php
$ac=new ACMECert('INSERT_URL_TO_ACME_CA_DIRECTORY_HERE');
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

#### Register Account Key with CA
```php
$ac->loadAccountKey('file://'.'account_key.pem');
$ret=$ac->register(true,'info@example.com');
print_r($ret);
```

#### Register Account Key with CA using External Account Binding
```php
$ac->loadAccountKey('file://'.'account_key.pem');
$ret=$ac->registerEAB(true,'INSERT_EAB_KEY_ID_HERE','INSERT_EAB_HMAC_HERE','info@example.com');
print_r($ret);
```

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

// Generate new certificate key
$private_key=$ac->generateRSAKey(2048);

$fullchain=$ac->getCertificateChain($private_key,$domain_config,$handler);
file_put_contents('fullchain.pem',$fullchain);
file_put_contents('private_key.pem',$private_key);
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
        proc_terminate($resource);
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

#### Get alternate chains
```php
$chains=$ac->getCertificateChains('file://'.'cert_private_key.pem',$domain_config,$handler);
if (isset($chains['ISRG Root X1'])){ // use alternate chain 'ISRG Root X1'
  $fullchain=$chains['ISRG Root X1'];
}else{ // use default chain if 'ISRG Root X1' is not present
  $fullchain=reset($chains);
}
file_put_contents('fullchain.pem',$fullchain);
```

#### Revoke Certificate
```php
$ac->loadAccountKey('file://'.'account_key.pem');
$ac->revoke('file://'.'fullchain.pem');
```

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

#### Get/Use ACME Renewal Information
```php
$ret=$ac->getARI('file://'.'fullchain.pem');
if ($ret['suggestedWindow']['start']-time()>0) {
  die('Certificate still good, exiting..');
}

$settings=array(
  'replaces'=>$ret['ari_cert_id']
);
$ac->getCertificateChain(..., ..., ..., $settings);
```

#### Get Remaining Percentage
```php
$percent=$ac->getRemainingPercent('file://'.'fullchain.pem'); // certificate or certificate-chain
if ($percent>33.333) { // certificate has still more than 1/3 (33.333%) of its lifetime left
  die('Certificate still good, exiting..');
}
// get new certificate here..
```
> This allows you to run your renewal script without the need to time it exactly, just run it often enough. (cronjob)


#### Get Remaining Days
```php
$days=$ac->getRemainingDays('file://'.'fullchain.pem'); // certificate or certificate-chain
if ($days>30) { // renew 30 days before expiry
  die('Certificate still good, exiting..');
}
// get new certificate here..
```

#### ACME certificate profiles
```php
$ret=$ac->getProfiles();
print_r($ret); // print available profiles

// use profile with name "classic"
$settings=array(
  'profile'=>'classic'
);
$ac->getCertificateChain(..., ..., ..., $settings);
```

## Logging

By default ACMECert logs its actions using `error_log` which logs messages to stderr in PHP CLI so it is easy to log to a file instead:
```php
error_reporting(E_ALL);
ini_set('log_errors',1);
ini_set('error_log',dirname(__FILE__).'/ACMECert.log');
```

> To disable the default logging, you can use [`setLogger`](#acmecertsetlog), Exceptions are nevertheless thrown:
```php
$ac->setLogger(false);
```
> Or you can you set it to a custom callback function:
```php
$ac->setLogger(function($txt){
	echo 'Log Message: '.$txt."\n";
});
```
## ACME_Exception

If the ACME-Server responded with an error message an `\skoerfgen\ACMECert\ACME_Exception` is thrown. (ACME_Exception extends Exception)

`ACME_Exception` has two additional functions:

* `getType()` to get the ACME error code:

```php
use skoerfgen\ACMECert\ACME_Exception;

try {
  echo $ac->getAccountID().PHP_EOL;
}catch(ACME_Exception $e){
  if ($e->getType()=='urn:ietf:params:acme:error:accountDoesNotExist'){
    echo 'Account does not exist'.PHP_EOL;
  }else{
    throw $e; // another error occurred
  }
}
```

* `getSubproblems()` to get an array of `ACME_Exception`s if there is more than one error returned from the ACME-Server:

```php
try {
  $cert=$ac->getCertificateChain('file://'.'cert_private_key.pem',$domain_config,$handler);
} catch (\skoerfgen\ACMECert\ACME_Exception $e){
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
public ACMECert::__construct ( string $ca_url = 'https://acme-v02.api.letsencrypt.org/directory' )
```
###### Parameters
> **`ca_url`**
>
> A string containing the URL to an ACME CA directory endpoint.

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

Associate the loaded account key with the CA account and optionally specify contacts.
```php
public array ACMECert::register ( bool $termsOfServiceAgreed = FALSE [, mixed $contacts = array() ] )
```
###### Parameters
> **`termsOfServiceAgreed`**
>
> By passing `TRUE`, you agree to the Terms Of Service of the selected CA. (Must be set to `TRUE` in order to successfully register an account.)
>
> Hint: Use [getTermsURL()](#acmecertgettermsurl) to get the link to the current Terms Of Service.


> **`contacts`**
>
> can be one of the following:
> 1. A string containing an e-mail address
> 2. Array of e-mail addresses
###### Return Values
> Returns an array containing the account information.
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other registration error occurred.

---

### ACMECert::registerEAB

Associate the loaded account key with the CA account using External Account Binding (EAB) credentials and optionally specify contacts.
```php
public array ACMECert::registerEAB ( bool $termsOfServiceAgreed, string $eab_kid, string $eab_hmac [, mixed $contacts = array() ] )
```
###### Parameters
> **`termsOfServiceAgreed`**
>
> By passing `TRUE`, you agree to the Terms Of Service of the selected CA. (Must be set to `TRUE` in order to successfully register an account.)
>
> Hint: Use [getTermsURL()](#acmecertgettermsurl) to get the link to the current Terms Of Service.

> **`eab_kid`**
>
> a string specifying the `EAB Key Identifier`

> **`eab_hmac`**
>
> a string specifying the `EAB HMAC Key`

> **`contacts`**
>
> can be one of the following:
> 1. A string containing an e-mail address
> 2. Array of e-mail addresses
###### Return Values
> Returns an array containing the account information.
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other registration error occurred.

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
> * Array of e-mail addresses
###### Return Values
> Returns an array containing the account information.
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occurred updating the account.

---

### ACMECert::getAccount

Get Account Information.
```php
public array ACMECert::getAccount()
```
###### Return Values
> Returns an array containing the account information.
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occurred getting the account information.

---

### ACMECert::getAccountID

Get Account ID.
```php
public string ACMECert::getAccountID()
```
###### Return Values
> Returns the Account ID
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occurred getting the account id.

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
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occurred during key change.

---

### ACMECert::deactivateAccount

Deactivate account.
```php
public array ACMECert::deactivateAccount()
```
###### Return Values
> Returns an array containing the account information.
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occurred during account deactivation.

---

### ACMECert::getCertificateChain

Get certificate-chain (certificate + the intermediate certificate(s)).

*This is what Apache >= 2.4.8 needs for [`SSLCertificateFile`](https://httpd.apache.org/docs/current/mod/mod_ssl.html#sslcertificatefile), and what Nginx needs for [`ssl_certificate`](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate).*
```php
public string ACMECert::getCertificateChain ( mixed $pem, array $domain_config, callable $callback, array $settings = array() )
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
> An Array defining the domains and the corresponding challenge types to get a certificate for.
>
> The first domain name in the array is used as `Common Name` for the certificate if it does not exceed 64 characters, otherwise the `Common Name` field will be empty.
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
> > Hint: To get access to variables of the parent scope inside the callback function use the [`use`](http://php.net/manual/en/functions.anonymous.php) language construct:
> > ```php
> > $handler=function($opts) use ($variable_from_parent_scope){};
> >                          ^^^
> > ```
>
> The `$opts` array passed to the callback function contains the following keys:
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


> **`settings`** (optional)
>
> This array can have the following keys:
>> **`authz_reuse`** (boolean / default: `TRUE`)
>>
>> If `FALSE` the callback function is always called for each domain and does not get skipped due to possibly already valid authorizations (authz) that are reused. This is achieved by deactivating already valid authorizations before getting new ones.
>>
>> > Hint: Under normal circumstances this is only needed when testing the callback function, not in production!
>
>> **`notBefore`** / **`notAfter`** (mixed)
>>
>> can be one of the following:
>> * a string containing a RFC 3339 formatted date
>> * a timestamp (integer)
>>
>> Example: Certificate valid for 3 days:
>> ```php
>> array( 'notAfter' => time() + (60*60*24) * 3 )
>> ```
>> or
>> ```php
>> array( 'notAfter' => '1970-01-01T01:22:17+01:00' )
>> ```
>
>> **`replaces`** (string)
>>
>> The ARI CertID uniquely identifying a previously-issued certificate which this order is intended to replace.
>>
>> Use: [getARI](#acmecertgetari) to get the ARI CertID for a certificate.
>>
>> Example: [Get/Use ACME Renewal Information](#getuse-acme-renewal-information)
>
>> **`profile`** (string)
>>
>> The name of the profile to use.
>>
>> Use: [getProfiles](#acmecertgetprofiles) to get a list of available profiles.
>>
>> Example: [ACME certificate profiles](#acme-certificate-profiles)
>
>> **`group`** (boolean / default: `TRUE`)
>>
>> When issuing certificates using the `dns-01` challenge for multiple domains that share the same `_acme-challenge` subdomain, such as:
>> - example.com
>> - *.example.com (wildcard)
>>
>> two distinct TXT records must be created under the same DNS name `_acme-challenge.example.com`
>>
>> By default, ACMECert groups these challenges together. This means all required TXT records for `_acme-challenge.example.com` are set simultaneously, and validation is triggered only after all records are in place. This approach prevents validation failures due to DNS caching delays.
>>
>> If set to `FALSE` challenges are handled independently. Each TXT record gets set and validated one at a time.



###### Return Values
> Returns a PEM encoded certificate chain.
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occurred obtaining the certificate.

---

### ACMECert::getCertificateChains

Get all (default and alternate) certificate-chains.
This function takes the same arguments as the [getCertificateChain](#acmecertgetcertificatechain) function above, but it returns an array of certificate chains instead of a single chain.

```php
public string ACMECert::getCertificateChains ( mixed $pem, array $domain_config, callable $callback, array $settings = array() )
```

###### Return Values
> Returns an array of PEM encoded certificate chains.
>
> The keys of the returned array correspond to the issuer `Common Name` (CN) of the topmost (closest to the root certificate) intermediate certificate.
>
> The first element of the returned array is the default chain.
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occurred obtaining the certificate chains.

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
> If the function completes without Exception, the certificate was successfully revoked.
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occurred revoking the certificate.

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

### ACMECert::getRemainingPercent

Get the percentage the certificate is still valid.

```php
public float ACMECert::getRemainingPercent( mixed $pem )
```
###### Parameters
> **`pem`**
>
> can be one of the following:
> * a string beginning with `file://` containing the filename to read a PEM encoded certificate or certificate-chain from.
> * a string containing the content of a certificate or certificate-chain, PEM encoded, may start with `-----BEGIN CERTIFICATE-----`
###### Return Values
> A float value containing the percentage the certificate is still valid.
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

### ACMECert::splitChain

Split a string containing a PEM encoded certificate chain into an array of individual certificates.
```php
public array ACMECert::splitChain ( string $pem )
```
###### Parameters
> **`pem`**
> * a certificate-chain as string, PEM encoded.
###### Return Values
> Returns an array of PEM encoded individual certificates.
###### Errors/Exceptions
> None

---

### ACMECert::getCAAIdentities

Get a list of all CAA Identities for the selected CA. (Useful for setting up CAA DNS Records)
```php
public array ACMECert::getCAAIdentities()
```
###### Return Values
> Returns an array containing all CAA Identities for the selected CA.
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occurred getting the CAA Identities.

---

### ACMECert::getSAN

Get all Subject Alternative Names of given certificate.
```php
public array ACMECert::getSAN( mixed $pem )
```

###### Parameters
> **`pem`**
>
> can be one of the following:
> * a string beginning with `file://` containing the filename to read a PEM encoded certificate or certificate-chain from.
> * a string containing the content of a certificate or certificate-chain, PEM encoded, may start with `-----BEGIN CERTIFICATE-----`


###### Return Values
> Returns an array containing all Subject Alternative Names of given certificate.
###### Errors/Exceptions
> Throws an `Exception` if an error occurred getting the Subject Alternative Names.

---

### ACMECert::getTermsURL

Get URL to Terms Of Service for the selected CA.
```php
public array ACMECert::getTermsURL()
```
###### Return Values
> Returns a string containing a URL to the Terms Of Service for the selected CA.
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occurred getting the Terms Of Service.

---

### ACMECert::setLogger

Turn on/off logging to stderr using `error_log` or provide a custom callback function.
```php
public void ACMECert::setLogger( bool|callable $value = TRUE )
```
###### Parameters
> **`value`**
>
> - If `TRUE`, logging to stderr using `error_log` is enabled. (default)
> - If `FALSE`, logging is disabled.
> - If a callback function is provided, the function gets called with the log message as first argument:
> ```php
> void callback( string $txt )
> ```
> see [Logging](#logging)
###### Return Values
> No value is returned.
###### Errors/Exceptions
> Throws an `Exception` if the value provided is not boolean or a callable function.

---
### ACMECert::getARI

Get ACME Renewal Information (ARI) for a given certificate.

```php
public array ACMECert::getARI( mixed $pem )
```
###### Parameters
> **`pem`**
>
> can be one of the following:
> * a string beginning with `file://` containing the filename to read a PEM encoded certificate or certificate-chain from.
> * a string containing the content of a certificate or certificate-chain, PEM encoded, may start with `-----BEGIN CERTIFICATE-----`
###### Return Values
> Returns an Array with the following keys:
>
>> `suggestedWindow` (array)
>>
>> An Array with two keys, `start` and `end`, whose values are unix timestamps, which bound the window of time in which the CA recommends renewing the certificate.
>>
>> `explanationURL` (string, optional)
>>
>> If present, contains a URL pointing to a page which may explain why the suggested renewal window is what it is. For example, it may be a page explaining the CA's dynamic load-balancing strategy, or a page documenting which certificates are affected by a mass revocation event.
>>
>> `ari_cert_id` (string)
>>
>> The ARI CertID of the given certificate.
>> 
>> See the documentation of [getCertificateChain](#acmecertgetcertificatechain) where the ARI CertID can be used to replace an existing certificate using the `replaces` option.
>> 
>> Example: [Get/Use ACME Renewal Information](#getuse-acme-renewal-information)
>>
>> `retry_after` (int, optional)
>>
>> If present, this value indicates the number of seconds a client should wait before retrying a request to [getARI](#acmecertgetari) for a given certificate, as the server may provide a different suggestedWindow.
>>
>> Clients SHOULD set reasonable limits on their checking interval. For example, values under one minute could be treated as if they were one minute, and values over one day could be treated as if they were one day.
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occurred getting the ACME Renewal Information.

---
### ACMECert::getProfiles

Get a list of supported profiles. (ACME certificate profiles)

```php
public array ACMECert::getProfiles()
```

> See the documentation of [getCertificateChain](#acmecertgetcertificatechain) where a profile can be selected using the `profile` option.
> 
> Example: [ACME certificate profiles](#acme-certificate-profiles)
###### Return Values
> Returns an Array with the profile name as key and the description as value.
>
> Example:
> ```php
> Array
> (
>     [classic] => The same profile you're accustomed to
>     [tlsserver] => https://letsencrypt.org/2025/01/09/acme-profiles/
> )
> ```
###### Errors/Exceptions
> Throws an `ACME_Exception` if the server responded with an error message or an `Exception` if an other error occurred getting the profiles.

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
