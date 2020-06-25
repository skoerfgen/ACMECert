<?php

require 'ACMECert.php';

$ac=new ACMECert(false);
$ac->loadAccountKey('file://account_key.pem');

$domain_config=array(
  'test.example.com'=>array('challenge'=>'http-01')
);


$add_handler=function($opts){
	echo 'In the DocumentRoot folder of the domain '.$opts['domain'].':'.PHP_EOL;

	echo '- Create a path/file named: '.substr($opts['key'],1).PHP_EOL;
	echo '- With the following content: '.$opts['value'].PHP_EOL;

	echo '- This file must be publicly accessible via this URL: http://'.$opts['domain'].$opts['key'].PHP_EOL;
};

$remove_handler=function($opts){
  return function($opts){
    echo 'The file '.$opts['key'].' can now be removed'.PHP_EOL;
  };
};

$challenges_only=true; // first set this to true to get the challenge tokens, then after setting them up, set this to false to do the validation

if ($challenges_only) {
	$ac->getCertificateChain('no_validation',$domain_config,$add_handler);
}else{
	$cert=$ac->getCertificateChain('file://'.'cert_private_key.pem',$domain_config,$remove_handler);
	echo $cert;
}