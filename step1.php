<?php

require 'ACMECert.php';
$ac=new ACMECert(false);
$ac->loadAccountKey('file://account_key.pem');

$domain_config=array(
  '*.example.com'=>array('challenge'=>'dns-01')
);

$handler=function($opts){
	echo 'Create DNS-TXT-Record '.$opts['key'].' with value '.$opts['value']."\n";
	// returning false prevents ACMECert from triggering the validation for the given challenge immediately
	return false;
};

$ret=$ac->getCertificateChain('file://domain_key.pem',$domain_config,$handler);

if (is_array($ret)) {
	echo 'Pending authorizations, here is the order url: '.$ret[0];
}else{
	echo 'All authorizations valid, here is your cert: '.$ret;
}
