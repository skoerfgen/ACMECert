<?php

require 'ACMECert.php';
$ac=new ACMECert(false);
$ac->loadAccountKey('file://account_key.pem');

$domain_config=array(
  '*.example.com'=>array('challenge'=>'dns-01')
);

// pass the order url instead of the handler function
$cert=$ac->getCertificateChain('file://domain_key.pem',$domain_config,'https://acme-v02.api.letsencrypt.org/acme/order/xxxxxxxxxx/xxxxxxxxx');

echo $cert;
