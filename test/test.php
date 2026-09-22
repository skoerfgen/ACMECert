<?php

echo 'PHP Version: '.PHP_VERSION,"\n";

require 'ACMECert.php';
use skoerfgen\ACMECert\ACMECert;

if (isset($argv[1]) && $argv[1]==='(psr18)') require 'vendor/autoload.php';

$ac=new ACMECert('https://127.0.0.1:14000/dir');
if (isset($argv[1]) && $argv[1]==='(psr18)') $ac->setHTTPHandler(new \GuzzleHttp\Client(),new \GuzzleHttp\Psr7\HttpFactory());
$ac->setLogger(function($txt){ echo $txt,"\n"; });

$ac_eab=new ACMECert('https://127.0.0.1:14001/dir');
if (isset($argv[1]) && $argv[1]==='(psr18)') $ac_eab->setHTTPHandler(new \GuzzleHttp\Client(),new \GuzzleHttp\Psr7\HttpFactory());
$ac_eab->setLogger(function($txt){ echo $txt,"\n"; });

$keys=array(
	2048=>'RSA',
	3072=>'RSA',
	4096=>'RSA',
	'P-256'=>'EC',
	'P-384'=>'EC',
	'P-521'=>'EC',
);

$domain_config=array(
	'*.example.net'=>array('challenge'=>'dns-01'),
	'example.net'=>array('challenge'=>'http-01'),
	'other.example.net'=>array('challenge'=>'tls-alpn-01'),
);
$domain_config['127.0.0.1']=array('challenge'=>'http-01');

open ('Domain config');
print_r($domain_config);
close();

$handler=function($opts) use ($ac){
	switch($opts['config']['challenge']){
		case 'dns-01':
			echo '-> Set DNS TXT record '.$opts['key'].' -> '.$opts['value'],"\n";
			req('set-txt',array(
				'host'=>$opts['key'].'.',
				'value'=>$opts['value']
			));
			
			return function($opts){
				echo '<- Remove DNS record '.$opts['key'].' <- '.$opts['value'],"\n";
				req('clear-txt',array(
					'host'=>$opts['key'].'.',
				));
			};
		break;
		case 'http-01':
			echo '-> Set file '.$opts['key'].' -> '.$opts['value'],"\n";
			req('add-http01',array(
				'token'=>basename($opts['key']),
				'content'=>$opts['value']
			));
	
			return function($opts){
				echo '<- Remove file '.$opts['key'].' <- '.$opts['value'],"\n";
				req('del-http01',array(
					'token'=>$opts['key'],
				));
			};
		break;
    case 'tls-alpn-01':
			file_put_contents('some_private_key.pem',$ac->generateRSAKey());
			$cert=$ac->generateALPNCertificate('file://'.'some_private_key.pem',$opts['domain'],$opts['value']);
      echo '-> Set ALPN certificate -> '.$opts['value'],"\n";
			echo $cert;
			file_put_contents('alpn_cert.pem',$cert);
      $resource=proc_open(
        'node alpn_responder.js some_private_key.pem alpn_cert.pem',
        array(
          0=>array('pipe','r'),
          1=>array('pipe','w')
        ),
        $pipes
      );

      echo trim(fgets($pipes[1])),"\n";

      return function($opts) use ($resource,$pipes,$ac){
        // Stop ALPN Responder
        fclose($pipes[0]);
        fclose($pipes[1]);
        proc_terminate($resource);
        proc_close($resource);
				echo 'ACMECert Example ALPN Responder - Terminated',"\n";
      };
    break;
	}
};


$k=0;
foreach($keys as $size=>$type){
	if (PHP_VERSION_ID<70100 && $type==='EC') continue;
	open('Generate '.$type.' '.$size.' Key ('.($k===0?'Register':'Account Key Rollover').') + EAB + Generate Certificate');
	$key=$ac->{'generate'.$type.'Key'}($size);
	echo $key;
	if ($k===0) {
		$ac->loadAccountKey($key);
		$ret=$ac->register(true);
		if ($ret['status']!=='valid') throw new Exception('Expected Status "valid", got "'.$ret['status'].'"');
		print_r($ret);
	}else{
		$ac->keyChange($key);
		$ret=$ac->getAccount();
		if ($ret['status']!=='valid') throw new Exception('Expected Status "valid", got "'.$ret['status'].'"');
		print_r($ret);
	}
	$ac_eab->loadAccountKey($key);
	$ret=$ac_eab->registerEAB(true,'kid-1','zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W');	
	if ($ret['status']!=='valid') throw new Exception('Expected Status "valid", got "'.$ret['status'].'"');
	print_r($ret);

	$fullchains=$ac->getCertificateChains($ac->{'generate'.$type.'Key'}($size),$domain_config,$handler);
	$ret=$ac->getSAN(reset($fullchains));
	echo 'Subject Alternative Names (SAN) ';
	print_r($ret);
	if (!empty(array_diff($ret,array_keys($domain_config)))) {
		throw new Exception('SAN does not match domain_config');
	}

	foreach($fullchains as $issuer=>$chain){
		echo 'Chain: '.$issuer.' ';
		print_r($ac->splitChain($chain));
	}

	print_r([
		'getRemainingPercent'=>$ac->getRemainingPercent(reset($fullchains)),
		'getRemainingDays'=>$ac->getRemainingDays(reset($fullchains))
	]);

	close();
	$k++;
}

// update
open('Update Account');
print_r($ac->getAccount());
$ac->update('info@example.net');
print_r($ac->getAccount());
$ac->update(['info@example.net','info2@example.net']);
print_r($ac->getAccount());
close();

open('Metadata');
print_r([
	'getTermsURL'=>$ac->getTermsURL(),
	'getCAAIdentities'=>$ac->getCAAIdentities(),
	'getProfiles'=>$ac->getProfiles(),
]);
close();

$rk=$ac->generateRSAKey();

if (PHP_VERSION_ID>=70201){
	open('ACME Renewal Information (ARI)');
	$ari=$ac->getARI(reset($fullchains));
	print_r($ari);
	close();
	open('Using ARI ('.$ari['ari_cert_id'].') ');
	$fullchains=$ac->getCertificateChains($rk,$domain_config,$handler,array('replaces'=>$ari['ari_cert_id']));
	print_r($fullchains);
	close();
}

open('Profiles');
foreach($ac->getProfiles() as $name=>$description){
	echo 'Using Profile "'.$name.'" ('.$description.')',"\n";
	$fullchains=$ac->getCertificateChains($rk,$domain_config,$handler,array('profile'=>$name));
	print_r($fullchains);
}
close();


open('Revoke Certificate');
$ac->revoke(reset($fullchains));
close();

open('Using pre-generated CSR');
$csr=$ac->generateCSR($rk,array_keys($domain_config));
echo 'CSR '.$csr,"\n";
$fullchains=$ac->getCertificateChains($csr,$domain_config,$handler);
print_r($fullchains);
close();

open('Deactivate Account');
print_r($ac->deactivateAccount());
close();


// ============================================================================

function req($path,$arr){
	static $ch=null;

	if ($ch===null){
		$ch=curl_init();
	}
	curl_setopt_array($ch,array(
		CURLOPT_URL=>'http://127.0.0.1:8055/'.$path,
		CURLOPT_RETURNTRANSFER=>true,
		CURLOPT_POSTFIELDS=>json_encode($arr),
	));
	curl_exec($ch);
}

function open($txt){
	echo '::group::'.$txt,"\n";
}
function close(){
	echo '::endgroup::',"\n";
}