/* ACMECert Example ALPN Responder (only needed when using tls-alpn-01 challenge) */
var tls=require('tls');
var fs=require('fs');

var server=tls.createServer({
	key:fs.readFileSync(process.argv[2]),
	cert:fs.readFileSync(process.argv[3]),
	ALPNProtocols:['acme-tls/1']
}).on('listening',function(){
	console.log('ACMECert Example ALPN Responder - Ready');
}).listen(443);

process.stdin.resume();
process.stdin.on('end',function(){
	server.close(function () {
		console.log('ACMECert Example ALPN Responder - Terminating');
		process.exit(0);
	});
});
