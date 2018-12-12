/* LECert Example ALPN Responder */
var tls=require('tls');
var fs=require('fs');

var server=tls.createServer({
	key:fs.readFileSync(process.argv[2]),
	cert:fs.readFileSync(process.argv[3]),
	ALPNProtocols:['acme-tls/1']
}).on('secureConnection',function(socket){
	console.log('Request',socket.servername,socket.remoteAddress,socket.getCipher());
	socket.on('error',function(){
		console.log(arguments);
	});
}).on('listening',function(){
	console.log('LECert Example ALPN Responder - Ready');
}).listen(443);

process.stdin.resume();
process.stdin.on('end',function(){
  server.close(function () {
    console.log('LECert Example ALPN Responder - Terminating');
		process.exit(0);
  });
});
