const http = require("http");
const url = require("url");
const oauth = require("./oauth");


http.createServer(function(req, res) {
	var path = url.parse(req.url).pathname; 
	var headers = req.headers;

	if(! ('authorization' in headers)) {
		res.writeHead(401, {'Content-Type': 'text/plain',
			'WWW-Authenticate': 'Basic realm="Access to OAUTH 2 server"'});
		res.end("unauthorized");
		return;
	}
	else {
		let creds = Buffer.from(headers['authorization'].split(" ")[1], "base64").toString().split(":");
		if(!oauth.authenticate(creds[0], creds[1])) {
			res.writeHead(403, {'Content-Type': 'text/plain'});
			res.end("forbidden");
			return;
		}
	}

	if(path === "/token") {
		res.writeHead(200, {'Content-Type': 'text/plain'});
		res.end(oauth.generate_token());
	} else {
		res.writeHead(404, {'Content-Type': 'text/plain'});
		res.end("not found :(");
	}
} ).listen(8080);
