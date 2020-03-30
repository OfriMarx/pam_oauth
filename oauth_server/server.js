const http = require("http");
const url = require("url");
const fs = require("fs");
const oauth = require("./oauth");


http.createServer(function(req, res) {
	var path = url.parse(req.url).pathname; 
	var headers = req.headers;
	var creds;

	if(! ('authorization' in headers)) {
		res.writeHead(401, {'Content-Type': 'text/plain',
			'WWW-Authenticate': 'Basic realm="Access to OAUTH 2 server"'});
		res.end("unauthorized");
		return;
	}
	else {
		creds = Buffer.from(headers['authorization'].split(" ")[1], "base64").toString().split(":");
		if(!oauth.authenticate(creds[0], creds[1])) {
			res.writeHead(403, {'Content-Type': 'text/plain'});
			res.end("forbidden");
			return;
		}
	}

	if(path === "/token") {
		if(req.method === "GET") {
			fs.readFile("token.html", function(err, data) {
				if(err) {
					res.writeHead(500, {'Content-Type': 'text/plain'});
					res.end(err.name + ": " + err.message);
				}
				else {
					res.writeHead(200, {'Content-Type': 'text/html'});
					res.end(data);
				}
			});
		} else if(req.method === "POST") {
			let body = "";
			req.on("data", chunk => {
				body += chunk.toString();
			});
			req.on("end", () => {
				body = body.split("=");
				if(body.length === 2 && body[0] === "grant_type" && body[1] === "client_credentials") {
					res.writeHead(200, {'Content-Type': 'application/json',
						'Cache-Control': 'no-store',
						'Pragma': 'no-cache'	
					});
					res.end(oauth.generate_token(creds[0]));
				} else {
					res.writeHead(400, {'Content-Type': 'application/json'});
					res.end('{"error": "invalid_request"}');
				}
			});
		} else {
			res.writeHead(405, {'Content-Type': 'text/plain', 
					'Allow': 'GET, POST'});
			res.end("Method Not Allowed");
		}
	} else {
		res.writeHead(404, {'Content-Type': 'text/plain'});
		res.end("not found :(");
	}
} ).listen(8080);
