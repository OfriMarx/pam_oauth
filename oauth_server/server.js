const http = require("http");
const url = require("url");
const fs = require("fs");
const oauth = require("./oauth");


function auth(headers) {
	var creds;

	if(! ('authorization' in headers)) {
		return [401, {'Content-Type': 'text/plain', 'WWW-Authenticate': 'Basic realm="JWS token"'}, "unauthorized"];
	} else if(headers['authorization'].split(" ")[0] !== "Basic") {
		return [401, {'Content-Type': 'text/plain', 'WWW-Authenticate': 'Basic realm="JWS token"'}, "unauthorized"];
	} else {
		creds = Buffer.from(headers['authorization'].split(" ")[1], "base64").toString().split(":");
		if(!oauth.authenticate_client(creds[0], creds[1])) {
			return [403, {'Content-Type': 'text/plain'}, 'forbidden'];
		}
	}

	return [200, creds]
}


http.createServer(function(req, res) {
	var path = url.parse(req.url).pathname; 
	var headers = req.headers;
	var creds;
	
	if(path === "/token") {
		var auth_resp = auth(headers);
		if(auth_resp[0] !== 200) {
			res.writeHead(auth_resp[0], auth_resp[1]);
			res.end(auth_resp[2]);
			return;
		}
		creds = auth_resp[1];

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
					res.end(oauth.generate_token(creds[0], 600));
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
	} else if(path === "/validate") {
		var token;
		if(! ('authorization' in headers)) {
			res.writeHead(401, {'Content-Type': 'text/plain', 'WWW-Authenticate': 'Bearer realm="Validate JWS token"'});
			res.end("unauthorized");
		} else if(headers['authorization'].split(" ")[0] !== "Bearer") {
			res.writeHead(401, {'Content-Type': 'text/plain', 'WWW-Authenticate': 'Bearer realm="Validate JWS token"'});
			res.end("unauthorized");
		} else {
			if(oauth.validate_token(headers['authorization'].split(" ")[1])) {
				res.writeHead(200, {'Content-Type': 'text/plain'});
				res.end("valid");
			}
			else {
				res.writeHead(403, {'Content-Type': 'text/plain'});
				res.end("forbidden");
			}
		}
	} else {
		res.writeHead(404, {'Content-Type': 'text/plain'});
		res.end("not found");
	}
} ).listen(8080);
