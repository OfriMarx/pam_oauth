const http = require("http");
const url = require("url");
const oauth = require("./oauth");

http.createServer(function(req, res) {
	var path = url.parse(req.url).pathname; 

	if(path === "/token") {
		res.writeHead(200, {'Content-Type': 'text/plain'});
		res.end(oauth.generate_token());
	} else {
		res.writeHead(404, {'Content-Type': 'text/plain'});
		res.end("not found :(");
	}
} ).listen(8080);
