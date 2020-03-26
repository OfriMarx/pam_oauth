const fs = require("fs");


var lines = fs.readFileSync("/etc/pasten.conf").toString().split("\n");
var creds = {};
for(let i=0; i < lines.length; i++) {
	if(!lines[i])
		continue;

	let line = lines[i].split("=");
	creds[line[0]] = line[1];
}

exports.generate_token = function() {
	return "token123";
}

exports.authenticate = function(client_id, client_secret) {
	return creds[client_id] === client_secret;
}
