const fs = require("fs");


var lines = fs.readFileSync("/etc/pasten.conf").toString().split("\n");
var creds = {};
for(let i=0; i < lines.length; i++) {
	if(!lines[i])
		continue;

	let line = lines[i].split("=");
	creds[line[0]] = line[1];
}

function replaceAll(str1, str2, str3) {
	return str1.split(str2).join(str3)
}

function base64urlencode(json) {
	let ret = Buffer.from(JSON.stringify(json)).toString("base64");
	ret = replaceAll(ret, "=", "");
	ret = replaceAll(ret, "+", "-");
	ret = replaceAll(ret, "/", "_");
	return ret;
}

exports.generate_token = function(client_id) {
	let exp_seconds = 600
	let jwt_header = {
		"alg": "none"
	};
	let jwt_claims = {
		"sub": client_id,
		"exp": Math.round(new Date() / 1000 + exp_seconds)
	};
	let token_response = {
		"access_token": base64urlencode(jwt_header) + "." + base64urlencode(jwt_claims) + ".",
		"token_type": "bearer",
		"expires_in": exp_seconds
	};

	return JSON.stringify(token_response);
}

exports.authenticate = function(client_id, client_secret) {
	return creds[client_id] === client_secret;
}
