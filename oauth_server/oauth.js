const fs = require("fs");
const crypto = require("crypto");

var creds = import_data("/etc/pasten.conf");
var keys = import_data("/etc/keys.conf");

function import_data(filepath) {
	var lines = fs.readFileSync(filepath).toString().split("\n");
	var data = {};
	for(let i=0; i<lines.length; i++) {
		if(!lines[i])
			continue;

		let line = lines[i].split("=");
		data[line[0]] = line[1];
	}

	return data;
}

function replaceAll(str1, str2, str3) {
	return str1.split(str2).join(str3)
}

function base64urlencode(buf) {
	let ret = buf.toString("base64");
	ret = replaceAll(ret, "=", "");
	ret = replaceAll(ret, "+", "-");
	ret = replaceAll(ret, "/", "_");
	return ret;
}

function hmac_sha256(data, key) {
	const BLOCK_SIZE = 64;

	if(key.length > BLOCK_SIZE) {
		key = crypto.createHash("sha256").update(key).digest();
	}
	key = Buffer.concat([key, Buffer.alloc(BLOCK_SIZE - key.length, 0x0)]);

	var i_key = Buffer.from(key);
	var o_key = Buffer.from(key);
	for(let i=0; i<BLOCK_SIZE; i++) {
		i_key[i] ^= 0x36;
		o_key[i] ^= 0x5C;
	}

	data = Buffer.concat([i_key, data]);
	data = crypto.createHash("sha256").update(data).digest();
	data = Buffer.concat([o_key, data]);
	return crypto.createHash("sha256").update(data).digest();
}

function get_key(kid) {
	if(!(kid in keys))
		return Buffer.alloc(0);

	var keyobj = crypto.createPrivateKey(fs.readFileSync(keys[kid]));
	return keyobj.export({"type":"pkcs1", "format":"der"});
}

exports.generate_token = function(client_id) {
	let exp_seconds = 600
	let jwt_header = {
		"alg": "HS256",
		"kid": 1
	};
	let jwt_claims = {
		"sub": client_id,
		"exp": Math.round(new Date() / 1000 + exp_seconds)
	};

	let token_body = base64urlencode(Buffer.from(JSON.stringify(jwt_header))) + "." + base64urlencode(Buffer.from(JSON.stringify(jwt_claims)));
	let signature = base64urlencode(hmac_sha256(Buffer.from(token_body), get_key(jwt_header["kid"])));

	let token_response = {
		"access_token": token_body + "." + signature,
		"token_type": "bearer",
		"expires_in": exp_seconds
	};

	return JSON.stringify(token_response);
}

exports.authenticate = function(client_id, client_secret) {
	return creds[client_id] === client_secret;
}
