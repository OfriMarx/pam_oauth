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
	var ret = buf.toString("base64");
	ret = replaceAll(ret, "=", "");
	ret = replaceAll(ret, "+", "-");
	ret = replaceAll(ret, "/", "_");
	return ret;
}

function base64urldecode(str) {
	str = replaceAll(str, "-", "+");
	str = replaceAll(str, "_", "/");
	return Buffer.from(str, "base64");
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

function get_random_kid() {
	var key_list = Object.keys(keys);
	return key_list[key_list.length * Math.random() << 0];
}

exports.generate_token = function(client_id, exp_seconds) {
	var kid = get_random_kid();
	var time = Math.round(new Date() / 1000);
	var jwt_header = {
		"alg": "HS256",
		"kid": kid
	};
	var jwt_claims = {
		"iss": "ofri",
		"sub": client_id,
		"exp": time + exp_seconds,
		"nbf": time
	};

	var token_body = base64urlencode(Buffer.from(JSON.stringify(jwt_header))) + "." + base64urlencode(Buffer.from(JSON.stringify(jwt_claims)));
	var signature = base64urlencode(hmac_sha256(Buffer.from(token_body), get_key(kid)));

	var token_response = {
		"access_token": token_body + "." + signature,
		"token_type": "bearer",
		"expires_in": exp_seconds
	};

	return JSON.stringify(token_response);
}

exports.authenticate_client = function(client_id, client_secret) {
	return creds[client_id] === client_secret;
}

exports.validate_token = function(token) {
	token = token.split(".");
	if(token.length != 3) {
		return false;
	}
	
	var header = base64urldecode(token[0]);
	var claims = base64urldecode(token[1]);
	var signature = base64urldecode(token[2]);

	try {
		header = JSON.parse(header.toString());
		claims = JSON.parse(header.toString());
	} catch(e) {
		return false;
	}

	if(!("alg" in header && "kid" in header && "iss" in claims && "sub" in claims && "exp" in claims && "nbf" in claims)) {
		return false;
	}

	if(header["alg"] !== "HS256") {
		return false;
	}

	if(claims["iss"] !== "ofri") {
		return false;
	}

	if(!(claims["sub"] in creds)) {
		return false;
	}

	var time = Math.round(new Date() / 1000);
	if(time < claims["nbf"] || time > claims["exp"]) {
		return false;
	}

	if(Buffer.compare(hmac_sha256(Buffer.from(token[0] + "." + token[1]), get_key(header["kid"])), signature)) {
		return false;
	}

	return true;
}
