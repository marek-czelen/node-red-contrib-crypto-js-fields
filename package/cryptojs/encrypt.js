module.exports = function (RED) {
	var CryptoJS = require("crypto-js");

	function EncryptNode(config) {
		RED.nodes.createNode(this, config);

		var node = this;
		node.algorithm = config.algorithm;
		node.key = config.key;
		node.iv=config.iv
		node.field = config.fieldname

		node.on('input', function (msg) {
			// check configurations
			if(!node.algorithm || !node.key) {
				// rising misconfiguration error
				node.error("Missing configuration, please check your algorithm or secret key.", msg);
			} else {
				// check the payload
				let itemToEncrypt = msg.payload;
				if (node.field != ''){
					var fieldsArray=node.field.split('.')
					msg.payload.fieldsArray = fieldsArray
					for (const fieldItem of fieldsArray) {
						if (itemToEncrypt.hasOwnProperty(fieldItem)) itemToEncrypt = itemToEncrypt[fieldItem]
					}
				}
								
				var key = CryptoJS.enc.Utf8.parse(node.key);
				var iv  = CryptoJS.enc.Utf8.parse(node.iv);
				let stringToEncrypt = itemToEncrypt;
				
				if(stringToEncrypt) {
					// debugging message
					node.debug('Encrypting payload using '+node.algorithm);
					// encrypt with CryptoJS
					msg.payload.encrypted = CryptoJS[node.algorithm].encrypt(
						stringToEncrypt, 
						key, 
						{ iv: iv,
						 padding: CryptoJS.pad.Pkcs7,
						 mode: CryptoJS.mode.CBC
						}).ciphertext.toString(CryptoJS.enc.Base64);
				} else {
					// debugging message
					node.trace('Nothing to encrypt: empty payload');
				}

				node.send(msg);
			}
		});
	}

	RED.nodes.registerType("encrypt", EncryptNode);
};