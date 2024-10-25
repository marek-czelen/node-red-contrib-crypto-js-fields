module.exports = function (RED) {
	var CryptoJS = require("crypto-js");

	function EncryptNode(config) {
		RED.nodes.createNode(this, config);

		var node = this;
		node.algorithm = config.algorithm;
		node.key = config.key;
		node.field = config.field

		node.on('input', function (msg) {
			// check configurations
			if(!node.algorithm || !node.key) {
				// rising misconfiguration error
				node.error("Missing configuration, please check your algorithm or secret key.", msg);
			} else {
				// check the payload
				var fieldsArray=node.field.split('.')
				var item = msg
				for (const fieldItem of fieldsArray) {
					if (item.hasOwnProperty(fieldItem)) item = item[fieldItem]
				}
				if(item) {
					// debugging message
					node.debug('Encrypting payload using '+node.algorithm);
					// encrypt with CryptoJS
					item = CryptoJS[node.algorithm].encrypt(item, node.key).toString();
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