(function () {
	const fs = require("fs");
	const appendFileSync = fs.appendFileSync.bind(fs);
	function mzRustLog(message) {
		try {
			appendFileSync("mz_rust.log", "[mz-js] " + String(message) + "\r\n");
		} catch (e) {}
	}
	globalThis.__mzRustLog = mzRustLog;
	mzRustLog("first script guard installed");
	return true;
})();
