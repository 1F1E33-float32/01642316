(function () {
	const target = globalThis.__mzHookTarget;
	const fs = require("fs");
	const path = require("path");
	const originals =
		globalThis.__mzFsOriginals ||
		(globalThis.__mzFsOriginals = {
			writeFile: fs.writeFile,
			writeFileSync: fs.writeFileSync,
			appendFile: fs.appendFile,
			appendFileSync: fs.appendFileSync,
		});

	function log(message) {
		try {
			if (typeof globalThis.__mzRustLog === "function") {
				globalThis.__mzRustLog(message);
			} else {
				originals.appendFileSync.call(fs, path.join(process.cwd(), "mz_rust.log"), "[mz-js] " + String(message) + "\r\n");
			}
		} catch (e) {}
	}

	function installDiagnostics(obj) {
		if (obj && typeof obj.addEventListener === "function" && !obj.__mzDiagnosticsHooked) {
			try {
				obj.addEventListener("error", (event) =>
					log("window error " + ((event && event.error && event.error.stack) || (event && event.message) || "")),
				);
				obj.addEventListener("unhandledrejection", (event) =>
					log("window unhandledrejection " + ((event && event.reason && event.reason.stack) || (event && event.reason) || "")),
				);
				Object.defineProperty(obj, "__mzDiagnosticsHooked", { value: true });
			} catch (_) {}
		}
	}

	function gameRoot() {
		try {
			const root = path.dirname(process.execPath);
			return path.basename(root).toLowerCase() === "js" ? path.dirname(root) : root;
		} catch (_) {
			return "";
		}
	}

	function makeXhrLike(status, response) {
		return {
			status: status,
			readyState: 4,
			response: response,
			responseType: "arraybuffer",
		};
	}

	function installBitmapHook(obj) {
		if (!obj || !obj.Bitmap || !obj.Bitmap.prototype) return false;
		const proto = obj.Bitmap.prototype;
		if (proto.__mzBitmapHooked) return true;
		if (typeof globalThis.__mzIw10 !== "function") return false;
		if (typeof proto._startDecrypting !== "function" || typeof proto._onXhrLoad !== "function") return false;

		const nativeStartDecrypting = proto._startDecrypting;
		let loggedBitmapPath = false;
		proto._startDecrypting = function () {
			const bitmap = this;
			const url = String(bitmap._url || "");
			const root = gameRoot();
			try {
				globalThis.__mzIw10(url, root, function (arrayBuffer, errorCode) {
					try {
						if (arrayBuffer && !errorCode) {
							if (!loggedBitmapPath) {
								loggedBitmapPath = true;
								log("bitmap __mzIw10 path url=" + url + " bytes=" + arrayBuffer.byteLength);
							}
							return bitmap._onXhrLoad(makeXhrLike(200, arrayBuffer));
						}
						log("bitmap __mzIw10 fail url=" + url + " code=" + errorCode);
						return bitmap._onError();
					} catch (e) {
						log("bitmap callback error url=" + url + " error=" + (e && e.message ? e.message : e));
						return bitmap._onError();
					}
				});
			} catch (e) {
				log("bitmap __mzIw10 throw url=" + url + " error=" + (e && e.message ? e.message : e));
				return nativeStartDecrypting.apply(bitmap, arguments);
			}
		};

		Object.defineProperty(proto, "__mzBitmapHooked", { value: true });
		log("bitmap hook installed");
		return true;
	}

	function deferBitmapHook(obj) {
		let wait = 0;
		function step() {
			if (installBitmapHook(obj)) return;
			if (++wait > 96000) return;
			try {
				setTimeout(step, 0);
			} catch (_) {}
		}
		step();
	}

	installDiagnostics(target);
	deferBitmapHook(target);
	return true;
})();
