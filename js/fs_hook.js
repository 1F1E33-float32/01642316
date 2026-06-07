(function () {
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
			originals.appendFileSync.call(fs, path.join(process.cwd(), "mz_rust.log"), "[mz-js] " + String(message) + "\r\n");
		} catch (e) {}
	}
	if (fs.__mzRustHooked) {
		log("fs hook already installed");
		return true;
	}
	function normalizeWin(p) {
		return String(p || "")
			.replace(/\//g, "\\")
			.toLowerCase();
	}
	function isAllowedFsWrite(file) {
		const full = path.resolve(process.cwd(), String(file));
		const fullLower = normalizeWin(full);
		const rootLower = normalizeWin(process.cwd());
		const base = path.basename(full).toLowerCase();
		return (
			fullLower.indexOf("\\save\\") >= 0 ||
			base === "package.json" ||
			base === "c" ||
			base === "mz_rust.log" ||
			(fullLower.indexOf(rootLower + "\\data\\") === 0 && base.endsWith(".rmmzsave"))
		);
	}
	function rejectIfNeeded(file) {
		if (!isAllowedFsWrite(file)) {
			const err = new Error("blocked by mz native fs policy: " + file);
			err.code = "EACCES";
			throw err;
		}
	}
	fs.writeFile = function (file, ...args) {
		try {
			rejectIfNeeded(file);
		} catch (e) {
			const cb = args.find((v) => typeof v === "function");
			if (cb) return process.nextTick(cb, e);
			throw e;
		}
		return originals.writeFile.call(this, file, ...args);
	};
	fs.appendFile = function (file, ...args) {
		try {
			rejectIfNeeded(file);
		} catch (e) {
			const cb = args.find((v) => typeof v === "function");
			if (cb) return process.nextTick(cb, e);
			throw e;
		}
		return originals.appendFile.call(this, file, ...args);
	};
	fs.writeFileSync = function (file, ...args) {
		rejectIfNeeded(file);
		return originals.writeFileSync.call(this, file, ...args);
	};
	fs.appendFileSync = function (file, ...args) {
		rejectIfNeeded(file);
		return originals.appendFileSync.call(this, file, ...args);
	};
	Object.defineProperty(fs, "__mzRustHooked", { value: true });
	log("fs write hooks installed");
	return true;
})();
