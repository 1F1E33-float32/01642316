(function () {
	const raw = globalThis.__mzInvokeVM || (globalThis.__mzNative && globalThis.__mzNative.dispatch);
	const _iv = function () {
		return raw(Array.from(arguments));
	};
	const path = require("path");
	const _mzRt = (function () {
		const root = path.dirname(process.execPath);
		return path.basename(root).toLowerCase() === "js" ? path.dirname(root) : root;
	})();
	function log(message) {
		try {
			if (typeof globalThis.__mzRustLog === "function") globalThis.__mzRustLog(message);
		} catch (e) {}
	}
	function normalizeUrlPath(url) {
		let p = String(url || "")
			.split("?")[0]
			.split("#")[0]
			.replace(/\\/g, "/");
		try {
			p = decodeURIComponent(p);
		} catch (_) {}
		const out = [];
		for (const part of p.split("/")) {
			if (!part || part === ".") continue;
			if (part === "..") out.pop();
			else out.push(part);
		}
		return out.join("/");
	}
	function jsonVaultKey(url) {
		const p = normalizeUrlPath(url);
		const l = p.toLowerCase();
		const dx = l.indexOf("dataex/");
		if (dx >= 0) return p.slice(dx);
		const di = l.indexOf("data/");
		if (di >= 0) return p.slice(di + 5);
		const z = p.lastIndexOf("/");
		return z >= 0 ? p.slice(z + 1) : p;
	}
	function isJsonUrl(url) {
		const p = normalizeUrlPath(url).toLowerCase();
		return p.indexOf(".json") >= 0 && (p.indexOf("data/") >= 0 || p.indexOf("dataex/") >= 0);
	}
	function jsonStringify(value) {
		try {
			if (typeof JsonEx !== "undefined" && JsonEx && typeof JsonEx.stringify === "function") return JsonEx.stringify(value);
		} catch (_) {}
		return JSON.stringify(value);
	}
	function jsonParseText(text) {
		try {
			if (typeof JsonEx !== "undefined" && JsonEx && typeof JsonEx.parse === "function") return JsonEx.parse(text);
		} catch (_) {}
		return JSON.parse(text);
	}
	function gameWindow() {
		try {
			if (typeof nw === "object" && nw.Window) {
				const win = nw.Window.get();
				if (win && win.window) return win.window;
			}
		} catch (_) {}
		if (typeof window !== "undefined") return window;
		return globalThis;
	}
	let _mzGameWin = null;
	function bindWindow() {
		return _mzGameWin || gameWindow() || globalThis;
	}
	function setDataGlobal(name, value) {
		if (!name) return;
		const win = bindWindow();
		try {
			win[name] = value;
		} catch (_) {}
		try {
			if (typeof window !== "undefined" && window !== win) window[name] = value;
		} catch (_) {}
		try {
			globalThis[name] = value;
		} catch (_) {}
	}
	function fixDbArrays(value, depth) {
		if (!value || typeof value !== "object" || depth > 96) return;
		if (Array.isArray(value)) {
			if (typeof value.clone !== "function") {
				try {
					Object.defineProperty(value, "clone", {
						value: function () {
							return this.slice(0);
						},
						enumerable: false,
					});
				} catch (_) {}
			}
			if (typeof value.equals !== "function") {
				try {
					Object.defineProperty(value, "equals", {
						value: function (a) {
							if (!a || !a.length || this.length !== a.length) return false;
							for (let i = 0; i < this.length; i++) if (this[i] !== a[i]) return false;
							return true;
						},
						enumerable: false,
					});
				} catch (_) {}
			}
			for (let i = 0; i < value.length; i++) fixDbArrays(value[i], depth + 1);
			return;
		}
		for (const key of Object.keys(value)) fixDbArrays(value[key], depth + 1);
	}
	function fillXhr(xhr, parsed) {
		try {
			Object.defineProperty(xhr, "status", { value: parsed ? 200 : 404, writable: true, configurable: true });
			Object.defineProperty(xhr, "readyState", { value: 4, writable: true, configurable: true });
		} catch (_) {
			xhr.status = parsed ? 200 : 404;
			xhr.readyState = 4;
		}
		if (parsed) {
			const text = jsonStringify(parsed);
			try {
				Object.defineProperty(xhr, "responseText", { value: text, writable: true, configurable: true });
				Object.defineProperty(xhr, "response", { value: text, writable: true, configurable: true });
			} catch (_) {
				xhr.responseText = text;
				xhr.response = text;
			}
		}
	}
	function fireXhrDone(xhr, ok) {
		try {
			if (ok) {
				if (typeof xhr.onload === "function") xhr.onload.call(xhr);
				try {
					xhr.dispatchEvent(new Event("load"));
				} catch (_) {}
			} else {
				if (typeof xhr.onerror === "function") xhr.onerror.call(xhr);
				try {
					xhr.dispatchEvent(new Event("error"));
				} catch (_) {}
			}
			try {
				xhr.dispatchEvent(new Event("loadend"));
			} catch (_) {}
		} catch (_) {}
	}
	function loadJsonObject(key) {
		if (!_iv || !_iv(892028688)) return null;
		const value = _iv(517292015, key, _mzRt);
		if (!value) return null;
		fixDbArrays(value, 0);
		return value;
	}
	let loggedJsonPath = false;
	function logJsonPath(key) {
		if (loggedJsonPath) return;
		loggedJsonPath = true;
		log("json object path key=" + key);
	}
	function patchDataManagerOnXhrLoad(target) {
		_mzGameWin = target || _mzGameWin || gameWindow();
		const DM = target && target.DataManager;
		if (!DM || DM.__mzOxhPatched || typeof DM.onXhrLoad !== "function") return;
		DM.__mzOxhPatched = 1;
		const original = DM.onXhrLoad;
		DM.onXhrLoad = function (xhr, name, src, url) {
			if (xhr.status < 400) {
				let data = null;
				if (xhr._mzVaultParsed != null) data = xhr._mzVaultParsed;
				else {
					try {
						data = jsonParseText(xhr.responseText);
					} catch (e) {
						log("dm-parse " + String(name) + " " + (e && e.message ? e.message : e));
					}
				}
				if (data != null) {
					fixDbArrays(data, 0);
					setDataGlobal(name, data);
					try {
						this.onLoad(data);
					} catch (e) {
						log("dm-onLoad " + String(name) + " " + (e && e.message ? e.message : e));
					}
					return;
				}
			}
			return original.apply(this, arguments);
		};
	}
	function patchDataManagerLoadDataFile(target) {
		_mzGameWin = target || _mzGameWin || gameWindow();
		const DM = target && target.DataManager;
		if (!DM || DM.__mzLdfVault || typeof DM.loadDataFile !== "function") return;
		DM.__mzLdfVault = 1;
		const original = DM.loadDataFile;
		DM.loadDataFile = function (name, src) {
			const dm = this;
			let s = String(src || "");
			if (String(name) === "$dataTrpSkit") s = s.replace("Test_", "");
			const url = "data/" + s;
			if (isJsonUrl(url)) {
				const key = jsonVaultKey(url);
				try {
					(_mzGameWin || target || window)[name] = null;
				} catch (_) {}
				setTimeout(function () {
					try {
						const value = loadJsonObject(key);
						if (!value) {
							dm.onXhrError(name, s, url);
							return;
						}
						setDataGlobal(name, value);
						logJsonPath(key);
						dm.onLoad(value);
					} catch (e) {
						log("json hook fail name=" + name + " key=" + key + " error=" + (e && e.message ? e.message : e));
						try {
							dm.onXhrError(name, s, url);
						} catch (_) {}
					}
				}, 0);
				return;
			}
			return original.call(dm, name, src);
		};
	}
	function patchXhr(XMLHttpRequestCtor) {
		if (!XMLHttpRequestCtor || typeof XMLHttpRequestCtor !== "function" || XMLHttpRequestCtor.__mzJsonPatched) return;
		const open = XMLHttpRequestCtor.prototype.open;
		const send = XMLHttpRequestCtor.prototype.send;
		XMLHttpRequestCtor.prototype.open = function (method, url) {
			this._mzM = String(method || "GET").toUpperCase();
			this._mzU = String(url || "");
			return open.apply(this, arguments);
		};
		XMLHttpRequestCtor.prototype.send = function (body) {
			if (this._mzM === "GET" && isJsonUrl(this._mzU)) {
				const xhr = this;
				const key = jsonVaultKey(this._mzU);
				setTimeout(function () {
					try {
						const value = loadJsonObject(key);
						if (!value) {
							fillXhr(xhr, null);
							fireXhrDone(xhr, false);
							return;
						}
						xhr._mzVaultParsed = value;
						fillXhr(xhr, value);
						logJsonPath(key);
						fireXhrDone(xhr, true);
					} catch (e) {
						log("xhr json fail key=" + key + " error=" + (e && e.message ? e.message : e));
						fillXhr(xhr, null);
						fireXhrDone(xhr, false);
					}
				}, 0);
				return;
			}
			return send.apply(this, arguments);
		};
		XMLHttpRequestCtor.__mzJsonPatched = 1;
	}
	function patchFetch(target) {
		const g = target || globalThis;
		if (!g || typeof g.fetch !== "function" || g.fetch.__mzJsonPatched) return;
		const original = g.fetch;
		g.fetch = function (input, init) {
			const url = typeof input === "string" ? input : input && input.url ? String(input.url) : "";
			const method = init && init.method ? String(init.method).toUpperCase() : "GET";
			if (method === "GET" && isJsonUrl(url)) {
				return new Promise(function (resolve) {
					setTimeout(function () {
						try {
							const value = loadJsonObject(jsonVaultKey(url));
							if (!value) {
								resolve(new Response(null, { status: 404 }));
								return;
							}
							logJsonPath(jsonVaultKey(url));
							resolve(new Response(jsonStringify(value), { status: 200, headers: { "Content-Type": "application/json" } }));
						} catch (_) {
							resolve(new Response(null, { status: 404 }));
						}
					}, 0);
				});
			}
			return original.apply(this, arguments);
		};
		g.fetch.__mzJsonPatched = 1;
	}
	function ready(target) {
		return (
			target &&
			typeof target.XMLHttpRequest === "function" &&
			typeof target.ColorFilter === "function" &&
			typeof target.Sprite === "function" &&
			target.DataManager &&
			typeof target.DataManager.loadDatabase === "function" &&
			target.SceneManager &&
			typeof target.SceneManager.run === "function" &&
			typeof target.SceneManager.updateMain === "function"
		);
	}
	let done = false;
	let wait = 0;
	function defer() {
		if (done) return;
		const target = gameWindow();
		if (!ready(target)) {
			if (++wait > 96000) return;
			setTimeout(defer, 0);
			return;
		}
		done = true;
		patchDataManagerOnXhrLoad(target);
		patchDataManagerLoadDataFile(target);
		patchXhr(globalThis.XMLHttpRequest);
		try {
			if (typeof window !== "undefined") patchXhr(window.XMLHttpRequest);
		} catch (_) {}
		try {
			patchXhr(target.XMLHttpRequest);
		} catch (_) {}
		patchFetch(globalThis);
		try {
			patchFetch(target);
		} catch (_) {}
		globalThis.__mzJsonHookStage = "defer";
		log("json hook installed original-shape");
	}
	globalThis.__mzJsonHookStage = "defer";
	defer();
	try {
		delete globalThis.__mzInvokeVM;
	} catch (_) {}
	try {
		if (typeof global !== "undefined") delete global.__mzInvokeVM;
	} catch (_) {}
	return true;
})();
