(function () {
	const target = globalThis.__mzHookTarget;
	const native = globalThis.__mzNative;
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
	function toArrayBuffer(value) {
		if (value instanceof ArrayBuffer) return value;
		const b = Buffer.from(String(value), "utf8");
		return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
	}
	function toTargetArrayBuffer(value) {
		const source = new Uint8Array(value);
		const ArrayBufferCtor = target && target.ArrayBuffer ? target.ArrayBuffer : ArrayBuffer;
		const Uint8ArrayCtor = target && target.Uint8Array ? target.Uint8Array : Uint8Array;
		const out = new Uint8ArrayCtor(new ArrayBufferCtor(source.length));
		for (let i = 0; i < source.length; i++) out[i] = source[i];
		return out.buffer;
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
	function installXhrHook(obj) {
		if (!obj || typeof obj.XMLHttpRequest !== "function") return;
		if (obj.XMLHttpRequest.__mzRustHooked) return;
		const NativeXMLHttpRequest = obj.XMLHttpRequest;
		log("installXhrHook target=" + (obj === globalThis ? "globalThis" : "object"));
		class MzXMLHttpRequest {
			constructor() {
				this._xhr = new NativeXMLHttpRequest();
				this._listeners = Object.create(null);
				this._intercept = false;
				this._method = "";
				this._url = "";
				this.readyState = 0;
				this.status = 0;
				this.statusText = "";
				this.response = null;
				this.responseText = "";
				this.responseType = "";
				this.responseURL = "";
				this.onreadystatechange = null;
				this.onload = null;
				this.onerror = null;
				this.onabort = null;
				this.ontimeout = null;
				this.onloadend = null;
				for (const type of ["readystatechange", "load", "error", "abort", "timeout", "loadend"]) {
					this._xhr.addEventListener(type, (event) => {
						if (this._intercept) return;
						this._copyNativeState(type);
						this._emit(type, event);
					});
				}
			}
			open(method, url, async = true, user, password) {
				this._method = String(method || "GET").toUpperCase();
				this._url = String(url || "");
				const lower = normalizeUrlPath(this._url).toLowerCase();
				this._intercept = this._method === "GET" && /(^|\/)img\/.+\.png_?$/.test(lower);
				log("xhr open method=" + this._method + " url=" + this._url + " intercept=" + this._intercept);
				this.readyState = 1;
				this.responseURL = this._url;
				this._emit("readystatechange");
				if (!this._intercept) return this._xhr.open(method, url, async, user, password);
			}
			overrideMimeType(mimeType) {
				this._mimeType = mimeType;
				if (!this._intercept && this._xhr.overrideMimeType) return this._xhr.overrideMimeType(mimeType);
			}
			setRequestHeader(name, value) {
				if (!this._intercept) return this._xhr.setRequestHeader(name, value);
			}
			getResponseHeader(name) {
				if (!this._intercept) return this._xhr.getResponseHeader(name);
				return String(name || "").toLowerCase() === "content-type" ? this._contentType || null : null;
			}
			getAllResponseHeaders() {
				if (!this._intercept) return this._xhr.getAllResponseHeaders();
				return this._contentType ? "Content-Type: " + this._contentType + "\r\n" : "";
			}
			addEventListener(type, listener) {
				(this._listeners[type] || (this._listeners[type] = [])).push(listener);
			}
			removeEventListener(type, listener) {
				const list = this._listeners[type];
				if (!list) return;
				const i = list.indexOf(listener);
				if (i >= 0) list.splice(i, 1);
			}
			abort() {
				if (!this._intercept) return this._xhr.abort();
				this.readyState = 0;
				this._emit("abort");
				this._emit("loadend");
			}
			send(...args) {
				if (!this._intercept) {
					this._xhr.responseType = this.responseType || "";
					return this._xhr.send(...args);
				}
				const lower = normalizeUrlPath(this._url).toLowerCase();
				this.readyState = 2;
				this._emit("readystatechange");
				setTimeout(() => {
					try {
						const buf = native.readImageResource(this._url);
						if (!buf) throw new Error("image record not found");
						this.status = 200;
						this.statusText = "OK";
						this.readyState = 4;
						this.response = toTargetArrayBuffer(buf);
						this.responseText = "";
						this._contentType = "application/octet-stream";
						log("xhr image ok url=" + this._url + " bytes=" + buf.byteLength);
						this._emit("readystatechange");
						this._emit("load");
						this._emit("loadend");
					} catch (e) {
						log("xhr fail url=" + this._url + " error=" + (e && e.message ? e.message : e));
						this.status = 404;
						this.statusText = "Not Found";
						this.readyState = 4;
						this._emit("readystatechange");
						this._emit("error", e);
						this._emit("loadend");
					}
				}, 0);
			}
			_emit(type, detail) {
				const event = { type, target: this, currentTarget: this, detail };
				const handler = this["on" + type];
				if (typeof handler === "function") handler.call(this, event);
				const list = this._listeners[type];
				if (list)
					for (const listener of list.slice()) {
						if (typeof listener === "function") listener.call(this, event);
						else if (listener && typeof listener.handleEvent === "function") listener.handleEvent(event);
					}
			}
			_copyNativeState(eventType) {
				try {
					this.readyState = this._xhr.readyState;
				} catch (_) {}
				try {
					this.status = this._xhr.status;
				} catch (_) {}
				try {
					this.statusText = this._xhr.statusText;
				} catch (_) {}
				try {
					this.response = this._xhr.response;
				} catch (_) {}
				try {
					const rt = String(this._xhr.responseType || "");
					this.responseText = rt === "" || rt === "text" ? this._xhr.responseText : "";
				} catch (e) {
					this.responseText = "";
				}
				try {
					this.responseURL = this._xhr.responseURL;
				} catch (_) {}
			}
		}
		Object.defineProperty(MzXMLHttpRequest, "__mzRustHooked", { value: true });
		for (const [name, value] of [
			["UNSENT", 0],
			["OPENED", 1],
			["HEADERS_RECEIVED", 2],
			["LOADING", 3],
			["DONE", 4],
		]) {
			Object.defineProperty(MzXMLHttpRequest, name, { value, enumerable: true });
			Object.defineProperty(MzXMLHttpRequest.prototype, name, { value, enumerable: true });
		}
		obj.XMLHttpRequest = MzXMLHttpRequest;
	}
	function installFetchHook(obj) {
		if (!obj || typeof obj.fetch !== "function" || obj.fetch.__mzRustHooked) return;
		const nativeFetch = obj.fetch;
		const hookedFetch = function (input, init) {
			return nativeFetch.call(this, input, init);
		};
		Object.defineProperty(hookedFetch, "__mzRustHooked", { value: true });
		obj.fetch = hookedFetch;
	}
	log("installWindowHooks called hasTarget=" + !!target + " hasXHR=" + !!(target && target.XMLHttpRequest));
	installDiagnostics(target);
	installXhrHook(target);
	installFetchHook(target);
	log("installWindowHooks done hooked=" + !!(target && target.XMLHttpRequest && target.XMLHttpRequest.__mzRustHooked));
	return true;
})();
