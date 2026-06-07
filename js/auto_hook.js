(function () {
	const native = globalThis.__mzNative;
	if (!native || typeof native.installWindowHooks !== "function") return false;
	function install(target) {
		try {
			if (target) native.installWindowHooks(target);
		} catch (e) {
			try {
				if (typeof globalThis.__mzRustLog === "function") {
					globalThis.__mzRustLog("auto hook target failed " + (e && e.message ? e.message : e));
				}
			} catch (_) {}
		}
	}
	install(globalThis);
	try {
		if (typeof window !== "undefined") install(window);
	} catch (_) {}
	try {
		if (typeof nw === "object" && nw.Window) {
			const win = nw.Window.get();
			if (win && win.window) install(win.window);
		}
	} catch (_) {}
	try {
		setTimeout(function () {
			install(globalThis);
			try {
				if (typeof window !== "undefined") install(window);
			} catch (_) {}
			try {
				if (typeof nw === "object" && nw.Window) {
					const win = nw.Window.get();
					if (win && win.window) install(win.window);
				}
			} catch (_) {}
		}, 0);
	} catch (_) {}
	return true;
})();
