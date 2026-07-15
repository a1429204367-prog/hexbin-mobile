type RequestMessage = { id: number; method: string; args: unknown[] };
type PyProxy = { [name: string]: unknown; destroy?: () => void };
type PyodideRuntime = {
  FS: { writeFile: (path: string, value: string) => void };
  runPython: (source: string) => unknown;
  pyimport: (name: string) => PyProxy;
};

let runtime: Promise<PyodideRuntime> | null = null;
let phase = "尚未启动";
const runtimeLogs: string[] = [];
const originalConsoleError = console.error.bind(console);
const originalConsoleWarn = console.warn.bind(console);
console.error = (...values: unknown[]) => {
  runtimeLogs.push(values.map(String).join(" "));
  originalConsoleError(...values);
};
console.warn = (...values: unknown[]) => {
  runtimeLogs.push(values.map(String).join(" "));
  originalConsoleWarn(...values);
};

async function getRuntime(): Promise<PyodideRuntime> {
  if (!runtime) {
    runtime = (async () => {
      phase = "加载运行器脚本";
      const appRoot = new URL("../", self.location.href);
      const runtimeRoot = new URL("runtime/", appRoot);
      const loaderUrl = new URL("pyodide.mjs", runtimeRoot).href;
      const { loadPyodide } = await import(/* @vite-ignore */ loaderUrl) as {
        loadPyodide: (options: { indexURL: string; stdLibURL: string; lockFileURL: string; stdout: (value: string) => void; stderr: (value: string) => void }) => Promise<PyodideRuntime>;
      };
      phase = "初始化运行器";
      const remember = (value: string) => {
        runtimeLogs.push(value);
        if (runtimeLogs.length > 12) runtimeLogs.shift();
      };
      const pyodide = await loadPyodide({
        indexURL: runtimeRoot.href,
        stdLibURL: new URL("python_stdlib.data", runtimeRoot).href,
        lockFileURL: new URL("pyodide-lock.json", runtimeRoot).href,
        stdout: remember,
        stderr: remember,
      });
      const files = ["hexbin_core.py", "line_checksum_core.py", "bridge.py"];
      for (const file of files) {
        phase = `读取核心文件 ${file}`;
        const response = await fetch(new URL(`python/${file}`, appRoot));
        if (!response.ok) throw new Error(`核心文件加载失败：${file}`);
        pyodide.FS.writeFile(`/home/pyodide/${file}`, await response.text());
      }
      phase = "导入核心模块";
      pyodide.runPython("import sys; sys.path.insert(0, '/home/pyodide'); import bridge");
      phase = "运行就绪";
      return pyodide;
    })();
  }
  return runtime;
}

self.onmessage = async (event: MessageEvent<RequestMessage>) => {
  const { id, method, args } = event.data;
  try {
    const pyodide = await getRuntime();
    const bridge = pyodide.pyimport("bridge");
    const fn = bridge[method] as ((...values: unknown[]) => string) & { destroy?: () => void };
    if (typeof fn !== "function") throw new Error(`核心方法不存在：${method}`);
    const result = fn(...args);
    fn.destroy?.();
    bridge.destroy?.();
    self.postMessage({ id, ok: true, result });
  } catch (error) {
    const message = error instanceof Error
      ? `${error.message}\n${error.stack || ""}`
      : typeof error === "object" && error && "message" in error
        ? String((error as { message: unknown }).message)
        : JSON.stringify(error) || String(error);
    self.postMessage({ id, ok: false, error: `${phase}：${message}${runtimeLogs.length ? `\n${runtimeLogs.join("\n")}` : ""}` });
  }
};
