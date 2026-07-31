import "./style.css";
import { core, type FileMetadata, type PageData, type ToolId } from "./api";

const PAGE_SIZE = 16 * 64;
const BYTES_PER_ROW = 16;
const COLUMN_LABELS = Array.from(
  { length: BYTES_PER_ROW },
  (_, index) => index.toString(16).toUpperCase().padStart(2, "0"),
);

type ToolState = {
  metadata: FileMetadata | null;
  page: PageData | null;
  pageStart: number;
  selectedOffset: number | null;
  searchOffset: number;
  busy: boolean;
};

const states: Record<ToolId, ToolState> = {
  v50: { metadata: null, page: null, pageStart: 0, selectedOffset: null, searchOffset: -1, busy: false },
  v11: { metadata: null, page: null, pageStart: 0, selectedOffset: null, searchOffset: -1, busy: false },
};

let activeTool: ToolId = "v50";

const app = document.querySelector<HTMLDivElement>("#app");
if (!app) throw new Error("页面初始化失败。");

app.innerHTML = `
  <header class="topbar">
    <div>
      <p class="eyebrow">文件仅在本机处理 · 支持离线安装</p>
      <h1>固件文件工具箱</h1>
    </div>
    <button class="ghost" id="installButton" hidden>安装到桌面</button>
  </header>
  <main>
    <nav class="tool-tabs" aria-label="工具选择">
      <button class="tool-tab active" data-tool="v50"><strong>主转换工具</strong><span>V50 · 总校验与格式转换</span></button>
      <button class="tool-tab" data-tool="v11"><strong>行校验工具</strong><span>V11 · 单行校验与通用导出</span></button>
    </nav>
    <section id="workspace"></section>
  </main>
  <div id="toast" role="status" aria-live="polite"></div>
`;

const workspace = document.querySelector<HTMLElement>("#workspace")!;
const toast = document.querySelector<HTMLDivElement>("#toast")!;

function toolTitle(tool: ToolId): string {
  return tool === "v50" ? "主转换工具 V50" : "行校验工具 V11";
}

function acceptedFiles(tool: ToolId): string {
  return tool === "v50" ? ".hex,.HEX,.hex_tmp,.s19,.S19,.s28,.S28,.s37,.S37,.mot,.MOT,.srec,.SREC,.bin,.BIN" : ".hex,.HEX,.bin,.BIN,.s19,.S19,.s28,.S28,.s37,.S37,.mot,.MOT";
}

function showToast(message: string, error = false): void {
  toast.textContent = message;
  toast.className = error ? "show error" : "show";
  window.setTimeout(() => { toast.className = ""; }, 3200);
}

function formatHex(value: number, width = 8): string {
  return `0x${value.toString(16).toUpperCase().padStart(width, "0")}`;
}

function render(): void {
  const state = states[activeTool];
  const meta = state.metadata;
  workspace.innerHTML = `
    <section class="upload-card ${meta ? "compact" : ""}">
      <div>
        <p class="section-label">${toolTitle(activeTool)}</p>
        <h2>${meta ? escapeHtml(meta.name) : "打开一个固件文件"}</h2>
        <p>${meta ? `${escapeHtml(meta.format)} · ${escapeHtml(meta.family)}` : "支持 HEX、BIN、S19、S28、S37、MOT 等格式，文件不会上传。"}</p>
      </div>
      <label class="primary ${state.busy ? "disabled" : ""}">
        ${state.busy ? "正在载入核心…" : meta ? "更换文件" : "选择文件"}
        <input id="fileInput" type="file" accept="${acceptedFiles(activeTool)}" ${state.busy ? "disabled" : ""} />
      </label>
    </section>
    ${meta && state.page ? renderEditor(state, meta) : renderEmptyGuide()}
  `;
  bindWorkspaceEvents();
}

function renderEmptyGuide(): string {
  return `
    <section class="empty-guide">
      <div><span>1</span><h3>选择文件</h3><p>浏览器直接读取手机或电脑中的文件。</p></div>
      <div><span>2</span><h3>查看与编辑</h3><p>按地址分页，点选字节进行修改。</p></div>
      <div><span>3</span><h3>校验并导出</h3><p>自动重算校验，下载新的文件。</p></div>
    </section>
  `;
}

function renderEditor(state: ToolState, meta: FileMetadata): string {
  const page = state.page!;
  const selected = state.selectedOffset;
  const selectedValue = selected === null || selected < page.start || selected >= page.end ? null : page.bytes[selected - page.start];
  const firstPage = page.start === 0;
  const lastPage = page.end >= page.total;
  const rows: string[] = [];
  for (let rowStart = 0; rowStart < page.bytes.length; rowStart += BYTES_PER_ROW) {
    const offset = page.start + rowStart;
    const values = page.bytes.slice(rowStart, rowStart + BYTES_PER_ROW);
    rows.push(`<div class="hex-row"><button class="address" data-jump-offset="${offset}">${formatHex(meta.baseAddress + offset)}</button><div class="byte-row">${values.map((value, index) => {
      const absoluteOffset = offset + index;
      return `<button class="byte ${selected === absoluteOffset ? "selected" : ""}" data-offset="${absoluteOffset}">${value.toString(16).toUpperCase().padStart(2, "0")}</button>`;
    }).join("")}</div><div class="ascii">${values.map((value) => value >= 32 && value <= 126 ? escapeHtml(String.fromCharCode(value)) : ".").join("")}</div></div>`);
  }

  return `
    <div class="workspace-grid">
      <aside class="info-panel">
        <div class="stat-grid">
          <div><span>起始地址</span><strong>${formatHex(meta.baseAddress)}</strong></div>
          <div><span>数据长度</span><strong>${meta.size.toLocaleString()} 字节</strong></div>
          <div><span>识别结构</span><strong>${escapeHtml(meta.family)}</strong></div>
          <div><span>校验方式</span><strong>${escapeHtml(meta.checksumScheme)}</strong></div>
        </div>
        <details open><summary>数据段 (${meta.segments.length})</summary><div class="detail-list">${meta.segments.map((item, index) => `<p><b>${index + 1}</b><span>${formatHex(item.start)} — ${formatHex(item.end)}<small>${item.size.toLocaleString()} 字节</small></span></p>`).join("")}</div></details>
        ${meta.checksums.length ? `<details open><summary>总校验</summary><div class="checksum-list">${meta.checksums.map((item) => `<p><span>段 ${item.segment}</span><code>${item.current || "—"}</code><small>${formatHex(item.start)} — ${formatHex(item.end)}</small></p>`).join("")}</div></details>` : ""}
      </aside>
      <section class="editor-panel">
        <div class="controls">
          <form id="jumpForm"><input id="jumpInput" inputmode="text" placeholder="跳转地址，如 2047F0" /><button>跳转</button></form>
          <form id="searchForm"><input id="searchInput" inputmode="text" placeholder="搜索，如 AA 55 01" /><button>搜索</button></form>
        </div>
        <div class="pager"><button id="previousPage" ${firstPage ? "disabled" : ""}>上一页</button><span>${formatHex(meta.baseAddress + page.start)} — ${formatHex(meta.baseAddress + Math.max(page.start, page.end - 1))}</span><button id="nextPage" ${lastPage ? "disabled" : ""}>下一页</button></div>
        <div class="hex-table" aria-label="十六进制编辑器"><div class="hex-header"><span>地址</span><div class="byte-columns">${COLUMN_LABELS.map((label) => `<span>${label}</span>`).join("")}</div><span>ASCII</span></div>${rows.join("")}</div>
        <div class="edit-bar ${selected === null ? "disabled" : ""}">
          <div><span>当前字节</span><strong>${selected === null ? "未选择" : `${formatHex(meta.baseAddress + selected)} · 偏移 ${formatHex(selected)}`}</strong></div>
          <label>十六进制<input id="hexEdit" maxlength="2" inputmode="text" enterkeyhint="next" autocomplete="off" autocapitalize="characters" spellcheck="false" value="${selectedValue === null ? "" : selectedValue.toString(16).toUpperCase().padStart(2, "0")}" ${selected === null ? "disabled" : ""} /></label>
          <label>字符<input id="asciiEdit" maxlength="1" value="${selectedValue !== null && selectedValue >= 32 && selectedValue <= 126 ? escapeHtml(String.fromCharCode(selectedValue)) : ""}" ${selected === null ? "disabled" : ""} /></label>
          <div class="edit-actions">
            <button id="previousByte" class="byte-nav" type="button" title="上一字节" aria-label="上一字节" ${selected === null || selected <= 0 ? "disabled" : ""}>←</button>
            <button id="applyEdit" class="primary" type="button" ${selected === null ? "disabled" : ""}>应用修改</button>
            <button id="nextByte" class="byte-nav" type="button" title="下一字节" aria-label="下一字节" ${selected === null || selected >= meta.size - 1 ? "disabled" : ""}>→</button>
          </div>
        </div>
        <div class="export-bar"><span>导出后会自动应用镜像和校验规则</span><div>${exportButtons(activeTool)}</div></div>
      </section>
    </div>
  `;
}

function exportButtons(tool: ToolId): string {
  const formats = tool === "v50" ? ["hex", "bin"] : ["hex", "bin", "s19", "mot", "s28", "s37"];
  return formats.map((format) => `<button class="export" data-format="${format}">导出 ${format.toUpperCase()}</button>`).join("");
}

async function saveExport(file: File): Promise<void> {
  const shareData = { files: [file], title: file.name };
  if (navigator.share && navigator.canShare?.(shareData)) {
    try {
      await navigator.share(shareData);
      window.setTimeout(() => showToast(`已生成 ${file.name}，可保存到文件管理或分享给其他应用。`), 50);
      return;
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") return;
    }
  }

  const url = URL.createObjectURL(file);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = file.name;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  window.setTimeout(() => showToast(`已下载 ${file.name}，请到浏览器下载记录或文件管理的“下载”中查找。`), 50);
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]!);
}

async function loadPage(tool: ToolId, start: number): Promise<void> {
  const state = states[tool];
  if (!state.metadata) return;
  state.pageStart = Math.max(0, Math.floor(start / 16) * 16);
  state.page = await core.readPage(state.metadata.sessionId, state.pageStart, PAGE_SIZE);
  render();
}

function focusHexEditor(): void {
  window.requestAnimationFrame(() => {
    const input = document.querySelector<HTMLInputElement>("#hexEdit");
    if (!input || input.disabled) return;
    input.focus();
    input.select();
  });
}

async function selectByte(tool: ToolId, offset: number): Promise<void> {
  const state = states[tool];
  if (!state.metadata || offset < 0 || offset >= state.metadata.size) return;
  state.selectedOffset = offset;
  const targetPageStart = Math.floor(offset / PAGE_SIZE) * PAGE_SIZE;
  if (!state.page || targetPageStart !== state.pageStart) {
    state.pageStart = targetPageStart;
    state.page = await core.readPage(state.metadata.sessionId, targetPageStart, PAGE_SIZE);
  }
  render();
  focusHexEditor();
}

function parseAddress(raw: string, meta: FileMetadata): number {
  const normalized = raw.trim().replace(/[_\s]/g, "").replace(/^0x/i, "");
  if (!/^[0-9a-f]+$/i.test(normalized)) throw new Error("请输入有效的十六进制地址。 ");
  const value = Number.parseInt(normalized, 16);
  if (value >= meta.baseAddress && value < meta.baseAddress + meta.size) return value - meta.baseAddress;
  if (value >= 0 && value < meta.size) return value;
  throw new Error(`地址范围是 ${formatHex(meta.baseAddress)} 到 ${formatHex(meta.baseAddress + meta.size - 1)}。`);
}

function bindWorkspaceEvents(): void {
  const state = states[activeTool];
  document.querySelector<HTMLInputElement>("#fileInput")?.addEventListener("change", async (event) => {
    const file = (event.currentTarget as HTMLInputElement).files?.[0];
    if (!file) return;
    state.busy = true;
    render();
    try {
      state.metadata = await core.open(activeTool, file);
      state.pageStart = 0;
      state.selectedOffset = null;
      state.searchOffset = -1;
      state.page = await core.readPage(state.metadata.sessionId, 0, PAGE_SIZE);
      showToast("文件已打开，核心算法在本机运行。 ");
    } catch (error) {
      state.metadata = null;
      state.page = null;
      showToast(error instanceof Error ? error.message : String(error), true);
    } finally {
      state.busy = false;
      render();
    }
  });

  document.querySelectorAll<HTMLButtonElement>(".byte").forEach((button) => button.addEventListener("click", () => {
    void selectByte(activeTool, Number(button.dataset.offset));
  }));

  document.querySelector("#previousPage")?.addEventListener("click", () => void loadPage(activeTool, state.pageStart - PAGE_SIZE));
  document.querySelector("#nextPage")?.addEventListener("click", () => void loadPage(activeTool, state.pageStart + PAGE_SIZE));

  document.querySelector<HTMLFormElement>("#jumpForm")?.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!state.metadata) return;
    try {
      const offset = parseAddress(document.querySelector<HTMLInputElement>("#jumpInput")!.value, state.metadata);
      state.selectedOffset = offset;
      void loadPage(activeTool, Math.floor(offset / PAGE_SIZE) * PAGE_SIZE);
    } catch (error) { showToast(error instanceof Error ? error.message : String(error), true); }
  });

  document.querySelector<HTMLFormElement>("#searchForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!state.metadata) return;
    try {
      const value = document.querySelector<HTMLInputElement>("#searchInput")!.value;
      const result = await core.search(state.metadata.sessionId, value, state.searchOffset + 1);
      if (result.offset < 0) return showToast("没有找到该内容。 ", true);
      state.searchOffset = result.offset;
      state.selectedOffset = result.offset;
      await loadPage(activeTool, Math.floor(result.offset / PAGE_SIZE) * PAGE_SIZE);
      showToast(`已找到 ${formatHex(state.metadata.baseAddress + result.offset)}。`);
    } catch (error) { showToast(error instanceof Error ? error.message : String(error), true); }
  });

  let applyingEdit = false;
  const applySelectedEdit = async (): Promise<void> => {
    if (!state.metadata || state.selectedOffset === null) return;
    const input = document.querySelector<HTMLInputElement>("#hexEdit")!;
    if (!/^[0-9a-f]{2}$/i.test(input.value)) return showToast("十六进制值必须是两位，例如 0A。", true);
    if (applyingEdit) return;
    applyingEdit = true;
    const editedOffset = state.selectedOffset;
    try {
      const result = await core.editByte(state.metadata.sessionId, editedOffset, Number.parseInt(input.value, 16));
      state.metadata = { ...result.metadata, sessionId: state.metadata.sessionId };
      const nextOffset = Math.min(editedOffset + 1, state.metadata.size - 1);
      state.selectedOffset = nextOffset;
      state.pageStart = Math.floor(nextOffset / PAGE_SIZE) * PAGE_SIZE;
      state.page = await core.readPage(state.metadata.sessionId, state.pageStart, PAGE_SIZE);
      render();
      focusHexEditor();
      showToast(nextOffset === editedOffset ? "修改成功，已到文件末尾。" : "修改成功，已移到下一字节。");
    } catch (error) { showToast(error instanceof Error ? error.message : String(error), true); }
    finally { applyingEdit = false; }
  };

  document.querySelector("#applyEdit")?.addEventListener("click", () => void applySelectedEdit());
  document.querySelector("#previousByte")?.addEventListener("click", () => {
    if (state.selectedOffset !== null) void selectByte(activeTool, state.selectedOffset - 1);
  });
  document.querySelector("#nextByte")?.addEventListener("click", () => {
    if (state.selectedOffset !== null) void selectByte(activeTool, state.selectedOffset + 1);
  });

  const hexInput = document.querySelector<HTMLInputElement>("#hexEdit");
  hexInput?.addEventListener("focus", () => window.requestAnimationFrame(() => hexInput.select()));
  hexInput?.addEventListener("pointerup", (event) => {
    event.preventDefault();
    hexInput.select();
  });
  hexInput?.addEventListener("input", () => {
    const normalized = hexInput.value.replace(/[^0-9a-f]/gi, "").toUpperCase();
    if (hexInput.value !== normalized) hexInput.value = normalized;
  });
  hexInput?.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    void applySelectedEdit();
  });

  document.querySelector<HTMLInputElement>("#asciiEdit")?.addEventListener("input", (event) => {
    const value = (event.currentTarget as HTMLInputElement).value;
    if (value) document.querySelector<HTMLInputElement>("#hexEdit")!.value = value.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0");
  });

  document.querySelectorAll<HTMLButtonElement>(".export").forEach((button) => button.addEventListener("click", async () => {
    if (!state.metadata) return;
    button.disabled = true;
    try {
      const output = await core.export(state.metadata.sessionId, button.dataset.format!);
      const binary = atob(output.payload);
      const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
      await saveExport(new File([bytes], output.name, { type: output.mime }));
      showToast(`已生成 ${output.name}。`);
    } catch (error) { showToast(error instanceof Error ? error.message : String(error), true); }
    finally { button.disabled = false; }
  }));
}

document.querySelectorAll<HTMLButtonElement>(".tool-tab").forEach((button) => button.addEventListener("click", () => {
  activeTool = button.dataset.tool as ToolId;
  document.querySelectorAll(".tool-tab").forEach((item) => item.classList.toggle("active", item === button));
  render();
}));

let installPrompt: Event | null = null;
window.addEventListener("beforeinstallprompt", (event) => {
  event.preventDefault();
  installPrompt = event;
  const button = document.querySelector<HTMLButtonElement>("#installButton")!;
  button.hidden = false;
  button.onclick = () => (installPrompt as Event & { prompt: () => void }).prompt();
});

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => navigator.serviceWorker.register(new URL("./sw.js", document.baseURI)));
}
render();
