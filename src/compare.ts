import {
  core,
  type CompareMetadata,
  type ComparePage,
  type CompareSession,
  type CompareSnapshot,
} from "./api";

const BYTES_PER_ROW = 16;
const COMPARE_PAGE_ROWS = 192;
const COMPARE_MAX_RENDER_ROWS = COMPARE_PAGE_ROWS * 2;
const COMPARE_SCROLL_THRESHOLD = 120;
const COMPARE_FILE_ACCEPT = ".hex,.HEX,.hex_tmp,.s19,.S19,.s28,.S28,.s37,.S37,.mot,.MOT,.srec,.SREC,.bin,.BIN";
const BYTE_COLUMN_LABELS = Array.from(
  { length: BYTES_PER_ROW },
  (_, index) => index.toString(16).toUpperCase(),
);

type CompareSide = "left" | "right";
type CompareRenderState = {
  leftFile: File | null;
  rightFile: File | null;
  session: CompareSession | null;
  page: ComparePage | null;
  selectedSide: CompareSide | null;
  selectedAddress: number | null;
  currentDifferenceIndex: number;
  busy: boolean;
  loading: boolean;
};

const state: CompareRenderState = {
  leftFile: null,
  rightFile: null,
  session: null,
  page: null,
  selectedSide: null,
  selectedAddress: null,
  currentDifferenceIndex: -1,
  busy: false,
  loading: false,
};

type Toast = (message: string, error?: boolean) => void;
type SaveExport = (file: File) => Promise<void>;
let activeToast: Toast | null = null;
let activeSaveExport: SaveExport | null = null;

function escapeHtml(value: string): string {
  return value.replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]!);
}

function formatHex(value: number, width = 8): string {
  return `0x${value.toString(16).toUpperCase().padStart(width, "0")}`;
}

function sideLabel(side: CompareSide): string {
  return side === "left" ? "A" : "B";
}

function metadataFor(side: CompareSide): CompareMetadata | null {
  if (!state.session) return null;
  return state.session[side];
}

function currentDifferenceIndex(snapshot: CompareSnapshot, preferred: number | null): number {
  const addresses = snapshot.differenceAddresses;
  if (!addresses.length) return -1;
  if (preferred === null) return 0;
  let bestIndex = 0;
  let bestDistance = Math.abs(addresses[0] - preferred);
  for (let index = 1; index < addresses.length; index += 1) {
    const distance = Math.abs(addresses[index] - preferred);
    if (distance < bestDistance) {
      bestIndex = index;
      bestDistance = distance;
    }
  }
  return bestIndex;
}

function syncDifferenceSelection(preferred: number | null = state.selectedAddress): number | null {
  if (!state.session) return null;
  const snapshot = state.session.snapshot;
  state.currentDifferenceIndex = currentDifferenceIndex(snapshot, preferred);
  if (state.currentDifferenceIndex < 0) return preferred;
  return snapshot.differenceAddresses[state.currentDifferenceIndex];
}

function renderFilePicker(side: CompareSide): string {
  const file = side === "left" ? state.leftFile : state.rightFile;
  const label = sideLabel(side);
  return `
    <div class="compare-file-picker">
      <div class="compare-file-heading"><strong>文件${label}</strong><span>${file ? escapeHtml(file.name) : "尚未选择"}</span></div>
      <label class="primary ${state.busy ? "disabled" : ""}">
        ${file ? `更换文件${label}` : `选择文件${label}`}
        <input id="compare${label}Input" type="file" accept="${COMPARE_FILE_ACCEPT}" ${state.busy ? "disabled" : ""} />
      </label>
    </div>
  `;
}

function renderCompareEmpty(): string {
  return `
    <section class="empty-guide compare-empty">
      <div><span>1</span><h3>选择两个文件</h3><p>分别载入文件 A 和文件 B，浏览器只在本机处理。</p></div>
      <div><span>2</span><h3>查看差异</h3><p>两个文件按绝对地址对齐，差异会直接标记在对应字节。</p></div>
      <div><span>3</span><h3>编辑并导出</h3><p>任一侧都可以修改、重算校验并导出 HEX 或 BIN。</p></div>
    </section>
  `;
}

function renderMetadata(meta: CompareMetadata, side: CompareSide): string {
  return `
    <div class="compare-meta-head"><strong>文件${sideLabel(side)}</strong><span>${escapeHtml(meta.name)}</span></div>
    <div class="compare-meta-grid">
      <span>格式<strong>${escapeHtml(meta.format)}</strong></span>
      <span>结构<strong>${escapeHtml(meta.family)}</strong></span>
      <span>地址<strong>${formatHex(meta.baseAddress)} - ${formatHex(meta.endAddress)}</strong></span>
      <span>长度<strong>${meta.size.toLocaleString()} 字节</strong></span>
    </div>
  `;
}

function renderByteHeader(): string {
  return `<div class="compare-byte-header" aria-hidden="true">${BYTE_COLUMN_LABELS.map((label) => `<span>${label}</span>`).join("")}</div>`;
}

function asciiValue(value: number | null): string {
  if (value === null) return "·";
  return value >= 32 && value <= 126 ? escapeHtml(String.fromCharCode(value)) : ".";
}

function renderCompareRows(page: ComparePage, side: CompareSide): string {
  return page.rows.map((row) => {
    const values = row[side];
    return `
      <div class="compare-side-row" data-compare-side-row="${side}-${row.address}">
        <button class="compare-address" type="button" data-compare-jump-address="${row.address}" data-compare-jump-side="${side}">${formatHex(row.address)}</button>
        <div class="compare-byte-grid">${values.map((value, index) => {
            const address = row.address + index;
            const type = row.diffTypes[index];
            const selected = state.selectedAddress === address ? " selected" : "";
            const selectedSide = state.selectedAddress === address && state.selectedSide === side ? " selected-side" : "";
            const missing = value === null ? " missing" : "";
            return `<button class="compare-byte diff-${type ?? "same"}${missing}${selected}${selectedSide}" data-compare-side="${side}" data-compare-address="${address}" type="button" ${value === null ? "disabled" : ""}>${value === null ? "--" : value.toString(16).toUpperCase().padStart(2, "0")}</button>`;
          }).join("")}</div>
        <div class="compare-ascii">${values.map((value) => `<span>${asciiValue(value)}</span>`).join("")}</div>
      </div>
    `;
  }).join("");
}

function renderCompareEditor(meta: CompareMetadata, side: CompareSide, page: ComparePage | null): string {
  const label = sideLabel(side);
  return `
    <section class="compare-editor compare-editor-${side}">
      <div class="compare-side-card">
        ${renderMetadata(meta, side)}
        <div class="compare-side-actions">
          <button class="compare-command" type="button" data-recalculate-side="${side}">重算校验</button>
          <button class="compare-command" type="button" data-export-side="${side}" data-export-format="hex">导出 HEX</button>
          <button class="compare-command" type="button" data-export-side="${side}" data-export-format="bin">导出 BIN</button>
          <form class="compare-jump" data-jump-side="${side}">
            <input inputmode="text" placeholder="地址或偏移" aria-label="文件${label}跳转地址" />
            <button type="submit">跳转</button>
          </form>
        </div>
      </div>
      <div class="compare-editor-table" aria-label="文件${label}十六进制数据">
        <div class="compare-table-header"><span>Offset（偏移）:</span>${renderByteHeader()}<span class="compare-ascii-heading">ASCII（字符）</span></div>
        ${page ? renderCompareRows(page, side) : ""}
      </div>
    </section>
  `;
}

function renderEditBar(): string {
  const selectedSide = state.selectedSide;
  const selectedAddress = state.selectedAddress;
  const selectedMeta = selectedSide ? metadataFor(selectedSide) : null;
  let selectedValue: number | null = null;
  if (selectedSide && selectedAddress !== null && state.page) {
    const row = state.page.rows.find((item) => selectedAddress >= item.address && selectedAddress < item.address + BYTES_PER_ROW);
    if (row) selectedValue = row[selectedSide][selectedAddress - row.address];
  }
  const disabled = selectedValue === null || !selectedMeta;
  return `
    <section class="compare-edit-bar ${disabled ? "disabled" : ""}">
      <div class="compare-edit-current"><span>当前字节</span><strong>${selectedAddress === null ? "未选择" : `${formatHex(selectedAddress)} · 文件${selectedSide ? sideLabel(selectedSide) : ""}`}</strong></div>
      <label>十六进制<input id="compareHexEdit" maxlength="2" inputmode="text" autocomplete="off" autocapitalize="characters" spellcheck="false" value="${selectedValue === null ? "" : selectedValue.toString(16).toUpperCase().padStart(2, "0")}" ${disabled ? "disabled" : ""} /></label>
      <label>字符<input id="compareAsciiEdit" maxlength="1" value="${selectedValue !== null && selectedValue >= 32 && selectedValue <= 126 ? escapeHtml(String.fromCharCode(selectedValue)) : ""}" ${disabled ? "disabled" : ""} /></label>
      <button id="compareApplyEdit" class="primary" type="button" ${disabled ? "disabled" : ""}>应用修改</button>
    </section>
  `;
}

function renderCompareSession(): string {
  const session = state.session!;
  const { snapshot } = session;
  const page = state.page;
  const totalRows = page?.total ?? 0;
  const firstRow = page?.index ?? 0;
  const lastRow = page ? Math.min(page.index + page.rows.length, page.total) : 0;
  const differenceCount = snapshot.totalDifferenceCount;
  const current = state.currentDifferenceIndex >= 0 ? state.currentDifferenceIndex + 1 : 0;
  return `
    <section class="compare-panel">
      <div class="compare-summary">
        <div><p class="section-label">V55 参数对比</p><h2>${differenceCount.toLocaleString()} 处差异</h2><p>按绝对地址同步显示文件 A 和文件 B，文件不会上传。</p></div>
        <div class="compare-counts"><span>参数差异<strong>${snapshot.parameterDifferenceCount.toLocaleString()}</strong></span><span>校验差异<strong>${snapshot.checksumDifferenceCount.toLocaleString()}</strong></span><span>单侧缺失<strong>${(snapshot.leftOnlyCount + snapshot.rightOnlyCount).toLocaleString()}</strong></span></div>
      </div>
      <div class="compare-navigation">
        <button id="comparePrevious" type="button" ${differenceCount ? "" : "disabled"}>上一处</button>
        <strong>${current} / ${differenceCount}</strong>
        <button id="compareNext" type="button" ${differenceCount ? "" : "disabled"}>下一处</button>
        <span class="compare-page-status">${totalRows ? `第 ${firstRow + 1}-${lastRow} / ${totalRows} 行` : "尚未加载数据"}</span>
      </div>
      <div class="compare-editors" aria-label="V55 双文件十六进制对比">
        ${renderCompareEditor(session.left, "left", page)}
        ${renderCompareEditor(session.right, "right", page)}
      </div>
      ${renderEditBar()}
    </section>
  `;
}

function render(workspace: HTMLElement): void {
  workspace.innerHTML = `
    <section class="upload-card compare-upload-card ${state.session ? "compact" : ""}">
      <div><p class="section-label">V55 双文件对比</p><h2>${state.session ? "更换对比文件" : "同时对比两个固件文件"}</h2><p>支持 HEX、BIN、S19、S28、S37、MOT 等格式，解析和校验都在浏览器本机完成。</p></div>
      <div class="compare-file-pickers">${renderFilePicker("left")}${renderFilePicker("right")}</div>
    </section>
    ${state.session ? renderCompareSession() : renderCompareEmpty()}
  `;
}

function updateSession(result: { snapshot: CompareSnapshot; left: CompareMetadata; right: CompareMetadata }): void {
  if (!state.session) return;
  state.session = { ...state.session, left: result.left, right: result.right, snapshot: result.snapshot };
}

function parseJumpAddress(raw: string, meta: CompareMetadata): number {
  const normalized = raw.trim().replace(/[_\s]/g, "").replace(/^0x/i, "");
  if (!/^[0-9a-f]+$/i.test(normalized)) throw new Error("请输入有效的十六进制地址。 ");
  const value = Number.parseInt(normalized, 16);
  const displaySize = Math.max(meta.displaySize, meta.size);
  const displayEnd = meta.baseAddress + displaySize - 1;
  if (meta.baseAddress <= value && value <= displayEnd) return value;
  if (value >= 0 && value < displaySize) return meta.baseAddress + value;
  if (value >= 0 && value < meta.size) return meta.baseAddress + value;
  throw new Error(`文件${meta.name}的地址范围是 ${formatHex(meta.baseAddress)} 到 ${formatHex(displayEnd)}。`);
}

async function loadAddress(workspace: HTMLElement, address: number, side: CompareSide): Promise<void> {
  if (!state.session || state.loading) return;
  state.loading = true;
  state.selectedAddress = address;
  state.selectedSide = side;
  try {
    const rowAddress = address & ~(BYTES_PER_ROW - 1);
    const pageStart = Math.max(
      0,
      rowAddress - Math.floor(COMPARE_PAGE_ROWS / 2) * BYTES_PER_ROW,
    );
    state.page = await core.readComparePage(state.session.sessionId, pageStart, COMPARE_PAGE_ROWS);
    render(workspace);
    if (activeToast && activeSaveExport) bind(workspace, activeToast, activeSaveExport);
    window.requestAnimationFrame(() => {
      scrollCompareTablesToAddress(address, rowAddress);
    });
  } finally {
    state.loading = false;
  }
}

function compareTables(): HTMLElement[] {
  return Array.from(document.querySelectorAll<HTMLElement>(".compare-editor-table"));
}

function scrollCompareTablesToAddress(address: number, rowAddress: number): void {
  for (const table of compareTables()) {
    const row = table.querySelector<HTMLElement>(`[data-compare-side-row$="-${rowAddress}"]`);
    if (!row) continue;
    const tableRect = table.getBoundingClientRect();
    const rowRect = row.getBoundingClientRect();
    const rowTop = rowRect.top - tableRect.top + table.scrollTop;
    const maximum = Math.max(0, table.scrollHeight - table.clientHeight);
    const centeredTop = rowTop - Math.max(0, (table.clientHeight - row.offsetHeight) / 2);
    table.scrollTop = Math.min(maximum, Math.max(0, centeredTop));

    const byte = table.querySelector<HTMLElement>(`.compare-byte[data-compare-address="${address}"]`);
    if (!byte) continue;
    const byteRect = byte.getBoundingClientRect();
    const byteLeft = byteRect.left - tableRect.left + table.scrollLeft;
    const horizontalMaximum = Math.max(0, table.scrollWidth - table.clientWidth);
    const centeredLeft = byteLeft - Math.max(0, (table.clientWidth - byteRect.width) / 2);
    table.scrollLeft = Math.min(horizontalMaximum, Math.max(0, centeredLeft));
  }
}

function restoreCompareScroll(top: number, left: number): void {
  for (const table of compareTables()) {
    table.scrollTop = top;
    table.scrollLeft = left;
  }
}

async function loadAdjacentComparePage(
  workspace: HTMLElement,
  direction: -1 | 1,
  oldScrollTop: number,
  oldScrollLeft: number,
  rowHeight: number,
): Promise<void> {
  if (!state.session || !state.page?.rows.length || state.loading) return;
  const currentPage = state.page;
  const firstRow = currentPage.rows[0];
  const lastRow = currentPage.rows[currentPage.rows.length - 1];
  const hasPrevious = currentPage.index > 0;
  const hasNext = currentPage.index + currentPage.rows.length < currentPage.total;
  if ((direction < 0 && !hasPrevious) || (direction > 0 && !hasNext)) return;

  const startAddress = direction < 0
    ? firstRow.address - COMPARE_MAX_RENDER_ROWS * BYTES_PER_ROW
    : lastRow.address + BYTES_PER_ROW;
  const readCount = direction < 0 ? COMPARE_MAX_RENDER_ROWS : COMPARE_PAGE_ROWS;
  state.loading = true;
  try {
    const adjacentPage = await core.readComparePage(state.session.sessionId, startAddress, readCount);
    const adjacentRows = direction < 0
      ? adjacentPage.rows.filter((row) => row.address < firstRow.address).slice(-COMPARE_PAGE_ROWS)
      : adjacentPage.rows;
    if (!adjacentRows.length) return;

    const combinedRows = direction < 0
      ? [...adjacentRows, ...currentPage.rows]
      : [...currentPage.rows, ...adjacentRows];
    const trimCount = Math.max(0, combinedRows.length - COMPARE_MAX_RENDER_ROWS);
    const rows = direction < 0
      ? combinedRows.slice(0, COMPARE_MAX_RENDER_ROWS)
      : combinedRows.slice(trimCount);
    const nextIndex = direction < 0 ? currentPage.index - adjacentRows.length : currentPage.index + trimCount;
    const retainedCurrentFirst = rows.findIndex((row) => row.address === firstRow.address);
    const prependedRows = retainedCurrentFirst >= 0 ? retainedCurrentFirst : adjacentRows.length;
    const nextScrollTop = direction < 0
      ? oldScrollTop + prependedRows * rowHeight
      : Math.max(0, oldScrollTop - trimCount * rowHeight);

    state.page = { index: nextIndex, total: adjacentPage.total, rows };
    render(workspace);
    if (activeToast && activeSaveExport) bind(workspace, activeToast, activeSaveExport);
    window.requestAnimationFrame(() => restoreCompareScroll(nextScrollTop, oldScrollLeft));
  } finally {
    state.loading = false;
  }
}

async function refreshCompareView(workspace: HTMLElement): Promise<void> {
  if (!state.session) return;
  const selectedAddress = state.selectedAddress;
  const startAddress = selectedAddress
    ?? state.page?.rows[0]?.address
    ?? Math.min(state.session.left.baseAddress, state.session.right.baseAddress);
  state.loading = true;
  try {
    state.page = await core.readComparePage(state.session.sessionId, startAddress, COMPARE_PAGE_ROWS);
  } finally {
    state.loading = false;
  }
  render(workspace);
  if (activeToast && activeSaveExport) bind(workspace, activeToast, activeSaveExport);
  if (selectedAddress !== null) {
    window.requestAnimationFrame(() => {
      const rowAddress = selectedAddress & ~(BYTES_PER_ROW - 1);
      scrollCompareTablesToAddress(selectedAddress, rowAddress);
    });
  }
}

async function chooseFile(workspace: HTMLElement, side: CompareSide, file: File, showToast: Toast, saveExport: SaveExport): Promise<void> {
  if (side === "left") state.leftFile = file;
  else state.rightFile = file;
  state.session = null;
  state.page = null;
  state.selectedAddress = null;
  state.selectedSide = null;
  if (!state.leftFile || !state.rightFile) {
    render(workspace);
    bind(workspace, showToast, saveExport);
    return;
  }

  state.busy = true;
  render(workspace);
  try {
    state.session = await core.openCompare(state.leftFile, state.rightFile);
    const firstAddress = Math.min(state.session.left.baseAddress, state.session.right.baseAddress);
    state.page = await core.readComparePage(state.session.sessionId, firstAddress, COMPARE_PAGE_ROWS);
    syncDifferenceSelection(null);
    render(workspace);
    showToast("V55 对比已打开，两个文件按地址对齐。", false);
  } catch (error) {
    state.session = null;
    state.page = null;
    showToast(error instanceof Error ? error.message : String(error), true);
  } finally {
    state.busy = false;
    render(workspace);
    bind(workspace, showToast, saveExport);
  }
}

async function applyEdit(workspace: HTMLElement, showToast: Toast): Promise<void> {
  if (!state.session || !state.selectedSide || state.selectedAddress === null) return;
  const input = document.querySelector<HTMLInputElement>("#compareHexEdit");
  if (!input || !/^[0-9a-f]{2}$/i.test(input.value)) {
    showToast("十六进制值必须是两位，例如 0A。", true);
    return;
  }
  const previousAddress = state.selectedAddress;
  const editedSide = state.selectedSide;
  const editedMeta = metadataFor(editedSide);
  const result = await core.editCompareByte(
    state.session.sessionId,
    editedSide,
    previousAddress,
    Number.parseInt(input.value, 16),
  );
  updateSession(result);
  state.currentDifferenceIndex = -1;
  const nextAddress = editedMeta && previousAddress < editedMeta.endAddress
    ? previousAddress + 1
    : previousAddress;
  state.selectedAddress = nextAddress;
  await loadAddress(workspace, nextAddress, editedSide);
  showToast(`文件${sideLabel(editedSide)}已修改，校验已自动重算。`, false);
}

function bind(workspace: HTMLElement, showToast: Toast, saveExport: SaveExport): void {
  for (const side of ["left", "right"] as const) {
    const label = sideLabel(side);
    document.querySelector<HTMLInputElement>(`#compare${label}Input`)?.addEventListener("change", (event) => {
      const file = (event.currentTarget as HTMLInputElement).files?.[0];
      if (file) void chooseFile(workspace, side, file, showToast, saveExport);
    });
  }

  document.querySelectorAll<HTMLButtonElement>("[data-compare-side][data-compare-address]").forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedSide = button.dataset.compareSide as CompareSide;
      state.selectedAddress = Number(button.dataset.compareAddress);
      render(workspace);
      bind(workspace, showToast, saveExport);
      window.requestAnimationFrame(() => document.querySelector<HTMLInputElement>("#compareHexEdit")?.select());
    });
  });

  document.querySelectorAll<HTMLButtonElement>("[data-compare-jump-address]").forEach((button) => {
    button.addEventListener("click", () => void loadAddress(
      workspace,
      Number(button.dataset.compareJumpAddress),
      (button.dataset.compareJumpSide as CompareSide | undefined) ?? state.selectedSide ?? "left",
    ));
  });

  document.querySelectorAll<HTMLFormElement>("[data-jump-side]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      if (!state.session) return;
      const side = form.dataset.jumpSide as CompareSide;
      const meta = metadataFor(side);
      const input = form.querySelector<HTMLInputElement>("input");
      if (!meta || !input) return;
      try {
        void loadAddress(workspace, parseJumpAddress(input.value, meta), side);
      } catch (error) {
        showToast(error instanceof Error ? error.message : String(error), true);
      }
    });
  });

  document.querySelector<HTMLButtonElement>("#comparePrevious")?.addEventListener("click", () => {
    if (!state.session?.snapshot.differenceAddresses.length) return;
    const addresses = state.session.snapshot.differenceAddresses;
    const index = state.currentDifferenceIndex < 0 ? 0 : (state.currentDifferenceIndex - 1 + addresses.length) % addresses.length;
    state.currentDifferenceIndex = index;
    void loadAddress(workspace, addresses[index], state.selectedSide ?? "left");
  });
  document.querySelector<HTMLButtonElement>("#compareNext")?.addEventListener("click", () => {
    if (!state.session?.snapshot.differenceAddresses.length) return;
    const addresses = state.session.snapshot.differenceAddresses;
    const index = state.currentDifferenceIndex < 0 ? 0 : (state.currentDifferenceIndex + 1) % addresses.length;
    state.currentDifferenceIndex = index;
    void loadAddress(workspace, addresses[index], state.selectedSide ?? "left");
  });

  const tables = compareTables();
  let syncingScroll = false;
  for (const table of tables) {
    table.addEventListener("scroll", (event) => {
      if (syncingScroll || state.loading || !state.page?.rows.length) return;
      const source = event.currentTarget as HTMLElement;
      const scrollTop = source.scrollTop;
      const scrollLeft = source.scrollLeft;
      syncingScroll = true;
      for (const other of tables) {
        if (other === source) continue;
        other.scrollTop = scrollTop;
        other.scrollLeft = scrollLeft;
      }
      window.requestAnimationFrame(() => { syncingScroll = false; });

      const nearTop = scrollTop <= COMPARE_SCROLL_THRESHOLD;
      const nearBottom = source.scrollHeight - scrollTop - source.clientHeight <= COMPARE_SCROLL_THRESHOLD;
      const canLoadPrevious = nearTop && state.page.index > 0;
      const canLoadNext = nearBottom && state.page.index + state.page.rows.length < state.page.total;
      if (!canLoadPrevious && !canLoadNext) return;

      const direction: -1 | 1 = canLoadPrevious ? -1 : 1;
      const rowHeight = source.querySelector<HTMLElement>(".compare-side-row")?.getBoundingClientRect().height ?? 0;
      void loadAdjacentComparePage(workspace, direction, scrollTop, scrollLeft, rowHeight).catch((error) => {
        showToast(error instanceof Error ? error.message : String(error), true);
      });
    }, { passive: true });
  }

  document.querySelector<HTMLButtonElement>("#compareApplyEdit")?.addEventListener("click", () => {
    void applyEdit(workspace, showToast).catch((error) => showToast(error instanceof Error ? error.message : String(error), true));
  });
  const hexInput = document.querySelector<HTMLInputElement>("#compareHexEdit");
  hexInput?.addEventListener("input", () => {
    const normalized = hexInput.value.replace(/[^0-9a-f]/gi, "").toUpperCase();
    if (hexInput.value !== normalized) hexInput.value = normalized;
  });
  hexInput?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      void applyEdit(workspace, showToast).catch((error) => showToast(error instanceof Error ? error.message : String(error), true));
    }
  });
  document.querySelector<HTMLInputElement>("#compareAsciiEdit")?.addEventListener("input", (event) => {
    const value = (event.currentTarget as HTMLInputElement).value;
    if (value && hexInput) hexInput.value = value.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0");
  });

  document.querySelectorAll<HTMLButtonElement>("[data-recalculate-side]").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!state.session) return;
      const side = button.dataset.recalculateSide as CompareSide;
      button.disabled = true;
      try {
        updateSession(await core.recalculateCompareSide(state.session.sessionId, side));
        state.selectedAddress = syncDifferenceSelection(state.selectedAddress);
        await refreshCompareView(workspace);
        showToast(`文件${sideLabel(side)}校验已重算。`, false);
      } catch (error) {
        showToast(error instanceof Error ? error.message : String(error), true);
        button.disabled = false;
      }
    });
  });

  document.querySelectorAll<HTMLButtonElement>("[data-export-side]").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!state.session) return;
      const side = button.dataset.exportSide as CompareSide;
      button.disabled = true;
      try {
        const output = await core.exportCompare(state.session.sessionId, side, button.dataset.exportFormat!);
        updateSession(output);
        state.selectedAddress = syncDifferenceSelection(state.selectedAddress);
        await refreshCompareView(workspace);
        const binary = atob(output.payload);
        const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
        await saveExport(new File([bytes], output.name, { type: output.mime }));
        showToast(`已生成 ${output.name}。`, false);
      } catch (error) {
        showToast(error instanceof Error ? error.message : String(error), true);
      } finally {
        button.disabled = false;
      }
    });
  });
}

export function renderCompare(workspace: HTMLElement, showToast: Toast, saveExport: SaveExport): void {
  activeToast = showToast;
  activeSaveExport = saveExport;
  render(workspace);
  bind(workspace, showToast, saveExport);
}
