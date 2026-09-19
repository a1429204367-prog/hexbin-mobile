type WorkerResponse = { id: number; ok: boolean; result?: string; error?: string };

export type ToolId = "v50" | "v12";
export type ChecksumRow = { segment: number; start: number; end: number; original: string; current: string };
export type Segment = { start: number; end: number; size: number };
export type FileMetadata = {
  sessionId: string;
  name: string;
  tool: ToolId;
  format: string;
  family: string;
  checksumScheme: string;
  baseAddress: number;
  size: number;
  displaySize: number;
  segments: Segment[];
  checksums: ChecksumRow[];
  logicalSegmentSize?: number | null;
  mirrorSpan?: number | null;
  checksumErrors?: string[];
};

export type PageData = { start: number; end: number; total: number; bytes: number[] };
export type CompareMetadata = Omit<FileMetadata, "tool" | "sessionId"> & { endAddress: number };
export type CompareRow = {
  address: number;
  left: (number | null)[];
  right: (number | null)[];
  diffTypes: ("parameter" | "checksum" | "missing" | null)[];
};
export type ComparePage = { index: number; total: number; rows: CompareRow[] };
export type CompareSnapshot = {
  matchingCount: number;
  parameterDifferenceCount: number;
  checksumDifferenceCount: number;
  leftOnlyCount: number;
  rightOnlyCount: number;
  totalDifferenceCount: number;
  differenceAddresses: number[];
};
export type CompareSession = {
  sessionId: string;
  left: CompareMetadata;
  right: CompareMetadata;
  snapshot: CompareSnapshot;
};
export type CompareMutation = {
  changedAddresses: number[];
  snapshot: CompareSnapshot;
  left: CompareMetadata;
  right: CompareMetadata;
};

class CoreApi {
  private worker = new Worker(new URL("./pyodide.worker.ts", import.meta.url), { type: "module" });
  private sequence = 0;
  private pending = new Map<number, { resolve: (value: string) => void; reject: (reason: Error) => void }>();

  constructor() {
    this.worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
      const response = event.data;
      const request = this.pending.get(response.id);
      if (!request) return;
      this.pending.delete(response.id);
      if (response.ok) request.resolve(response.result ?? "null");
      else request.reject(new Error(response.error || "核心处理失败。"));
    };
  }

  private call<T>(method: string, ...args: unknown[]): Promise<T> {
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve: (value) => resolve(JSON.parse(value) as T), reject });
      this.worker.postMessage({ id, method, args });
    });
  }

  async open(tool: ToolId, file: File): Promise<FileMetadata> {
    const bytes = new Uint8Array(await file.arrayBuffer());
    let binary = "";
    const chunk = 0x8000;
    for (let index = 0; index < bytes.length; index += chunk) {
      binary += String.fromCharCode(...bytes.subarray(index, index + chunk));
    }
    return this.call<FileMetadata>("open_file", tool, file.name, btoa(binary));
  }

  readPage(sessionId: string, start: number, count: number): Promise<PageData> {
    return this.call("read_page", sessionId, start, count);
  }

  editByte(sessionId: string, offset: number, value: number): Promise<{ changed: number[]; metadata: FileMetadata }> {
    return this.call("edit_byte", sessionId, offset, value);
  }

  search(sessionId: string, value: string, start: number): Promise<{ offset: number; length: number }> {
    return this.call("search", sessionId, value, start);
  }

  export(sessionId: string, extension: string): Promise<{ name: string; mime: string; payload: string }> {
    return this.call("export_file", sessionId, extension);
  }

  async openCompare(left: File, right: File): Promise<CompareSession> {
    const encode = async (file: File): Promise<string> => {
      const bytes = new Uint8Array(await file.arrayBuffer());
      let binary = "";
      const chunk = 0x8000;
      for (let index = 0; index < bytes.length; index += chunk) {
        binary += String.fromCharCode(...bytes.subarray(index, index + chunk));
      }
      return btoa(binary);
    };
    return this.call<CompareSession>(
      "open_compare",
      left.name,
      await encode(left),
      right.name,
      await encode(right),
    );
  }

  readComparePage(sessionId: string, startAddress: number, count: number): Promise<ComparePage> {
    return this.call("read_compare_page", sessionId, startAddress, count);
  }

  editCompareByte(sessionId: string, side: "left" | "right", address: number, value: number): Promise<CompareMutation> {
    return this.call("edit_compare_byte", sessionId, side, address, value);
  }

  recalculateCompareSide(sessionId: string, side: "left" | "right"): Promise<CompareMutation> {
    return this.call("recalculate_compare_side", sessionId, side);
  }

  exportCompare(sessionId: string, side: "left" | "right", extension: string): Promise<CompareMutation & {
    name: string;
    mime: string;
    payload: string;
  }> {
    return this.call("export_compare", sessionId, side, extension);
  }
}

export const core = new CoreApi();
