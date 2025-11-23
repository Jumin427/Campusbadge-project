/*
  CampusBadge – 인증서 DApp (온체인/로컬 겸용 데모)
  TypeScript (ethers v6, Vite)

  사전 준비
  1) npm i ethers
  2) .env.local 에 아래 추가 (데모/개발용. 운영은 서버 프록시 권장)
     VITE_INFURA_IPFS_PROJECT_ID=xxxxxxxx
     VITE_INFURA_IPFS_PROJECT_SECRET=yyyyyyyy
*/

import type { ContractTransactionReceipt, InterfaceAbi } from "ethers";
import { BrowserProvider, Contract } from "ethers";

// ---------- DOM 헬퍼 ----------
const $ = <T extends Element = Element>(sel: string) => document.querySelector(sel) as T;
const $$ = (sel: string) => document.querySelectorAll(sel);
const today = () => new Date().toISOString().slice(0, 10);
const API_BASE = import.meta.env.VITE_API_BASE as string;

// 토스트
const TOAST = (() => {
  const el = $("#toast") as HTMLDivElement;
  const show = (msg: string, ms = 1800) => {
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout((show as any)._t);
    (show as any)._t = setTimeout(() => el.classList.remove("show"), ms);
  };
  return { show };
})();

function nanoid(n = 8): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let s = "";
  for (let i = 0; i < n; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

// ---------- 로컬 DB ----------
const DB_KEY = "campusbadge.requests";
function db_load(): RequestRow[] {
  try { return JSON.parse(localStorage.getItem(DB_KEY) || "[]"); } catch { return []; }
}
function db_save(arr: RequestRow[]): void { localStorage.setItem(DB_KEY, JSON.stringify(arr)); }
function db_push(item: RequestRow): RequestRow[] { const arr = db_load(); arr.unshift(item); db_save(arr); return arr; }

// ---------- 간단 로그인/회원가입 (백엔드 API + LocalStorage 세션) ----------
type AuthRole = "ADMIN" | "USER";
type AuthUser = {
  id: string;
  username: string;
  role: AuthRole;
  nickname: string;
  email: string;
  wallet_address?: string;
};

const AUTH_CURRENT_KEY = "campusbadge.auth.current";
const CHAIN_CONF_KEY = "campusbadge.chainConf";

function authSetCurrent(user: AuthUser | null): void {
  if (user) localStorage.setItem(AUTH_CURRENT_KEY, JSON.stringify(user));
  else localStorage.removeItem(AUTH_CURRENT_KEY);
}
function authGetCurrent(): AuthUser | null {
  try {
    const raw = localStorage.getItem(AUTH_CURRENT_KEY);
    return raw ? (JSON.parse(raw) as AuthUser) : null;
  } catch { return null; }
}

// ---------- 타입 ----------
export type Attribute = { trait_type: string; value: string };
export type Metadata = {
  name: string;
  description: string;
  image?: string;
  attributes: Attribute[];
};
export type RequestRow = {
  id: string;                 // 로컬 ID
  createdAt: string;          // ISO time
  status: "Pending" | "Approved" | "Rejected" | "Minted" | "Revoked";
  tokenId?: string;           // 데모용
  meta: Metadata;
};

// ---------- ABI ----------
export const ABI: InterfaceAbi = [
  // view (온체인 대시보드용)
  "function requestCount() view returns (uint256)",
  // ★ beneficiary 필드 포함 버전
  "function requests(uint256) view returns (address requester, address beneficiary, string tokenURI, uint8 status)",

  // ownable
  "function owner() view returns (address)",

  // write
  // ★ createRequest 시그니처 변경 (address beneficiary, string tokenURI)
  "function createRequest(address beneficiary, string tokenURI) external returns (uint256)",
  "function approveRequest(uint256 requestId) external",
  "function rejectRequest(uint256 requestId, string reason) external",
  "function mintNFT(uint256 requestId) external returns (uint256)",

  // events
  // ★ beneficiary 인자 추가
  "event RequestCreated(uint256 indexed requestId, address indexed requester, address indexed beneficiary, string tokenURI)",
  "event RequestApproved(uint256 indexed requestId)",
  "event RequestRejected(uint256 indexed requestId, string reason)",
  "event NFTMinted(uint256 indexed requestId, uint256 indexed tokenId, address indexed to)",
];

// 컨트랙트 타입 (간단 보강)
type CampusContract = Contract & {
  owner(): Promise<string>;
  requestCount(): Promise<bigint>;
  requests(
    id: bigint | number,
  ): Promise<{ requester: string; beneficiary: string; tokenURI: string; status: bigint }>;
  createRequest(
    beneficiary: string,
    tokenURI: string,
  ): Promise<{ wait: () => Promise<ContractTransactionReceipt | null> }>;
  approveRequest(
    requestId: bigint | number,
  ): Promise<{ wait: () => Promise<ContractTransactionReceipt | null> }>;
  rejectRequest(
    requestId: bigint | number,
    reason: string,
  ): Promise<{ wait: () => Promise<ContractTransactionReceipt | null> }>;
  mintNFT(
    requestId: bigint | number,
  ): Promise<{ wait: () => Promise<ContractTransactionReceipt | null> }>;
};


// ---------- Ethers 상태 ----------
let provider: BrowserProvider | null = null;
let signer: any = null; // JsonRpcSigner
let contract: CampusContract | null = null;
let ownerAddr: string | null = null;

// ---------- IPFS (Infura) ----------
const INFURA_PID = import.meta.env.VITE_INFURA_IPFS_PROJECT_ID as string;
const INFURA_PSEC = import.meta.env.VITE_INFURA_IPFS_PROJECT_SECRET as string;
const INFURA_IPFS_ADD = "https://ipfs.infura.io:5001/api/v0/add?pin=true";

async function uploadJSONToIPFSViaInfura(obj: any, filename = "metadata.json"): Promise<string> {
  if (!INFURA_PID || !INFURA_PSEC) throw new Error("Missing Infura IPFS env (VITE_INFURA_IPFS_PROJECT_ID/SECRET)");
  const form = new FormData();
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
  form.append("file", blob, filename);

  const auth = btoa(`${INFURA_PID}:${INFURA_PSEC}`);
  const res = await fetch(INFURA_IPFS_ADD, { method: "POST", headers: { Authorization: `Basic ${auth}` }, body: form });
  const txt = await res.text();
  if (!res.ok) throw new Error(`IPFS upload failed: ${res.status} ${txt}`);
  // 다중 라인 JSON 대비
  const lastLine = txt.trim().split("\n").pop()!;
  const { Hash } = JSON.parse(lastLine); // { Name, Hash, Size }
  return Hash as string; // CID
}
const tokenUriFromCid = (cid: string) => `ipfs://${cid}`;

// ---------- 유틸리티 ----------
function isOwner(addr?: string | null): boolean {
  return !!ownerAddr && !!addr && ownerAddr.toLowerCase() === addr.toLowerCase();
}
const statusFromU8 = (n: number): RequestRow["status"] =>
  (["Pending", "Approved", "Rejected", "Minted"] as const)[n] ?? "Pending";

function attr(meta: Metadata, key: string): string | null {
  const f = (meta.attributes || []).find(a => a.trait_type === key);
  return f?.value ?? null;
}
function statusBadge(s: RequestRow["status"]): string {
  const map: Record<string, string> = { Pending: "s-pending", Approved: "s-pending", Rejected: "s-rejected", Minted: "s-minted", Revoked: "s-revoked" };
  return `<span class="status ${map[s] || ""}">${s}</span>`;
}

// ---------- 화면 전환 (login / register / main) ----------
type View = "login" | "register" | "main";
function setView(v: View): void {
  const loginSec = $("#view-login") as HTMLElement;
  const regSec = $("#view-register") as HTMLElement;
  const mainSec = $("#view-main") as HTMLElement;
  loginSec.hidden = v !== "login";
  regSec.hidden = v !== "register";
  mainSec.hidden = v !== "main";
}

// ---------- 체인 연결 ----------
async function connectChain(auto = false): Promise<void> {
  const chainIdInput = $("#chain-id") as HTMLInputElement;
  const addrInput = $("#chain-address") as HTMLInputElement;
  const who = $("#whoami") as HTMLDivElement;

  if (!(window as any).ethereum) {
    if (!auto) TOAST.show("지갑이 없습니다 (MetaMask 등)");
    return;
  }

  provider = new BrowserProvider((window as any).ethereum);

  const needChainId = Number(chainIdInput.value || 0);
  if (needChainId) {
    try {
      await (window as any).ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: "0x" + needChainId.toString(16) }],
      });
    } catch {
      // 사용자 취소/네트워크 미추가
    }
  }

  signer = await provider.getSigner();
  const addr = (addrInput.value || "").trim();
  if (!addr) {
    if (!auto) TOAST.show("컨트랙트 주소를 입력하세요");
    return;
  }

  contract = new Contract(addr, ABI, signer) as CampusContract;
  ownerAddr = await contract.owner();

  // 체인 설정 저장 (자동 연결용)
  localStorage.setItem(CHAIN_CONF_KEY, JSON.stringify({
    address: addr,
    chainId: chainIdInput.value || "",
  }));

  who.innerHTML = `연결됨: <b>${await signer.getAddress()}</b> · 컨트랙트 소유자: <b>${ownerAddr}</b>`;
  wireEvents();
  TOAST.show("체인 연결 완료");
  await renderTable(); // 온체인 테이블 즉시 로드
}

function disconnectChain(): void {
  provider = null; signer = null; contract = null; ownerAddr = null;
  const who = $("#whoami") as HTMLDivElement;
  who.textContent = "지갑 미연결";
  void renderTable(); // 로컬 테이블로 전환
}

function autoConnectChain(): void {
  const confRaw = localStorage.getItem(CHAIN_CONF_KEY);
  if (confRaw) {
    try {
      const conf = JSON.parse(confRaw) as { address?: string; chainId?: string };
      const addrInput = $("#chain-address") as HTMLInputElement;
      const chainIdInput = $("#chain-id") as HTMLInputElement;
      if (conf.address) addrInput.value = conf.address;
      if (conf.chainId) chainIdInput.value = conf.chainId;
    } catch {
      // 무시
    }
  }
  void connectChain(true);
}

// ---------- 로그인 상태에 따른 UI/역할 분기 ----------
function applyAuthUI(): void {
  const loginPill = $("#login-pill") as HTMLDivElement;
  const logoutBtn = $("#btn-logout") as HTMLButtonElement;

  const secRequest = $("#sec-request") as HTMLElement;
  const secAdmin   = $("#sec-admin") as HTMLElement;
  const secVerify  = $("#sec-verify") as HTMLElement;
  const welcome    = $("#welcome-text") as HTMLSpanElement;

  const currentUser = authGetCurrent();   // ← 항상 여기서만 유저 가져오기

  // 로그인 안 된 상태
  if (!currentUser) {
    setView("login");
    loginPill.innerHTML = '계정: <b>로그인 필요</b>';
    logoutBtn.style.display = "none";
    welcome.textContent = "게스트";
    disconnectChain();
    return;
  }

  // 로그인 된 상태
  setView("main");
  const displayName = currentUser.nickname || currentUser.username;
  const isAdmin = (currentUser.role || "").toUpperCase() === "ADMIN";

  const walletInfo = currentUser.wallet_address
    ? ` · 지갑: <span style="font-family:monospace">${currentUser.wallet_address.slice(0, 6)}…${currentUser.wallet_address.slice(-4)}</span>`
    : "";

  loginPill.innerHTML = `계정: <b>${displayName}</b> (${isAdmin ? "관리자" : "일반 유저"})${walletInfo}`;
  logoutBtn.style.display = "inline-flex";
  welcome.textContent = `${displayName} · 역할: ${isAdmin ? "관리자" : "일반 유저"}`;

  // 역할별 섹션 토글
  if (isAdmin) {
    secAdmin.style.display   = "";
    secRequest.style.display = "none";
    secVerify.style.display  = "none";
  } else {
    secAdmin.style.display   = "none";
    secRequest.style.display = "";
    secVerify.style.display  = "";
  }

  // 로그인 이후 자동 체인 연결
  if (!provider) {
    autoConnectChain();
  }
}


// ---------- 폼 & 메타데이터 ----------
function collectForm() {
  const f = {
    name: ($("#f-name") as HTMLInputElement).value.trim(),
    issuer: ($("#f-issuer") as HTMLInputElement).value.trim(),
    image: ($("#f-image") as HTMLInputElement).value.trim(),
    certificateId: ($("#f-certid") as HTMLInputElement).value.trim(),
    issuedTo: ($("#f-issuedto") as HTMLInputElement).value.trim(),
    studentId: ($("#f-studentid") as HTMLInputElement).value.trim(),
    issuedAt: ($("#f-issuedat") as HTMLInputElement).value || today(),
    description: ($("#f-desc") as HTMLTextAreaElement).value.trim(),
    tokenURI: ($("#f-tokenuri") as HTMLInputElement).value.trim(),
  };
  return f;
}

function buildMetadata(f: ReturnType<typeof collectForm>): Metadata {
  const image = f.image.startsWith("ipfs://") || f.image.startsWith("http")
    ? f.image
    : (f.image ? "ipfs://" + f.image : "");
  return {
    name: f.name || "Campus Certificate",
    description: f.description || "University certificate issued as NFT",
    image,
    attributes: [
      f.issuedTo ? { trait_type: "IssuedTo", value: f.issuedTo } : null,
      f.studentId ? { trait_type: "StudentID", value: f.studentId } : null,
      f.issuedAt ? { trait_type: "IssuedAt", value: f.issuedAt } : null,
      f.issuer ? { trait_type: "Issuer", value: f.issuer } : null,
      f.certificateId ? { trait_type: "CertificateID", value: f.certificateId } : null,
    ].filter(Boolean) as Attribute[],
  };
}

function download(filename: string, text: string): void {
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

// ---------- 탭 ----------
(function initTabs() {
  $$(".tabbar button").forEach(btn => {
    btn.addEventListener("click", () => {
      $$(".tabbar button").forEach(b => b.classList.remove("active"));
      (btn as HTMLButtonElement).classList.add("active");
      ["t1", "t2", "t3"].forEach(id => ($("#tab-" + id) as HTMLElement).hidden = true);
      const id = (btn as HTMLButtonElement).dataset.tab!;
      ($("#tab-" + id) as HTMLElement).hidden = false;
    });
  });
})();

// 초기값
($("#f-issuedat") as HTMLInputElement).value = today();

// ---------- 로그인 / 회원가입 / 로그아웃 바인딩 ----------
($("#btn-login") as HTMLButtonElement).addEventListener("click", async () => {
  const username = ($("#login-username") as HTMLInputElement).value.trim();
  const password = ($("#login-password") as HTMLInputElement).value.trim();

  if (!username || !password) {
    TOAST.show("아이디와 비밀번호를 입력하세요.");
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    if (!res.ok) {
      let msg = "로그인 실패";
      try {
        const err = await res.json();
        if (err?.detail) msg = err.detail;
      } catch { }
      TOAST.show(msg);
      return;
    }

    const user = await res.json() as AuthUser;
    authSetCurrent(user);
    TOAST.show(`${user.nickname || user.username}님 환영합니다.`);
    applyAuthUI();
  } catch (e) {
    console.error(e);
    TOAST.show("서버 연결 오류 (로그인 실패)");
  }

});

// 로그인 화면 → 회원가입 화면으로
($("#btn-go-register") as HTMLButtonElement | null)?.addEventListener("click", (e) => {
  e.preventDefault();
  setView("register");
});

// 회원가입 화면 → 로그인 화면으로
($("#btn-go-login") as HTMLButtonElement | null)?.addEventListener("click", (e) => {
  e.preventDefault();
  setView("login");
});

// 역할 선택 시 관리자 지갑 입력칸 표시/숨김
($("#signup-role") as HTMLSelectElement).addEventListener("change", () => {
  const role = ($("#signup-role") as HTMLSelectElement).value;
  const walletField = $("#admin-wallet-field") as HTMLElement;
  walletField.hidden = (role !== "admin");
});


($("#btn-signup") as HTMLButtonElement).addEventListener("click", async () => {
  const username = ($("#signup-username") as HTMLInputElement).value.trim();
  const password = ($("#signup-password") as HTMLInputElement).value.trim();
  const email = ($("#signup-email") as HTMLInputElement).value.trim();
  const nickname = ($("#signup-nickname") as HTMLInputElement).value.trim();
  // const role     = ( $("#signup-role") as HTMLSelectElement ).value as AuthRole;
  // 현재 백엔드 /auth/register 는 role을 받지 않고 기본 USER로 만듦
  const role = ($("#signup-role") as HTMLSelectElement).value;
  const adminWallet = ($("#signup-wallet") as HTMLInputElement).value.trim();

  const payload: any = { username, password, email, nickname, role };

  if (role === "admin") {
    if (!adminWallet.startsWith("0x")) {
      TOAST.show("올바른 지갑 주소를 입력하세요.");
      return;
    }
    payload.wallet_address = adminWallet;
  }


  if (!username || !password || !email || !nickname) {
    TOAST.show("필수 항목을 모두 입력하세요.");
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),   // payload 사용!
    });


    if (!res.ok) {
      let msg = "회원가입 실패";
      try {
        const err = await res.json();
        if (err?.detail) msg = err.detail;
      } catch { }
      TOAST.show(msg);
      return;
    }

    TOAST.show("회원가입 완료. 이제 로그인하세요.");
    setView("login");
  } catch (e) {
    console.error(e);
    TOAST.show("서버 연결 오류 (회원가입 실패)");
  }
});

($("#btn-logout") as HTMLButtonElement).addEventListener("click", () => {
  authSetCurrent(null);
  disconnectChain();
  TOAST.show("로그아웃 되었습니다.");
  applyAuthUI();
});

// ---------- 미리보기/다운로드 ----------
($("#btn-preview") as HTMLButtonElement).addEventListener("click", () => {
  const meta = buildMetadata(collectForm());
  ($("#preview-box") as HTMLPreElement).textContent = JSON.stringify(meta, null, 2);
  ($("#dlg") as HTMLDialogElement).showModal();
});
($("#dlg-close") as HTMLButtonElement).addEventListener("click", () => ($("#dlg") as HTMLDialogElement).close());
($("#dlg-copy") as HTMLButtonElement).addEventListener("click", () => {
  navigator.clipboard.writeText(($("#preview-box") as HTMLPreElement).textContent || "{}");
  TOAST.show("메타데이터 복사 완료");
});
($("#btn-download") as HTMLButtonElement).addEventListener("click", () => {
  const f = collectForm();
  const meta = buildMetadata(f);
  const fname = (f.certificateId || "metadata") + ".json";
  download(fname, JSON.stringify(meta, null, 2));
  TOAST.show("JSON 다운로드 시작");
});

// ---------- 요청 생성 (IPFS 자동 업로드 + 온체인/로컬) ----------
($("#btn-create") as HTMLButtonElement).addEventListener("click", async () => {
  const current = authGetCurrent();
  if (!current) {
    TOAST.show("먼저 로그인 해주세요.");
    return;
  }

  const f = collectForm();
  let tokenURI = f.tokenURI;

  // tokenURI 비어있으면 자동 업로드
  if (!tokenURI) {
    try {
      TOAST.show("IPFS 업로드 중...");
      const meta = buildMetadata(f);
      const filename = (f.certificateId || "metadata") + ".json";
      const cid = await uploadJSONToIPFSViaInfura(meta, filename);
      tokenURI = tokenUriFromCid(cid);
      ($("#f-tokenuri") as HTMLInputElement).value = tokenURI;
      TOAST.show(`IPFS 업로드 완료: ${cid}`);
    } catch (e) {
      console.error(e);
      TOAST.show("IPFS 업로드 실패");
      return;
    }
  }

  // 온체인 모드
  if (contract && tokenURI) {
    try {
      // ★ beneficiary 지정 로직
      // - 폼의 IssuedTo에 주소를 넣으면 그 주소로 발급
      // - 비어 있으면 현재 연결된 지갑 주소로 발급
      let beneficiary = f.issuedTo;
      if (!beneficiary && signer) {
        beneficiary = await signer.getAddress();
      }
      if (!beneficiary) {
        TOAST.show("beneficiary 지갑 주소가 필요합니다 (발급 대상 주소 또는 지갑 연결)");
        return;
      }

      TOAST.show("요청 트랜잭션 전송...");
      const tx = await contract.createRequest(beneficiary, tokenURI); // ★ 변경
      const rc = await tx.wait();
      const ev = (rc?.logs || [])
        .map(l => contract!.interface.parseLog(l))
        .find((e: any) => e?.name === "RequestCreated");
      const requestId = ev?.args?.requestId?.toString?.() ?? "(unknown)";
      TOAST.show(`온체인 요청 생성: #${requestId}`);
      await renderTable(); // 목록 갱신
    } catch (e) {
      console.error(e);
      TOAST.show("온체인 요청 실패");
    }
    return;
  }

  // 로컬 모드
  if (!f.name || !f.issuer || !f.certificateId) {
    TOAST.show("name, issuer, CertificateID는 필수입니다.");
    return;
  }
  const request: RequestRow = {
    id: nanoid(10),
    createdAt: new Date().toISOString(),
    status: "Pending",
    meta: buildMetadata(f),
  };
  db_push(request);
  await renderTable();
  TOAST.show(`요청 생성 완료: #${request.id} (로컬)`);
});

// ---------- 관리자 대시보드 (온체인/로컬 자동 분기) ----------
const T_BODY = $("#tbody") as HTMLTableSectionElement;
const COUNT = $("#count-total") as HTMLSpanElement;

type OnchainRow = {
  requestId: number;
  requester: string;
  beneficiary: string; // ★ 추가
  tokenURI: string;
  status: RequestRow["status"];
  issuedAt?: string;
  name?: string;
  certId?: string;
  studentId?: string;
  issuedTo?: string;
};

async function fetchOnchainRows(): Promise<OnchainRow[]> {
  if (!contract) return [];
  const total = Number(await contract.requestCount());
  if (!Number.isFinite(total) || total <= 0) return [];

  const rows: OnchainRow[] = [];
  for (let i = total; i >= 1; i--) {
    const r = await contract.requests(i);
    const row: OnchainRow = {
      requestId: i,
      requester: r.requester,
      beneficiary: r.beneficiary, // ★ 추가
      tokenURI: r.tokenURI,
      status: statusFromU8(Number(r.status)),
    };
    // 메타데이터 일부 필드 채우기(선택)
    try {
      if (row.tokenURI?.startsWith("ipfs://")) {
        const url = row.tokenURI.replace("ipfs://", "https://ipfs.io/ipfs/");
        const meta = await fetch(url, { cache: "no-store" }).then(r => r.json());
        row.name = meta?.name || "";
        const attrs = Array.isArray(meta?.attributes) ? meta.attributes : [];
        const val = (k: string) => attrs.find((a: any) => a?.trait_type === k)?.value || "";
        row.certId = val("CertificateID");
        row.studentId = val("StudentID");
        row.issuedTo = val("IssuedTo");
        row.issuedAt = val("IssuedAt");
      }
    } catch {
      // ignore
    }

    rows.push(row);
  }
  return rows;
}

async function renderTable(): Promise<void> {
  // 온체인 모드
  if (contract) {
    const list = await fetchOnchainRows();
    COUNT.textContent = String(list.length);

    const q = ($("#filter-q") as HTMLInputElement).value.trim().toLowerCase();
    const s = ($("#filter-status") as HTMLSelectElement).value as RequestRow["status"] | "";

    const filt = list.filter(it => {
      const hitStatus = s ? (it.status === s) : true;
      const hay = [String(it.requestId), it.certId || "", it.studentId || "", it.issuedTo || "", it.name || "", it.beneficiary || ""]
        .join(" ").toLowerCase(); // ★ beneficiary도 검색 대상에 포함
      const hitQ = q ? hay.includes(q) : true;
      return hitStatus && hitQ;
    });

    const rows = filt.map(it => `
      <tr>
        <td class="small"><a href="#" data-rid="${it.requestId}">#${it.requestId}</a></td>
        <td>${it.certId || "-"}</td>
        <td>${it.studentId || "-"}</td>
        <td>${it.issuedTo || "-"}</td>
        <td>${statusBadge(it.status)}</td>
        <td>${it.issuedAt || "-"}</td>
        <td class="small">
          <button class="btn ok" data-approve-on="${it.requestId}" ${it.status !== "Pending" ? "disabled" : ""}>승인</button>
          <button class="btn warn" data-reject-on="${it.requestId}" ${it.status !== "Pending" ? "disabled" : ""}>반려</button>
          <button class="btn" data-mint-on="${it.requestId}" ${it.status !== "Approved" ? "disabled" : ""}>민팅</button>
          <span class="pill right small">req ${it.requester.slice(0, 6)}…${it.requester.slice(-4)}</span>
          <span class="pill right small">to ${it.beneficiary ? (it.beneficiary.slice(0, 6) + "…" + it.beneficiary.slice(-4)) : "-"}</span>
        </td>
      </tr>
    `).join("");

    T_BODY.innerHTML = rows || `<tr><td colspan="7" class="muted small">온체인 데이터가 없습니다.</td></tr>`;
    return;
  }

  // 로컬 모드
  const list = db_load();
  COUNT.textContent = String(list.length);
  const q = ($("#filter-q") as HTMLInputElement).value.trim().toLowerCase();
  const s = ($("#filter-status") as HTMLSelectElement).value as RequestRow["status"] | "";
  const rows = list
    .filter(it => {
      const hitStatus = s ? (it.status === s) : true;
      const m = it.meta, cid = attr(m, "CertificateID"), sid = attr(m, "StudentID"), to = attr(m, "IssuedTo");
      const hay = [it.id, cid, sid, to].join(" ").toLowerCase();
      const hitQ = q ? hay.includes(q) : true;
      return hitStatus && hitQ;
    })
    .map(it => {
      const m = it.meta, cid = attr(m, "CertificateID"), sid = attr(m, "StudentID"), to = attr(m, "IssuedTo");
      return `<tr>
        <td class="small"><a href="#" data-view="${it.id}">#${it.id}</a></td>
        <td>${cid || "-"}</td>
        <td>${sid || "-"}</td>
        <td>${to || "-"}</td>
        <td>${statusBadge(it.status)}</td>
        <td>${attr(m, "IssuedAt") || "-"}</td>
        <td class="small">
          <button class="btn ok" data-approve="${it.id}" ${it.status !== "Pending" ? "disabled" : ""}>승인</button>
          <button class="btn warn" data-reject="${it.id}" ${it.status !== "Pending" ? "disabled" : ""}>반려</button>
          <button class="btn" data-mint="${it.id}" ${it.status !== "Pending" ? "" : "disabled"}>민팅</button>
          <button class="btn err" data-revoke="${it.id}" ${it.status !== "Minted" ? "disabled" : ""}>회수</button>
        </td>
      </tr>`;
    })
    .join("");

  T_BODY.innerHTML = rows || `<tr><td colspan="7" class="muted small">데이터가 없습니다.</td></tr>`;
}

// 테이블 클릭 핸들러 (온체인/로컬)
T_BODY.addEventListener("click", async (e) => {
  const target = e.target as HTMLElement;

  // 온체인 모드
  if (contract) {
    const ap = target.closest("[data-approve-on]") as HTMLElement | null;
    const rj = target.closest("[data-reject-on]") as HTMLElement | null;
    const mn = target.closest("[data-mint-on]") as HTMLElement | null;
    const link = target.closest("[data-rid]") as HTMLElement | null;

    if (link) {
      e.preventDefault();
      const rid = Number(link.getAttribute("data-rid")!);
      try {
        const r = await contract.requests(rid);
        const data: any = {
          requestId: rid,
          requester: r.requester,
          beneficiary: r.beneficiary, // ★ 프리뷰에도 표시
          tokenURI: r.tokenURI,
          status: statusFromU8(Number(r.status))
        };
        if (r.tokenURI?.startsWith?.("ipfs://")) {
          const meta = await fetch(r.tokenURI.replace("ipfs://", "https://ipfs.io/ipfs/")).then(r => r.json()).catch(() => null);
          if (meta) data.metadata = meta;
        }
        ($("#preview-box") as HTMLPreElement).textContent = JSON.stringify(data, null, 2);
        ($("#dlg") as HTMLDialogElement).showModal();
      } catch { }
      return;
    }

    if (ap) { const rid = Number(ap.getAttribute("data-approve-on")!); await mutateOnchain(rid, "approve"); await renderTable(); return; }
    if (rj) { const rid = Number(rj.getAttribute("data-reject-on")!); await mutateOnchain(rid, "reject"); await renderTable(); return; }
    if (mn) { const rid = Number(mn.getAttribute("data-mint-on")!); await mutateOnchain(rid, "mint"); await renderTable(); return; }
    return;
  }

  // 로컬 모드
  const a = target.closest("[data-view]") as HTMLElement | null;
  const ap = target.closest("[data-approve]") as HTMLElement | null;
  const rj = target.closest("[data-reject]") as HTMLElement | null;
  const rv = target.closest("[data-revoke]") as HTMLElement | null;
  const mn = target.closest("[data-mint]") as HTMLElement | null;

  if (a) {
    e.preventDefault();
    const id = a.getAttribute("data-view")!;
    const it = db_load().find(x => x.id === id);
    if (it) {
      ($("#preview-box") as HTMLPreElement).textContent = JSON.stringify(it, null, 2);
      ($("#dlg") as HTMLDialogElement).showModal();
    }
  }
  if (ap) await mutateLocal(ap.getAttribute("data-approve")!, "approve");
  if (rj) await mutateLocal(rj.getAttribute("data-reject")!, "reject");
  if (rv) await mutateLocal(rv.getAttribute("data-revoke")!, "revoke");
  if (mn) await mutateLocal(mn.getAttribute("data-mint")!, "mint");
});

// 로컬 변이
async function mutateLocal(id: string, op: "approve" | "reject" | "revoke" | "mint"): Promise<void> {
  const arr = db_load();
  const i = arr.findIndex(x => x.id === id);
  if (i < 0) return;
  if (op === "approve" && arr[i].status === "Pending") { arr[i].status = "Minted"; arr[i].tokenId = "T-" + nanoid(6); }
  if (op === "reject" && arr[i].status === "Pending") { arr[i].status = "Rejected"; }
  if (op === "mint") { TOAST.show("지갑 미연결: 민팅은 로컬에선 상태 변화 없음"); }
  if (op === "revoke" && arr[i].status === "Minted") { arr[i].status = "Revoked"; }
  db_save(arr); await renderTable(); TOAST.show(`#${id} → ${arr[i].status} (로컬)`);
}

// 온체인 변이
async function mutateOnchain(reqId: number, op: "approve" | "reject" | "mint"): Promise<void> {
  if (!contract || !signer) return;
  const me = await signer.getAddress();
  if (!isOwner(me)) { TOAST.show("소유자만 승인/반려/민팅 가능"); return; }
  try {
    if (op === "approve") { await (await contract.approveRequest(reqId)).wait(); TOAST.show(`Approved #${reqId}`); }
    if (op === "reject") { const reason = prompt("반려 사유 입력") || ""; await (await contract.rejectRequest(reqId, reason)).wait(); TOAST.show(`Rejected #${reqId}`); }
    if (op === "mint") {
      const rc = await (await contract.mintNFT(reqId)).wait();
      const ev = (rc?.logs || []).map(l => contract!.interface.parseLog(l)).find((e: any) => e?.name === "NFTMinted");
      const tokenId = ev?.args?.tokenId?.toString?.() ?? "?";
      TOAST.show(`Minted #${reqId} → token ${tokenId}`);
    }
  } catch (e) { console.error(e); TOAST.show("온체인 처리 실패"); }
}

// ---------- 버튼 바인딩 ----------
($("#btn-connect") as HTMLButtonElement).addEventListener("click", () => { void connectChain(false); });
($("#btn-disconnect") as HTMLButtonElement).addEventListener("click", () => { disconnectChain(); });
($("#btn-apply") as HTMLButtonElement).addEventListener("click", () => { void renderTable(); });
($("#btn-reset") as HTMLButtonElement).addEventListener("click", () => {
  ($("#filter-status") as HTMLSelectElement).value = "";
  ($("#filter-q") as HTMLInputElement).value = "";
  void renderTable();
});
($("#btn-refresh") as HTMLButtonElement).addEventListener("click", () => { void renderTable(); });
($("#btn-export") as HTMLButtonElement).addEventListener("click", () => {
  const arr = db_load();
  const head = ["RequestID", "Status", "CertificateID", "StudentID", "IssuedTo", "IssuedAt", "Name", "Issuer", "TokenId"];
  const rows = arr.map(it => {
    const m = it.meta;
    const issuer = attr(m, "Issuer") || (m.attributes?.find(a => a.trait_type === "Issuer")?.value || "");
    return [
      it.id, it.status,
      attr(m, "CertificateID") || "", attr(m, "StudentID") || "", attr(m, "IssuedTo") || "",
      attr(m, "IssuedAt") || "", m.name || "", issuer, it.tokenId || "",
    ].map(v => `"${String(v).replaceAll('"', '""')}"`).join(",");
  });
  const csv = [head.join(","), ...rows].join("\n");
  download("campusbadge_requests.csv", csv);
});
($("#btn-clear") as HTMLButtonElement).addEventListener("click", () => {
  if (confirm("모든 로컬 데이터를 삭제할까요?")) { localStorage.removeItem(DB_KEY); void renderTable(); TOAST.show("삭제 완료"); }
});

// ---------- 이벤트 구독(온체인) ----------
function wireEvents(): void {
  if (!contract) return;
  contract.on("RequestCreated", (requestId: bigint) => { TOAST.show(`RequestCreated #${requestId}`); void renderTable(); });
  contract.on("RequestApproved", (requestId: bigint) => { TOAST.show(`Approved #${requestId}`); void renderTable(); });
  contract.on("RequestRejected", (requestId: bigint) => { TOAST.show(`Rejected #${requestId}`); void renderTable(); });
  contract.on("NFTMinted", (requestId: bigint, tokenId: bigint) => { TOAST.show(`Minted #${requestId} → token ${tokenId}`); void renderTable(); });
}

// ---------- 초기 렌더 ----------
applyAuthUI();
void renderTable();

export { };
