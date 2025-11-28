/*
  CampusBadge – 인증서 DApp (온체인/로컬 겸용 데모)
  TypeScript (ethers v6, Vite)

  사전 준비
  1) npm i ethers
  2) .env.local 에 아래 추가 (데모/개발용. 운영은 서버 프록시 권장)
     VITE_PINATA_JWT=eyJhbGciOi...
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
  // beneficiary 필드 포함 버전
  "function requests(uint256) view returns (address requester, address beneficiary, string tokenURI, uint8 status)",

  // ownable
  "function owner() view returns (address)",

  // write
  // createRequest(address beneficiary, string tokenURI)
  "function createRequest(address beneficiary, string tokenURI) external returns (uint256)",
  "function approveRequest(uint256 requestId) external",
  "function rejectRequest(uint256 requestId, string reason) external",
  "function mintNFT(uint256 requestId) external returns (uint256)",

  // events
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

// ---------- IPFS (Pinata) ----------
const PINATA_JWT = import.meta.env.VITE_PINATA_JWT as string;
const PINATA_JSON_ENDPOINT = "https://api.pinata.cloud/pinning/pinJSONToIPFS";

async function uploadJSONToIPFSViaPinata(obj: any, filename = "metadata.json"): Promise<string> {
  if (!PINATA_JWT) {
    throw new Error("Missing Pinata JWT (VITE_PINATA_JWT)");
  }

  const body = {
    pinataMetadata: { name: filename },
    pinataContent: obj,
  };

  const res = await fetch(PINATA_JSON_ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${PINATA_JWT}`,
    },
    body: JSON.stringify(body),
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(`Pinata upload failed: ${res.status} ${JSON.stringify(data)}`);
  }

  const cid = data.IpfsHash as string;
  return cid;
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
function ipfsToHttp(uri?: string): string {
  if (!uri) return "";
  return uri.startsWith("ipfs://") ? uri.replace("ipfs://", "https://ipfs.io/ipfs/") : uri;
}

// ---------- 화면 전환 (login / register / main + home/mypage) ----------
type View = "login" | "register" | "main";
function setView(v: View): void {
  const loginSec = $("#view-login") as HTMLElement;
  const regSec = $("#view-register") as HTMLElement;
  const mainSec = $("#view-main") as HTMLElement;
  loginSec.hidden = v !== "login";
  regSec.hidden = v !== "register";
  mainSec.hidden = v !== "main";
}

type MainPage = "home" | "mypage";
function setMainPage(p: MainPage): void {
  const home = $("#page-home") as HTMLElement;
  const my = $("#page-mypage") as HTMLElement;
  if (p === "home") {
    home.hidden = false;
    my.hidden = true;
  } else {
    home.hidden = true;
    my.hidden = false;
    void renderMyPage();
  }
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
  const welcome    = $("#welcome-text") as HTMLSpanElement;

  const currentUser = authGetCurrent();

  // 로그인 안 된 상태
  if (!currentUser) {
    setView("login");
    loginPill.innerHTML = '계정: <b>로그인 필요</b>';
    logoutBtn.style.display = "none";
    welcome.textContent = "게스트";
    disconnectChain();
    setMainPage("home");
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

  // 역할별 섹션 토글 (기업검증 제거, 요청/관리자만)
  if (isAdmin) {
    secAdmin.style.display   = "";
    secRequest.style.display = "none";
  } else {
    secAdmin.style.display   = "none";
    secRequest.style.display = "";
  }

  // 로그인 이후 자동 체인 연결
  if (!provider) {
    autoConnectChain();
  }

  // 로그인 시 기본 화면은 대시보드
  setMainPage("home");
}


// ---------- 폼 & 메타데이터 ----------
function collectForm() {
  const current = authGetCurrent();
  const wallet = (current?.wallet_address || "").trim();

  const imageSelect = $("#f-image-category") as HTMLSelectElement | null;
  const image = imageSelect ? imageSelect.value.trim() : "";

  const f = {
    name: ($("#f-name") as HTMLInputElement).value.trim(),
    issuer: ($("#f-issuer") as HTMLInputElement).value.trim(),
    image,
    certificateId: ($("#f-certid") as HTMLInputElement).value.trim(),
    // beneficiary / IssuedTo 는 로그인 계정의 지갑 주소로 자동 설정
    issuedTo: wallet,
    studentId: ($("#f-studentid") as HTMLInputElement).value.trim(),
    issuedAt: ($("#f-issuedat") as HTMLInputElement).value || today(),
    tokenURI: ($("#f-tokenuri") as HTMLInputElement).value.trim(),
  };
  return f;
}

function buildMetadata(f: ReturnType<typeof collectForm>): Metadata {
  const image = f.image
    ? (f.image.startsWith("ipfs://") || f.image.startsWith("http")
        ? f.image
        : "ipfs://" + f.image)
    : "";

  // 설명은 사용자 입력 대신, name 기반 기본 문구
  const description = f.name
    ? `${f.name} – CampusBadge 인증서`
    : "CampusBadge 인증서";

  return {
    name: f.name || "Campus Certificate",
    description,
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

// ---------- 탭 (요약 가이드는 삭제되었지만 코드 호환용) ----------
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
      body: JSON.stringify(payload),
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

// 상단 쇼트컷: 인증서 요청 / 내 인증서 보기
($("#shortcut-request") as HTMLButtonElement).addEventListener("click", () => {
  setMainPage("home");
  const secReq = $("#sec-request") as HTMLElement | null;
  if (secReq) {
    secReq.scrollIntoView({ behavior: "smooth", block: "start" });
  }
});

($("#shortcut-mypage") as HTMLButtonElement).addEventListener("click", () => {
  setMainPage("mypage");
  window.scrollTo({ top: 0, behavior: "smooth" });
});

// 내 인증서 화면 → 대시보드로
($("#btn-mypage-back") as HTMLButtonElement).addEventListener("click", (e) => {
  e.preventDefault();
  setMainPage("home");
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

  if (!current.wallet_address) {
    TOAST.show("계정에 등록된 지갑 주소가 없습니다. 관리자에게 문의하세요.");
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
      const cid = await uploadJSONToIPFSViaPinata(meta, filename);
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
      const beneficiary = current.wallet_address;

      TOAST.show("요청 트랜잭션 전송...");
      const tx = await contract.createRequest(beneficiary, tokenURI);
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
  beneficiary: string;
  tokenURI: string;
  status: RequestRow["status"];
  issuedAt?: string;
  name?: string;
  certId?: string;
  studentId?: string;
  issuedTo?: string;
  image?: string;
  issuer?: string;
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
      beneficiary: r.beneficiary,
      tokenURI: r.tokenURI,
      status: statusFromU8(Number(r.status)),
    };
    // 메타데이터 일부 필드 채우기
    try {
      if (row.tokenURI?.startsWith("ipfs://")) {
        const url = row.tokenURI.replace("ipfs://", "https://ipfs.io/ipfs/");
        const meta = await fetch(url, { cache: "no-store" }).then(r => r.json());
        row.name = meta?.name || "";
        row.image = meta?.image || "";
        const attrs = Array.isArray(meta?.attributes) ? meta.attributes : [];
        const val = (k: string) => attrs.find((a: any) => a?.trait_type === k)?.value || "";
        row.certId = val("CertificateID");
        row.studentId = val("StudentID");
        row.issuedTo = val("IssuedTo");
        row.issuedAt = val("IssuedAt");
        row.issuer = val("Issuer");
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
        .join(" ").toLowerCase();
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
          <button class="btn" data-mint="${it.id}" ${it.status !== "Pending" ? "disabled" : ""}>민팅</button>
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
          beneficiary: r.beneficiary,
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

// ---------- 내 인증서 렌더링 ----------
async function renderMyPage(): Promise<void> {
  const current = authGetCurrent();
  const info = $("#mypage-wallet-info") as HTMLParagraphElement;
  const listEl = $("#mypage-list") as HTMLDivElement;
  const emptyEl = $("#mypage-empty") as HTMLDivElement;

  listEl.innerHTML = "";
  emptyEl.style.display = "none";

  if (!current) {
    info.textContent = "로그인 정보가 없습니다. 먼저 로그인 해 주세요.";
    emptyEl.style.display = "block";
    return;
  }

  const wallet = (current.wallet_address || "").trim().toLowerCase();
  if (!wallet) {
    info.textContent = "이 계정에는 지갑 주소가 등록되어 있지 않습니다.";
    emptyEl.style.display = "block";
    return;
  }

  info.innerHTML = `지갑 주소 <span style="font-family:monospace">${wallet.slice(0, 6)}…${wallet.slice(-4)}</span> 기준으로 요청/발급된 인증서를 표시합니다.`;

  type MyCert = {
    id: string;
    status: RequestRow["status"];
    name: string;
    issuer: string;
    image?: string;
    tokenURI?: string;
    certId?: string;
    studentId?: string;
    issuedAt?: string;
  };

  let certs: MyCert[] = [];

  if (contract) {
    const rows = await fetchOnchainRows();
    certs = rows
      .filter(r => r.beneficiary && r.beneficiary.toLowerCase() === wallet)
      .map(r => ({
        id: `#${r.requestId}`,
        status: r.status,
        name: r.name || "(이름 없음)",
        issuer: r.issuer || "",
        image: r.image,
        tokenURI: r.tokenURI,
        certId: r.certId || "",
        studentId: r.studentId || "",
        issuedAt: r.issuedAt || "",
      }));
  } else {
    const rows = db_load();
    certs = rows
      .filter(r => {
        const meta = r.meta;
        const to = attr(meta, "IssuedTo")?.toLowerCase() || "";
        return wallet && to === wallet;
      })
      .map(r => ({
        id: r.id,
        status: r.status,
        name: r.meta.name || "(이름 없음)",
        issuer: attr(r.meta, "Issuer") || "",
        image: r.meta.image,
        tokenURI: undefined,
        certId: attr(r.meta, "CertificateID") || "",
        studentId: attr(r.meta, "StudentID") || "",
        issuedAt: attr(r.meta, "IssuedAt") || "",
      }));
  }

  if (!certs.length) {
    emptyEl.style.display = "block";
    return;
  }

  listEl.innerHTML = certs.map(c => {
    const img = ipfsToHttp(c.image);
    const cid = c.tokenURI?.startsWith("ipfs://")
      ? c.tokenURI.slice("ipfs://".length)
      : (c.tokenURI || "");
    return `
      <article class="card" style="padding:12px;">
        <div class="row" style="gap:8px">
          ${img ? `<div><img src="${img}" alt="${c.name}" style="width:100%;border-radius:12px;max-height:180px;object-fit:cover"/></div>` : ""}
          <div>
            <div class="small muted">${c.certId || c.id}</div>
            <h3 style="margin:4px 0 4px;font-size:15px;">${c.name}</h3>
            <div class="small muted">발급기관: ${c.issuer || "-"}</div>
            <div class="small muted">학번: ${c.studentId || "-"}</div>
            <div class="small muted">발급일: ${c.issuedAt || "-"}</div>
            <div class="small muted">상태: ${statusBadge(c.status)}</div>
            ${cid ? `<div class="small" style="margin-top:4px;word-break:break-all;">CID: <code>${cid}</code></div>` : ""}
          </div>
        </div>
      </article>
    `;
  }).join("");
}

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
