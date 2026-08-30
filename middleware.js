// Vercel Edge Middleware — 모든 요청을 서버 측에서 잠근다.
// 비밀은 이 파일에 없다: Vercel 환경변수 ACCESS_SHA256(코드의 SHA-256 해시)와
// 브라우저 Basic 인증으로 들어온 입력의 해시를 대조한다.
// 환경변수가 없으면 통과(fail-open) — 변수 등록 전에는 사이트가 잠기지 않는다.

async function sha256hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

export default async function middleware(request) {
  const HASH = process.env.ACCESS_SHA256;
  if (!HASH) return; // 잠금 해제 상태

  const auth = request.headers.get("authorization") || "";
  if (auth.startsWith("Basic ")) {
    const decoded = atob(auth.slice(6));
    const pw = decoded.slice(decoded.indexOf(":") + 1);
    if ((await sha256hex(pw)) === HASH) return; // 통과
  }
  return new Response("열람 코드가 필요합니다.", {
    status: 401,
    headers: { "WWW-Authenticate": 'Basic realm="greenbio", charset="UTF-8"' },
  });
}
