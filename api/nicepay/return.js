// 나이스페이 인증 결과 수신 → 위변조 검증 → 결제 승인 → 결과 페이지로 이동
const crypto = require('crypto');

// 서버 기준 상품 가격 (index.html의 PRODUCTS 가격과 같아야 함)
const PRICES = {
  p7: 289000, p1: 189000, p2: 169000, p6: 139000, p5: 119000,
  p9: 129000, p4: 89000, p8: 69000, p3: 79000, p10: 99000
};

const API = process.env.NICEPAY_API || 'https://sandbox-api.nicepay.co.kr';

// mallReserved("p7:1,p1:2")로 주문 금액을 서버에서 다시 계산
function expectedAmount(mallReserved) {
  let sub = 0;
  for (const part of String(mallReserved || '').split(',')) {
    const [id, q] = part.split(':');
    const qty = parseInt(q, 10);
    if (!PRICES[id] || !(qty > 0 && qty < 100)) return null;
    sub += PRICES[id] * qty;
  }
  if (!sub) return null;
  return sub + (sub >= 100000 ? 0 : 3000);
}

function back(res, params) {
  res.writeHead(303, { Location: '/?' + new URLSearchParams(params).toString() });
  res.end();
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return back(res, { pay: 'fail', msg: '잘못된 접근입니다.' });

  const b = typeof req.body === 'string'
    ? Object.fromEntries(new URLSearchParams(req.body))
    : (req.body || {});

  const clientId = process.env.NICEPAY_CLIENT_ID;
  const secretKey = process.env.NICEPAY_SECRET_KEY;
  if (!clientId || !secretKey) {
    return back(res, { pay: 'fail', msg: '서버에 나이스페이 키가 설정되지 않았습니다.' });
  }

  // 1. 인증 결과 확인
  if (b.authResultCode !== '0000') {
    return back(res, { pay: 'fail', msg: b.authResultMsg || '결제가 취소되었습니다.' });
  }

  // 2. 위변조 검증: sha256(authToken + clientId + amount + secretKey)
  const sig = crypto.createHash('sha256')
    .update(String(b.authToken) + clientId + String(b.amount) + secretKey)
    .digest('hex');
  if (sig !== b.signature) {
    return back(res, { pay: 'fail', msg: '결제 정보 검증에 실패했습니다.' });
  }

  // 3. 금액 검증
  const amount = Number(b.amount);
  if (expectedAmount(b.mallReserved) !== amount) {
    return back(res, { pay: 'fail', msg: '결제 금액이 주문 금액과 다릅니다.' });
  }

  // 4. 승인 요청
  try {
    const r = await fetch(`${API}/v1/payments/${encodeURIComponent(b.tid)}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Basic ' + Buffer.from(`${clientId}:${secretKey}`).toString('base64')
      },
      body: JSON.stringify({ amount })
    });
    const d = await r.json();

    if (d.resultCode !== '0000') {
      return back(res, { pay: 'fail', msg: d.resultMsg || '결제 승인에 실패했습니다.' });
    }

    const out = {
      pay: 'success',
      orderId: d.orderId,
      amount: d.amount,
      method: d.payMethod || '',
      tid: d.tid
    };
    if (d.card && d.card.cardName) out.card = d.card.cardName;
    if (d.vbank) {
      out.vbank = `${d.vbank.vbankName || ''} ${d.vbank.vbankNumber || ''}`.trim();
      out.vbankExp = d.vbank.vbankExpDate || '';
    }
    return back(res, out);
  } catch (e) {
    return back(res, { pay: 'fail', msg: '승인 요청 중 오류가 발생했습니다.' });
  }
};