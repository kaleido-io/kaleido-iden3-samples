window.onload = () => {
  const url = new URL(document.URL);
  const example = url.searchParams.get("example") || 'kyc_age';
  const qrUrl = `${url.origin}/api/sign-in?example=${encodeURIComponent(example)}`;
  console.log("qrUrl:", qrUrl);
  
  const qrCodeEl = document.querySelector('#qrcode');
  fetch(qrUrl)
    .then((r) => {
      return Promise.all([
        r.status, 
        r.headers.get('x-id'),
        r.json()
      ])
    })
    .then(([status, id, data]) => {
      console.log({status, id, data});
      if (status === 200) {
        makeQr(qrCodeEl, data);
      } else {
        console.error(`QR request failed with status: ${status}, error: ${data?.error}`);
      }
      return id;
    })
    .catch((err) => console.log(err));
};

function makeQr(el, data) {
  return new QRCode(el, {
    text: JSON.stringify(data),
    width: 600,
    height: 600,
    colorDark: '#000',
    colorLight: '#ffffff',
    correctLevel: QRCode.CorrectLevel.H,
  });
}
