window.onload = () => {
  document.querySelectorAll('.btn-qr').forEach((el) => {
    el.addEventListener('click', (e) => {
      const example = e.target.getAttribute("data-example");    
      location.href = `qr.html?example=${encodeURIComponent(example)}`;
    });
  });
};
