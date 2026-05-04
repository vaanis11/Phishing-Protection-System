// PhishGuard — Hex Grid + Particle Background
(function () {
  const canvas = document.getElementById('hexCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const HEX_SIZE = 28;
  const HEX_GAP  = 4;
  const COL = '#00ff88';

  let W, H, hexes = [], particles = [];

  function hexPoints(cx, cy, r) {
    const pts = [];
    for (let i = 0; i < 6; i++) {
      const a = Math.PI / 180 * (60 * i - 30);
      pts.push([cx + r * Math.cos(a), cy + r * Math.sin(a)]);
    }
    return pts;
  }

  function buildHexes() {
    hexes = [];
    const w = HEX_SIZE * 2;
    const h = Math.sqrt(3) * HEX_SIZE;
    const cols = Math.ceil(W / (w * 0.75)) + 2;
    const rows = Math.ceil(H / h) + 2;

    for (let row = -1; row < rows; row++) {
      for (let col = -1; col < cols; col++) {
        const x = col * w * 0.75;
        const y = row * h + (col % 2 === 0 ? 0 : h / 2);
        hexes.push({
          x, y,
          pulse: Math.random(),
          speed: 0.002 + Math.random() * 0.004,
          bright: Math.random() * 0.06,
          maxBright: 0.04 + Math.random() * 0.10,
        });
      }
    }
  }

  function buildParticles() {
    particles = Array.from({ length: 40 }, () => ({
      x: Math.random() * W,
      y: Math.random() * H,
      vx: (Math.random() - 0.5) * 0.3,
      vy: -0.2 - Math.random() * 0.4,
      size: 1 + Math.random() * 2,
      alpha: Math.random() * 0.5 + 0.1,
    }));
  }

  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
    buildHexes();
    buildParticles();
  }

  function drawHex(pts, alpha) {
    ctx.beginPath();
    ctx.moveTo(pts[0][0], pts[0][1]);
    for (let i = 1; i < 6; i++) ctx.lineTo(pts[i][0], pts[i][1]);
    ctx.closePath();
    ctx.strokeStyle = `rgba(0,255,136,${alpha})`;
    ctx.lineWidth = 0.5;
    ctx.stroke();
  }

  function tick() {
    ctx.clearRect(0, 0, W, H);

    // Hex grid
    for (const h of hexes) {
      h.pulse += h.speed;
      if (h.pulse > 1) h.pulse = 0;
      const a = h.bright + Math.sin(h.pulse * Math.PI * 2) * h.maxBright;
      drawHex(hexPoints(h.x, h.y, HEX_SIZE - HEX_GAP), Math.max(0, a));
    }

    // Floating particles
    for (const p of particles) {
      p.x += p.vx;
      p.y += p.vy;
      if (p.y < -10) { p.y = H + 10; p.x = Math.random() * W; }
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(0,255,136,${p.alpha * 0.4})`;
      ctx.fill();
    }

    requestAnimationFrame(tick);
  }

  resize();
  window.addEventListener('resize', resize);
  tick();
})();