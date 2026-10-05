"use client";

import React, { useEffect, useRef } from "react";

interface Blob {
  x: number;
  y: number;
  vx: number;
  vy: number;
  r: number;
  phase: number;
}

export interface MetaballMorphProps {
  title?: string;
  description?: string;
  className?: string;
}

export function MetaballMorph({
  title = "Vue",
  description = "Thresholded potential field. Blobs merge like mercury — the cursor is another drop.",
  className = "",
}: MetaballMorphProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;
    const ctx = canvas.getContext("2d", { alpha: false });
    if (!ctx) return;

    let raf = 0;
    let width = 0;
    let height = 0;
    let time = 0;
    const mouse = { x: 0, y: 0, tx: 0, ty: 0 };
    let blobs: Blob[] = [];

    // Increased step slightly (from 3 to 5) to dramatically boost performance, 
    // while maintaining a smooth visual threshold.
    const step = 5;

    const spawn = () => {
      blobs = [];
      for (let i = 0; i < 7; i++) {
        blobs.push({
          x: width * (0.2 + Math.random() * 0.6),
          y: height * (0.2 + Math.random() * 0.6),
          vx: (Math.random() - 0.5) * 0.8,
          vy: (Math.random() - 0.5) * 0.8,
          r: 55 + Math.random() * 50,
          phase: Math.random() * Math.PI * 2,
        });
      }
    };

    const resize = () => {
      const rect = container.getBoundingClientRect();
      // Cap DPR at 2 for performance stability on retina displays
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = rect.width;
      height = rect.height;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      mouse.tx = width * 0.5;
      mouse.ty = height * 0.5;
      spawn();
    };

    const onMove = (e: PointerEvent) => {
      const rect = container.getBoundingClientRect();
      mouse.tx = e.clientX - rect.left;
      mouse.ty = e.clientY - rect.top;
    };

    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(container);
    container.addEventListener("pointermove", onMove);

    let lastTime = performance.now();

    const tick = (now: number) => {
      const dt = Math.min((now - lastTime) / 1000, 0.1);
      lastTime = now;
      time += dt;

      // Smooth interpolation for mouse position
      mouse.x += (mouse.tx - mouse.x) * 0.15;
      mouse.y += (mouse.ty - mouse.y) * 0.15;

      ctx.fillStyle = "#05080a";
      ctx.fillRect(0, 0, width, height);

      for (let i = 0; i < blobs.length; i++) {
        const b = blobs[i];
        b.phase += dt * 0.6;
        b.x += b.vx + Math.sin(time * 0.4 + b.phase) * 0.25;
        b.y += b.vy + Math.cos(time * 0.35 + b.phase) * 0.25;
        if (b.x < b.r || b.x > width - b.r) b.vx *= -1;
        if (b.y < b.r || b.y > height - b.r) b.vy *= -1;
      }

      // Pre-calculate field sources to save cycles inside the pixel loop
      const fieldCount = blobs.length + 1;
      const fieldX = new Float32Array(fieldCount);
      const fieldY = new Float32Array(fieldCount);
      const fieldR2 = new Float32Array(fieldCount);

      for (let i = 0; i < blobs.length; i++) {
        const b = blobs[i];
        const r = b.r * (1 + Math.sin(b.phase) * 0.08);
        fieldX[i] = b.x;
        fieldY[i] = b.y;
        fieldR2[i] = r * r;
      }
      // Mouse blob
      fieldX[blobs.length] = mouse.x;
      fieldY[blobs.length] = mouse.y;
      fieldR2[blobs.length] = 78 * 78;

      ctx.fillStyle = "#c8ff3a";
      ctx.beginPath();

      const cols = Math.ceil(width / step);
      const rows = Math.ceil(height / step);
      const thresh = 1.05;

      for (let j = 0; j < rows; j++) {
        const y = j * step;
        for (let i = 0; i < cols; i++) {
          const x = i * step;
          let v = 0;

          for (let k = 0; k < fieldCount; k++) {
            const dx = x - fieldX[k];
            const dy = y - fieldY[k];
            v += fieldR2[k] / (dx * dx + dy * dy + 1);
          }

          if (v > thresh) {
            ctx.rect(x, y, step + 0.4, step + 0.4);
          }
        }
      }
      ctx.fill();

      raf = requestAnimationFrame(tick);
    };

    raf = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      container.removeEventListener("pointermove", onMove);
    };
  }, []);

  return (
    <div
      ref={containerRef}
      className={`relative h-screen w-full overflow-hidden select-none bg-[#05080a] ${className}`}
    >
      <canvas ref={canvasRef} className="absolute inset-0 block cursor-none" />
      <div className="pointer-events-none relative z-10 flex h-full flex-col items-center justify-center px-4 text-center mix-blend-difference text-white">
        <h1 className="font-mono text-6xl font-black uppercase leading-none tracking-tighter md:text-9xl">
          {title}
        </h1>
        <p className="mt-4 max-w-lg font-mono text-xs opacity-70 md:text-sm">{description}</p>
      </div>
    </div>
  );
}

export default MetaballMorph;
