"use client";

import { motion, useScroll, useTransform } from "framer-motion";

export function Background() {
  const { scrollY } = useScroll();

  const gridY = useTransform(scrollY, [0, 4000], [0, -60]);
  const violetY = useTransform(scrollY, [0, 4000], [0, -220]);
  const cyanY = useTransform(scrollY, [0, 4000], [0, -120]);
  const tealY = useTransform(scrollY, [0, 4000], [0, -320]);

  return (
    <div className="fixed inset-0 -z-10 overflow-hidden bg-background">
      <motion.div
        className="absolute inset-0 opacity-[0.15]"
        style={{
          y: gridY,
          backgroundImage:
            "linear-gradient(hsl(var(--border)) 1px, transparent 1px), linear-gradient(90deg, hsl(var(--border)) 1px, transparent 1px)",
          backgroundSize: "48px 48px",
        }}
      />

      <motion.div
        className="absolute -top-40 -left-40 h-[32rem] w-[32rem]"
        style={{ y: violetY }}
      >
        <motion.div
          animate={{ x: [0, 24, 0], y: [0, -32, 0] }}
          transition={{ duration: 18, repeat: Infinity, ease: "easeInOut" }}
          className="h-full w-full rounded-full opacity-30 blur-[120px]"
          style={{ background: "hsl(var(--brand-violet))" }}
        />
      </motion.div>

      <motion.div
        className="absolute top-1/3 -right-40 h-[28rem] w-[28rem]"
        style={{ y: cyanY }}
      >
        <motion.div
          animate={{ x: [0, -28, 0], y: [0, 26, 0] }}
          transition={{ duration: 20, repeat: Infinity, ease: "easeInOut", delay: 2 }}
          className="h-full w-full rounded-full opacity-25 blur-[120px]"
          style={{ background: "hsl(var(--brand-cyan))" }}
        />
      </motion.div>

      <motion.div
        className="absolute bottom-0 left-1/3 h-[26rem] w-[26rem]"
        style={{ y: tealY }}
      >
        <motion.div
          animate={{ x: [0, 20, 0], y: [0, 28, 0] }}
          transition={{ duration: 22, repeat: Infinity, ease: "easeInOut", delay: 4 }}
          className="h-full w-full rounded-full opacity-20 blur-[120px]"
          style={{ background: "hsl(var(--brand-teal))" }}
        />
      </motion.div>

      <div
        className="absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse at center, transparent 0%, hsl(var(--background)) 75%)",
        }}
      />
    </div>
  );
}
