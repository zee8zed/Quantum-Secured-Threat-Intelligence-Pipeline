"use client";

import { motion } from "framer-motion";

import { cn } from "@/lib/utils";

export function SectionHeading({
  eyebrow,
  title,
  description,
  className,
}: {
  eyebrow: string;
  title: string;
  description?: string;
  className?: string;
}) {
  return (
    <div className={cn("max-w-2xl", className)}>
      <span className="font-mono text-xs uppercase tracking-[0.2em] text-brand-cyan/80">
        {eyebrow}
      </span>
      <motion.div
        initial={{ width: 0 }}
        whileInView={{ width: "3rem" }}
        viewport={{ once: true }}
        transition={{ duration: 0.6, delay: 0.15, ease: "easeOut" }}
        className="mt-2 h-px bg-brand-gradient"
      />
      <h2 className="mt-4 text-3xl sm:text-4xl font-semibold tracking-tight text-foreground">
        {title}
      </h2>
      {description ? (
        <p className="mt-4 text-muted-foreground leading-relaxed">{description}</p>
      ) : null}
    </div>
  );
}
