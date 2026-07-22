"use client";

import { motion } from "framer-motion";
import { Atom, ChevronRight, FileJson, FileText, Lock, ScanSearch } from "lucide-react";

import { ScrollReveal } from "@/components/scroll-reveal";
import { SectionHeading } from "@/components/section-heading";
import { PIPELINE_FLOW } from "@/lib/constants";

const ICONS = [FileText, ScanSearch, Atom, Lock, FileJson];

export function HowItWorks() {
  return (
    <section className="relative px-6 py-28 sm:py-36">
      <div className="mx-auto max-w-6xl">
        <ScrollReveal>
          <SectionHeading
            eyebrow="How it works"
            title="One flow, from raw text to encrypted brief."
            description="Each stage hands off a structured artifact to the next — hover a node for detail."
          />
        </ScrollReveal>

        <div className="mt-16 flex flex-col items-stretch gap-4 lg:flex-row lg:items-center lg:gap-2">
          {PIPELINE_FLOW.map((node, i) => {
            const Icon = ICONS[i];
            const isLast = i === PIPELINE_FLOW.length - 1;
            return (
              <div key={node.label} className="flex flex-1 items-center gap-2">
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true, margin: "-80px" }}
                  transition={{ duration: 0.5, delay: i * 0.12 }}
                  className="group relative flex flex-1 flex-col items-center"
                >
                  <div className="relative flex w-full flex-col items-center rounded-xl border border-border bg-card/60 p-5 text-center backdrop-blur-sm transition-all duration-300 hover:-translate-y-1 hover:border-brand-cyan/50 hover:shadow-[0_0_30px_-10px_hsl(var(--brand-cyan))]">
                    <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-secondary text-brand-cyan transition-transform duration-300 group-hover:scale-110 group-hover:rotate-3">
                      <Icon className="h-5 w-5" />
                    </div>
                    <span className="mt-3 font-mono text-xs uppercase tracking-wide text-foreground">
                      {node.label}
                    </span>

                    <div className="pointer-events-none absolute left-1/2 top-full z-10 mt-3 w-56 -translate-x-1/2 rounded-lg border border-border bg-popover p-3 text-xs leading-relaxed text-popover-foreground opacity-0 shadow-xl transition-opacity duration-200 group-hover:opacity-100">
                      {node.description}
                    </div>
                  </div>
                </motion.div>

                {!isLast ? (
                  <motion.div
                    animate={{ x: [0, 5, 0], opacity: [0.5, 1, 0.5] }}
                    transition={{
                      duration: 1.6,
                      repeat: Infinity,
                      ease: "easeInOut",
                      delay: i * 0.2,
                    }}
                    className="hidden shrink-0 lg:block"
                  >
                    <ChevronRight className="h-5 w-5 text-brand-cyan/70" />
                  </motion.div>
                ) : null}
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
