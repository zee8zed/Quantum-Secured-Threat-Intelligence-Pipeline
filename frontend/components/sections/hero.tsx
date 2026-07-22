"use client";

import { motion } from "framer-motion";
import { ArrowRight, ExternalLink } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { StaggerGroup, StaggerItem } from "@/components/stagger";
import { HERO_TAGS, REPO_URL } from "@/lib/constants";
import { startPipeline } from "@/lib/actions";

export function Hero() {
  return (
    <section className="relative flex min-h-[92vh] flex-col items-center justify-center px-6 pt-24 text-center">
      <StaggerGroup viewport={false} className="flex flex-wrap items-center justify-center gap-2">
        {HERO_TAGS.map((tag) => (
          <StaggerItem key={tag}>
            <Badge variant="outline">{tag}</Badge>
          </StaggerItem>
        ))}
      </StaggerGroup>

      <motion.h1
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.1 }}
        className="mt-8 max-w-4xl text-balance text-4xl font-semibold tracking-tight sm:text-6xl"
      >
        Quantum-secured threat intelligence,{" "}
        <span className="text-gradient-brand">end to end.</span>
      </motion.h1>

      <motion.p
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.2 }}
        className="mt-6 max-w-2xl text-balance text-lg text-muted-foreground"
      >
        Raw threat reports go in; NER extraction, quantum-kernel classification, and
        post-quantum encrypted briefs come out.
      </motion.p>

      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.3 }}
        className="mt-10 flex flex-wrap items-center justify-center gap-4"
      >
        <Button size="lg" onClick={() => startPipeline()}>
          Start the pipeline
          <ArrowRight className="ml-2 h-4 w-4 transition-transform duration-300 group-hover:translate-x-1" />
        </Button>
        <Button asChild size="lg" variant="outline">
          <a href={REPO_URL} target="_blank" rel="noopener noreferrer">
            <ExternalLink className="mr-2 h-4 w-4 transition-transform duration-300 group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
            View on GitHub
          </a>
        </Button>
      </motion.div>
    </section>
  );
}
