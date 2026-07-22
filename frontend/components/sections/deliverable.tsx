import { Terminal } from "lucide-react";

import { ScrollReveal } from "@/components/scroll-reveal";
import { SectionHeading } from "@/components/section-heading";
import { StaggerGroup, StaggerItem } from "@/components/stagger";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const STEPS = [
  "Input a raw threat report",
  "Run named-entity recognition",
  "Classify with the quantum kernel",
  "Encrypt with CRYSTALS-Kyber",
  "Output a signed, encrypted JSON brief",
];

export function Deliverable() {
  return (
    <section className="relative px-6 py-28 sm:py-36">
      <div className="mx-auto max-w-5xl">
        <ScrollReveal>
          <SectionHeading
            eyebrow="What you get"
            title="A single CLI, end to end."
          />
        </ScrollReveal>

        <ScrollReveal delay={0.1} className="mt-12">
          <Card className="bg-card/60 backdrop-blur-sm">
            <CardHeader className="flex-row items-center gap-3 space-y-0">
              <Terminal className="h-5 w-5 text-brand-teal transition-transform duration-300 group-hover:scale-110" />
              <CardTitle>threat-intel-pipeline</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground leading-relaxed">
                A command-line pipeline that takes a raw report as input and returns a
                post-quantum encrypted intelligence brief as output.
              </p>
              <StaggerGroup className="mt-6 space-y-3 font-mono text-sm">
                {STEPS.map((step, i) => (
                  <StaggerItem key={step}>
                    <div className="flex items-center gap-3 text-foreground">
                      <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-brand-cyan/30 text-xs text-brand-cyan transition-colors duration-300 group-hover:border-brand-cyan/60">
                        {i + 1}
                      </span>
                      {step}
                    </div>
                  </StaggerItem>
                ))}
              </StaggerGroup>
            </CardContent>
          </Card>
        </ScrollReveal>
      </div>
    </section>
  );
}
