import { FileWarning, ShieldAlert } from "lucide-react";

import { ScrollReveal } from "@/components/scroll-reveal";
import { SectionHeading } from "@/components/section-heading";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const PROBLEMS = [
  {
    icon: FileWarning,
    title: "Unstructured signal, everywhere",
    description:
      "CVEs, dark web feeds, and MITRE ATT&CK reports arrive as raw, unstructured text — hard to search, correlate, or act on at scale.",
  },
  {
    icon: ShieldAlert,
    title: "Pipelines are themselves a target",
    description:
      "Existing intelligence pipelines are vulnerable to adversarial injection and interception, undermining the very systems meant to defend against attackers.",
  },
];

export function Problem() {
  return (
    <section className="relative px-6 py-28 sm:py-36">
      <div className="mx-auto max-w-5xl">
        <ScrollReveal>
          <SectionHeading
            eyebrow="The problem"
            title="Threat intelligence is noisy, and the pipeline is exposed."
          />
        </ScrollReveal>

        <div className="mt-12 grid gap-6 sm:grid-cols-2">
          {PROBLEMS.map((problem, i) => (
            <ScrollReveal key={problem.title} delay={i * 0.1}>
              <Card className="h-full bg-card/60 backdrop-blur-sm">
                <CardHeader>
                  <problem.icon className="h-6 w-6 text-brand-cyan transition-transform duration-300 group-hover:scale-110 group-hover:-rotate-6" />
                  <CardTitle className="mt-2">{problem.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-muted-foreground leading-relaxed">
                    {problem.description}
                  </p>
                </CardContent>
              </Card>
            </ScrollReveal>
          ))}
        </div>
      </div>
    </section>
  );
}
