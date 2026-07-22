import { Building2, Landmark, Radar } from "lucide-react";

import { ScrollReveal } from "@/components/scroll-reveal";
import { SectionHeading } from "@/components/section-heading";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const AUDIENCES = [
  {
    icon: Radar,
    title: "SOC teams & CERT agencies",
    description:
      "Security operations centers and computer emergency response teams triaging high volumes of threat data daily.",
  },
  {
    icon: Building2,
    title: "Threat intel platforms",
    description:
      "Platforms in the mold of Recorded Future or VirusTotal, aggregating and enriching intelligence feeds at scale.",
  },
  {
    icon: Landmark,
    title: "Regulated financial infrastructure",
    description:
      "Institutions operating under SEBI and CERT-In mandates for Indian financial infrastructure security.",
  },
];

export function WhoItsFor() {
  return (
    <section className="relative px-6 py-28 sm:py-36">
      <div className="mx-auto max-w-6xl">
        <ScrollReveal>
          <SectionHeading
            eyebrow="Who it's for"
            title="Built for the teams defending critical infrastructure."
          />
        </ScrollReveal>

        <div className="mt-12 grid gap-6 sm:grid-cols-3">
          {AUDIENCES.map((audience, i) => (
            <ScrollReveal key={audience.title} delay={i * 0.1}>
              <Card className="h-full bg-card/60 backdrop-blur-sm">
                <CardHeader>
                  <audience.icon className="h-6 w-6 text-brand-violet transition-transform duration-300 group-hover:scale-110 group-hover:rotate-6" />
                  <CardTitle className="mt-2 text-base">{audience.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground leading-relaxed">
                    {audience.description}
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
