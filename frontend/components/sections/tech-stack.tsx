import { ScrollReveal } from "@/components/scroll-reveal";
import { SectionHeading } from "@/components/section-heading";
import { StaggerGroup, StaggerItem } from "@/components/stagger";
import { Badge } from "@/components/ui/badge";
import { TECH_STACK } from "@/lib/constants";

export function TechStack() {
  return (
    <section className="relative px-6 py-28 sm:py-36">
      <div className="mx-auto max-w-5xl">
        <ScrollReveal>
          <SectionHeading eyebrow="Tech stack" title="What's under the hood." />
        </ScrollReveal>

        <StaggerGroup className="mt-10 flex flex-wrap gap-3">
          {TECH_STACK.map((tech) => (
            <StaggerItem key={tech}>
              <Badge variant="outline" className="px-4 py-2 text-sm">
                {tech}
              </Badge>
            </StaggerItem>
          ))}
        </StaggerGroup>
      </div>
    </section>
  );
}
