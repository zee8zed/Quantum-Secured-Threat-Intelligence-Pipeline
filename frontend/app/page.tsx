import { Background } from "@/components/background";
import { Hero } from "@/components/sections/hero";
import { Problem } from "@/components/sections/problem";
import { HowItWorks } from "@/components/sections/how-it-works";
import { Deliverable } from "@/components/sections/deliverable";
import { WhoItsFor } from "@/components/sections/who-its-for";
import { TechStack } from "@/components/sections/tech-stack";
import { SiteFooter } from "@/components/sections/site-footer";

export default function Home() {
  return (
    <>
      <Background />
      <main className="relative">
        <Hero />
        <Problem />
        <HowItWorks />
        <Deliverable />
        <WhoItsFor />
        <TechStack />
      </main>
      <SiteFooter />
    </>
  );
}
