import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-3 py-1 text-xs font-mono font-medium transition-all duration-200 hover:scale-105",
  {
    variants: {
      variant: {
        default:
          "border-border bg-secondary text-secondary-foreground hover:border-brand-violet/40",
        outline:
          "border-brand-cyan/30 text-foreground bg-transparent hover:border-brand-cyan/70 hover:shadow-[0_0_16px_-6px_hsl(var(--brand-cyan))]",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge, badgeVariants };
