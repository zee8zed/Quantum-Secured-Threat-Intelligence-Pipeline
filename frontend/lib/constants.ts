// TODO: backend team / project lead — replace with the real GitHub repo URL once created.
export const REPO_URL = "#";

// TODO: replace with real team member names before deploying.
export const TEAM_CREDITS = [
  "TODO: Team Member One",
  "TODO: Team Member Two",
  "TODO: Team Member Three",
];

// TODO: confirm final institution/course tag for the footer credit line.
export const BUILT_FOR_TAG = "TODO: built for <institution / course name>";

export const HERO_TAGS = ["Quantum", "NLP", "ML", "Cybersecurity"] as const;

export const TECH_STACK = [
  "BioBERT",
  "spaCy",
  "Qiskit",
  "PennyLane",
  "CRYSTALS-Kyber",
  "MITRE ATT&CK",
  "scikit-learn",
  "Python",
] as const;

export const PIPELINE_FLOW = [
  {
    label: "Raw Report",
    description: "Unstructured CVE, dark web, or MITRE ATT&CK source text.",
  },
  {
    label: "NER (BioBERT)",
    description: "Extracts entities: actors, malware, CVEs, indicators of compromise.",
  },
  {
    label: "Quantum Kernel Classifier",
    description: "Classifies threat severity and category via a quantum-enhanced kernel.",
  },
  {
    label: "CRYSTALS-Kyber Encryption",
    description: "Post-quantum encryption secures the classified brief before transit.",
  },
  {
    label: "Encrypted JSON Brief",
    description: "A structured, encrypted intelligence brief ready for downstream systems.",
  },
] as const;
