export interface Tech {
  name: string;
  /** Iconify id, e.g. "simple-icons:kubernetes" */
  icon: string;
  /** Official brand colour — used for hover glow + light-theme tint */
  color: string;
}

/** Platform-engineering stack featured across the site. */
export const techStack: Tech[] = [
  { name: "Kubernetes",     icon: "simple-icons:kubernetes",        color: "#326CE5" },
  { name: "Docker",         icon: "simple-icons:docker",            color: "#2496ED" },
  { name: "Terraform",      icon: "simple-icons:terraform",         color: "#7B42BC" },
  { name: "HashiCorp Vault",icon: "simple-icons:vault",             color: "#FFCF25" },
  { name: "Go",             icon: "simple-icons:go",                color: "#00ADD8" },
  { name: "Rust",           icon: "simple-icons:rust",              color: "#E43717" },
  { name: "TypeScript",     icon: "simple-icons:typescript",        color: "#3178C6" },
  { name: "React",          icon: "simple-icons:react",             color: "#61DAFB" },
  { name: "PostgreSQL",     icon: "simple-icons:postgresql",        color: "#4169E1" },
  { name: "Prometheus",     icon: "simple-icons:prometheus",        color: "#E6522C" },
  { name: "Grafana",        icon: "simple-icons:grafana",           color: "#F46800" },
  { name: "AWS",            icon: "simple-icons:amazonwebservices", color: "#FF9900" },
  { name: "GitHub Actions", icon: "simple-icons:githubactions",     color: "#2088FF" },
  { name: "Linux",          icon: "simple-icons:linux",             color: "#F6C915" },
];

/** Lookup by name — used by project cards / CV to attach a brand icon to a tag. */
export const techByName: Record<string, Tech> = Object.fromEntries(
  techStack.map((t) => [t.name.toLowerCase(), t])
);

/** Extra brand icons referenced by name on project cards but not in the hero rail. */
export const extraTech: Tech[] = [
  { name: "Security",       icon: "lucide:shield",         color: "#06D6F0" },
  { name: "WebAssembly",    icon: "simple-icons:webassembly", color: "#654FF0" },
  { name: "Z3",             icon: "lucide:brain",          color: "#7B68EE" },
  { name: "Algorithms",     icon: "lucide:binary",         color: "#E6A52D" },
  { name: "Computer Science", icon: "lucide:cpu",          color: "#E6A52D" },
  { name: "Formal Methods", icon: "lucide:sigma",          color: "#06D6F0" },
];

const allTech: Record<string, Tech> = Object.fromEntries(
  [...techStack, ...extraTech].map((t) => [t.name.toLowerCase(), t])
);

export function lookupTech(name: string): Tech | undefined {
  return allTech[name.toLowerCase()];
}
