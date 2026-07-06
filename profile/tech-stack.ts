/**
 * Full technology inventory — source of truth for the blog redesign.
 *
 * Extracted from the GitHub "About Me" profile. Each entry carries:
 *  - `icon`   Iconify id (simple-icons / devicon) for `astro-icon`.
 *  - `color`  Official brand colour (hover glow + light-theme tint).
 *  - `source` Original icon URL from the GitHub profile (fallback / provenance).
 *
 * `icon` falls back to `source` when no clean Iconify id exists (grpc, spock,
 * saltstack) — render those via <img src={source}>.
 */

export type TechCategory =
  | "Frameworks & Tools"
  | "Languages"
  | "DevOps"
  | "Databases"
  | "Cloud Providers";

export interface Tech {
  name: string;
  /** Iconify id, e.g. "simple-icons:kubernetes". Empty when only `source` works. */
  icon: string;
  /** Official brand colour. */
  color: string;
  category: TechCategory;
  /** Original icon URL from the GitHub profile. */
  source: string;
}

export const tech: Tech[] = [
  // ── Frameworks & Tools ──────────────────────────────────────────────
  { name: "Spring",        icon: "simple-icons:spring",        color: "#6DB33F", category: "Frameworks & Tools", source: "https://www.vectorlogo.zone/logos/springio/springio-icon.svg" },
  { name: "Apache Kafka",  icon: "simple-icons:apachekafka",   color: "#231F20", category: "Frameworks & Tools", source: "https://www.vectorlogo.zone/logos/apache_kafka/apache_kafka-icon.svg" },
  { name: "Angular",       icon: "simple-icons:angular",       color: "#DD0031", category: "Frameworks & Tools", source: "https://angular.io/assets/images/logos/angular/angular.svg" },
  { name: "GraphQL",       icon: "simple-icons:graphql",       color: "#E10098", category: "Frameworks & Tools", source: "https://www.vectorlogo.zone/logos/graphql/graphql-icon.svg" },
  { name: "Tailwind CSS",  icon: "simple-icons:tailwindcss",   color: "#06B6D4", category: "Frameworks & Tools", source: "https://github.com/devicons/devicon/raw/master/icons/tailwindcss/tailwindcss-original.svg" },
  { name: "React",         icon: "simple-icons:react",         color: "#61DAFB", category: "Frameworks & Tools", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/react/react-original-wordmark.svg" },
  { name: "Redux",         icon: "simple-icons:redux",         color: "#764ABC", category: "Frameworks & Tools", source: "https://github.com/devicons/devicon/raw/master/icons/redux/redux-original.svg" },
  { name: "Jest",          icon: "simple-icons:jest",          color: "#C21325", category: "Frameworks & Tools", source: "https://www.vectorlogo.zone/logos/jestjsio/jestjsio-icon.svg" },
  { name: "NestJS",        icon: "simple-icons:nestjs",        color: "#E0234E", category: "Frameworks & Tools", source: "https://github.com/devicons/devicon/raw/master/icons/nestjs/nestjs-original.svg" },
  { name: "Node.js",       icon: "simple-icons:nodedotjs",     color: "#5FA04E", category: "Frameworks & Tools", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/nodejs/nodejs-original-wordmark.svg" },
  { name: "GitLab",        icon: "simple-icons:gitlab",        color: "#FC6D26", category: "Frameworks & Tools", source: "https://github.com/devicons/devicon/raw/master/icons/gitlab/gitlab-original-wordmark.svg" },
  { name: "PyTorch",       icon: "simple-icons:pytorch",       color: "#EE4C2C", category: "Frameworks & Tools", source: "https://www.vectorlogo.zone/logos/pytorch/pytorch-icon.svg" },
  { name: "Gradle",        icon: "simple-icons:gradle",        color: "#02303A", category: "Frameworks & Tools", source: "https://github.com/devicons/devicon/raw/master/icons/gradle/gradle-original-wordmark.svg" },
  { name: "OpenTelemetry", icon: "simple-icons:opentelemetry", color: "#000000", category: "Frameworks & Tools", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/opentelemetry/opentelemetry-original-wordmark.svg" },
  { name: "Gatling",       icon: "simple-icons:gatling",       color: "#FF9E2A", category: "Frameworks & Tools", source: "https://github.com/devicons/devicon/raw/master/icons/gatling/gatling-original.svg" },
  { name: "gRPC",          icon: "",                           color: "#2D9CDB", category: "Frameworks & Tools", source: "https://github.com/devicons/devicon/raw/master/icons/grpc/grpc-original.svg" },
  { name: "Spock",         icon: "",                           color: "#1A1A1A", category: "Frameworks & Tools", source: "https://avatars.githubusercontent.com/u/297723?s=48&v=4" },
  { name: "Cucumber",      icon: "simple-icons:cucumber",      color: "#23D96C", category: "Frameworks & Tools", source: "https://cucumber.io/cucumber/media/images/logos/icons/cucumber-open-icon.svg" },
  { name: "Cypress",       icon: "simple-icons:cypress",       color: "#69D3A7", category: "Frameworks & Tools", source: "https://static-00.iconduck.com/assets.00/cypress-icon-512x512-zi8589rq.png" },
  { name: "SonarQube",     icon: "simple-icons:sonarqube",     color: "#4E9BCD", category: "Frameworks & Tools", source: "https://github.com/devicons/devicon/raw/master/icons/sonarqube/sonarqube-original-wordmark.svg" },
  { name: "Jira",          icon: "simple-icons:jira",          color: "#0052CC", category: "Frameworks & Tools", source: "https://github.com/devicons/devicon/raw/master/icons/jira/jira-original-wordmark.svg" },
  { name: "LaTeX",         icon: "simple-icons:latex",         color: "#008080", category: "Frameworks & Tools", source: "https://github.com/devicons/devicon/raw/master/icons/latex/latex-original.svg" },

  // ── Languages ───────────────────────────────────────────────────────
  { name: "Java",          icon: "",                           color: "#ED8B00", category: "Languages", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/java/java-original.svg" },
  { name: "Kotlin",        icon: "simple-icons:kotlin",        color: "#7F52FF", category: "Languages", source: "https://github.com/devicons/devicon/raw/master/icons/kotlin/kotlin-original.svg" },
  { name: "Groovy",        icon: "simple-icons:apachegroovy",  color: "#4298B8", category: "Languages", source: "https://github.com/devicons/devicon/raw/master/icons/groovy/groovy-original.svg" },
  { name: "Scala",         icon: "simple-icons:scala",         color: "#DC322F", category: "Languages", source: "https://github.com/devicons/devicon/raw/master/icons/scala/scala-original-wordmark.svg" },
  { name: "Go",            icon: "simple-icons:go",            color: "#00ADD8", category: "Languages", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/go/go-original.svg" },
  { name: "Rust",          icon: "simple-icons:rust",          color: "#E43717", category: "Languages", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/rust/rust-original.svg" },
  { name: "TypeScript",    icon: "simple-icons:typescript",    color: "#3178C6", category: "Languages", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/typescript/typescript-original.svg" },
  { name: "JavaScript",    icon: "simple-icons:javascript",    color: "#F7DF1E", category: "Languages", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/javascript/javascript-original.svg" },
  { name: "Python",        icon: "simple-icons:python",        color: "#3776AB", category: "Languages", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/python/python-original.svg" },
  { name: "C",             icon: "simple-icons:c",             color: "#A8B9CC", category: "Languages", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/c/c-original.svg" },
  { name: "Bash",          icon: "simple-icons:gnubash",       color: "#4EAA25", category: "Languages", source: "https://www.vectorlogo.zone/logos/gnu_bash/gnu_bash-icon.svg" },

  // ── DevOps ──────────────────────────────────────────────────────────
  { name: "Kubernetes",    icon: "simple-icons:kubernetes",    color: "#326CE5", category: "DevOps", source: "https://www.vectorlogo.zone/logos/kubernetes/kubernetes-icon.svg" },
  { name: "Linux",         icon: "simple-icons:linux",         color: "#FCC624", category: "DevOps", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/linux/linux-original.svg" },
  { name: "Packer",        icon: "simple-icons:packer",        color: "#02A8EF", category: "DevOps", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/packer/packer-plain-wordmark.svg" },
  { name: "Jenkins",       icon: "simple-icons:jenkins",       color: "#D24939", category: "DevOps", source: "https://www.vectorlogo.zone/logos/jenkins/jenkins-icon.svg" },
  { name: "Docker",        icon: "simple-icons:docker",        color: "#2496ED", category: "DevOps", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/docker/docker-original-wordmark.svg" },
  { name: "Vagrant",       icon: "simple-icons:vagrant",       color: "#1868F2", category: "DevOps", source: "https://www.vectorlogo.zone/logos/vagrantup/vagrantup-icon.svg" },
  { name: "Prometheus",    icon: "simple-icons:prometheus",    color: "#E6522C", category: "DevOps", source: "https://github.com/devicons/devicon/raw/master/icons/prometheus/prometheus-original.svg" },
  { name: "Nginx",         icon: "simple-icons:nginx",         color: "#009639", category: "DevOps", source: "https://github.com/devicons/devicon/raw/master/icons/nginx/nginx-original.svg" },
  { name: "Grafana",       icon: "simple-icons:grafana",       color: "#F46800", category: "DevOps", source: "https://github.com/devicons/devicon/raw/master/icons/grafana/grafana-original-wordmark.svg" },
  { name: "HashiCorp Vault", icon: "simple-icons:vault",       color: "#FFCF25", category: "DevOps", source: "https://github.com/devicons/devicon/raw/master/icons/vault/vault-original-wordmark.svg" },
  { name: "Consul",        icon: "simple-icons:consul",        color: "#F24C53", category: "DevOps", source: "https://github.com/devicons/devicon/raw/master/icons/consul/consul-original.svg" },
  { name: "Terraform",     icon: "simple-icons:terraform",     color: "#844FBA", category: "DevOps", source: "https://github.com/devicons/devicon/raw/master/icons/terraform/terraform-original.svg" },
  { name: "Ansible",       icon: "simple-icons:ansible",       color: "#EE0000", category: "DevOps", source: "https://github.com/devicons/devicon/raw/master/icons/ansible/ansible-original.svg" },
  { name: "SaltStack",     icon: "",                           color: "#00E3AC", category: "DevOps", source: "https://www.vectorlogo.zone/logos/saltstack/saltstack-ar21.svg" },

  // ── Databases ───────────────────────────────────────────────────────
  { name: "MongoDB",       icon: "simple-icons:mongodb",       color: "#47A248", category: "Databases", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/mongodb/mongodb-original-wordmark.svg" },
  { name: "MySQL",         icon: "simple-icons:mysql",         color: "#4479A1", category: "Databases", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/mysql/mysql-original-wordmark.svg" },
  { name: "Oracle",        icon: "simple-icons:oracle",        color: "#F80000", category: "Databases", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/oracle/oracle-original.svg" },
  { name: "PostgreSQL",    icon: "simple-icons:postgresql",    color: "#4169E1", category: "Databases", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/postgresql/postgresql-original-wordmark.svg" },
  { name: "Redis",         icon: "simple-icons:redis",         color: "#FF4438", category: "Databases", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/redis/redis-original-wordmark.svg" },

  // ── Cloud Providers ─────────────────────────────────────────────────
  { name: "AWS",           icon: "simple-icons:amazonwebservices", color: "#FF9900", category: "Cloud Providers", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/amazonwebservices/amazonwebservices-original-wordmark.svg" },
  { name: "OpenStack",     icon: "simple-icons:openstack",     color: "#ED1944", category: "Cloud Providers", source: "https://raw.githubusercontent.com/devicons/devicon/master/icons/openstack/openstack-original-wordmark.svg" },
];

export const categories: TechCategory[] = [
  "Languages",
  "Frameworks & Tools",
  "DevOps",
  "Databases",
  "Cloud Providers",
];

export const techByCategory: Record<TechCategory, Tech[]> = categories.reduce(
  (acc, c) => ({ ...acc, [c]: tech.filter((t) => t.category === c) }),
  {} as Record<TechCategory, Tech[]>,
);

export const techByName: Record<string, Tech> = Object.fromEntries(
  tech.map((t) => [t.name.toLowerCase(), t]),
);
