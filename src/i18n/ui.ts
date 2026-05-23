export const languages = {
  en: 'EN',
  pt: 'PT',
} as const;

export type Lang = keyof typeof languages;

export const ui = {
  en: {
    // Navigation
    'nav.home': 'Home',
    'nav.projects': 'Projects',
    'nav.blog': 'Blog',
    'nav.resume': 'Resume',
    'nav.contact': 'Contact',

    // Home — hero
    'home.greeting': "Hey, I'm",
    'home.eyebrow': 'Philosopher · Platform Engineer · Furry Lion',
    'home.bio':
      "I believe the pursuit of knowledge and wisdom is one of the most noble things a person can do. Platform engineer by day, philosopher at heart — always asking bigger questions, building systems that scale, and inspiring others to live with purpose.",
    'home.cta.projects': 'Explore Projects',
    'home.cta.novatera': 'Novatera.org ✦',
    'home.cta.github': 'GitHub',
    'home.cta.twitter': 'Twitter',
    'home.status': 'Available for new projects',
    'home.facts.location': 'Brazil',
    'home.facts.languages': 'EN · PT',
    'home.facts.focus': 'Platform & Security',

    // Home — tech stack
    'home.tech.eyebrow': 'Tech I build with',
    'home.tech.title': 'A platform-engineering toolkit',
    'home.tech.sub': 'The tools I reach for to build, secure, and scale systems.',

    // Home — Novatera
    'home.novatera.label': 'Current Initiative',
    'home.novatera.desc':
      "A platform to connect people and inspire the practice of good. Where kindness, collaboration, and purpose meet technology — to make a real difference in the world.",
    'home.novatera.cta': 'Visit Novatera →',

    // Home — pillars
    'home.pillar1.title': 'Philosophy',
    'home.pillar1.desc':
      'Exploring the nature of reality, ethics, and meaning. Philosophy gives us tools to live a more intentional, purposeful life.',
    'home.pillar2.title': 'Platform Engineering',
    'home.pillar2.desc':
      'Kubernetes, observability, infrastructure as code — building environments where applications thrive and teams move with confidence.',
    'home.pillar3.title': 'Giving Back',
    'home.pillar3.desc':
      "Code, advice, or just a listening ear — I'm always open to helping. You don't have to face your challenges alone.",

    // Home — blog section
    'home.blog.title': 'Latest from the blog',
    'home.blog.all': 'All posts →',

    // Home — connect CTA
    'home.help.title': 'Need help or want to connect?',
    'home.help.desc':
      "Struggling with a problem, curious about philosophy, or just want to talk? Reach out — you don't have to face challenges alone.",
    'home.help.cta': 'Send a message',
    'home.help.twitter': 'Twitter DM',

    // Projects
    'projects.eyebrow': 'What I build',
    'projects.title': 'Projects',
    'projects.subtitle':
      'Platforms to connect people, tools to secure systems, experiments born from curiosity. Everything here is built with care.',
    'projects.novatera.active': 'Active',
    'projects.novatera.philanthropy': 'Philanthropy',
    'projects.novatera.desc':
      "A platform built to connect people and inspire the practice of good. Where technology meets purpose — helping individuals find meaningful ways to contribute, collaborate, and make a real impact. Born from the belief that good people, when connected, can do extraordinary things.",
    'projects.novatera.cta': 'Visit Novatera →',
    'projects.oss.title': 'Open Source & Tools',
    'projects.vault.title': 'Vault Policy Escalation Checker',
    'projects.vault.desc':
      "An interactive tool to analyze and validate HashiCorp Vault escalation policies — helping security teams catch misconfigurations before they become incidents.",
    'projects.heap.title': 'Heap Sort Deep Dive',
    'projects.heap.desc':
      'Exploring the heap sort algorithm — theoretical underpinnings, performance characteristics, and practical intuition with worked examples.',
    'projects.z3.title': 'Z3 SMT Solver in the Browser',
    'projects.z3.desc':
      'This site embeds the Z3 Theorem Prover via WebAssembly — enabling interactive logic and constraint-solving experiments directly in the browser.',
    'projects.more': 'More on the way',
    'projects.more.sub': 'Always building something new',
    'projects.cta.title': 'Want to collaborate?',
    'projects.cta.desc':
      "Open to interesting projects, conversations, or lending a hand. Let's build something meaningful together.",
    'projects.cta.btn': 'Get in touch',
    'projects.read': 'Read the post →',

    // Blog
    'blog.title': 'Blog',
    'blog.empty': 'No blog posts yet. Check back later!',
    'blog.recent': 'Recent posts',
    'blog.older': 'Older Posts',

    // CV / Resume
    'cv.title': 'Resume',
    'cv.eyebrow': 'Who I am',
    'cv.profile': 'Profile',
    'cv.profile.body':
      "Platform engineer and lifelong philosopher. I build infrastructure that scales, secure systems people can trust, and tools that make hard problems approachable. I care about doing good work — and using it to help others live with purpose.",
    'cv.education': 'Education',
    'cv.experience': 'Experience',
    'cv.certifications': 'Certifications',
    'cv.skills': 'Skills',
    'cv.skills.sub': 'The technologies I work with day to day.',
  },

  pt: {
    // Navigation
    'nav.home': 'Início',
    'nav.projects': 'Projetos',
    'nav.blog': 'Blog',
    'nav.resume': 'Currículo',
    'nav.contact': 'Contato',

    // Home — hero
    'home.greeting': 'Olá, sou',
    'home.eyebrow': 'Filósofo · Engenheiro de Plataforma · Leão Furry',
    'home.bio':
      'Acredito que a busca pelo conhecimento e pela sabedoria é uma das coisas mais nobres que uma pessoa pode fazer. Engenheiro de plataforma durante o dia, filósofo de coração — sempre fazendo perguntas maiores, construindo sistemas que escalam e inspirando outros a viver com propósito.',
    'home.cta.projects': 'Ver Projetos',
    'home.cta.novatera': 'Novatera.org ✦',
    'home.cta.github': 'GitHub',
    'home.cta.twitter': 'Twitter',
    'home.status': 'Disponível para novos projetos',
    'home.facts.location': 'Brasil',
    'home.facts.languages': 'EN · PT',
    'home.facts.focus': 'Plataforma & Segurança',

    // Home — tech stack
    'home.tech.eyebrow': 'Tecnologias que uso',
    'home.tech.title': 'Um kit de engenharia de plataforma',
    'home.tech.sub': 'As ferramentas que uso para construir, proteger e escalar sistemas.',

    // Home — Novatera
    'home.novatera.label': 'Iniciativa Atual',
    'home.novatera.desc':
      'Uma plataforma para conectar pessoas e inspirar a prática do bem. Onde bondade, colaboração e propósito encontram a tecnologia — para fazer uma diferença real no mundo.',
    'home.novatera.cta': 'Visitar Novatera →',

    // Home — pillars
    'home.pillar1.title': 'Filosofia',
    'home.pillar1.desc':
      'Explorando a natureza da realidade, ética e significado. A filosofia nos dá ferramentas para viver uma vida mais intencional e com propósito.',
    'home.pillar2.title': 'Engenharia de Plataforma',
    'home.pillar2.desc':
      'Kubernetes, observabilidade, infraestrutura como código — construindo ambientes onde aplicações prosperam e equipes trabalham com confiança.',
    'home.pillar3.title': 'Retribuir',
    'home.pillar3.desc':
      'Código, conselho ou apenas um ouvido — estou sempre aberto a ajudar. Você não precisa enfrentar seus desafios sozinho.',

    // Home — blog section
    'home.blog.title': 'Últimas do blog',
    'home.blog.all': 'Todos os posts →',

    // Home — connect CTA
    'home.help.title': 'Precisa de ajuda ou quer se conectar?',
    'home.help.desc':
      'Com dificuldades, curioso sobre filosofia ou apenas quer conversar? Entre em contato — você não precisa enfrentar desafios sozinho.',
    'home.help.cta': 'Enviar mensagem',
    'home.help.twitter': 'DM no Twitter',

    // Projects
    'projects.eyebrow': 'O que construo',
    'projects.title': 'Projetos',
    'projects.subtitle':
      'Plataformas para conectar pessoas, ferramentas para proteger sistemas, experimentos nascidos da curiosidade. Tudo aqui é construído com cuidado.',
    'projects.novatera.active': 'Ativo',
    'projects.novatera.philanthropy': 'Filantropia',
    'projects.novatera.desc':
      'Uma plataforma construída para conectar pessoas e inspirar a prática do bem. Onde a tecnologia encontra o propósito — ajudando indivíduos a encontrar formas significativas de contribuir, colaborar e causar um impacto real. Nascida da crença de que pessoas boas, quando conectadas, podem fazer coisas extraordinárias.',
    'projects.novatera.cta': 'Visitar Novatera →',
    'projects.oss.title': 'Open Source & Ferramentas',
    'projects.vault.title': 'Verificador de Políticas de Escalação do Vault',
    'projects.vault.desc':
      'Uma ferramenta interativa para analisar e validar políticas de escalação do HashiCorp Vault — ajudando equipes de segurança a identificar configurações incorretas antes que se tornem incidentes.',
    'projects.heap.title': 'Mergulho Profundo no Heap Sort',
    'projects.heap.desc':
      'Explorando o algoritmo heap sort — fundamentos teóricos, características de desempenho e intuição prática com exemplos detalhados.',
    'projects.z3.title': 'Solucionador SMT Z3 no Navegador',
    'projects.z3.desc':
      'Este site incorpora o Provador de Teoremas Z3 via WebAssembly — permitindo experimentos interativos de lógica e resolução de restrições diretamente no navegador.',
    'projects.more': 'Mais por vir',
    'projects.more.sub': 'Sempre construindo algo novo',
    'projects.cta.title': 'Quer colaborar?',
    'projects.cta.desc':
      "Aberto a projetos interessantes, conversas ou a dar uma mão. Vamos construir algo significativo juntos.",
    'projects.cta.btn': 'Entre em contato',
    'projects.read': 'Ler o post →',

    // Blog
    'blog.title': 'Blog',
    'blog.empty': 'Nenhum post ainda. Volte mais tarde!',
    'blog.recent': 'Posts recentes',
    'blog.older': 'Posts mais antigos',

    // CV / Resume
    'cv.title': 'Currículo',
    'cv.eyebrow': 'Quem eu sou',
    'cv.profile': 'Perfil',
    'cv.profile.body':
      'Engenheiro de plataforma e filósofo por vocação. Construo infraestrutura que escala, sistemas seguros nos quais as pessoas podem confiar e ferramentas que tornam problemas difíceis acessíveis. Me importo em fazer um bom trabalho — e usá-lo para ajudar os outros a viver com propósito.',
    'cv.education': 'Educação',
    'cv.experience': 'Experiência',
    'cv.certifications': 'Certificações',
    'cv.skills': 'Habilidades',
    'cv.skills.sub': 'As tecnologias com que trabalho no dia a dia.',
  },
} as const;

export type UiKey = keyof typeof ui['en'];
