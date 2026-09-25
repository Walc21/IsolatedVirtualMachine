# IsolateVM

## Estado da implementação

O código atual está na versão **0.3.10**. O aplicativo GTK administra VMs Ubuntu cloud por meio do Incus local, com manifestos revisáveis e autorização explícita para rede, mounts, cópias, secrets e dispositivos. Também inclui snapshots de proteção, ciclos de vida configuráveis, persistência separada de `/workspace`, discos de dados Incus com propriedade validada e cópia independente ao clonar, comparação de alterações antes de aplicá-las, aumento revisável do disco raiz para VMs paradas, exportação versionada de manifestos e templates, consulta das versões instaladas dos pacotes selecionados, ferramentas de coding com IA opcionais no guest e terminal VTE integrado.

O terminal integrado usa VTE GTK4 para abrir `incus exec` em um PTY, sem expor os comandos digitados ao shell do host. A sessão entra como root dentro do guest. O terminal externo permanece disponível como alternativa.

Há validações de integração registradas com VMs descartáveis no Incus, incluindo cópias pontuais, snapshots e restauração, comparação de recursos, ciclo de vida, clone e volume persistente `/workspace`, além da política de egress e entrega de secrets. São resultados de um host e configuração específicos; consulte [o registro de validação](docs/LIVE-VALIDATION.md) antes de extrapolá-los para outro ambiente.

Ainda não foram validados o boot das novas opções de software DevOps, o modo LAN-only, passthrough físico de USB, GPU ou PCI genérico, nem login visual interativo em um desktop guest. O projeto atende guests Ubuntu cloud e não configura diretamente portas seriais virtuais, pois o Incus limita `unix-char`/`unix-hotplug` a containers; adaptadores seriais USB podem ser anexados pela opção USB. O registro de validação descreve esses limites e quais fluxos foram testados apenas com mocks.

O wizard separa **Copiar uma vez** de **Compartilhar permanentemente**. A cópia explícita entra no disco da VM após o primeiro start, sem mount e sem sincronização posterior; o compartilhamento usa um mount persistente com permissão RO ou RW. O preview informa destinos e tamanho antes da criação. Consulte [o contrato do manifesto](docs/MANIFEST.md).

Em **Configurações**, a opção de snapshot de proteção pode ser ativada antes de mudanças em mounts, dispositivos, rede, CPU/RAM, aumento de disco e restauração de snapshots. Ela vem desligada, registra a origem automática no Histórico e impede a mudança se o snapshot falhar. Snapshots ficam no mesmo pool Incus da VM e não substituem um backup externo.

Manifestos e templates podem ser exportados em versões numeradas (`-v0001`, `-v0002`, …). A gravação recusa arquivos existentes. Templates excluem mounts e fontes de cópia pessoais; manifestos exportados preservam os caminhos declarados e devem ser tratados como dados privados.

O wizard oferece ciclos de vida **persistente**, **excluir manualmente**, **excluir ao fechar**, **restaurar snapshot inicial ao fechar** e **persistir somente `/workspace`**. Os dois modos de restauração salvam `isolatevm-initial`; ao fechar, a VM é parada se necessário e o snapshot restaurado. No modo persistir `/workspace`, o disco do sistema retorna ao estado inicial e o volume customizado separado conserva os dados. O clone desse modo recebe uma cópia independente do volume. A exclusão manual remove a VM e seu volume após conferir os marcadores de propriedade. Snapshots e backup completo da VM não incluem esse volume: use **Exportar /workspace**, que grava uma exportação separada com modo `0600`. O snapshot inicial protegido não pode ser renomeado ou excluído pela interface. **Fechar sem aplicar** mantém as VMs como estão. Encerramento forçado do aplicativo não executa ações de fechamento.

Ao alterar CPU/RAM, mounts, rede, dispositivos ou aumentar o disco de uma VM existente, a interface consulta a configuração efetiva do Incus e mostra um diff de antes/depois com **Cancelar** e **Aplicar alterações**. Antes de aplicar, compara novamente o estado relevante e pede nova revisão se ele mudou. Snapshots de proteção ativados são criados depois dessa comparação e antes da alteração.

**IsolateVM** é um aplicativo desktop GTK local para criar e administrar máquinas virtuais Incus no Ubuntu. Ele oferece manifestos revisáveis, recursos e dispositivos explícitos, um perfil offline por padrão e uma política opcional de proxy de saída por VM.

> IsolateVM é uma interface para operadores, não uma fronteira de segurança contra um administrador Incus. Revise as permissões Incus concedidas à conta que executa o aplicativo. A interface gráfica deve rodar como usuário comum, nunca como root.

## O que oferece

- Detecta Ubuntu, arquitetura, virtualização, KVM, QEMU, Incus e recursos disponíveis sem alterar a configuração do host.
- Cria VMs Ubuntu cloud por um assistente GTK. CPU, memória, pool, disco, rede, mounts, software, desktop e manifesto são revisados antes da criação. O catálogo inclui SDKs .NET compatíveis com a release Ubuntu, uv e Poetry via pipx, Rustup `stable`, toolchains pnpm/Yarn/Bun, ferramentas de coding com IA (Codex, Claude Code, Aider e OpenCode) e opções DevOps para kubectl, Helm e Terraform. Os instaladores opcionais rodam no guest; opções novas ainda precisam de validação em boot real.
- Inicia, para, reinicia, clona, cria e restaura snapshots e remove VMs criadas pelo aplicativo. Ações destrutivas exigem confirmação explícita.
- Exibe a configuração Incus efetiva e métricas sob demanda de CPU, memória, disco, rede e uptime quando o Incus as fornece.
- Em **Permissões efetivas**, consulta por gerenciador as versões instaladas dos pacotes selecionados no manifesto salvo, sinaliza ausências e versões divergentes e distingue falha de consulta de pacote ausente. Exige VM em execução e agente Incus ativo; o guest fornece os dados e pode alterá-los.
- Importa e exporta manifestos YAML versionados, instala software no guest pelo cloud-init, exporta backup completo da VM e exporta separadamente `/workspace` ou cada disco de dados gerenciado, em arquivos novos com modo `0600`.
- Instala npm global sob o usuário `ubuntu` da VM, sem gravar pacotes npm em diretórios root. Ferramentas de coding com IA não recebem tokens ou arquivos de autenticação do host; autentique na VM ou referencie um secret explicitamente.
- Inclui backend mock (`ISOLATEVM_MOCK=1`) para explorar a interface sem conectar ao Incus nem criar VMs.
- Oferece desktops opcionais Ubuntu GNOME, KDE e XFCE, terminal externo e console VGA Incus por cliente SPICE.
- Abre terminal integrado com VTE GTK4 sobre um PTY `incus exec`; identifica que o shell inicia como root dentro do guest e permite encerrar a conexão sem enviar texto de interface a um shell local.
- Descobre USB, GPUs e outras funções PCI em modo somente leitura. USB, GPU e PCI exigem ação explícita; USB usa serial único ou endereço atual do dispositivo. GPU e PCI bruto exigem VM parada e autorização do projeto Incus. O seletor PCI exclui funções de rede, GPU e bridge, incluindo funções irmãs da mesma placa. O passthrough PCI pode interromper o host e requer revisão de IOMMU e grupos; nenhum dispositivo físico foi anexado nesta validação.
- Incus oferece dispositivos `unix-char` e `unix-hotplug` para containers, não VMs. Adaptadores seriais USB podem ser entregues como USB; uma porta serial virtual da VM não é configurada pelo IsolateVM.
- O disco raiz pode ser aumentado com a VM parada e uma prévia revisável. Redução não é oferecida e o crescimento não redimensiona o sistema de arquivos dentro do guest.
- Para VMs, o editor ajusta a quantidade de vCPUs e oferece pinning opcional por IDs de CPUs lógicas/threads anunciados pelo Incus. A seleção deve ter a mesma quantidade de IDs e vCPUs, é revalidada contra CPUs online imediatamente antes da mudança e exige VM parada; não reserva CPUs exclusivamente. Prioridade e limite por allowance são opções de containers no Incus.

## Rede e perfis de isolamento

O manifesto padrão pede **rede offline**, nenhum mount do host e nenhum dispositivo repassado. O perfil `maximum-isolation` exige rede offline e zero mounts. A política `restricted-development` usa um proxy dedicado por VM e regras de firewall geradas para aceitar somente combinações declaradas de domínio/IP/CIDR canônicos e portas TCP. O modo `lan-only` reusa esse caminho, mas aceita somente CIDRs IPv4 privados explícitos, com portas TCP. O helper revalida o modo e as regras separadamente via Polkit, enquanto o processo GTK continua sem privilégios. Para restaurar o filtro antes do daemon Incus no boot, o helper instala um serviço systemd e um drop-in protegido; se a restauração falhar, o daemon não inicia. A remoção da última política limpa essa dependência, e a desinstalação do pacote é bloqueada enquanto existirem políticas restritas.

O modo de rede `normal` é uma rede comum para a VM e não filtra domínios. Uma bridge customizada pode ser selecionada se já existir como bridge gerenciada do Incus; o IsolateVM não configura redes globais nem promete que uma LAN particular seja alcançável pelo host. No modo `lan-only`, somente os CIDRs RFC1918 escolhidos e suas portas TCP são encaminhados pelo proxy; DNS e conexões diretas do guest permanecem bloqueados. A política de proxy restrito controla a saída de rede do guest; não audita os dados ou programas dentro dele, outros caminhos até o host nem políticas externas ao Incus. Inspecione a configuração efetiva antes de confiar em qualquer perfil. O Incus é a fonte de verdade do estado das VMs, portanto manifestos locais podem divergir depois de alterações externas.

Em `restricted`, regras `domain` verificam domínio, porta e endereço resolvido pelo Squid; respostas IPv4 especiais/não globais são negadas e qualquer resposta IPv6 faz a regra falhar. Assim, domínios permitidos não liberam implicitamente loopback, link-local, RFC1918, CGNAT ou multicast. Isso não se aplica a `ip`/`cidr`: esses tipos mantêm autorização explícita para os endereços declarados, inclusive privados. A validação desta revisão executou Squid real com respostas públicas, privadas, mistas e alteradas para loopback, mas não fez uma nova VM Incus por indisponibilidade do daemon neste host.

Variáveis comuns de ambiente ficam visíveis ao guest e podem ser armazenadas na configuração Incus; use-as somente para dados públicos. Secrets são guardados no Secret Service da sessão do usuário, e o manifesto registra apenas seus nomes. Depois da criação, uma ação explícita envia os valores pela entrada padrão do agente Incus para arquivos no tmpfs `/run` do guest; eles não são incorporados ao manifesto, cloud-init ou configuração Incus. Use `isolatevm-run --secret NOME -- comando` no guest para iniciar um processo com a variável definida. Processos executados como o usuário `ubuntu` podem ler os secrets entregues; limpeza ou desligamento remove os arquivos, mas não apaga cópias já carregadas em processos. O perfil `maximum-isolation` bloqueia secrets. Pastas do host nunca são montadas automaticamente. Selecione somente caminhos que pretende expor e prefira mounts somente para leitura quando possível.

Consulte [SECURITY.md](SECURITY.md), [ARCHITECTURE.md](ARCHITECTURE.md), o [schema do manifesto](docs/MANIFEST.md) e o resumo de [validação de integração](docs/LIVE-VALIDATION.md) para detalhes e limitações.

## Requisitos

- Ubuntu 24.04 ou mais recente com Python 3.11, PyGObject, GTK 4, libadwaita, VTE GTK4 (`gir1.2-vte-3.91`), PyYAML e Secret Service (`python3-secretstorage` mais um provedor de sessão, como GNOME Keyring).
- Cliente e daemon Incus configurados localmente para operações reais com VMs. Incus é opcional no modo mock e para explorar a interface.
- Um pool de armazenamento Incus e, para modos com rede, uma bridge gerenciada adequada. Imagens, pacotes do guest e cloud-init dependem dos remotes e repositórios configurados.
- A política de egress restrito requer o helper Polkit separado, Squid, nftables e Polkit.
- Para console VGA, instale `virt-viewer` ou outro cliente SPICE compatível.

O runner de CI usa Ubuntu 24.04. As validações de integração descritas neste repositório incluem VMs com imagens Ubuntu 24.04; versões posteriores podem funcionar, mas não há evidência documentada aqui.

O aplicativo não configura Incus, não adiciona usuários a grupos privilegiados, não altera o firewall do host e não instala pacotes no host durante o provisionamento normal de uma VM. Revise as permissões e mudanças necessárias para sua instalação Incus antes de conceder acesso.

## Executar pelo código-fonte

Instale os pacotes Ubuntu:

```bash
sudo apt install python3 python3-gi python3-yaml \
  gir1.2-gtk-4.0 gir1.2-adw-1 gir1.2-vte-3.91 python3-pytest python3-secretstorage
```

Abra a interface em modo mock ou conecte ao serviço Incus local configurado:

```bash
ISOLATEVM_MOCK=1 python3 -m isolatevm
python3 -m isolatevm
```

O mock mantém os dados em memória e não cria VMs reais. O backend real requer acesso local autorizado ao Incus. Não use `sudo` ou `pkexec` para abrir a interface.

## Testes e CI

Execute a suíte unitária e de UI com mocks:

```bash
python3 -m pytest -q
```

Execute os testes GTK em uma sessão gráfica:

```bash
ISOLATEVM_UI_TEST=1 python3 -m pytest -q
```

O workflow do GitHub Actions usa um runner Ubuntu 24.04, compila os módulos Python, executa a suíte com smoke tests GTK via Xvfb e constrói/inspeciona o `.deb` Ubuntu. Essas verificações não se conectam ao Incus nem comprovam o ciclo real de vida de VMs, rede ou login gráfico.

## Construir o pacote Ubuntu

```bash
./scripts/build-deb.sh
dpkg-deb --contents dist/isolatevm_0.3.10_all.deb
```

O pacote é gerado localmente em `dist/`; arquivos `.deb` gerados ficam fora do Git. O launcher roda como usuário da sessão. Configurar Incus e as permissões necessárias continua sendo responsabilidade do operador. Consulte [PACKAGING.md](PACKAGING.md) para o conteúdo do pacote e operações opcionais no host.

## Estrutura do projeto

| Caminho | Finalidade |
| --- | --- |
| `isolatevm/` | Interface GTK, modelo de manifesto, adaptadores Incus, políticas, provisionamento e armazenamento |
| `tests/` | Testes unitários, integração mock, políticas e smoke tests GTK opcionais |
| `packaging/` | Entrada desktop, ícone, política Polkit, unidade de serviço e helper de egress restrito |
| `docs/MANIFEST.md` | Campos e regras de validação do manifesto |
| `ARCHITECTURE.md` | Componentes e fluxo de dados |
| `SECURITY.md` | Modelo de ameaças, limites de permissão e restrições conhecidas |
| `DEVELOPMENT.md` | Ambiente de desenvolvimento e contratos de implementação |
| `PACKAGING.md` | Construção do pacote Ubuntu e instalação |

## Escopo atual

A implementação atende imagens Ubuntu cloud e a API/CLI Incus local. Allowlist de rede depende da política de proxy restrito; rede normal não filtra domínios. A entrega temporária de secrets está disponível como ação separada depois da criação. Consulte o [estado e os limites de validação](#estado-da-implementação) e o [registro de integração](docs/LIVE-VALIDATION.md) para saber o que foi exercitado e o que falta.
