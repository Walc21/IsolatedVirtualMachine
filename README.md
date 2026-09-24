# IsolateVM

## Estado da implementação

O código atual está na versão **0.3.2**. O aplicativo GTK administra VMs Ubuntu cloud por meio do Incus local, com manifestos revisáveis e autorização explícita para rede, mounts, cópias, secrets e dispositivos. Também inclui snapshots de proteção, ciclos de vida configuráveis, persistência separada de `/workspace`, comparação de alterações antes de aplicá-las e exportação versionada de manifestos e templates.

A última validação automatizada registrada para esta revisão passou **181 testes**. Também passaram a compilação Python, a checagem de sintaxe do helper DevOps e `git diff --check`. O pacote Ubuntu `0.3.2` (`all`) foi construído e inspecionado, mas não instalado nesta revisão. Essas verificações não executam os instaladores DevOps em uma VM nem exercitam dispositivos físicos.

Há validações de integração registradas com VMs descartáveis no Incus, incluindo cópias pontuais, snapshots e restauração, comparação de recursos, ciclo de vida, clone e volume persistente `/workspace`, além da política de egress e entrega de secrets. São resultados de um host e configuração específicos; consulte [o registro de validação](docs/LIVE-VALIDATION.md) antes de extrapolá-los para outro ambiente.

Ainda não foram validados o boot das novas opções de software DevOps, passthrough físico de USB ou GPU, nem login visual interativo em um desktop guest. O projeto não oferece terminal integrado no guest, guests não Ubuntu ou passthrough PCI genérico/serial. O registro de validação descreve esses limites e quais fluxos foram testados apenas com mocks.

O wizard separa **Copiar uma vez** de **Compartilhar permanentemente**. A cópia explícita entra no disco da VM após o primeiro start, sem mount e sem sincronização posterior; o compartilhamento usa um mount persistente com permissão RO ou RW. O preview informa destinos e tamanho antes da criação. Consulte [o contrato do manifesto](docs/MANIFEST.md).

Em **Configurações**, a opção de snapshot de proteção pode ser ativada antes de mudanças em mounts, dispositivos, rede, CPU/RAM e restauração de snapshots. Ela vem desligada, registra a origem automática no Histórico e impede a mudança se o snapshot falhar. Snapshots ficam no mesmo pool Incus da VM e não substituem um backup externo.

Manifestos e templates podem ser exportados em versões numeradas (`-v0001`, `-v0002`, …). A gravação recusa arquivos existentes. Templates excluem mounts e fontes de cópia pessoais; manifestos exportados preservam os caminhos declarados e devem ser tratados como dados privados.

O wizard oferece ciclos de vida **persistente**, **excluir manualmente**, **excluir ao fechar**, **restaurar snapshot inicial ao fechar** e **persistir somente `/workspace`**. Os dois modos de restauração salvam `isolatevm-initial`; ao fechar, a VM é parada se necessário e o snapshot restaurado. No modo persistir `/workspace`, o disco do sistema retorna ao estado inicial e o volume customizado separado conserva os dados. O clone desse modo recebe uma cópia independente do volume. A exclusão manual remove a VM e seu volume após conferir os marcadores de propriedade. Snapshots e backup completo da VM não incluem esse volume: use **Exportar /workspace**, que grava uma exportação separada com modo `0600`. O snapshot inicial protegido não pode ser renomeado ou excluído pela interface. **Fechar sem aplicar** mantém as VMs como estão. Encerramento forçado do aplicativo não executa ações de fechamento.

Ao alterar CPU/RAM, mounts, rede ou dispositivos de uma VM existente, a interface consulta a configuração efetiva do Incus e mostra um diff de antes/depois com **Cancelar** e **Aplicar alterações**. Antes de aplicar, compara novamente o estado relevante e pede nova revisão se ele mudou. Snapshots de proteção ativados são criados depois dessa comparação e antes da alteração.

**IsolateVM** é um aplicativo desktop GTK local para criar e administrar máquinas virtuais Incus no Ubuntu. Ele oferece manifestos revisáveis, recursos e dispositivos explícitos, um perfil offline por padrão e uma política opcional de proxy de saída por VM.

> IsolateVM é uma interface para operadores, não uma fronteira de segurança contra um administrador Incus. Revise as permissões Incus concedidas à conta que executa o aplicativo. A interface gráfica deve rodar como usuário comum, nunca como root.

## O que oferece

- Detecta Ubuntu, arquitetura, virtualização, KVM, QEMU, Incus e recursos disponíveis sem alterar a configuração do host.
- Cria VMs Ubuntu cloud por um assistente GTK. CPU, memória, pool, disco, rede, mounts, software, desktop e manifesto são revisados antes da criação. O catálogo inclui SDKs .NET compatíveis com a release Ubuntu, uv e Poetry via pipx, Rustup `stable`, toolchains pnpm/Yarn/Bun e opções DevOps para kubectl, Helm e Terraform. Os instaladores opcionais rodam no guest; as opções DevOps ainda não foram testadas em boot real.
- Inicia, para, reinicia, clona, cria e restaura snapshots e remove VMs criadas pelo aplicativo. Ações destrutivas exigem confirmação explícita.
- Exibe a configuração Incus efetiva e métricas sob demanda de CPU, memória, disco, rede e uptime quando o Incus as fornece.
- Importa e exporta manifestos YAML versionados, instala software no guest pelo cloud-init, exporta backup completo da VM e exporta separadamente o volume persistente `/workspace`, em arquivos novos com modo `0600`.
- Inclui backend mock (`ISOLATEVM_MOCK=1`) para explorar a interface sem conectar ao Incus nem criar VMs.
- Oferece desktops opcionais Ubuntu GNOME, KDE e XFCE, terminal externo e console VGA Incus por cliente SPICE.
- Descobre dispositivos USB e GPUs em modo somente leitura. Anexar USB e GPU é uma ação explícita e confirmada; USB usa serial único ou o endereço atual de barramento/dispositivo e exige nova seleção após reconexão. O passthrough de GPU exige VM parada e depende de autorização do projeto Incus. PCI genérico e serial não são suportados.

## Rede e perfis de isolamento

O manifesto padrão pede **rede offline**, nenhum mount do host e nenhum dispositivo repassado. O perfil `maximum-isolation` exige rede offline e zero mounts. A política `restricted-development` usa um proxy dedicado por VM e regras de firewall geradas para aceitar somente combinações declaradas de domínio/IP/CIDR e portas TCP. O helper executa separadamente via Polkit, enquanto o processo GTK continua sem privilégios.

O modo de rede `normal` é uma rede comum para a VM e não filtra domínios. A política de proxy restrito controla a saída de rede do guest; não audita os dados ou programas dentro dele, outros caminhos até o host nem políticas externas ao Incus. Inspecione a configuração efetiva antes de confiar em qualquer perfil. O Incus é a fonte de verdade do estado das VMs, portanto manifestos locais podem divergir depois de alterações externas.

Variáveis comuns de ambiente ficam visíveis ao guest e podem ser armazenadas na configuração Incus; use-as somente para dados públicos. Secrets são guardados no Secret Service da sessão do usuário, e o manifesto registra apenas seus nomes. Depois da criação, uma ação explícita envia os valores pela entrada padrão do agente Incus para arquivos no tmpfs `/run` do guest; eles não são incorporados ao manifesto, cloud-init ou configuração Incus. Use `isolatevm-run --secret NOME -- comando` no guest para iniciar um processo com a variável definida. Processos executados como o usuário `ubuntu` podem ler os secrets entregues; limpeza ou desligamento remove os arquivos, mas não apaga cópias já carregadas em processos. O perfil `maximum-isolation` bloqueia secrets. Pastas do host nunca são montadas automaticamente. Selecione somente caminhos que pretende expor e prefira mounts somente para leitura quando possível.

Consulte [SECURITY.md](SECURITY.md), [ARCHITECTURE.md](ARCHITECTURE.md), o [schema do manifesto](docs/MANIFEST.md) e o resumo de [validação de integração](docs/LIVE-VALIDATION.md) para detalhes e limitações.

## Requisitos

- Ubuntu com Python 3.11 ou mais recente, PyGObject, GTK 4, libadwaita, PyYAML e Secret Service (`python3-secretstorage` mais um provedor de sessão, como GNOME Keyring).
- Cliente e daemon Incus configurados localmente para operações reais com VMs. Incus é opcional no modo mock e para explorar a interface.
- Um pool de armazenamento Incus e, para modos com rede, uma bridge gerenciada adequada. Imagens, pacotes do guest e cloud-init dependem dos remotes e repositórios configurados.
- A política de egress restrito requer o helper Polkit separado, Squid, nftables e Polkit.
- Para console VGA, instale `virt-viewer` ou outro cliente SPICE compatível.

O aplicativo não configura Incus, não adiciona usuários a grupos privilegiados, não altera o firewall do host e não instala pacotes no host durante o provisionamento normal de uma VM. Revise as permissões e mudanças necessárias para sua instalação Incus antes de conceder acesso.

## Executar pelo código-fonte

Instale os pacotes Ubuntu:

```bash
sudo apt install python3 python3-gi python3-yaml \
  gir1.2-gtk-4.0 gir1.2-adw-1 python3-pytest python3-secretstorage
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

O workflow do GitHub Actions executa os testes GTK via Xvfb, compila o pacote Python e constrói/inspeciona o `.deb` Ubuntu. Essas verificações não se conectam ao Incus nem comprovam o ciclo real de vida de VMs, rede ou login gráfico.

## Construir o pacote Ubuntu

```bash
./scripts/build-deb.sh
dpkg-deb --contents dist/isolatevm_0.3.2_all.deb
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
