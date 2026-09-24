# IsolateVM

**IsolateVM** é um aplicativo desktop GTK local para criar e administrar máquinas virtuais Incus no Ubuntu. Ele oferece manifestos revisáveis, recursos e dispositivos explícitos, um perfil offline por padrão e uma política opcional de proxy de saída por VM.

> IsolateVM é uma interface para operadores, não uma fronteira de segurança contra um administrador Incus. Revise as permissões Incus concedidas à conta que executa o aplicativo. A interface gráfica deve rodar como usuário comum, nunca como root.

## O que oferece

- Detecta Ubuntu, arquitetura, virtualização, KVM, QEMU, Incus e recursos disponíveis sem alterar a configuração do host.
- Cria VMs Ubuntu cloud por um assistente GTK. CPU, memória, pool, disco, rede, mounts, software, desktop e manifesto são revisados antes da criação.
- Inicia, para, reinicia, clona, cria e restaura snapshots e remove VMs criadas pelo aplicativo. Ações destrutivas exigem confirmação explícita.
- Exibe a configuração Incus efetiva e métricas sob demanda de CPU, memória, disco, rede e uptime quando o Incus as fornece.
- Importa e exporta manifestos YAML versionados, instala software no guest pelo cloud-init e exporta backup completo para um arquivo novo com modo `0600`.
- Inclui backend mock (`ISOLATEVM_MOCK=1`) para explorar a interface sem conectar ao Incus nem criar VMs.
- Oferece desktops opcionais Ubuntu GNOME, KDE e XFCE, terminal externo e console VGA Incus por cliente SPICE.
- Descobre dispositivos USB e GPUs em modo somente leitura. Anexar USB é uma ação explícita e confirmada; GPU, PCI, serial e outros tipos de passthrough não estão implementados.

## Rede e perfis de isolamento

O manifesto padrão pede **rede offline**, nenhum mount do host e nenhum dispositivo repassado. O perfil `maximum-isolation` exige rede offline e zero mounts. A política `restricted-development` usa um proxy dedicado por VM e regras de firewall geradas para aceitar somente combinações declaradas de domínio/IP/CIDR e portas TCP. O helper executa separadamente via Polkit, enquanto o processo GTK continua sem privilégios.

O modo de rede `normal` é uma rede comum para a VM e não filtra domínios. A política de proxy restrito controla a saída de rede do guest; não audita os dados ou programas dentro dele, outros caminhos até o host nem políticas externas ao Incus. Inspecione a configuração efetiva antes de confiar em qualquer perfil. O Incus é a fonte de verdade do estado das VMs, portanto manifestos locais podem divergir depois de alterações externas.

Secrets não são suportados. Valores de ambiente do manifesto ficam visíveis ao guest e podem ser armazenados na configuração Incus; não inclua senhas, tokens ou chaves. Pastas do host nunca são montadas automaticamente. Selecione somente caminhos que pretende expor e prefira mounts somente para leitura quando possível.

Consulte [SECURITY.md](SECURITY.md), [ARCHITECTURE.md](ARCHITECTURE.md), o [schema do manifesto](docs/MANIFEST.md) e o resumo de [validação de integração](docs/LIVE-VALIDATION.md) para detalhes e limitações.

## Requisitos

- Ubuntu com Python 3.11 ou mais recente, PyGObject, GTK 4, libadwaita e PyYAML.
- Cliente e daemon Incus configurados localmente para operações reais com VMs. Incus é opcional no modo mock e para explorar a interface.
- Um pool de armazenamento Incus e, para modos com rede, uma bridge gerenciada adequada. Imagens, pacotes do guest e cloud-init dependem dos remotes e repositórios configurados.
- A política de egress restrito requer o helper Polkit separado, Squid, nftables e Polkit.
- Para console VGA, instale `virt-viewer` ou outro cliente SPICE compatível.

O aplicativo não configura Incus, não adiciona usuários a grupos privilegiados, não altera o firewall do host e não instala pacotes no host durante o provisionamento normal de uma VM. Revise as permissões e mudanças necessárias para sua instalação Incus antes de conceder acesso.

## Executar pelo código-fonte

Instale os pacotes Ubuntu:

```bash
sudo apt install python3 python3-gi python3-yaml \
  gir1.2-gtk-4.0 gir1.2-adw-1 python3-pytest
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
dpkg-deb --contents dist/isolatevm_0.2.2_all.deb
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

A implementação atende imagens Ubuntu cloud e a API/CLI Incus local. Allowlist de rede depende da política de proxy restrito; rede normal não filtra domínios. Injeção de secrets, passthrough geral de GPU/PCI/serial, terminal integrado no guest, guests não Ubuntu e teste visual automatizado de login não fazem parte do escopo atual. Consulte o [resumo de validação](docs/LIVE-VALIDATION.md) para o que foi exercitado e o que falta.
