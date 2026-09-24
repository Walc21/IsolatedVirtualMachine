# IsolateVM: arquitetura e plano

Para alterações em VMs existentes, `change_diff.py` gera uma prévia de antes/depois a partir da configuração Incus efetiva. A UI busca novamente essa configuração antes de aplicar e rejeita uma prévia obsoleta; o backend mantém suas próprias validações. O snapshot opcional de proteção é criado após essa verificação e antes da mutação. A comparação cobre os campos envolvidos na operação, não afirma que todo o host ou guest permaneceu imutável.

Os modos `delete-on-close`, `restore-initial-on-close` e `persist-workspace` são confirmados no evento normal de fechamento da janela. A ação exige correspondência entre manifesto local e marcadores Incus na VM sem perfis herdados; o modo de volume também valida o dispositivo `/workspace`, a propriedade e o tamanho do volume separado. Instâncias não verificáveis são mantidas. `persist-workspace` restaura o snapshot reservado do disco da VM e preserva o volume customizado; snapshots e backups da VM não incluem seus dados. Clones desse modo recebem uma cópia independente do volume; os demais clones continuam persistentes. O encerramento abrupto do processo/host não executa as ações de fechamento.

Para cópias únicas, o manifesto guarda apenas origem/destino/tipo e a confirmação de arquivos ocultos. O adaptador confere o estado gerenciado da VM e lê cada arquivo por descritores com `O_NOFOLLOW`; o agente Incus leva os bytes por stdin ao helper estático criado no guest pelo cloud-init. O helper cria somente arquivos novos no disco raiz, verifica SHA-256 e aceita repetição com conteúdo idêntico. O estado `pending`/`done` e um digest de recibo ficam na configuração Incus. A cópia não concede um mount contínuo e não sincroniza alterações posteriores.

## Objetivo e limites

Aplicativo local para VMs Incus no Ubuntu. A interface GTK4/libadwaita executa como usuário comum. O backend Python é separado da interface, expõe apenas operações tipadas, valida os dados novamente e chama um adaptador `IncusService`. A configuração declarativa tem `schemaVersion: 1`. Incus é a fonte de verdade para estado, recursos e dispositivos; os templates são arquivos locais.

O primeiro corte usa REST sobre o socket administrativo para consultas de instâncias, pools e redes. No socket de usuário restrito, as leituras também usam o cliente `incus` para preservar a seleção automática do projeto `user-<uid>`. O cliente `incus` é usado para criação com imagem remota, alterações de estado, dispositivos, snapshots e terminal; cada chamada usa `subprocess.run` com vetor de argumentos, sem shell. A interface não recebe um canal de execução genérica.

### Decisão de stack

A implementação usa GTK4/libadwaita e PyGObject para manter a interface nativa ao Ubuntu e o backend em Python. O contrato de serviço separa UI e operações Incus, permitindo que a interface evolua sem expor comandos genéricos.

## Fronteiras de confiança

1. **Manifesto e interface → backend Python:** dados não confiáveis; schema fechado, validação e limites.
2. **Backend → Incus:** o socket administrativo pode equivaler a root. A aplicação não solicita inclusão em `incus-admin`. O socket de usuário pode direcionar a um projeto restrito; o adaptador recusa mounts do host quando a política do projeto os proíbe.
3. **Incus → guest:** imagem e `cloud-init` são executados dentro da VM. Somente imagens explicitamente escolhidas e pacotes declarados são usados.
4. **Host → VM:** nenhum caminho, dispositivo ou segredo é compartilhado implicitamente. Cada mount é listado e confirmado.
5. **Rede:** sem NIC significa modo offline. `normal` usa a bridge indicada pelo operador. `restricted` usa um helper Polkit com JSON fechado para criar um Squid por VM, IPv4/MAC reservados e uma tabela `nftables` bridge. O modo LAN-only usa o mesmo caminho e aceita somente CIDRs RFC1918 e portas TCP declaradas. O MAC só pode fazer ARP, DHCP e TCP até seu proxy; conexões diretas, DNS do guest e IPv6 são descartados. O proxy resolve nomes em modo restricted e encaminha somente destinos e portas explicitamente permitidos. Uma bridge Incus customizada pode ser escolhida quando já existe e é gerenciada pelo Incus; a aplicação não cria bridge de host.

## Fluxo de criação

O wizard percorre nome, sistema, hardware, disco, rede, acesso ao host, software, ferramentas, variáveis públicas e referências de secrets, preview de provisionamento, segurança, revisão e criação. `editar → validar → revisão/dry run → confirmar → criar (parada) → aplicar dispositivos/configuração → iniciar → auditar`. Caso uma etapa intermediária falhe, o backend tenta apagar a VM que acabou de criar e registra se a limpeza falhou. Nunca apaga uma VM preexistente. Segredos não são enviados durante a criação: uma ação separada recupera valores do Secret Service e, por stdin do agente Incus, preenche arquivos temporários em `/run`.

O dry run reaproveita o preflight do serviço, lê metadados da imagem e, se o socket permitir, `GET /1.0/storage-pools/<pool>/resources`. A aplicação não estima o uso físico inicial a partir do limite lógico do disco; informa capacidade ausente quando a consulta de pool não está disponível. O plano não executa operações de escrita nem cria recursos.

A etapa **AI Coding** converte seleções para campos npm/pipx do manifesto, sem um canal próprio de execução. npm e pipx rodam como `ubuntu` dentro do guest; npm usa prefixo `/home/ubuntu/.local`. Nenhuma sessão, chave ou arquivo de autenticação do host é copiado. O login é feito pelo usuário dentro da VM, ou um secret explicitamente referenciado é passado ao processo escolhido. Aider 0.86.2 requer Python 3.10–3.12 e é recusado para Ubuntu 26.04.

## Fases

- **Fase 1:** diagnóstico, listagem, estado, criação Ubuntu, recursos, mounts e auditoria. Terminal externo e terminal integrado VTE sobre `incus exec`.
- **Fase 2:** manifesto versionado, templates locais, `cloud-init` para APT, snapshots, clone e import/export.
- **Fase 3:** resumo efetivo, `maximum-isolation` e `restricted-development` com proxy de egress por VM estão implementados e validados ao vivo. O modo LAN-only reusa esse proxy com CIDRs RFC1918 e portas TCP explícitas; sua regra é validada offline, mas ainda não foi exercitada em uma LAN real. Secrets usam Secret Service no host e entrega manual para tmpfs `/run` no guest; a limpeza não apaga cópias já carregadas por processos.
- **Fase 4:** console VGA por SPICE, backup completo e métricas sob demanda estão implementados. O terminal integrado VTE abre um PTY Incus no guest e executa o shell como root da VM, com ambiente local mínimo. O wizard declara desktop GNOME/KDE/XFCE e instala o metapacote correspondente no primeiro boot; login gráfico ainda requer configurar senha no guest e validar numa VM real. USB, GPU física e funções PCI genéricas são descobertas e anexadas somente após revisão explícita; GPU e PCI exigem VM parada, e o PCI bruto pode interromper o host. Não houve validação com periféricos físicos nesta revisão. Portas seriais virtuais não são anexáveis a VMs pelo Incus; um adaptador USB serial pode usar o caminho de USB.

O disco raiz de uma VM gerenciada pode ser aumentado com diff revisável e VM parada; o guest poderá precisar expandir a partição ou sistema de arquivos no próximo boot. No editor de recursos, IsolateVM configura a quantidade de vCPUs e memória. O pinning opcional usa IDs de threads lógicas que o Incus anuncia, requer a mesma quantidade de IDs e vCPUs, e é guardado em manifestos e templates. O backend revalida os IDs online antes de criar ou alterar a VM. Pinning não reserva CPUs exclusivamente e o Incus pode rejeitar conjuntos que não correspondam à topologia física. A documentação atual do Incus reserva `limits.cpu.allowance` e prioridade a containers. As opções de CPU/VM e a arquitetura da imagem são explicadas na interface.

O detalhe de cada VM é organizado em abas de visão geral, hardware, armazenamento, arquivos compartilhados, rede, software, segurança, snapshots, logs, terminal, provisionamento e configuração avançada. A aba de logs mostra o histórico local de operações IsolateVM, não o journal do host ou logs internos do guest. A aba de snapshots lê data, sinalizador stateful e tamanho quando a versão do Incus expõe esse metadado; a API atual não oferece descrição personalizada na criação de snapshots. A tela de armazenamento cria volumes customizados de dados com propriedade marcada e validada, exige VM parada para anexar/remover/exportar, clona o conteúdo para volume independente e exclui/exporta somente após confirmar a propriedade. Como volumes customizados são separados da instância, snapshots e backups da VM não os incluem; a tela exporta cada volume gerenciado para um arquivo próprio novo, modo `0600`. A lista de bridges mostra somente bridges existentes e gerenciadas pelo Incus; configurar ou alterar redes globais do host continua sendo responsabilidade do operador.

Na tela **Permissões efetivas**, a ação de inventário executa consultas fixas por gerenciador para os itens do manifesto local: `dpkg-query`, pip/pipx/npm, `cargo install --list`, metadados Go e `rustc --version`. Ela não instala nem remove pacotes. A consulta precisa de uma VM ligada e do agente Incus. Versões são afirmações do guest, não prova de integridade ou procedência; pacotes acrescentados fora do manifesto não aparecem nessa lista.

## Referências verificadas

- [Incus REST API](https://linuxcontainers.org/incus/docs/main/rest-api/) e [especificação](https://linuxcontainers.org/incus/docs/main/rest-api-spec/)
- [Autorização Incus](https://linuxcontainers.org/incus/docs/main/authorization/) e [segurança](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [Dispositivo disk](https://linuxcontainers.org/incus/docs/main/reference/devices_disk/)
- [Opções de instância e CPU pinning](https://linuxcontainers.org/incus/docs/main/reference/instance_options/)
- [Expansão de storage volumes](https://linuxcontainers.org/incus/docs/main/howto/storage_volumes/)
- [Cloud-init](https://linuxcontainers.org/incus/docs/main/cloud-init/)
- [ACL de rede](https://linuxcontainers.org/incus/docs/main/howto/network_acls/)

O backend verifica versão e erros do cliente Incus instalado em tempo de execução.
