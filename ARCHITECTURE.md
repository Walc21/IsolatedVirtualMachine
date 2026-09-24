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
5. **Rede:** sem NIC significa modo offline. `normal` usa a rede indicada pelo operador. `restricted` usa um helper Polkit com JSON fechado para criar um Squid por VM, IPv4/MAC reservados e uma tabela `nftables` bridge. O MAC só pode fazer ARP, DHCP e TCP até seu proxy; conexões diretas, DNS do guest e IPv6 são descartados. O proxy resolve nomes e aplica as combinações declaradas de domínio/IP/CIDR e porta TCP.

## Fluxo de criação

O wizard percorre nome, sistema, hardware, disco, rede, acesso ao host, software, ferramentas, variáveis públicas e referências de secrets, preview de provisionamento, segurança, revisão e criação. `editar → validar → revisão/dry run → confirmar → criar (parada) → aplicar dispositivos/configuração → iniciar → auditar`. Caso uma etapa intermediária falhe, o backend tenta apagar a VM que acabou de criar e registra se a limpeza falhou. Nunca apaga uma VM preexistente. Segredos não são enviados durante a criação: uma ação separada recupera valores do Secret Service e, por stdin do agente Incus, preenche arquivos temporários em `/run`.

O dry run reaproveita o preflight do serviço, lê metadados da imagem e, se o socket permitir, `GET /1.0/storage-pools/<pool>/resources`. A aplicação não estima o uso físico inicial a partir do limite lógico do disco; informa capacidade ausente quando a consulta de pool não está disponível. O plano não executa operações de escrita nem cria recursos.

## Fases

- **Fase 1:** diagnóstico, listagem, estado, criação Ubuntu, recursos, mounts e auditoria. Terminal via cliente Incus externo inicialmente.
- **Fase 2:** manifesto versionado, templates locais, `cloud-init` para APT, snapshots, clone e import/export.
- **Fase 3:** resumo efetivo, `maximum-isolation` e `restricted-development` com proxy de egress por VM estão implementados e validados ao vivo. Secrets usam Secret Service no host e entrega manual para tmpfs `/run` no guest; a limpeza não apaga cópias já carregadas por processos.
- **Fase 4:** console VGA por SPICE, backup completo e métricas sob demanda foram iniciados. O wizard declara desktop GNOME/KDE/XFCE e instala o metapacote correspondente no primeiro boot; login gráfico ainda requer configurar senha no guest e validar numa VM real. USB é descoberto por sysfs e anexado apenas após confirmação, por ID vendor/product; GPU explícita está implementada, mas ainda sem teste físico ao vivo. PCI genérico e serial continuam pendentes.

## Referências verificadas

- [Incus REST API](https://linuxcontainers.org/incus/docs/main/rest-api/) e [especificação](https://linuxcontainers.org/incus/docs/main/rest-api-spec/)
- [Autorização Incus](https://linuxcontainers.org/incus/docs/main/authorization/) e [segurança](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [Dispositivo disk](https://linuxcontainers.org/incus/docs/main/reference/devices_disk/)
- [Cloud-init](https://linuxcontainers.org/incus/docs/main/cloud-init/)
- [ACL de rede](https://linuxcontainers.org/incus/docs/main/howto/network_acls/)

O backend verifica versão e erros do cliente Incus instalado em tempo de execução.
