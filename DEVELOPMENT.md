# Desenvolvimento

Para verificar a cópia única sem dados pessoais: `python3 -m pytest -q tests/test_copies.py`. Com acesso autorizado ao projeto Incus restrito e a imagem Ubuntu 24.04 disponível, `sg incus -c 'PYTHONPATH=. python3 scripts/live-copy-smoke.py'` cria uma VM descartável, confere o hash no guest e a remove ao sair. O script usa apenas conteúdo sintético.

`python3 -m pytest -q tests/test_snapshot_policy.py` cobre a preferência e a ordem da proteção. Com o mesmo acesso Incus, `sg incus -c 'PYTHONPATH=. python3 scripts/live-protection-snapshot-smoke.py'` cria uma VM descartável parada, toma um snapshot e só então altera a CPU; o script a remove ao sair.

`tests/test_model.py` cobre exportação create-only, versões numeradas e round-trip de importação sem conexão Incus.

`tests/test_software_inventory.py` cobre os parsers de APT, pip, pipx, npm, Cargo, Go e Rust, estados ausentes/divergentes e que a consulta real usa apenas comandos separados e validados. A verificação do guest só percorre pacotes do manifesto local de uma VM IsolateVM em execução.

`tests/test_incus.py` verifica o argv fechado do terminal Incus e que o cliente interativo recebe ambiente mínimo, sem variáveis secretas do host. Os testes GTK confirmam que o modo mock não abre um processo de terminal.

Com acesso deliberado ao projeto Incus restrito e a imagem Ubuntu 24.04 em cache, `sg incus -c 'PYTHONPATH=. python3 scripts/live-software-inventory-smoke.py'` cria uma VM offline descartável, consulta APT sem instalar pacotes e remove a VM ao sair. Esse smoke não valida inventário real dos demais gerenciadores.

`tests/test_change_diff.py` cobre as prévias de recursos, mounts, rede e dispositivos. O smoke GTK verifica os botões Cancelar/Aplicar e recusa uma prévia obsoleta. O script `live-protection-snapshot-smoke.py` também confere o diff de CPU/RAM contra uma configuração Incus real, usando uma imagem Ubuntu 24.04 já presente no cache local.

O smoke GTK `test_disposable_close_requires_confirmation_and_deletes_only_after_apply` percorre o fluxo de fechamento com serviço simulado: cancelar mantém a VM; confirmar remove VM, manifesto local e registra a auditoria. O teste também aciona o handler de fechamento usando um adapter confinado simulado.

## Dependências no Ubuntu

```bash
sudo apt install python3 python3-gi python3-yaml \
  gir1.2-gtk-4.0 gir1.2-adw-1 gir1.2-vte-3.91 python3-pytest python3-secretstorage squid
```

Para os testes gráficos em um ambiente sem sessão de desktop, instale `xvfb` e execute `ISOLATEVM_UI_TEST=1 xvfb-run -a python3 -m pytest -q`. A suíte não precisa de daemon Incus. Os testes de ACL iniciam Squid localmente com `hosts_file` sintético; não conectam a uma VM ou bridge Incus.

## Executar e validar

```bash
ISOLATEVM_MOCK=1 python3 -m isolatevm
python3 -m pytest -q
python3 -m compileall -q isolatevm
ISOLATEVM_UI_TEST=1 xvfb-run -a python3 -m pytest -q
./scripts/build-deb.sh
```

Nunca execute a interface GTK como root. Testes reais de integração precisam de um serviço Incus configurado deliberadamente e acesso apropriado ao usuário; revise o projeto-alvo e os efeitos antes de executá-los. O backend mock é a opção segura para desenvolver a interface.

## Contratos de implementação

- `isolatevm.model.Manifest` valida manifestos versão 1 e rejeita campos desconhecidos.
- `isolatevm.incus.IncusService` separa a interface do backend Incus; `MockIncus` implementa o mesmo contrato para testes.
- `isolatevm.api.IncusUnixApi` faz consultas REST locais permitidas.
- `LocalIncus` usa arrays de argumentos em vez de strings shell e configura explicitamente os dispositivos de armazenamento e rede das VMs.
- cloud-init instala software e helpers estáticos dentro do guest. Valores de secrets são buscados no Secret Service apenas após confirmação separada e enviados por stdin do agente Incus para tmpfs `/run`; nunca copie credenciais do host durante a criação.
- O Incus é a fonte de verdade do estado real da VM; um manifesto salvo descreve a configuração solicitada/criada e pode divergir após edições externas.
- Actions de terceiros no CI devem usar SHA completo e comentário de release. O workflow atual fixa `actions/checkout` em v7.0.1 e usa apenas `contents: read`.

Antes de criar uma VM real, verifique o alias da imagem, pool, bridge, limites de recursos, mounts e política de egress solicitada na revisão do aplicativo. Mounts e acesso à rede devem permanecer explícitos.
