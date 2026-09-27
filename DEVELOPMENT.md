# Desenvolvimento

Este guia cobre a execução local, a suíte automatizada e os smokes que criam VMs descartáveis. Os testes unitários/GTK não exigem daemon Incus; os scripts `live-*` exigem um host configurado e autorização deliberada. O [registro de validação](docs/LIVE-VALIDATION.md) informa o que já foi exercitado.

## Dependências

Em Ubuntu:

```bash
sudo apt install python3 python3-gi python3-yaml python3-pytest \
  python3-secretstorage gir1.2-gtk-4.0 gir1.2-adw-1 \
  gir1.2-vte-3.91 squid xvfb
```

O Squid é usado nos testes de ACL com resolver sintético. O Xvfb fornece a sessão gráfica dos smoke tests GTK em CI.

## Fluxo rápido

```bash
ISOLATEVM_MOCK=1 python3 -m isolatevm
python3 -m compileall -q isolatevm packaging/isolatevm-egress-helper.py packaging/guest
python3 -m pytest -q
ISOLATEVM_UI_TEST=1 xvfb-run -a python3 -m pytest -q
./scripts/build-deb.sh
```

O mock mantém VMs em memória e não conecta ao daemon. **Nunca execute a interface GTK como root.**

## Mapa dos testes

| Área | Testes | Evidência fornecida |
| --- | --- | --- |
| Manifesto e armazenamento | `tests/test_model.py` | Schema, import/export, nomes versionados, log limitado, concorrência e erro de escrita |
| Egress | `tests/test_egress.py` | Regras, DNS sintético, falhas parciais e estado do helper |
| Incus e terminal | `tests/test_incus.py` | Argumentos tipados, seleção de CPU, ambiente do cliente e operações mock |
| Cópia única e snapshots | `tests/test_copies.py`, `tests/test_snapshot_policy.py` | Limites, recibos e ordem da proteção |
| Inventário e prévia | `tests/test_software_inventory.py`, `tests/test_change_diff.py` | Consultas somente leitura e diff de estado relevante |
| Interface | `tests/test_ui_smoke.py` | Fluxos GTK sob sessão gráfica, incluindo log cheio e fechamento confirmado |

A suíte automatizada não demonstra comportamento em todos os drivers, versões Incus, políticas do host ou hardware físico. O CI em Ubuntu 24.04 executa compileall, suíte GTK sob Xvfb, construção do pacote e inspeção de metadados.

## Testes com Incus real

Os comandos abaixo pressupõem acesso autorizado ao projeto Incus restrito, imagem Ubuntu 24.04 disponível e revisão prévia do pool, bridge e efeitos. Os scripts usam dados sintéticos e tentam excluir suas VMs descartáveis ao sair; uma interrupção pode exigir inspeção manual.

```bash
sg incus -c 'PYTHONPATH=. python3 scripts/live-copy-smoke.py'
sg incus -c 'PYTHONPATH=. python3 scripts/live-protection-snapshot-smoke.py'
sg incus -c 'PYTHONPATH=. python3 scripts/live-software-inventory-smoke.py'
```

| Script | Verificação principal |
| --- | --- |
| `live-copy-smoke.py` | Cópia única e SHA-256 no guest |
| `live-protection-snapshot-smoke.py` | Snapshot antes de alterar CPU e comparação com estado Incus |
| `live-software-inventory-smoke.py` | Consulta APT em uma VM offline; não valida todos os gerenciadores |

O [registro de validação](docs/LIVE-VALIDATION.md) contém outros fluxos live da revisão 0.3.10 e suas condições, separados dos smokes acima.

## Contratos para alterações

- `Manifest` mantém `schemaVersion: 1`, valida campos conhecidos e recusa valores fora dos limites.
- `IncusService` separa a interface do backend; `MockIncus` fornece o mesmo contrato para testes sem daemon. `IncusUnixApi` restringe consultas REST locais.
- `LocalIncus` usa vetores de argumentos, configuração local explícita e valida novamente instâncias, recursos e dispositivos antes de operações sensíveis.
- A configuração `cloud-init` instala software dentro do guest. Secrets só são recuperados após ação explícita e enviados por stdin para tmpfs `/run`; credenciais do host não são copiadas na criação.
- Incus é a fonte de verdade da configuração efetiva. Manifestos locais descrevem a escolha da aplicação e podem divergir após edições externas.
- Actions de terceiros no CI usam SHA completo e permissões mínimas. O workflow atual fixa `actions/checkout` em v7.0.1 com `contents: read`.

Antes de propor mudanças de rede, dispositivos ou armazenamento, atualize testes que cubram falhas parciais e os limites declarados em [SECURITY.md](SECURITY.md).
