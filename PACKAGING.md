# Empacotamento Ubuntu

A versão 0.3.11 é distribuída como fonte; o `.deb` é construído localmente a partir da tag/checkout correspondente. O pacote instala uma interface de usuário comum e um helper Polkit separado para políticas de rede restrita. **Instalar o pacote não configura Incus nem concede permissões Incus ao usuário.**

## Construir e inspecionar

```bash
./scripts/build-deb.sh
dpkg-deb --field dist/isolatevm_0.3.11_all.deb Package Version Architecture
dpkg-deb --contents dist/isolatevm_0.3.11_all.deb
```

O script não requer root e grava o resultado em `dist/`, fora do Git. Confira conteúdo e dependências antes de instalar:

```bash
sudo apt install ./dist/isolatevm_0.3.11_all.deb
dpkg-query -W isolatevm
dpkg -V isolatevm
```

O launcher deve ser aberto na sessão do usuário, sem `sudo`. Incus é opcional como dependência do pacote para permitir diagnóstico e modo mock antes da configuração do host. Operações reais requerem cliente/daemon Incus, projeto, pool, bridge quando aplicável e permissões apropriadas.

## Conteúdo e dependências

| Parte | Finalidade |
| --- | --- |
| `/usr/bin/isolatevm` e módulos Python | Interface GTK4/libadwaita, backend, modelo e provisionamento |
| Helper de egress + policy Polkit | Operações enumeradas e autorizadas para proxy por VM e nftables |
| Units systemd de egress | Restauração da política antes da inicialização Incus quando uma política restrita existe |
| Helpers estáticos do guest | Cópia única, secrets em `/run` e instalação opcional de ferramentas no guest |
| Arquivos desktop e documentação | Integração da aplicação e contratos de operação |

O pacote depende dos bindings GTK4/libadwaita, PyYAML, VTE GTK4 (`gir1.2-vte-3.91`) e `python3-secretstorage` dos repositórios Ubuntu. Para guardar valores de secrets é necessário um provedor Secret Service na sessão, como GNOME Keyring. O console VGA é opcional e requer `virt-viewer` (`remote-viewer`) ou outro cliente SPICE compatível.

## Remoção e dados persistentes

Uma remoção com política de egress restrito ativa é recusada pelo `prerm` para não retirar o helper enquanto firewall e estado ainda dependem dele. Exclua a VM/política pelo fluxo validado antes de remover o pacote. O pacote não apaga automaticamente dados externos à sua lista de arquivos, como configurações e históricos do usuário ou estado root-only de egress.

No ciclo de validação da **0.3.10**, foram exercitados downgrade de um pacote local 0.3.8, upgrade, reinstall, remove, purge e fresh install. `dpkg -V` não reportou divergências após a instalação; o launcher iniciou em modo mock sob Xvfb. Também foi comprovada a recusa de `dpkg -r` com política ativa, preservando state e firewall. Os arquivos de configuração do usuário mantiveram modo `0600` e hashes. Esses resultados pertencem ao host e à versão documentados em [LIVE-VALIDATION.md](docs/LIVE-VALIDATION.md); o pacote 0.3.11 recebeu CI, sem repetição completa da matriz live.

## Integração opcional com Docker

Em hosts onde a política `FORWARD` do Docker bloqueia uma bridge Incus, avalie `packaging/isolatevm-docker-forward.*`. Esses arquivos **não** são instalados nem habilitados pelo `.deb`. Revise o script e a unit, defina `ISOLATEVM_BRIDGE=incusbr-<id>` em `/etc/default/isolatevm-docker-forward` com a bridge real e confira as regras frente à política do host antes de habilitar o serviço. A desativação remove as regras adicionadas por ele.

## Evidência de distribuição

O CI compila, executa testes sob Xvfb, constrói o `.deb` e inspeciona Package/Version/Architecture. Isso verifica empacotamento e testes automatizados; não comprova uma instalação ou reboot físico em cada host. Consulte [README.md](README.md) para requisitos e [SECURITY.md](SECURITY.md) para o impacto de rede e privilégios.
