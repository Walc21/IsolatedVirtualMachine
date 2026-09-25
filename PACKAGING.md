# Pacote Ubuntu

Gerar `.deb` sem root:

```bash
./scripts/build-deb.sh
```

O pacote sai em `dist/isolatevm_0.3.10_all.deb`. Inspecione com `dpkg-deb --contents` antes da instalação. O launcher executa como usuário comum. A rede restrita instala um helper Polkit separado que só configura proxy por VM e regras nftables geradas de regras validadas. O pacote inclui helpers estáticos usados pela entrega de secrets em `/run`, pela cópia única ao disco do guest e pela instalação opcional de ferramentas DevOps nos guests; depende de `python3-secretstorage`, e um provedor Secret Service da sessão do usuário, como GNOME Keyring, é necessário para armazenar valores. O terminal integrado requer `gir1.2-vte-3.91`, o widget VTE construído para GTK4.

O pacote depende dos bindings GTK4/libadwaita/PyYAML disponíveis nos repositórios Ubuntu. Incus é opcional no pacote para permitir diagnóstico e modo mock antes de uma configuração consciente do host.

O pacote `0.3.10` foi construído, inspecionado e instalado neste host. A matriz local usou o `.deb` anterior `0.3.8`, gerado de um checkout local, e executou downgrade, upgrade para `0.3.10`, reinstall da mesma versão, remove, purge e fresh install de `0.3.10`. A remoção foi testada sem política ativa; como o pacote não tem conffiles, `dpkg -r` removeu o registro e os arquivos do pacote, e o `dpkg -P` seguinte não tinha estado remanescente para purgar. A instalação posterior concluiu e `/usr/bin/python3` importou `0.3.10` de `/usr/lib/python3/dist-packages/isolatevm`. O launcher iniciou em modo mock sob Xvfb; terminou apenas pelo limite externo de 8 segundos. `dpkg -V isolatevm` não reportou divergências. Launcher e helper privilegiado são `0755`; demais arquivos empacotados são `0644`; diretórios `0755`.

Durante a política `restricted` ativa, `dpkg -r isolatevm` foi recusado pelo `prerm`; state e firewall permaneceram ativos. Depois da remoção segura da VM/política, o pacote pôde ser removido. Arquivos de estado fora da lista do pacote não são apagados: o state de egress terminou `{}`, os locks root-only permaneceram sob `/var/lib/isolatevm/egress`, os diretórios de config/log ficaram vazios, e `/etc/modules-load.d/isolatevm-br-netfilter.conf` foi preservado. Os dois arquivos existentes em `~/.local/share/isolatevm` mantiveram hashes e modo `0600` durante remove/purge/fresh install.

A proteção de `main` foi aplicada e confirmada no GitHub: exige pull request, check `test-and-package` verde, branch atualizada antes do merge e bloqueia force-push e exclusão; também vale para administradores. A regra não exige aprovação de outra pessoa (`0` aprovações), para manter o fluxo utilizável por um único mantenedor. Ela é uma configuração remota do repositório, independente do `.deb`.

Em hosts onde a política `FORWARD` do Docker bloqueia uma bridge Incus, o operador pode avaliar os arquivos `packaging/isolatevm-docker-forward.*`. Eles não são instalados nem habilitados pelo `.deb`. Inspecione o script e a unidade, crie `/etc/default/isolatevm-docker-forward` com `ISOLATEVM_BRIDGE=incusbr-<id>` usando a bridge real, e confirme que as regras correspondem à política do host antes de habilitar o serviço. A desativação do serviço remove as regras que ele adiciona.

Para a console VGA de VMs em execução, instale `virt-viewer` (fornece `remote-viewer`) ou um cliente SPICE compatível. O pacote apenas sugere essa dependência; o dashboard desativa a ação quando ela está ausente.
