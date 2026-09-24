# Pacote Ubuntu

Gerar `.deb` sem root:

```bash
./scripts/build-deb.sh
```

O pacote sai em `dist/isolatevm_0.3.2_all.deb`. Inspecione com `dpkg-deb --contents` antes da instalação. O launcher executa como usuário comum. A rede restrita instala um helper Polkit separado que só configura proxy por VM e regras nftables geradas de regras validadas. O pacote inclui helpers estáticos usados pela entrega de secrets em `/run`, pela cópia única ao disco do guest e pela instalação opcional de ferramentas DevOps nos guests; depende de `python3-secretstorage`, e um provedor Secret Service da sessão do usuário, como GNOME Keyring, é necessário para armazenar valores.

O pacote depende dos bindings GTK4/libadwaita/PyYAML disponíveis nos repositórios Ubuntu. Incus é opcional no pacote para permitir diagnóstico e modo mock antes de uma configuração consciente do host.

Em hosts onde a política `FORWARD` do Docker bloqueia uma bridge Incus, o operador pode avaliar os arquivos `packaging/isolatevm-docker-forward.*`. Eles não são instalados nem habilitados pelo `.deb`. Inspecione o script e a unidade, crie `/etc/default/isolatevm-docker-forward` com `ISOLATEVM_BRIDGE=incusbr-<id>` usando a bridge real, e confirme que as regras correspondem à política do host antes de habilitar o serviço. A desativação do serviço remove as regras que ele adiciona.

Para a console VGA de VMs em execução, instale `virt-viewer` (fornece `remote-viewer`) ou um cliente SPICE compatível. O pacote apenas sugere essa dependência; o dashboard desativa a ação quando ela está ausente.
