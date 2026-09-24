# Desenvolvimento

## Dependências no Ubuntu

```bash
sudo apt install python3 python3-gi python3-yaml \
  gir1.2-gtk-4.0 gir1.2-adw-1 python3-pytest
```

Para os testes gráficos em um ambiente sem sessão de desktop, instale `xvfb` e execute `ISOLATEVM_UI_TEST=1 xvfb-run -a python3 -m pytest -q`. A suíte padrão usa mocks e não precisa de daemon Incus.

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
- cloud-init instala software dentro do guest. Não deve instalar pacotes no host nem copiar credenciais do host.
- O Incus é a fonte de verdade do estado real da VM; um manifesto salvo descreve a configuração solicitada/criada e pode divergir após edições externas.

Antes de criar uma VM real, verifique o alias da imagem, pool, bridge, limites de recursos, mounts e política de egress solicitada na revisão do aplicativo. Mounts e acesso à rede devem permanecer explícitos.
