# Histórico de versões

Este arquivo resume mudanças relevantes para operadores. O [registro de validação](docs/LIVE-VALIDATION.md) distingue testes automatizados, exercícios em host real e áreas ainda não verificadas. Versões abaixo de 1.0 podem alterar contratos; revise o [manifesto v1](docs/MANIFEST.md) antes de importar configurações antigas.

## 0.3.11 — 2026-09-27

### Destaques

- **Rede restrita mais previsível:** inicialização do firewall sem deadlock no primeiro uso, verificação de prontidão do proxy pela resposta de negação padrão, recuperação conservadora após falhas e recusa de remover a política quando a VM ainda existe ou o inventário Incus falha.
- **Compatibilidade com o host:** inventário de CPUs confinadas consulta o endpoint JSON `/1.0/resources`; a preparação de logs migra o layout anterior com verificação do diretório aberto.
- **Histórico local:** escritores e leitores usam locks; o limite de 16 MiB é verificado sob o lock. Em falha de escrita/sincronização, o app tenta restaurar o tamanho anterior. Uma falha de auditoria após uma operação não impede o salvamento do manifesto nem apresenta a ação Incus concluída como falha.
- **Evidência de validação:** testes de regressão cobrem concorrência, escrita parcial, log cheio na interface, etapas de falha do egress e seleção de CPU. O CI compila, executa a suíte unitária/GTK e constrói o pacote Ubuntu.

### Validação e limites

O ciclo 0.3.10 foi exercitado em um host Ubuntu 26.04.1 com Incus 6.0.5 e VMs Ubuntu 24.04, incluindo uma VM com egress restrito e atualizações de política. As correções de auditoria posteriores foram cobertas por testes automatizados e CI; não há alegação de nova validação live completa da 0.3.11. Reboot físico, LAN-only em LAN real, passthrough físico, login gráfico no guest, autenticação live das CLIs de IA e quota efetiva em outros drivers permanecem fora da comprovação. Veja [docs/LIVE-VALIDATION.md](docs/LIVE-VALIDATION.md).

### Distribuição

O checkout desta versão constrói `dist/isolatevm_0.3.11_all.deb` com `./scripts/build-deb.sh`. O repositório não versiona o binário `.deb`; inspecione e construa o pacote a partir da tag antes de instalar. O aplicativo não configura Incus nem concede acesso privilegiado automaticamente. Veja [PACKAGING.md](PACKAGING.md).

## 0.3.10 — candidato validado em 2026-09-25

A revisão candidata concentrou a validação live de ciclo de vida, volumes, cópias, secrets e egress restrito, além de corrigir o caminho de CPU confinada e endurecer inicialização/recuperação do proxy. Os patches de auditoria foram integrados posteriormente na linha 0.3.11. O registro detalhado preserva as condições e as limitações desse ciclo.
