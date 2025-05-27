
# ProxyMiTM Tool

**ProxyMiTM Tool** é um proxy HTTP/HTTPS desenvolvido em Go, projetado para interceptar, inspecionar e registrar tráfego de rede em formato **HAR (HTTP Archive)**. Esta ferramenta visa facilitar a análise de tráfego, debug de APIs e monitoramento de comunicações HTTP, com foco em segurança, rastreabilidade e automação.

---

## 🚀 Funcionalidades

- ✅ Interceptação de tráfego HTTP e HTTPS com suporte a **MITM (Man-in-the-Middle)**.
- ✅ Registro completo de requisições e respostas no formato **HAR**.
- ✅ Filtragem por domínio, caminhos e métodos HTTP.
- ✅ Escrita automática e periódica do arquivo `proxy.har`.
- ✅ Estrutura concorrente segura utilizando **mutex**.
- ✅ Logger interno para rastreamento de eventos e erros.

---

## 🛠️ Tecnologias Utilizadas

- [Go (Golang)](https://golang.org/)
- [GoProxy](https://github.com/elazarl/goproxy) – biblioteca para criação de proxies em Go.
- Certificados TLS para interceptação HTTPS.

---

## 📋 Como Funciona

1. O proxy intercepta requisições HTTP e HTTPS.
2. Filtra requisições conforme:
   - **Domínio:** Ex.: `api.example.com`.
   - **Caminhos:** Ex.: `/test`, `/user`.
   - **Métodos:** Ex.: `GET`, `POST`.
3. As informações interceptadas são armazenadas no formato **HAR**.
4. O arquivo `proxy.har` é salvo periodicamente.

---

## 📦 Estrutura do Código

- **/har:** Modelos e funções para geração do arquivo HAR.
- **/proxy:** Configuração e inicialização do proxy HTTP/HTTPS.
- **/utils:** Utilitários diversos como configuração de logs e leitura de certificados.
- **main.go:** Ponto de entrada da aplicação.

---

## ⚙️ Configurações Importantes

- **Certificados TLS:**
  - É necessário possuir ou gerar `ca-cert.pem` e `ca-key.pem` para o funcionamento do MITM.
- **Parâmetros de Filtro:**
  - `targetDomain`: Domínio alvo a ser monitorado.
  - `targetPaths`: Lista de caminhos a serem interceptados.
  - `targetMethods`: Métodos HTTP permitidos.

---

## 🏗️ Pré-requisitos

- Go 1.20 ou superior instalado.
- Certificado e chave privados (`ca-cert.pem` e `ca-key.pem`).
- Configuração do cliente para aceitar o certificado gerado.
- Acesso à rede para rodar o proxy.

---

## 💻 Instalação e Execução

1. **Clone o repositório:**

```bash
git clone https://github.com/Tx-Bovo/ProxyMiTM.git
cd proxymitm
```

2. **Instale as dependências:**

```bash
go mod tidy
```

3. **Compile o projeto:**

```bash
go build -o proxymitm
```

4. **Execute o proxy:**

```bash
./proxymitm
```

- O proxy será iniciado na **porta 8080**.

---

## ⚠️ Atenção

O uso de técnicas **MITM** pode ser considerado invasivo ou ilegal dependendo do contexto.

✅ Utilize **apenas** em ambientes **controlados** e com devida **autorização**.  
✅ Não esqueça de **importar e confiar no certificado** gerado nos clientes que realizarão as requisições, evitando erros relacionados a segurança TLS/SSL.
