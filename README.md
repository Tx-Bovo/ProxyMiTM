# SecProxy

SecProxy é um proxy HTTP/HTTPS desenvolvido em Go que intercepta, inspeciona e registra tráfego de rede em formato **HAR (HTTP Archive)**. Este projeto visa fornecer uma ferramenta eficiente para análise de tráfego, debug de APIs e monitoramento de comunicações HTTP, com foco em segurança e rastreabilidade.

---

## :rocket: Funcionalidades

- ✅ Interceptação de tráfego HTTP e HTTPS com suporte a MITM (Man-in-the-Middle).
- ✅ Registro completo das requisições e respostas em formato **HAR**.
- ✅ Suporte a múltiplos métodos HTTP (`GET`, `POST`, etc.).
- ✅ Filtro de domínio e caminhos específicos para captura.
- ✅ Escrita automática do arquivo `proxy.har` a cada 10 segundos.
- ✅ Estrutura segura, com uso de **mutex** para evitar race conditions.

---

## :hammer_and_wrench: Tecnologias Utilizadas

- [Go (Golang)](https://golang.org/)
- [GoProxy](https://github.com/elazarl/goproxy) - biblioteca para criação de proxies em Go.
- Certificados TLS para interceptação HTTPS.

---

## :clipboard: Como Funciona

1. O proxy intercepta requisições HTTP e HTTPS.
2. Filtra e captura somente as requisições que:
   - Pertencem ao domínio configurado (`api.example.com`).
   - Tenham caminhos específicos (`/test`, `/user`).
   - Utilizem métodos configurados (`GET`, `POST`).
3. As informações da requisição e resposta são armazenadas no formato **HAR**.
4. O arquivo `proxy.har` é salvo periodicamente.

---

## :package: Estrutura do Código

- **HAR Model:** Estruturas para representar requisições e respostas no formato HAR.
- **Proxy:** Configuração e inicialização do proxy com GoProxy.
- **Interceptação:** Manipulação de `Request` e `Response` com leitura de corpo.
- **Registro:** Salvamento seguro e periódico dos dados interceptados.

---

## :gear: Configurações Importantes

- **Certificados TLS:**
  - Necessário gerar ou possuir `ca-cert.pem` e `ca-key.pem` para funcionamento do MITM.
- **Filtros:**
  - `targetDomain`: Domínio a ser monitorado.
  - `targetPaths`: Caminhos de interesse.
  - `targetMethods`: Métodos HTTP a serem interceptados.

---

## :construction: Pré-requisitos

- Go 1.20 ou superior instalado.
- Certificado e chave privados válidos (`ca-cert.pem` e `ca-key.pem`).
- Conexão de rede para rodar o proxy.

---

## :computer: Instalação

1. **Clone o repositório:**

```bash
git clone https://github.com/seu-usuario/secproxy.git
cd secproxy
```
Instale as dependências:

```bash
go mod init secproxy
go get github.com/elazarl/goproxy
``` 
Compile o projeto:

```bash
go build -o secproxy
```
Execute o proxy:

```bash
./secproxy
```
O proxy será iniciado na porta 8080.

## :warning: Atenção
O uso de MITM pode ser considerado invasivo ou ilegal dependendo do contexto.
Utilize apenas em ambientes controlados e com autorização.

Certifique-se de importar e confiar no certificado gerado no cliente que fará as requisições, para evitar erros de segurança.
