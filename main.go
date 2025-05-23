package main

import (
	"crypto/tls"
	//"crypto/x509" // Not implemented make certificate dinamic mode
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
)

// Previnir race condition
var mu sync.RWMutex

var targetDomain = "api.example.com"
var targetPaths = []string{"/test", "/user"}
var targetMethods = []string{"POST", "GET"}

var harLog = HARLog{
	Log: struct {
		Version string     `json:"version"`
		Creator HARCreator `json:"creator"`
		Pages   []HARPage  `json:"pages"`
		Entries []HAREntry `json:"entries"`
	}{
		Version: "1.0",
		Creator: HARCreator{Name: "SecProxy", Version: "1.0"},
		Pages:   []HARPage{},
		Entries: []HAREntry{},
	},
}

type HARLog struct {
	Log struct {
		Version string     `json:"version"`
		Creator HARCreator `json:"creator"`
		Pages   []HARPage  `json:"pages"`
		Entries []HAREntry `json:"entries"`
	} `json:"log"`
}

type HARPage struct {
	StartedDateTime string `json:"startedDateTime"`
	ID              string `json:"id"`
	Title           string `json:"title"`
}

type HARCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type HAREntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            int64       `json:"time"` // tempo total em ms (não implementado)
	Request         HARRequest  `json:"request"`
	Response        HARResponse `json:"response"`
}

type HARRequest struct {
	Method      string         `json:"method"`
	URL         string         `json:"url"`
	HTTPVersion string         `json:"httpVersion"`
	Headers     []HARNameValue `json:"headers"`
	QueryString []HARNameValue `json:"queryString"`
	PostData    *HARPostData   `json:"postData,omitempty"`
	HeadersSize int            `json:"headersSize"` // -1 se não souber
	BodySize    int            `json:"bodySize"`    // -1 se não souber
}

type HARResponse struct {
	Status      int            `json:"status"`
	StatusText  string         `json:"statusText"`
	HTTPVersion string         `json:"httpVersion"`
	Headers     []HARNameValue `json:"headers"`
	Content     HARContent     `json:"content"`
	RedirectURL string         `json:"redirectURL"`
	HeadersSize int            `json:"headersSize"`
	BodySize    int            `json:"bodySize"`
}

type HARNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type HARContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

func headersToHAR(headers http.Header) []HARNameValue {
	harHeaders := make([]HARNameValue, 0, len(headers))
	for k, v := range headers {
		harHeaders = append(harHeaders, HARNameValue{Name: k, Value: strings.Join(v, ",")})
	}
	return harHeaders
}

func queryToHAR(query map[string][]string) []HARNameValue {
	harQuery := make([]HARNameValue, 0, len(query))
	for k, v := range query {
		harQuery = append(harQuery, HARNameValue{Name: k, Value: strings.Join(v, ",")})
	}
	return harQuery
}

func createHAREntry(req *http.Request, resp *http.Response, reqBody, respBody []byte) HAREntry {
	return HAREntry{
		StartedDateTime: time.Now().Format(time.RFC3339),
		Time:            0,
		Request: HARRequest{
			Method:      req.Method,
			URL:         req.URL.String(),
			HTTPVersion: req.Proto,
			Headers:     headersToHAR(req.Header),
			QueryString: queryToHAR(req.URL.Query()),
			PostData: func() *HARPostData {
				if len(reqBody) > 0 {
					return &HARPostData{
						MimeType: req.Header.Get("Content-Type"),
						Text:     string(reqBody),
					}
				}
				return nil
			}(),
			HeadersSize: -1,
			BodySize:    len(reqBody),
		},
		Response: HARResponse{
			Status:      resp.StatusCode,
			StatusText:  resp.Status,
			HTTPVersion: resp.Proto,
			Headers:     headersToHAR(resp.Header),
			Content: HARContent{
				Size:     len(respBody),
				MimeType: resp.Header.Get("Content-Type"),
				Text:     string(respBody),
			},
			RedirectURL: resp.Header.Get("Location"),
			HeadersSize: -1,
			BodySize:    len(respBody),
		},
	}
}

func saveHARToFile(filename string) {

	mu.RLock()
	defer mu.RUnlock()

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)

	if err != nil {
		log.Println("[Erro ao abrir arquivo HAR]", err)
		return
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "	")
	err = enc.Encode(harLog)
	if err != nil {
		log.Println("[Erro ao salvar HAR]", err)
	}

}

func shouldLog(req *http.Request) bool {
	host := req.URL.Hostname()

	if host == "" {
		host = req.Host
	}
	if !strings.HasSuffix(host, targetDomain) {
		return false
	}

	pathMatch := false
	for _, p := range targetPaths {
		if strings.HasPrefix(req.URL.Path, p) {
			pathMatch = true
			break
		}
	}
	if !pathMatch {
		return false
	}

	return slices.Contains(targetMethods, req.Method)
}

type ProxyData struct {
	ReqBody  []byte
	RespBody []byte
}

func main() {
	cert, err := tls.LoadX509KeyPair("ca-cert.pem", "ca-key.pem")
	if err != nil {
		log.Fatalf("Erro ao carregar certificado: %v", err)
	}

	goproxy.GoproxyCa = cert

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false

	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	proxy.OnRequest().DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			if req.Body != nil {
				bodyBytes, err := io.ReadAll(req.Body)
				if err != nil {
					log.Println("Erro ao ler corpo da requisição:", err)
					return req, nil
				}
				req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

				data, _ := ctx.UserData.(*ProxyData)
				if data == nil {
					data = &ProxyData{}
				}
				data.ReqBody = bodyBytes
				ctx.UserData = data
			}
			return req, nil
		})

	proxy.OnResponse().DoFunc(
		func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			if resp.Body != nil {
				bodyBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					log.Println("Erro ao ler corpo da resposta:", err)
				} else {
					resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

					data, _ := ctx.UserData.(*ProxyData)
					if data == nil {
						data = &ProxyData{}
					}
					data.RespBody = bodyBytes
					ctx.UserData = data
				}
			}

			var reqBody, respBody []byte
			if ctx.UserData != nil {
				if proxyData, ok := ctx.UserData.(*ProxyData); ok {
					reqBody = proxyData.ReqBody
					respBody = proxyData.RespBody
				}
			}

			if shouldLog(ctx.Req) {
				entry := createHAREntry(ctx.Req, resp, reqBody, respBody)
				harLog.Log.Entries = append(harLog.Log.Entries, entry)

			}

			return resp
		})

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			saveHARToFile("proxy.har")
		}

	}()

	log.Println("Proxy rodando na porta 8080")
	log.Fatal(http.ListenAndServe(":8080", proxy))

}
