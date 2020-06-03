package ntlm2basic

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/Azure/go-ntlmssp"
)

type Server struct {
	ServerConfig
	transport *http.Transport
	proxy     *httputil.ReverseProxy
}

type ServerConfig struct {
	BindAddr    string
	UpstreamURL *url.URL
	Domain      string
	EnableDump  bool
}

func NewServer(config *ServerConfig) *Server {
	proxy := httputil.NewSingleHostReverseProxy(config.UpstreamURL)
	proxy.ModifyResponse = func(resp *http.Response) error {
		dumpNTLMResponse(config, resp, "NotAuthorized")

		if isNTLMRequired(resp) {
			if _, _, ok := resp.Request.BasicAuth(); !ok {
				return fmt.Errorf("NotAuthorized")
			} else {
				return fmt.Errorf("Authenticating")
			}
		}
		return nil
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Printf("info: handleError: %s", err.Error())
		if err.Error() == "NotAuthorized" {
			rw.Header().Add("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, config.Domain))
			http.Error(rw, "Not authorized", http.StatusUnauthorized)
			return
		}
		if err.Error() == "Authenticating" {
			user, password, ok := req.BasicAuth()
			if !ok {
				log.Printf("error: unexpcted authenticating flow, try to re-authenticate")

				rw.Header().Add("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, config.Domain))
				http.Error(rw, "Not authorized", http.StatusUnauthorized)
				return
			}

			log.Printf("info: Authenticating with NTLM. user: %s", user)

			client := &http.Client{
				Transport: ntlmssp.Negotiator{
					RoundTripper: &http.Transport{},
				},
			}

			ctx := req.Context()
			if cn, ok := rw.(http.CloseNotifier); ok {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				notifyChan := cn.CloseNotify()
				go func() {
					select {
					case <-notifyChan:
						cancel()
					case <-ctx.Done():
					}
				}()
			}

			outreq := req.Clone(ctx)
			if req.ContentLength == 0 {
				outreq.Body = nil // Issue 16036: nil Body for http.Transport retries
			}
			if outreq.Header == nil {
				outreq.Header = make(http.Header) // Issue 33142: historical behavior was to always allocate
			}

			target := config.UpstreamURL
			targetQuery := target.RawQuery

			outreq.URL.Scheme = target.Scheme
			outreq.URL.Host = target.Host
			outreq.URL.Path = singleJoiningSlash(target.Path, outreq.URL.Path)
			if targetQuery == "" || outreq.URL.RawQuery == "" {
				outreq.URL.RawQuery = targetQuery + outreq.URL.RawQuery
			} else {
				outreq.URL.RawQuery = targetQuery + "&" + outreq.URL.RawQuery
			}
			if _, ok := outreq.Header["User-Agent"]; !ok {
				// explicitly disable User-Agent so it's not set to default value
				outreq.Header.Set("User-Agent", "")
			}

			outreq.Close = false
			outreq.SetBasicAuth(user, password)

			dumpRequest(config, outreq)

			resp, err := client.Do(outreq)
			if err != nil {
				log.Printf("error: Faild to read response. host: %v, err: %v", outreq.URL.Host, err.Error())
				if resp == nil {
					http.Error(rw, err.Error(), 500)
					return
				}
			}

			dumpNTLMResponse(config, resp, "Authenticating")

			if isNTLMRequired(resp) {
				log.Printf("warn: failed to authenticate with NTLM. user: %s", user)

				rw.Header().Add("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, config.Domain))
				rw.WriteHeader(http.StatusUnauthorized)
				http.Error(rw, "Not authorized", 401)
				return
			}

			log.Printf("info: authenticated with NTLM. user: %s", user)

			writeResponse(rw, resp)

			return
		}

		log.Printf("error: proxy error: %v", err)
		rw.WriteHeader(http.StatusBadGateway)
	}

	s := &Server{
		ServerConfig: *config,
		transport:    &http.Transport{},
		proxy:        proxy,
	}

	return s
}

func (s *Server) Start() error {
	if s.BindAddr == "" {
		log.Fatalf("alert: Bind address is empty.")
	}

	return http.ListenAndServe(s.BindAddr, s)
}

func (s *Server) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	dumpRequest(&s.ServerConfig, req)

	s.proxy.ServeHTTP(rw, req)
}

func isNTLMRequired(res *http.Response) bool {
	if res.StatusCode != 401 {
		return false
	}

	v := strings.ToUpper(res.Header.Get("WWW-Authenticate"))
	if v != "NTLM" && !strings.HasPrefix(v, "NTLM ") {
		return false
	}

	return true
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func writeResponse(w http.ResponseWriter, resp *http.Response) {
	// copy headers
	dest := w.Header()
	for k, vs := range resp.Header {
		for _, v := range vs {
			dest.Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	_, err := io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("warn: Can't read response body %v", err)
	}

	if err := resp.Body.Close(); err != nil {
		log.Printf("warn: Can't close response body %v", err)
	}
}

func logging(level, s string, v ...interface{}) {
	msg := fmt.Sprintf(s, v...)
	log.Printf("[%s] %s\n", level, msg)
}

func dumpRequest(config *ServerConfig, req *http.Request) {
	if config.EnableDump {
		fmt.Println("---------------------------------------------------------------------")
		fmt.Printf("-> Request : %s %s\n", req.Method, req.URL)
		fmt.Printf("== HEADER ==\n")
		for k, v := range req.Header {
			fmt.Printf("%s: %s\n", k, v)
		}
		// fmt.Printf("== DUMP ==\n")
		// dump, _ := httputil.DumpRequestOut(req, true)
		// fmt.Println(string(dump))
		fmt.Println("---------------------------------------------------------------------")
	}
}

func dumpResponse(config *ServerConfig, resp *http.Response) {
	if config.EnableDump {
		fmt.Println("---------------------------------------------------------------------")
		fmt.Printf("<- Response: %s %s %d\n", resp.Request.Method, resp.Request.URL, resp.StatusCode)
		fmt.Printf("== HEADER ==\n")
		for k, v := range resp.Header {
			fmt.Printf("%s: %s\n", k, v)
		}
		// fmt.Printf("== DUMP ==\n")
		// dumpResp, _ := httputil.DumpRequestOut(req, true)
		// fmt.Println(string(dumpResp))
		fmt.Println("---------------------------------------------------------------------")
	}
}

func dumpNTLMResponse(config *ServerConfig, resp *http.Response, label string) {
	if config.EnableDump {
		fmt.Println("---------------------------------------------------------------------")
		fmt.Printf("-- [%s] NTLM Response: %s %s %d\n", label, resp.Request.Method, resp.Request.URL, resp.StatusCode)
		fmt.Printf("== HEADER ==\n")
		for k, v := range resp.Header {
			fmt.Printf("%s: %s\n", k, v)
		}
		// fmt.Printf("== DUMP ==\n")
		// dumpResp, _ := httputil.DumpRequestOut(req, true)
		// fmt.Println(string(dumpResp))
		fmt.Println("---------------------------------------------------------------------")
	}
}
