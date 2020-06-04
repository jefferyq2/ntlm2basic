package ntlm2basic

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Azure/go-ntlmssp"
	"github.com/google/uuid"
)

var cookieName = "ntlm-proxy-sessionid"

type Server struct {
	ServerConfig
	transport   *http.Transport
	noAuthProxy *httputil.ReverseProxy
	proxyMap    ProxyMap
}

type ServerConfig struct {
	BindAddr                       string
	UpstreamURL                    *url.URL
	Domain                         string
	EnableDump                     bool
	RewriteHostHeader              string
	MaxSessionIdleTimeoutInSeconds time.Duration
}

type ProxyMap struct {
	s sync.Map
}

func (s *ProxyMap) Store(sessionId, username string, value *httputil.ReverseProxy) {
	s.s.Store(sessionId+"/"+username, value)
}

func (s *ProxyMap) Load(sessionId, username string) (*httputil.ReverseProxy, error) {
	v, ok := s.s.Load(sessionId + "/" + username)
	if !ok {
		return nil, errors.New("not found")
	}

	t, ok := v.(*httputil.ReverseProxy)
	if !ok {
		return nil, errors.New("stored type is invalid")
	}

	return t, nil
}

func NewServer(config *ServerConfig) *Server {
	noAuthProxy := httputil.NewSingleHostReverseProxy(config.UpstreamURL)
	noAuthProxy.ModifyResponse = func(resp *http.Response) error {
		if isNTLMRequired(resp) {
			return fmt.Errorf("NotAuthorized")
		}
		return nil
	}
	noAuthProxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Printf("info: handleError: %s", err.Error())
		if err.Error() == "NotAuthorized" {
			rw.Header().Add("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, config.Domain))
			http.Error(rw, "Not authorized", http.StatusUnauthorized)
			return
		}

		log.Printf("error: proxy error with normal connection: %v", err)
		rw.WriteHeader(http.StatusBadGateway)
	}

	s := &Server{
		ServerConfig: *config,
		transport:    &http.Transport{},
		noAuthProxy:  noAuthProxy,
		proxyMap:     ProxyMap{},
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
	if s.RewriteHostHeader != "" {
		req.Header.Del("Host")
		req.Header.Set("Host", s.RewriteHostHeader)
	}

	dumpRequest(&s.ServerConfig, req)

	if user, _, ok := req.BasicAuth(); ok {
		// When already authenticated, find the connection and proxy through the connection
		if cookie, err := req.Cookie(cookieName); cookie != nil && err != http.ErrNoCookie {
			log.Printf("debug: cookie: %v", cookie)

			if proxy, err := s.proxyMap.Load(cookie.Value, user); err != nil {
				proxy.ServeHTTP(rw, req)
				return
			}
		}

		proxy := httputil.NewSingleHostReverseProxy(s.UpstreamURL)
		proxy.Transport = ntlmssp.Negotiator{
			RoundTripper: &http.Transport{
				MaxConnsPerHost:     1,
				MaxIdleConnsPerHost: 1,
				MaxIdleConns:        1,
				IdleConnTimeout:     s.MaxSessionIdleTimeoutInSeconds * time.Second,
			},
		}
		proxy.ModifyResponse = func(resp *http.Response) error {
			if isNTLMRequired(resp) {
				dumpNTLMResponse(&s.ServerConfig, resp, "NotAuthorized")

				if cookie, err := req.Cookie(cookieName); err != nil {
					log.Printf("info: detected losting the authenticated connection. need to re-authentication. user: %s", user)
					// Remove current cookie
					cookie.MaxAge = -1
					resp.Header.Add("Set-Cookie", cookie.String())

				} else {
					log.Printf("info: invalid username or credential. user: %s", user)
				}

				return fmt.Errorf("NotAuthorized")
			}
			// Authenticated
			log.Printf("info: authenticated. user: %s", user)

			uuid := uuid.New().String()
			cookie := &http.Cookie{
				Name:  cookieName,
				Value: uuid,
			}
			resp.Header.Add("Set-Cookie", cookie.String())

			// Save
			s.proxyMap.Store(uuid, user, proxy)

			return nil
		}
		proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
			if err.Error() == "NotAuthorized" {
				rw.Header().Add("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, s.Domain))
				http.Error(rw, "Not authorized", http.StatusUnauthorized)
				return
			}

			log.Printf("error: proxy error when authenticating: %v", err)
			rw.WriteHeader(http.StatusBadGateway)
		}

		// Proxy with authenticated connection
		proxy.ServeHTTP(rw, req)
		return
	}

	// Proxy with normal connection
	s.noAuthProxy.ServeHTTP(rw, req)
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
