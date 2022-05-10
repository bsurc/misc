package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

// httpsCheck validates https flag combinations
func httpsCheck(addr, key, cert string, acme bool) bool {
	addrIsHttps := addr == ":https" || addr == ":443" || addr == ":8443"
	// if we are using https, but not lets encrypt, we must have both key and
	// cert
	if addrIsHttps && !acme && key == "" && cert == "" {
		return false
	}
	// don't provide a key/cert and acme
	if acme && (key != "" || cert != "") {
		return false
	}
	return true
}

func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return net.JoinHostPort(host, "443")
}

func setTLS(c *tls.Config) {
	c.MinVersion = tls.VersionTLS12
	//c.PreferServerCipherSuites = false // client chooses
	c.CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flagAddr := flag.String("addr", "", "address to listen on")
	flagProxy := flag.String("proxy", "", "address to proxy")
	flagAcme := flag.Bool("acme", true, "use TLS")
	flagAcmeDir := flag.String("acmedir", "/opt/acme", "let's encrypt cache")
	flagHosts := flag.String("host", "", "comma separated hostnames for tls")
	flagKey := flag.String("key", "", "tls private key")
	flagCert := flag.String("cert", "", "tls certificate")
	flagEmail := flag.String("email", "", "contact for let's encrypt")
	flag.Parse()
	var err error
	if *flagHosts == "" {
		log.Fatal("provide at least one hostname")
	}
	hosts := strings.Split(*flagHosts, ",")
	if *flagAddr == "" {
		log.Fatal("provide an address flag")
	}
	if !httpsCheck(*flagAddr, *flagKey, *flagCert, *flagAcme) {
		log.Fatalf("invalid TLS flags: addr: %s, key: %s, cert: %s, acme: %t",
			*flagAddr, *flagKey, *flagCert, *flagAcme)
	}
	u, err := url.Parse(*flagProxy)
	if err != nil {
		log.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	srv := http.Server{
		Addr:    *flagAddr,
		Handler: proxy,
	}
	if *flagAcme {
		m := &autocert.Manager{
			Cache:      autocert.DirCache(*flagAcmeDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(hosts...),
		}
		if *flagEmail != "" {
			m.Email = *flagEmail
		}
		go func() {
			log.Fatal(http.ListenAndServe(":http", m.HTTPHandler(nil)))
		}()
		srv.TLSConfig = &tls.Config{GetCertificate: m.GetCertificate}
		setTLS(srv.TLSConfig)
		log.Fatal(srv.ListenAndServeTLS("", ""))
	} else if *flagKey != "" && *flagCert != "" {
		go func() {
			log.Fatal(http.ListenAndServe(":http", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" && r.Method != "HEAD" {
					http.Error(w, "Use HTTPS", http.StatusBadRequest)
					return
				}
				target := "https://" + stripPort(r.Host) + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusFound)
			})))
		}()
		srv.TLSConfig = &tls.Config{}
		setTLS(srv.TLSConfig)
		log.Print("using local certs, min tls version: %x", srv.TLSConfig.MinVersion)
		log.Fatal(srv.ListenAndServeTLS(*flagCert, *flagKey))
	}
	log.Fatal(srv.ListenAndServe())
}
