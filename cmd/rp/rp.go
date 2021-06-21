package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"golang.org/x/crypto/acme/autocert"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flagAddr := flag.String("addr", "", "address to listen on")
	flagProxy := flag.String("proxy", "", "address to proxy")
	flagAcme := flag.Bool("acme", true, "use TLS")
	flagAcmeDir := flag.String("acmedir", "/opt/acme", "let's encrypt cache")
	flagHost := flag.String("host", "", "hostname for tls")
	flagEmail := flag.String("email", "", "contact for let's encrypt")
	flag.Parse()
	host := *flagHost
	var err error
	if host == "" {
		host, err = os.Hostname()
		if err != nil {
			log.Fatal(err)
		}
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
			HostPolicy: autocert.HostWhitelist(*flagHost),
		}
		if *flagEmail != "" {
			m.Email = *flagEmail
		}
		go func() {
			log.Fatal(http.ListenAndServe(":http", m.HTTPHandler(nil)))
		}()
		srv.TLSConfig = &tls.Config{GetCertificate: m.GetCertificate}
		srv.TLSConfig.MinVersion = tls.VersionTLS12
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}
	log.Fatal(srv.ListenAndServe())
}
