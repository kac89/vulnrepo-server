package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

type Config struct {
	Server struct {
		Host string `json:"host"`
		Port string `json:"port"`
	} `json:"Server"`
	Cert struct {
		Cert    string `json:"cert"`
		Certkey string `json:"certkey"`
	} `json:"Cert"`
	Auth struct {
		Apikey     string `json:"apikey"`
		User       string `json:"User"`
		CREATEDATE string `json:"CREATEDATE"`
	} `json:"Auth"`
	MAXSTORAGE int64 `json:"MAX_STORAGE"`
}

type Report struct {
	ReportID         string `json:"report_id"`
	ReportName       string `json:"report_name"`
	ReportCreatedate int64  `json:"report_createdate"`
	ReportLastupdate int64  `json:"report_lastupdate"`
	EncryptedData    string `json:"encrypted_data"`
}

func main() {

	file, _ := os.Open("conf.json")
	defer file.Close()
	decoder := json.NewDecoder(file)
	configuration := Config{}
	err := decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("error:", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/", sayHello)

	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	srv := &http.Server{
		Addr:         configuration.Server.Host + ":" + configuration.Server.Port,
		Handler:      mux,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	log.Fatal(srv.ListenAndServeTLS(configuration.Cert.Cert, configuration.Cert.Certkey))
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func DirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return err
	})
	return size, err
}

func sayHello(w http.ResponseWriter, r *http.Request) {

	file, _ := os.Open("conf.json")
	defer file.Close()
	decoder := json.NewDecoder(file)
	configuration := Config{}
	err := decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("error:", err)
	}

	if configuration.Auth.Apikey == "" {
		log.Fatal("Empty api key, check conf.json!!!")
	}

	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		return
	}

	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Headers", "vulnrepo-auth, vulnrepo-action")
	w.Header().Set("Content-Type", "application/json")

	if r.URL.Path != "/api/" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	myAuth := r.Header.Get("Vulnrepo-Auth")

	if configuration.Auth.Apikey == myAuth {

		Action := r.Header.Get("Vulnrepo-Action")
		switch Action {
		case "apiconnect":
			w.WriteHeader(http.StatusOK)
			//storage size
			dirsize, _ := DirSize("./reports")
			fmt.Fprintf(w, `{"AUTH": "OK", "WELCOME": "`+configuration.Auth.User+`", "CREATEDATE": "`+configuration.Auth.CREATEDATE+`", "EXPIRYDATE": "0", "CURRENT_STORAGE": "`+fmt.Sprint(dirsize)+`", "MAX_STORAGE": "`+fmt.Sprint(configuration.MAXSTORAGE)+`"}`)
		case "getreportslist":
			files, err := ioutil.ReadDir("./reports/")
			if err != nil {
				log.Fatal(err)
			}
			reports := []Report{}
			for _, f := range files {
				dat, err := ioutil.ReadFile("./reports/" + f.Name())
				if err != nil {
					log.Fatal(err)
				}

				if dat != nil {

					payload, err := url.QueryUnescape(string(dat))
					if err != nil {
						panic(err)
					}
					data, err := base64.StdEncoding.DecodeString(string(payload))
					if err != nil {
						log.Fatal("error:", err)
					}
					var report Report
					json.Unmarshal([]byte(data), &report)
					reports = append(reports, report)
				}
			}
			w.WriteHeader(http.StatusOK)
			encjson, _ := json.Marshal(reports)
			fmt.Fprintf(w, string(encjson))
		case "getreport":
			reportid := r.FormValue("reportid")
			files, err := ioutil.ReadDir("./reports/")
			if err != nil {
				log.Fatal(err)
			}
			reports := []Report{}
			for _, f := range files {
				dat, err := ioutil.ReadFile("./reports/" + f.Name())
				if err != nil {
					log.Fatal(err)
				}
				if dat != nil {

					str, err := url.QueryUnescape(string(dat))
					if err != nil {
						panic(err)
					}

					data, err := base64.StdEncoding.DecodeString(string(str))
					if err != nil {
						log.Fatal("error:", err)
					}
					var report Report
					json.Unmarshal([]byte(data), &report)
					if reportid == report.ReportID {
						reports = append(reports, report)
					}
				}
			}
			w.WriteHeader(http.StatusOK)
			encjson, _ := json.Marshal(reports)
			fmt.Fprintf(w, string(encjson))

		case "removereport":
			reportid := r.FormValue("reportid")
			files, err := ioutil.ReadDir("./reports/")
			if err != nil {
				log.Fatal(err)
			}

			for _, f := range files {
				dat, err := ioutil.ReadFile("./reports/" + f.Name())
				if err != nil {
					log.Fatal(err)
				}
				if dat != nil {

					payload, err := url.QueryUnescape(string(dat))
					if err != nil {
						panic(err)
					}

					data, err := base64.StdEncoding.DecodeString(string(payload))
					if err != nil {
						log.Fatal("error:", err)
					}
					var report Report
					json.Unmarshal([]byte(data), &report)
					if reportid == report.ReportID {
						e := os.Remove("./reports/" + f.Name())
						if e != nil {
							log.Fatal(e)
						}
						w.WriteHeader(http.StatusOK)
						fmt.Fprintf(w, `{"REMOVE_REPORT": "OK"}`)
					}
				}
			}
		case "savereport":
			reportdata := r.FormValue("reportdata")
			isdir, _ := exists("./reports/")
			files, err := ioutil.ReadDir("./reports/")
			if err != nil {
				log.Fatal(err)
			}

			if isdir {
				//storage size
				dirsize, err := DirSize("./reports")
				if dirsize > configuration.MAXSTORAGE {
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `{"STORAGE": "NOSPACE"}`)
					break
				}

				payload, err := url.QueryUnescape(string(reportdata))
				if err != nil {
					panic(err)
				}
				data, err := base64.StdEncoding.DecodeString(payload)
				if err != nil {
					log.Fatal("error payload base64:", err)
				}
				var payload_report Report
				json.Unmarshal([]byte(data), &payload_report)

				reportid := payload_report.ReportID

				if reportid != "" {

					if len(files) > 0 {
						for _, f := range files {
							dat, err := ioutil.ReadFile("./reports/" + f.Name())
							if err != nil {
								log.Fatal(err)
							}

							plang, err := url.QueryUnescape(string(dat))
							if err != nil {
								panic(err)
							}

							data, err := base64.StdEncoding.DecodeString(plang)
							if err != nil {
								log.Fatal("error base64:", err)
							}
							var report Report
							json.Unmarshal([]byte(data), &report)
							if reportid != report.ReportID {
								// If the file doesn't exist, create it, or append to the file
								f, err := os.OpenFile("./reports/"+reportid+".vulnr", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
								if err != nil {
									log.Fatal(err)
								}

								_, err = f.Write([]byte(url.QueryEscape(string(reportdata))))
								if err != nil {
									log.Fatal(err)
								}

								f.Close()
								w.WriteHeader(http.StatusOK)
								fmt.Fprintf(w, `{"REPORT_SAVED": "OK"}`)
								break
							}

						}
					} else {

						// If the file doesn't exist, create it, or append to the file
						f, err := os.OpenFile("./reports/"+reportid+".vulnr", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
						if err != nil {
							log.Fatal(err)
						}

						_, err = f.Write([]byte(url.QueryEscape(string(reportdata))))
						if err != nil {
							log.Fatal(err)
						}

						f.Close()
						w.WriteHeader(http.StatusOK)
						fmt.Fprintf(w, `{"REPORT_SAVED": "OK"}`)
						break

					}

				}

			}

		case "updatereport":
			reportdata := r.FormValue("reportdata")
			isdir, _ := exists("./reports/")
			files, err := ioutil.ReadDir("./reports/")
			if err != nil {
				log.Fatal(err)
			}

			if isdir {

				//storage size
				dirsize, err := DirSize("./reports")
				if dirsize > configuration.MAXSTORAGE {
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `{"STORAGE": "NOSPACE"}`)
					break
				}

				payload, err := url.QueryUnescape(string(reportdata))
				if err != nil {
					panic(err)
				}
				data, err := base64.StdEncoding.DecodeString(payload)
				if err != nil {
					log.Fatal("error payload base64:", err)
				}
				var payload_report Report
				json.Unmarshal([]byte(data), &payload_report)

				reportid := payload_report.ReportID

				if reportid != "" {

					if len(files) > 0 {
						for _, f := range files {
							dat, err := ioutil.ReadFile("./reports/" + f.Name())
							if err != nil {
								log.Fatal(err)
							}

							plang, err := url.QueryUnescape(string(dat))
							if err != nil {
								panic(err)
							}

							data, err := base64.StdEncoding.DecodeString(plang)
							if err != nil {
								log.Fatal("error base64:", err)
							}
							var report Report
							json.Unmarshal([]byte(data), &report)
							if reportid == report.ReportID {
								// If the file doesn't exist, create it, or append to the file
								f, err := os.OpenFile("./reports/"+f.Name(), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
								if err != nil {
									log.Fatal(err)
								}

								_, err = f.Write([]byte(url.QueryEscape(string(reportdata))))
								if err != nil {
									log.Fatal(err)
								}

								f.Close()
								w.WriteHeader(http.StatusOK)
								fmt.Fprintf(w, `{"REPORT_UPDATE": "OK"}`)
								break
							}

						}
					}

				}

			}
		default:
			fmt.Fprintf(w, "Sorry, missing action")
		}
	}

}
