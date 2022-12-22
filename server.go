package main

import (
	"archive/zip"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
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
	MAXSTORAGE           int64 `json:"MAX_STORAGE"`
	DOWNLOAD_VULNREPOAPP bool  `json:"DOWNLOAD_VULNREPOAPP"`
}

type Report struct {
	ReportID         string `json:"report_id"`
	ReportName       string `json:"report_name"`
	ReportCreatedate int64  `json:"report_createdate"`
	ReportLastupdate int64  `json:"report_lastupdate"`
	EncryptedData    string `json:"encrypted_data"`
}

func main() {

	ex, err2 := os.Executable()
	if err2 != nil {
		panic(err2)
	}
	exPath := filepath.Dir(ex) + "/"

	file, _ := os.Open(exPath + "conf.json")
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

	mux := http.NewServeMux()

	if configuration.DOWNLOAD_VULNREPOAPP {

		downloadFile(exPath+"vulnrepo-app-master.zip", "https://github.com/kac89/vulnrepo-build-prod/archive/refs/heads/master.zip")
		Unzip(exPath+"vulnrepo-app-master.zip", exPath+"vulnrepo-app/")
		// Removing file from the directory
		// Using Remove() function
		e := os.Remove(exPath + "vulnrepo-app-master.zip")
		if e != nil {
			log.Fatal(e)
		}

		fileServer := http.FileServer(http.Dir("./vulnrepo-app/vulnrepo-build-prod-master/"))
		mux.Handle("/", http.StripPrefix("/", fileServer))
		mux.Handle("/home/", http.StripPrefix("/home", fileServer))
		mux.Handle("/my-reports/", http.StripPrefix("/my-reports", fileServer))
		mux.Handle("/report/", http.StripPrefix("/report", fileServer))
		mux.Handle("/faq/", http.StripPrefix("/faq", fileServer))
		mux.Handle("/settings/", http.StripPrefix("/settings", fileServer))
		mux.Handle("/vuln-list/", http.StripPrefix("/vuln-list", fileServer))
		mux.Handle("/import-report/", http.StripPrefix("/import-report", fileServer))
		mux.Handle("/new-report/", http.StripPrefix("/new-report", fileServer))
		//mux.Handle("/assets/", http.StripPrefix("/assets", fileServer))

	}

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
	fmt.Println("-=[***************************************************************]=-")
	fmt.Println("[*] SERVER START: if no errors at this point, should works fine :-)")
	fmt.Println("[*] VULNREPO APP: https://" + configuration.Server.Host + ":" + configuration.Server.Port)
	if configuration.DOWNLOAD_VULNREPOAPP {
		fmt.Println("[*] API URL: https://" + configuration.Server.Host + ":" + configuration.Server.Port)
	}
	fmt.Println("-=[***************************************************************]=-")
	fmt.Println("")
	fmt.Println("")

	log.Fatal(srv.ListenAndServeTLS(configuration.Cert.Cert, configuration.Cert.Certkey))
}

func downloadFile(filepath string, url string) (err error) {

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Writer the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func Unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer func() {
		if err := r.Close(); err != nil {
			panic(err)
		}
	}()

	os.MkdirAll(dest, 0755)

	// Closure to address file descriptors issue with all the deferred .Close() methods
	extractAndWriteFile := func(f *zip.File) error {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if err := rc.Close(); err != nil {
				panic(err)
			}
		}()

		path := filepath.Join(dest, f.Name)

		// Check for ZipSlip (Directory traversal)
		if !strings.HasPrefix(path, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", path)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(path, f.Mode())
		} else {
			os.MkdirAll(filepath.Dir(path), f.Mode())
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer func() {
				if err := f.Close(); err != nil {
					panic(err)
				}
			}()

			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
		return nil
	}

	for _, f := range r.File {
		err := extractAndWriteFile(f)
		if err != nil {
			return err
		}
	}

	return nil
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

func logevent(event string) {
	// If the file doesn't exist, create it, or append to the file
	f, err := os.OpenFile("access.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := f.Write([]byte(event)); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}

func IsValidUUID(uuid string) bool {
	r := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
	return r.MatchString(uuid)
}

func sayHello(w http.ResponseWriter, r *http.Request) {
	currentTime := time.Now()
	ip := r.RemoteAddr
	logevent(currentTime.Format("2006/01/02 15:04:05") + " | Connection from: " + ip + "\n")
	fmt.Println(currentTime.Format("2006/01/02 15:04:05")+" | Connection from:", ip)

	file, _ := os.Open("conf.json")
	defer file.Close()
	decoder := json.NewDecoder(file)
	configuration := Config{}
	err := decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("error:", err)
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
			logevent(currentTime.Format("2006/01/02 15:04:05") + " | apiconnect from: " + ip + "\n")
			fmt.Println(currentTime.Format("2006/01/02 15:04:05")+" | apiconnect from:", ip)
		case "getreportslist":
			files, err := os.ReadDir("./reports/")
			if err != nil {
				log.Fatal(err)
			}
			reports := []Report{}
			for _, f := range files {
				if strings.Contains(f.Name(), ".vulnr") {
					dat, err := os.ReadFile("./reports/" + f.Name())
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
			}
			w.WriteHeader(http.StatusOK)
			encjson, _ := json.Marshal(reports)
			fmt.Fprint(w, string(encjson))
			logevent(currentTime.Format("2006/01/02 15:04:05") + " | getreportslist from: " + ip + "\n")
			fmt.Println(currentTime.Format("2006/01/02 15:04:05")+" | getreportslist from:", ip)
		case "getreport":
			reportid := r.FormValue("reportid")
			files, err := os.ReadDir("./reports/")
			if err != nil {
				log.Fatal(err)
			}
			reports := []Report{}
			for _, f := range files {
				dat, err := os.ReadFile("./reports/" + f.Name())
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
			fmt.Fprint(w, string(encjson))
			logevent(currentTime.Format("2006/01/02 15:04:05") + " | getreport from: " + ip + "\n")
			fmt.Println(currentTime.Format("2006/01/02 15:04:05")+" | getreport from:", ip)
		case "removereport":
			reportid := r.FormValue("reportid")
			files, err := os.ReadDir("./reports/")
			if err != nil {
				log.Fatal(err)
			}

			for _, f := range files {
				dat, err := os.ReadFile("./reports/" + f.Name())
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
			logevent(currentTime.Format("2006/01/02 15:04:05") + " | removereport from: " + ip + "\n")
			fmt.Println(currentTime.Format("2006/01/02 15:04:05")+" | removereport from:", ip)
		case "savereport":
			reportdata := r.FormValue("reportdata")
			isdir, _ := exists("./reports/")
			files, err := os.ReadDir("./reports/")
			if err != nil {
				log.Fatal(err)
			}

			if isdir {
				//storage size
				dirsize, err01 := DirSize("./reports")
				if err01 != nil {
					log.Fatal(err01)
				}
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

				if reportid != "" && IsValidUUID(reportid) {

					if len(files) > 0 {
						for _, f := range files {
							dat, err := os.ReadFile("./reports/" + f.Name())
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
			logevent(currentTime.Format("2006/01/02 15:04:05") + " | savereport from: " + ip + "\n")
			fmt.Println(currentTime.Format("2006/01/02 15:04:05")+" | savereport from:", ip)
		case "updatereport":
			reportdata := r.FormValue("reportdata")
			isdir, _ := exists("./reports/")
			files, err := os.ReadDir("./reports/")
			if err != nil {
				log.Fatal(err)
			}

			if isdir {

				//storage size
				dirsize, err23 := DirSize("./reports")
				if err23 != nil {
					log.Fatal(err23)
				}
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

				if reportid != "" && IsValidUUID(reportid) {

					if len(files) > 0 {
						for _, f := range files {
							dat, err := os.ReadFile("./reports/" + f.Name())
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
			logevent(currentTime.Format("2006/01/02 15:04:05") + " | updatereport from: " + ip + "\n")
			fmt.Println(currentTime.Format("2006/01/02 15:04:05")+" | updatereport from:", ip)
		default:
			fmt.Fprintf(w, "Sorry, missing action")
		}
	}

}
