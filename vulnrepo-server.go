package main

import (
	"archive/zip"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
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
	Auth []struct {
		Apikey     string `json:"apikey"`
		User       string `json:"User"`
		CREATEDATE string `json:"CREATEDATE"`
	} `json:"Auth"`
	MAX_STORAGE          int64 `json:"MAX_STORAGE"`
	DOWNLOAD_VULNREPOAPP bool  `json:"DOWNLOAD_VULNREPOAPP"`
}

type Report struct {
	ReportID         string `json:"report_id"`
	ReportName       string `json:"report_name"`
	ReportCreatedate int64  `json:"report_createdate"`
	ReportLastupdate int64  `json:"report_lastupdate"`
	EncryptedData    string `json:"encrypted_data"`
}

type ListReports struct {
	ReportID         string `json:"report_id"`
	ReportName       string `json:"report_name"`
	ReportCreatedate int64  `json:"report_createdate"`
	ReportLastupdate int64  `json:"report_lastupdate"`
}

type ReportProfile []struct {
	ProfileName              string `json:"profile_name"`
	ReportCSS                string `json:"report_css"`
	ReportCustomContent      string `json:"report_custom_content"`
	Logo                     string `json:"logo"`
	Logow                    int    `json:"logow"`
	Logoh                    int    `json:"logoh"`
	VideoEmbed               bool   `json:"video_embed"`
	RemoveLastpage           bool   `json:"remove_lastpage"`
	RemoveIssueStatus        bool   `json:"remove_issueStatus"`
	RemoveIssuecvss          bool   `json:"remove_issuecvss"`
	RemoveIssuecve           bool   `json:"remove_issuecve"`
	RemoveResearcher         bool   `json:"remove_researcher"`
	RemoveChangelog          bool   `json:"remove_changelog"`
	RemoveTags               bool   `json:"remove_tags"`
	ReportParsingDesc        bool   `json:"report_parsing_desc"`
	ReportParsingPocMarkdown bool   `json:"report_parsing_poc_markdown"`
	ReportRemoveAttachName   bool   `json:"report_remove_attach_name"`
	ResName                  string `json:"ResName"`
	ResEmail                 string `json:"ResEmail"`
	ResSocial                string `json:"ResSocial"`
	ResWeb                   string `json:"ResWeb"`
}

type ReportTemplate []struct {
	Title      string `json:"title"`
	Poc        string `json:"poc"`
	Desc       string `json:"desc"`
	Severity   string `json:"severity"`
	Ref        string `json:"ref"`
	Cvss       string `json:"cvss"`
	CvssVector string `json:"cvss_vector"`
	Cve        string `json:"cve"`
	Tags       []any  `json:"tags"`
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func configwizard() {

	fmt.Println("Enter Your Name: ")
	var username string
	fmt.Scanln(&username)

	current_time := time.Now().Local()
	var fs []any

	fs = append(fs, map[string]interface{}{
		"apikey":     randSeq(20),
		"User":       username,
		"CREATEDATE": current_time.Format("2006-01-02"),
	})
	configtruct := map[string]interface{}{
		"Server": map[string]interface{}{
			"host": "localhost",
			"port": "443",
		},
		"Cert": map[string]interface{}{
			"cert":    "cert/cert.crt",
			"certkey": "cert/cert.key",
		},
		"Auth":                 fs,
		"MAX_STORAGE":          1000000000,
		"DOWNLOAD_VULNREPOAPP": false,
	}

	b, err := json.Marshal(configtruct)
	if err != nil {
		log.Fatalf("Unable to marshal due to %s\n", err)
	}

	if err := ioutil.WriteFile("config.json", b, 0644); err != nil {
		log.Panic(err)
	}
	fmt.Println("User password saved in config.json")
	fmt.Println("Configuration file written successfully.")

}

func main() {

	ex, err2 := os.Executable()
	if err2 != nil {
		panic(err2)
	}
	exPath := filepath.Dir(ex) + "/"

	if _, err := os.Stat(exPath + "config.json"); err == nil || os.IsExist(err) {
		// your code here if file exists
	} else {
		configwizard()
	}

	file, _ := os.Open(exPath + "config.json")
	defer file.Close()
	decoder := json.NewDecoder(file)
	configuration := Config{}
	err := decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("error:", err)
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

		mux.Handle("/home/", http.StripPrefix("/home", fileServer))
		mux.Handle("/my-reports/", http.StripPrefix("/my-reports", fileServer))
		mux.Handle("/report/", http.StripPrefix("/report", fileServer))
		mux.Handle("/faq/", http.StripPrefix("/faq", fileServer))
		mux.Handle("/settings/", http.StripPrefix("/settings", fileServer))
		mux.Handle("/vuln-list/", http.StripPrefix("/vuln-list", fileServer))
		mux.Handle("/import-report/", http.StripPrefix("/import-report", fileServer))
		mux.Handle("/new-report/", http.StripPrefix("/new-report", fileServer))
		mux.Handle("/cve-search/", http.StripPrefix("/cve-search", fileServer))
		mux.Handle("/templates-list/", http.StripPrefix("/templates-list", fileServer))
		mux.Handle("/bugbounty-list/", http.StripPrefix("/bugbounty-list", fileServer))
		mux.Handle("/asvs4/", http.StripPrefix("/asvs4", fileServer))
		mux.Handle("/pcidss4/", http.StripPrefix("/pcidss4", fileServer))
		mux.Handle("/tbhm/", http.StripPrefix("/tbhm", fileServer))
		//mux.Handle("/assets/", http.StripPrefix("/assets", fileServer))
		mux.Handle("/", http.StripPrefix("/", fileServer))

	}

	mux.HandleFunc("/api/", handleApi)

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
	if configuration.DOWNLOAD_VULNREPOAPP {
		fmt.Println("[*] VULNREPO APP: https://" + configuration.Server.Host + ":" + configuration.Server.Port)
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

func logme(event string) {
	currentTime := time.Now()
	logevent(currentTime.Format("2006/01/02 15:04:05") + event + "\n")
	fmt.Println(currentTime.Format("2006/01/02 15:04:05") + event)
}

func IsValidUUID(uuid string) bool {
	r := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
	return r.MatchString(uuid)
}

func handleApi(w http.ResponseWriter, r *http.Request) {
	ip := r.RemoteAddr
	xforward := r.Header.Get("X-Forwarded-For")
	logme(" | Connection from " + ip)
	if xforward != "" {
		fmt.Println("X-Forwarded-For : ", xforward)
	}

	file, _ := os.Open("config.json")
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

	usraccess := false
	authuser := ""
	authcreatedate := ""

	for i := range configuration.Auth {
		if configuration.Auth[i].Apikey == myAuth {
			// Found!
			usraccess = true
			authuser = configuration.Auth[i].User
			authcreatedate = configuration.Auth[i].CREATEDATE
			break
		}
	}

	if usraccess {

		Action := r.Header.Get("Vulnrepo-Action")
		switch Action {
		case "apiconnect":
			w.WriteHeader(http.StatusOK)
			//storage size
			dirsize, _ := DirSize("./reports")

			welcomeStruct := map[string]interface{}{
				"AUTH":            "OK",
				"WELCOME":         authuser,
				"CREATEDATE":      authcreatedate,
				"EXPIRYDATE":      "0",
				"CURRENT_STORAGE": fmt.Sprint(dirsize),
				"MAX_STORAGE":     fmt.Sprint(configuration.MAX_STORAGE),
			}

			b, err := json.Marshal(welcomeStruct)
			if err != nil {
				log.Fatalf("Unable to marshal due to %s\n", err)
			}

			fmt.Fprintf(w, string(b))
			logme(" | apiconnect from: " + ip)
		case "getreportslist":
			files, err := os.ReadDir("./reports/")
			if err != nil {
				log.Fatal(err)
			}
			reports := []ListReports{}
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
						var reportsin ListReports
						json.Unmarshal([]byte(data), &reportsin)

						reports = append(reports, reportsin)
					}
				}
			}
			w.WriteHeader(http.StatusOK)
			encjson, _ := json.Marshal(reports)
			fmt.Fprint(w, string(encjson))

			logme(" | getreportslist from: " + ip)

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

			logme(" | getreport from: " + ip)

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

			logme(" | removereport from: " + ip)

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
				if dirsize > configuration.MAX_STORAGE {
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

			logme(" | savereport from: " + ip)

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
				if dirsize > configuration.MAX_STORAGE {
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

			logme(" | updatereport from: " + ip)

		case "getreportprofiles":
			files, err := os.ReadDir("./profiles/")
			if err != nil {
				log.Fatal(err)
			}
			reportprofiles := ReportProfile{}
			for _, f := range files {
				if strings.Contains(f.Name(), ".vulnrepo-profiles") {
					dat, err := os.ReadFile("./profiles/" + f.Name())
					if err != nil {
						log.Fatal(err)
					}

					if dat != nil {

						data := string(dat)
						var profile ReportProfile
						json.Unmarshal([]byte(data), &profile)
						reportprofiles = append(reportprofiles, profile...)
					}
				}
			}
			w.WriteHeader(http.StatusOK)
			encjson, _ := json.Marshal(reportprofiles)
			fmt.Fprint(w, string(encjson))

			logme(" | getreportprofiles from: " + ip)

		case "getreporttemplates":
			files, err := os.ReadDir("./templates/")
			if err != nil {
				log.Fatal(err)
			}
			reporttemplates := ReportTemplate{}
			for _, f := range files {
				if strings.Contains(f.Name(), ".vulnrepo-templates") {
					dat, err := os.ReadFile("./templates/" + f.Name())
					if err != nil {
						log.Fatal(err)
					}

					if dat != nil {

						data := string(dat)
						var template ReportTemplate
						json.Unmarshal([]byte(data), &template)
						reporttemplates = append(reporttemplates, template...)
					}
				}
			}
			w.WriteHeader(http.StatusOK)
			encjson, _ := json.Marshal(reporttemplates)
			fmt.Fprint(w, string(encjson))

			logme(" | getreporttemplates from: " + ip)

		default:
			fmt.Fprintf(w, "Sorry, missing action")
		}
	}

}
