package main

import (
	"bytes"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"path"
	"strconv"

	"github.com/julienschmidt/httprouter"
	"github.com/russross/blackfriday"
	"github.com/vulndb/webui/bindata"
	vulndbBindata "github.com/vulndb/vulndb-go/bindata"
	vulndb "github.com/vulndb/vulndb-go"
)

var vulndbPath = flag.String("vulndb-path", "", "path to vulndb database, if isn't set, then load from vulndb bindata")
var address = flag.String("http-addr", "127.0.0.1:8080", "http address")
var templates = flag.String("templates", "./templates", "path to templates")
var loadTemplates = flag.Bool("load-templates", false, "load templates from filesystem")

var funcMap = template.FuncMap{
	"severity": func(value string) string {
		switch value {
		case "high":
			return "danger"
		case "medium":
			return "warning"
		case "low":
			return "info"
		}
		return "default"
	},
	"markdown": func(value fmt.Stringer) (template.HTML, error) {
		return template.HTML(blackfriday.MarkdownCommon([]byte(value.String()))), nil
	},
}

type TemplateObj struct {
	Vulns vulndb.VulnList
	Vuln  *vulndb.Vuln
	Title string
	Err   error
}

func tPath(name string) string {
	return path.Join(*templates, name+".html")
}

func getVulns() (vulndb.VulnList, error) {
	if *vulndbPath != "" {
		return vulndb.LoadFromDir(*vulndbPath)
	}
	return vulndbBindata.LoadFromBin()
}

func renderTemplate(w http.ResponseWriter, tmplName string, obj *TemplateObj) {
	var err error
	t := template.New(tmplName).Funcs(funcMap)
	if *loadTemplates {
		t, err = t.ParseFiles(tPath(tmplName), tPath("base"))
	} else {
		var data []byte
		data, err = bindata.Asset(tPath(tmplName))
		if err == nil {
			t, err = t.Parse(string(data))
			if err == nil {
				data, err = bindata.Asset(tPath("base"))
				if err == nil {
					t, err = t.Parse(string(data))
				}
			}
		}
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	buf := bytes.NewBuffer(nil)
	err = t.ExecuteTemplate(buf, "base", obj)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.Copy(w, buf)
}

func IndexHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	vulns, err := getVulns()
	renderTemplate(w, "vulns", &TemplateObj{Err: err, Vulns: vulns})
}

func VulnHandler(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
	idStr := p.ByName("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		renderTemplate(w, "vuln", &TemplateObj{Err: err})
		return
	}
	vulns, err := getVulns()
	renderTemplate(w, "vuln", &TemplateObj{Err: err, Vuln: vulns.GetById(id)})
}

func VulnTagHandler(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
	tag := p.ByName("tag")
	vulns, err := getVulns()
	renderTemplate(w, "vulns", &TemplateObj{
		Err:   err,
		Vulns: vulns.FilterByTag(tag),
		Title: fmt.Sprintf("Filtered by tag '%s'", tag),
	})
}

func VulnSeverityHandler(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
	severity := p.ByName("severity")
	vulns, err := getVulns()
	renderTemplate(w, "vulns", &TemplateObj{
		Err:   err,
		Vulns: vulns.FilterBySeverity(severity),
		Title: fmt.Sprintf("Filtered by severity '%s'", severity),
	})
}

func main() {
	flag.Parse()
	router := httprouter.New()

	router.GET("/", IndexHandler)
	router.GET("/vuln/:id", VulnHandler)
	router.GET("/tag/:tag", VulnTagHandler)
	router.GET("/severity/:severity", VulnSeverityHandler)

	log.Printf("Listen on %s", *address)
	if err := http.ListenAndServe(*address, router); err != nil {
		panic(err)
	}
}
