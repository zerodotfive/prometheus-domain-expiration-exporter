package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/araddon/dateparse"
	whoisparser "github.com/likexian/whois-parser-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/pflag"
	whois "github.com/undiabler/golang-whois"
	yaml "gopkg.in/yaml.v2"
)

const (
	namespace = "domain_expiration"
)

// DomainExpirationExporter ...
type DomainExpirationExporter struct {
	domain       string
	checkTimeout time.Duration
	mutex        sync.RWMutex

	secondsLeft   prometheus.Gauge
	daysLeft      prometheus.Gauge
	daysLeftRound prometheus.Gauge
	checkError    prometheus.Gauge
}

// CreateExporters ...
func CreateExporters(d string, checkTimeout time.Duration) (*DomainExpirationExporter, error) {
	return &DomainExpirationExporter{
		domain:       d,
		checkTimeout: checkTimeout,
		secondsLeft: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   namespace,
			Name:        "seconds_left",
			Help:        "seconds left to expiration",
			ConstLabels: prometheus.Labels{"domain": d},
		}),
		daysLeft: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   namespace,
			Name:        "days_left",
			Help:        "days left to expiration",
			ConstLabels: prometheus.Labels{"domain": d},
		}),
		daysLeftRound: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   namespace,
			Name:        "days_left_round",
			Help:        "days left to expiration round",
			ConstLabels: prometheus.Labels{"domain": d},
		}),
		checkError: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   namespace,
			Name:        "check_error",
			Help:        "check error",
			ConstLabels: prometheus.Labels{"domain": d},
		}),
	}, nil
}

// Describe ...
func (d *DomainExpirationExporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- d.secondsLeft.Desc()
	ch <- d.daysLeft.Desc()
	ch <- d.daysLeftRound.Desc()
	ch <- d.checkError.Desc()
}

func doCheck(domain string, timeout time.Duration) (time.Duration, error) {
	whois_raw, err := whois.GetWhoisTimeout(domain, timeout)
	if err != nil {
		return time.Duration(0), err
	}
	result, err := whoisparser.Parse(whois_raw)
	if err != nil {
		return time.Duration(0), err
	}
	d, err := dateparse.ParseStrict(result.Registrar.ExpirationDate)
	if err != nil {
		return time.Duration(0), err
	}
	return d.Sub(time.Now()), nil
}

// Collect ...
func (d *DomainExpirationExporter) Collect(ch chan<- prometheus.Metric) {
	d.mutex.Lock()
	defer func() {
		ch <- d.secondsLeft
		ch <- d.daysLeft
		ch <- d.daysLeftRound
		ch <- d.checkError
		d.mutex.Unlock()
	}()
	res, err := doCheck(d.domain, d.checkTimeout)
	if err != nil {
		fmt.Printf("%s %s\n", d.domain, err)
		d.secondsLeft.Set(float64(math.MaxInt16))
		d.daysLeft.Set(float64(math.MaxInt16))
		d.daysLeftRound.Set(float64(math.MaxInt16))
		d.checkError.Set(float64(1))
		return
	}

	d.secondsLeft.Set(res.Seconds())
	d.daysLeft.Set(res.Hours() / 24)
	round := math.Floor((res.Hours() / 24))
	if time.Now().Hour() < 12 {
		round++
	}
	d.daysLeftRound.Set(round)
	d.checkError.Set(float64(0))
}

func main() {
	var listen string
	listenDef := "0.0.0.0:9043"
	pflag.StringVar(
		&listen,
		"listen",
		listenDef,
		"Listen address. Env LISTEN also can be used.",
	)

	var checklistFile string
	checklistFileDef := "/etc/prometheus/prometheus-domain-expiration-exporter.yaml"
	pflag.StringVar(
		&checklistFile,
		"checklist-file",
		checklistFileDef,
		"Checklist file",
	)

	var metricsPath string
	metricsPathDef := "/metrics"
	pflag.StringVar(
		&metricsPath,
		"metrics-path",
		metricsPathDef,
		"Metrics path",
	)

	var checkTimeout time.Duration
	checkTimeoutDef := time.Duration(5 * time.Second)
	pflag.DurationVar(
		&checkTimeout,
		"check_timeout",
		checkTimeoutDef,
		"Check timeout",
	)

	pflag.Parse()

	if listen == listenDef && len(os.Getenv("LISTEN")) > 0 {
		listen = os.Getenv("LISTEN")
	}
	if checklistFile == checklistFileDef && len(os.Getenv("CHECKLIST_FILE")) > 0 {
		checklistFile = os.Getenv("CHECKLIST_FILE")
	}
	if metricsPath == metricsPathDef && len(os.Getenv("METRICS_PATH")) > 0 {
		metricsPath = os.Getenv("METRICS_PATH")
	}
	if checkTimeout == checkTimeoutDef && len(os.Getenv("CHECK_TIMEOUT")) > 0 {
		var err error
		checkTimeout, err = time.ParseDuration(os.Getenv("CHECK_TIMEOUT"))
		if err != nil {
			panic(err)
		}
	}

	var checklist = make([]string, 256)
	config, err := ioutil.ReadFile(checklistFile)
	if err != nil {
		log.Fatal("Couldn't read config: ", err)
	}
	err = yaml.Unmarshal(config, &checklist)
	if err != nil {
		log.Fatal("Couldn't parse config: ", err)
	}

	for check := range checklist {
		exporter, err := CreateExporters(checklist[check], checkTimeout)
		if err != nil {
			log.Fatal(err)
		}

		prometheus.MustRegister(exporter)
	}

	log.Printf("Statring domain expiration exporter.")

	http.Handle(metricsPath, promhttp.Handler())
	err = http.ListenAndServe(listen, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
