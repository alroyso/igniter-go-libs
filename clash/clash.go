package clash

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"

	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	_ "github.com/Dreamacro/clash/hub"
	"github.com/Dreamacro/clash/hub/executor"
	"github.com/Dreamacro/clash/tunnel/statistic"

	log "github.com/sirupsen/logrus"
)

var (
	runningFlag atomic.Value
)

type ClashStartOptions struct {
	// HomeDir Clash config home directory
	HomeDir string
	// SocksListener Clash listener address and port
	SocksListener string
	// TrojanProxyServer Trojan proxy listening address and port
	ProxyServer        string
	ProxyType          string
	ProxyPassword      string
	Proxycipher        string
	Proxyobfs          string
	Proxyobfsparam     string
	Proxyorigin        string
	Proxyprotocol      string
	Proxyprotocolparam string
	// TrojanProxyServerUdpEnabled Whether UDP is enabled for Trojan Server
	ProxyServerUdpEnabled bool
}

func Start(opt *ClashStartOptions) {
	homedir := opt.HomeDir
	if homedir != "" {
		if !filepath.IsAbs(homedir) {
			currentDir, _ := os.Getwd()
			homedir = filepath.Join(currentDir, homedir)
		}
		C.SetHomeDir(homedir)
	}

	configFile := filepath.Join(C.Path.HomeDir(), "config.yaml")
	C.SetConfig(configFile)

	if err := config.Init(C.Path.HomeDir()); err != nil {
		log.Fatalf("Initial configuration directory error: %s", err.Error())
	}

	ApplyRawConfig(opt)
	runningFlag.Store(true)
	return
}

func IsRunning() bool {
	run := runningFlag.Load()
	return run.(bool)
}

func Stop() {
	snapshot := statistic.DefaultManager.Snapshot()
	for _, c := range snapshot.Connections {
		err := c.Close()
		if err != nil {
			log.Warnf("Clash Stop(): close conn err %v", err)
		}
	}
	//obfs: plain, obfsparam: null, protocol: origin, protocolparam: null
	opt := &ClashStartOptions{
		SocksListener:         "127.0.0.1:0",
		ProxyServer:           "127.0.0.1:0",
		ProxyServerUdpEnabled: true,
		ProxyPassword:         "",
		Proxycipher:           "",
		Proxyobfs:             "plain",
		Proxyobfsparam:        "",
		ProxyType:             "",
		Proxyprotocol:         "origin",
		Proxyprotocolparam:    "",
	}
	ApplyRawConfig(opt)

	runningFlag.Store(false)
}

func ApplyRawConfig(opt *ClashStartOptions) {

	// handle user input
	socksListenerHost, socksListenerPort, err := net.SplitHostPort(opt.SocksListener)
	if err != nil {
		log.Fatalf("SplitHostPort err: %v (%v)", err, opt.SocksListener)
	}
	if len(socksListenerHost) <= 0 {
		log.Fatalf("SplitHostPort host is empty: %v", socksListenerHost)
	}
	ProxyServerHost, ProxyServerPort, err := net.SplitHostPort(opt.ProxyServer)
	if err != nil {
		log.Fatalf("SplitHostPort err: %v (%v)", err, opt.ProxyServer)
	}
	if len(ProxyServerHost) <= 0 {
		log.Fatalf("SplitHostPort host is empty: %v", ProxyServerHost)
	}

	rawConfigBytes, err := readConfig(C.Path.Config())
	if err != nil {
		log.Fatalf("fail to read Clash config file")
	}
	rawCfg, err := config.UnmarshalRawConfig(rawConfigBytes)
	if err != nil {
		log.Fatalf("UnmarshalRawConfig: %v", err)
	}

	port, err := strconv.Atoi(socksListenerPort)
	if err != nil {
		log.Fatalf("fail to convert socksListenerPort %v", socksListenerPort)
	}
	if len(rawCfg.Proxy) <= 0 {
		log.Fatalf("should at least add one upstream proxy server")
	}

	rawCfg.AllowLan = true // whether we really use this feature is determined by BindAddress
	rawCfg.SocksPort = port
	rawCfg.BindAddress = socksListenerHost //default is *
	firstProxyServerMap := rawCfg.Proxy[0]
	//proxies:
	// - { name: ssr, type: ssr, server: 124.156.152.51, port: 10087, password: GN55YLnBct4FYcsT, cipher: aes-256-cfb, obfs: plain, obfsparam: null, protocol: origin, protocolparam: null, udp: 1 }
	//  - { name: "trojan", type: socks5, server: "127.0.0.1", port: 1081, udp: true}
	if firstProxyServerMap["type"] == "ssr" && firstProxyServerMap["name"] == "ssr" {
		firstProxyServerMap["server"] = ProxyServerHost
		firstProxyServerMap["port"] = ProxyServerPort
		firstProxyServerMap["password"] = opt.ProxyPassword
		firstProxyServerMap["cipher"] = opt.Proxycipher
		firstProxyServerMap["obfs"] = opt.Proxyobfs
		firstProxyServerMap["obfsparam"] = opt.Proxyobfsparam
		firstProxyServerMap["protocol"] = opt.Proxyprotocol
		firstProxyServerMap["protocolparam"] = opt.Proxyprotocolparam
		firstProxyServerMap["udp"] = opt.ProxyServerUdpEnabled
	} else if firstProxyServerMap["type"] == "socks5" && firstProxyServerMap["name"] == "trojan" {
		firstProxyServerMap["server"] = ProxyServerHost
		firstProxyServerMap["port"] = ProxyServerPort
		firstProxyServerMap["udp"] = opt.ProxyServerUdpEnabled
	} else {
		log.Fatalf("fail to find trojan proxy entry in Clash config")
	}

	cfg, err := config.ParseRawConfig(rawCfg)
	if err != nil {
		log.Fatalf("ParseRawConfig: %v", err)
	}

	executor.ApplyConfig(cfg, true)
}

func readConfig(path string) ([]byte, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("configuration file %s is empty", path)
	}

	return data, err
}

func init() {
	// default value
	runningFlag.Store(false)
}
