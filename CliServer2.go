package main

import (
	"bytes"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net"
	_ "net/http/pprof"
	"net/smtp"
	"reflect"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	log "github.com/sjqzhang/seelog"

	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	//	"encoding/json"
	"context"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/alicebob/miniredis"
	"github.com/astaxie/beego/httplib"

	"github.com/coreos/etcd/client"
	"github.com/deckarep/golang-set"
	"github.com/garyburd/redigo/redis"

	"github.com/go-xorm/xorm"

	_ "github.com/go-sql-driver/mysql"

	"github.com/go-martini/martini"
	"github.com/json-iterator/go"
	_ "github.com/mattn/go-sqlite3"
	"github.com/samuel/go-zookeeper/zk"
	"github.com/sjqzhang/googleAuthenticator"
	"github.com/sjqzhang/zksdk"
	"golang.org/x/crypto/ssh"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary
var engine *xorm.Engine
var cli = &CliServer{util: &Common{}, etcdDelKeys: make(chan string, 10000)}
var safeMap = &SafeMap{m: make(map[string]*MiniHeartBeat)}
var safeTokenMap = &SafeTokenMap{m: make(map[string]*WBIPSMap)}
var safeAuthMap = &SafeAuthMap{m: make(map[string]*TChAuth)}
var qpsMap = &CommonMap{m: make(map[string]interface{})}
var tokenCounterMap = &CommonMap{m: make(map[string]interface{})}
var logacc log.LoggerInterface
var sqliteCache = &SQLiteCache{}
var cmds = WatchChannels{Cmds: make(map[string]chan string)}

var USE_ETCD_CLINET = false

var GET_METHODS = []string{"download", "upgrade", "status",
	"run_status", "check_status", "help", "del_etcd_key", "confirm_offline", "upload",
	"download"}

const (
	CONST_RESULT_LIST_KEY           = "results"
	CONST_CALLBACK_PARAMETERS_KEY   = "callback_paramters"
	CONST_CALLBACK_LIST_KEY         = "callbacks"
	CONST_HEARTBEAT_LIST_KEY        = "heartbeats"
	CONST_AUTH_KEY_PREFIX           = "auth_"
	CONST_TOKEN_LIST_KEY            = "tokens"
	CONST_INTERVAL_CMDS_LIST_KEY    = "interval_cmds"
	CONST_UUIDS_KEY                 = "uuids"
	CONST_SYSTEM_STATUS_LIST_KEY    = "system_status"
	CONST_TASK_LIST_KEY             = "indexs"
	CONST_CMDB_OPTION_PREFIX        = "cmdb_options_"
	CONST_HEARTBEAT_UUID_MAP_IP_KEY = "heartbeat_uuid_ip"
	CONST_HEARTBEAT_IP_MAP_UUID_KEY = "heartbeat_ip_uuid"
	CONST_LOGIN_PREFIX_KEY          = "login_"
	CONST_RESULT_KEY_PREFIX         = "result_"
	CONST_CACHE_KEY_PREFIX          = "outer_"
	CONST_REMOVE_IPLIST_KEY         = "remove_ips"
	CONST_REMOVE_ETCD_LIST_KEY      = "remove_etcd_keys"
	CONST_ASYNC_LOG_KEY             = "asyn_db"
	CONST_ASYNC_API_HIT_KEY         = "asyn_api_counter"

	CONST_UPLOAD_DIR = "files"

	CONST_ETCD_PREFIX = "/v2/keys"

	CONST_MACHINE_OFFLINE_TIME = 60 * 10

	logConfigStr = `
<seelog type="asynctimer" asyncinterval="1000" minlevel="trace" maxlevel="error">  
	<outputs formatid="common">  
		<buffered formatid="common" size="1048576" flushperiod="1000">  
			<rollingfile type="size" filename="./log/channel.log" maxsize="104857600" maxrolls="10"/>  
		</buffered>
	</outputs>  	  
	 <formats>
		 <format id="common" format="%Date %Time [%LEV] [%File:%Line] [%Func] %Msg%n" />  
	 </formats>  
</seelog>
`

	logAccessConfigStr = `
<seelog type="asynctimer" asyncinterval="1000" minlevel="trace" maxlevel="error">  
	<outputs formatid="common">  
		<buffered formatid="common" size="1048576" flushperiod="1000">  
			<rollingfile type="size" filename="./log/access.log" maxsize="104857600" maxrolls="10"/>  
		</buffered>
	</outputs>  	  
	 <formats>
		 <format id="common" format="%Date %Time [%LEV] [%File:%Line] [%Func] %Msg%n" />  
	 </formats>  
</seelog>
`

	cfgJson = `
{
	"addr": ":9160",
	"white_ips":  [
		"127.0.0.1"
	],
	"db":{
		"type":"sqlite3",
		"url":"./cli.db"
	},
	"redis": {
		"address": "127.0.0.1:6379",
		"pwd": "",
		"maxIdle": 10,
		"maxActive": 100,
		"idleTimeout": 30,
		"connectTimeout": 2,
		"db": 0
	},
	"etcd_root": {
		"host": "http://127.0.0.1:4001",
		"user": "",
		"password": ""
	},
	"etcd": {
		"server": ["http://127.0.0.1:4001/v2/keys"],
		"user": "",
		"password": "",
		"prefix":"/keeper"
	},
	"mail":{
		"user":"abc@163.com",
		"password":"abc",
		"host":"smtp.163.com:25"
	},
	"debug": false,
	"benchmark":false,
	"result2db":false,
	"auto_create_table":true,
	"use_zk":false,
	"auto_repair":true,
	"super_admin":[],
	"result_retain":90,
	"history_retain":365,
	"log_retain":365,
	"builtin_redis":true,
	"builtin_etcd":true,
	"falcon_url":"http://127.0.0.1:1988/v1/push",
	"zkdb":{
		"zkhost":["127.0.0.1:2181"],
		"path":"",
		"cmd":"",
		"db":"",
		"host":"",
		"password":"",
		"user":"",
		"port":"" 
	},
	"zkredis":{
		"zkhost":["127.0.0.1:2181"],
		"path":"",
		"cmd":"",
		"db":"",
		"host":"",
		"password":"",
		"user":"",
		"port":"" 
	},
	"repair":{
		"cmd":"",
		"port":22,
		"user":"",
		"password":"",
		"key_file":""
	},
	"use_fastdfs":false,
	"fastdfs":{
		"upload_url":"http://127.0.0.1/fastdfs/upload",
		"return_key":"file",
		"host":"http://127.0.0.1/fastdfs/"
		
	}
}
`
)

/*************** DB MODEL **********************/

type TChUser struct {
	Fid         int       `xorm:"not null pk autoincr INT(11)"`
	Femail      string    `xorm:"not null default '' VARCHAR(256)"`
	Fuser       string    `xorm:"not null default '' unique VARCHAR(64)"`
	Fpwd        string    `xorm:"not null default '' VARCHAR(256)"`
	Fip         string    `xorm:"not null default '' VARCHAR(32)"`
	Flogincount int       `xorm:"not null default 0 INT(11)"`
	Ffailcount  int       `xorm:"not null default 0 INT(11)"`
	Flasttime   time.Time `xorm:"not null default '1970-01-01 00:00:00' DATETIME"`
	Fstatus     int       `xorm:"not null default 0 INT(11)"`
	FmodifyTime time.Time `xorm:"updated"`
	Fversion    int       `xorm:"not null default 0 INT(11)"`
}

type TChAuth struct {
	Fid         int       `json:"id" xorm:"not null pk autoincr INT(11)"`
	Furl        string    `json:"url" xorm:"not null default '' VARCHAR(128)"`
	Fip         string    `json:"ip" xorm:"not null default '' VARCHAR(1024)"`
	Fuser       string    `json:"user" xorm:"not null default '' VARCHAR(64)"`
	Fsudo       int       `json:"sudo" xorm:"not null default 0 INT(10)"`
	FblackIps   string    `json:"black_ips" xorm:"TEXT"`
	Fctime      int       `json:"ctime" xorm:"created"`
	Ftoken      string    `json:"token" json:"token" xorm:"not null default '' unique VARCHAR(64)"`
	FsudoIps    string    `json:"white_ips" xorm:"TEXT"`
	Fhit        int       `json:"hit" xorm:"not null default 0 INT(10)"`
	FlastUpdate int       `json:"last_update" xorm:"updated"`
	Fdesc       string    `json:"desc" xorm:"not null default '' VARCHAR(1024)"`
	Fenv        string    `json:"env" xorm:"not null default '' VARCHAR(64)"`
	FmodifyTime time.Time `json:"modify_time" xorm:"updated"`
	Fversion    int       `json:"version" xorm:"not null default 0 INT(11)"`
}

type TChResults struct {
	Fid         int       `json:"id" xorm:"not null pk autoincr INT(11)"`
	FtaskId     string    `json:"task_id" xorm:"not null default '' unique VARCHAR(36)"`
	Fip         string    `json:"i" xorm:"not null default '' VARCHAR(16)"`
	Fcmd        string    `json:"cmd"  xorm:"TEXT"`
	Fresult     string    `json:"result" xorm:"TEXT"`
	Fctime      int       `json:"ctime" xorm:"not null default 0 INT(11)"`
	Futime      int       `json:"utime" xorm:"created"`
	FopUser     string    `json:"user" xorm:"not null default '' VARCHAR(32)"`
	Fuuid       string    `json:"ip" xorm:"not null default '' index VARCHAR(36)"`
	FsysUser    string    `json:"sys_user" xorm:"not null default '' VARCHAR(32)"`
	FmodifyTime time.Time `json:"modifyTime" xorm:"created"`
	Fversion    int       `json:"version" xorm:"not null default 0 INT(11)"`
}

type TChResultsHistory struct {
	Fid         int       `xorm:"not null pk autoincr INT(11)"`
	FtaskId     string    `xorm:"not null default '' unique VARCHAR(36)"`
	Fip         string    `xorm:"not null default '' VARCHAR(16)"`
	Fcmd        string    `xorm:"TEXT"`
	Fresult     string    `xorm:"TEXT"`
	Fctime      int       `xorm:"not null default 0 index INT(11)"`
	Futime      int       `xorm:"not null default 0 INT(11)"`
	FopUser     string    `xorm:"not null default '' VARCHAR(32)"`
	Fuuid       string    `xorm:"not null default '' index VARCHAR(36)"`
	FsysUser    string    `xorm:"not null default '' VARCHAR(32)"`
	FmodifyTime time.Time `xorm:"not null default '1970-01-01 00:00:00' index DATETIME"`
	Fversion    int       `xorm:"not null default 0 INT(11)"`
}

type TChGoogleAuth struct {
	Fid         int64     `xorm:"not null pk autoincr BIGINT(20)"`
	Fseed       string    `json:"s" xorm:"not null default '' VARCHAR(32)"`
	Fuser       string    `json:"u" xorm:"not null default '' unique(uniq_user_platform) VARCHAR(32)"`
	Fplatform   string    `json:"p" xorm:"not null default '' unique(uniq_user_platform) VARCHAR(32)"`
	Ffail       int       `xorm:"not null default 0 INT(11)"`
	Fhit        int       `xorm:"not null default 0 INT(11)"`
	Fstatus     int       `xorm:"not null default 1 INT(11)"`
	Fctime      time.Time `xorm:"created"`
	Futime      time.Time `xorm:"created"`
	FmodifyTime time.Time `xorm:"created"`
	Fversion    int       `xorm:"not null default 0 INT(11)"`
}

type TChObjs struct {
	Fid         int       `xorm:"not null pk autoincr INT(11)"`
	Fip         string    `xorm:"not null default '' VARCHAR(16)"`
	Fkey        string    `json:"k" xorm:"not null default '' unique(uniq_otype_key) VARCHAR(36)"`
	Fotype      string    `json:"o" xorm:"not null default '' unique(uniq_otype_key) VARCHAR(32)"`
	Fname       string    `json:"n" xorm:"not null default '' VARCHAR(64)"`
	Fbody       string    `xorm:"TEXT"`
	Fuid        int       `xorm:"not null default 0 INT(11)"`
	Fgid        int       `xorm:"not null default 0 INT(11)"`
	Fstatus     int       `xorm:"not null default 0 INT(11)"`
	FmodifyTime time.Time `xorm:"updated"`
	Fversion    int       `xorm:"not null default 0 INT(11)"`
}

type TChLog struct {
	Fid         int       `xorm:"not null pk autoincr INT(11)"`
	Furl        string    `json:"url" xorm:"not null default '' VARCHAR(2048)"`
	Fparams     string    `json:"params" xorm:"TEXT"`
	Fmessage    string    `json:"message" xorm:"not null default '' VARCHAR(255)"`
	Fip         string    `json:"ip" xorm:"not null default '' CHAR(15)"`
	Fuser       string    `json:"user" xorm:"not null default '' VARCHAR(64)"`
	Ftime       int       `xorm:"updated"`
	FmodifyTime time.Time `xorm:"updated"`
	Fversion    int       `xorm:"not null default 0 INT(11)"`
}

type TChHeartbeat struct {
	Fuuid         string    `json:"uuid" xorm:"not null pk default '' VARCHAR(36)"`
	Fhostname     string    `json:"hostname" xorm:"not null default '' VARCHAR(255)"`
	Fip           string    `json:"ip" xorm:"not null default '' VARCHAR(32)"`
	Futime        string    `json:"utime"  xorm:"not null default '' VARCHAR(32)"`
	Fstatus       string    `json:"status" xorm:"not null default '' VARCHAR(16)"`
	FsystemStatus string    `json:"system_status" xorm:"TEXT"`
	FmodifyTime   time.Time `xorm:"updated"`
	Fversion      int       `xorm:"not null default 0 INT(11)"`
}

type TChFiles struct {
	Fid         int64     `xorm:"not null pk autoincr BIGINT(20)"`
	Fuser       string    `xorm:"not null default '' unique(uniq_user_file) VARCHAR(128)"`
	Fpath       string    `xorm:"not null default '' VARCHAR(128)"`
	Furl        string    `xorm:"VARCHAR(256)"`
	Fmd5        string    `xorm:"VARCHAR(32)"`
	Ffilename   string    `xorm:"not null default '' unique(uniq_user_file) VARCHAR(64)"`
	Fctime      string    `xorm:"not null default '' VARCHAR(32)"`
	Futime      string    `xorm:"not null default '' VARCHAR(32)"`
	Fatime      string    `xorm:"not null default '' VARCHAR(32)"`
	Fhit        int       `xorm:"not null default 0 INT(11)"`
	FmodifyTime time.Time `xorm:"updated"`
	Fversion    int       `xorm:"not null default 0 INT(11)"`
}

/****************************************/

type MetricValue struct {
	Endpoint  string      `json:"endpoint"`
	Metric    string      `json:"metric"`
	Value     interface{} `json:"value"`
	Step      int64       `json:"step"`
	Type      string      `json:"counterType"`
	Tags      string      `json:"tags"`
	Timestamp int64       `json:"timestamp"`
	FromType  int         `json:"fromType"` //fromtyme：0：machine，1：bussiness
	StatType  int         `json:"statType"` //stattype：0:total，1:avg 3:min 4:max 5：fail 6：sum
}

type EtcdResult struct {
	Action        string   `json:"action"`
	ModifiedIndex int64    `json:"modifiedIndex"`
	CreatedIndex  int64    `json:"createdIndex"`
	Node          EtcdNode `json:"node"`
}

type IntervalCmd struct {
	Ip      string            `json:"ip"`
	Cmd     string            `json:"cmd"`
	Kw      map[string]string `json:"kw"`
	EndTime int64             `json:"interval"`
}

type EtcdNode struct {
	Key           string      `json:"key"`
	Value         string      `json:"value"`
	ModifiedIndex int64       `json:"modifiedIndex"`
	CreatedIndex  int64       `json:"createdIndex"`
	Dir           bool        `json:"dir"`
	Nodes         []EtcdNodes `json:"nodes"`
}

type EtcdNodes struct {
	Key           string `json:"key"`
	Value         string `json:"value"`
	ModifiedIndex int64  `json:"modifiedIndex"`
	CreatedIndex  int64  `json:"createdIndex"`
}

type Repair struct {
	Cmd      string `json:"cmd"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	KeyFile  string `json:"key_file"`
}

type WatchChannels struct {
	Cmds map[string]chan string
}

type Redis struct {
	Address        string `json:"address"`
	Pwd            string `json:"pwd"`
	MaxIdle        int    `json:"maxIdle"`
	MaxActive      int    `json:"maxActive"`
	IdleTimeout    int    `json:"idleTimeout"`
	ConnectTimeout int    `json:"connectTimeout"`
	DB             int    `json:"db"`
}

type ZkInfo struct {
	ZkHost   []string `json:"zkhost"`
	Url      string   `json:"url"`
	Path     string   `json:"path"`
	Cmd      string   `json:"cmd"`
	DB       string   `json:"db"`
	Host     string   `json:"host"`
	Port     string   `json:"port"`
	Passowrd string   `json:"password"`
	User     string   `json:"user"`
	DBType   string   `json:"dbtype"`
}

type Mail struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Host     string `json:"host"`
}

type Etcd struct {
	Host string `json:"host"`
	User string `json:"user"`
	Pwd  string `json:"password"`
}

type HeartBeatEtcd struct {
	Prefix   string   `json:"prefix"`
	User     string   `json:"user"`
	Password string   `json:"password"`
	Server   []string `json:"server"`
}
type HeartBeatResult struct {
	Etcd  HeartBeatEtcd `json:"etcd"`
	shell string        `json:"shell"`
	Salt  string        `json:"salt"`
}

type DB struct {
	Type string `json:"type"`
	Url  string `json:"url"`
}

type WBIPSMap struct {
	whiteips mapset.Set
	blackips mapset.Set
}

type FastDFS struct {
	UploadURL string `json:"upload_url"`
	ReturnKey string `json:"return_key"`
	Host      string `json:"host"`
}

type SafeTokenMap struct {
	sync.Mutex
	m map[string]*WBIPSMap
}

type GloablConfig struct {
	Addr           string        `json:"addr"`
	WhitelIps      []string      `json:"white_ips"`
	Redis          Redis         `json:"redis"`
	Etcd           Etcd          `json:"etcd_root"`
	Debug          bool          `json:"debug"`
	EtcdGuest      HeartBeatEtcd `json:"etcd"`
	SuperAdmin     []string      `json:"super_admin"`
	Db             DB            `json:"db"`
	BenchMark      bool          `json:"benchmark"`
	Result2DB      bool          `json:"result2db"`
	AutoCreatTable bool          `json:"auto_create_table"`
	Mail           Mail          `json:"mail"`
	ZkDB           ZkInfo        `json:"zkdb"`
	ZkRedis        ZkInfo        `json:"zkredis"`
	UseZkDB        bool          `json:"use_zk_db"`
	UseZKRedis     bool          `json:"use_zk_redis"`
	FalconURL      string        `json:"falcon_url"`
	Repair         Repair        `json:"repair"`
	AutoRepair     bool          `json:"auto_repair"`
	UseGor         bool          `json:"use_gor"`
	URLProxy       string        `json:"url_proxy"`
	FastDFS        FastDFS       `json:"fastdfs"`
	UseFastDFS     bool          `json:"use_fastdfs"`
	BuiltInRedis   bool          `json:"builtin_redis"`
	BuiltInEtcd    bool          `json:"builtin_etcd"`
	ResultRetain   int           `json:"result_retain"`
	HistoryRetain  int           `json:"history_retain"`
	LogRetain      int           `json:"log_retain"`
}

type SQLiteCache struct {
	sync.Mutex
	SQLite *sql.DB
}

func (s SQLiteCache) Exec(query string, args ...interface{}) (sql.Result, error) {
	s.Lock()
	defer s.Unlock()
	if len(args) > 0 {
		return s.SQLite.Exec(query, args)
	} else {
		return s.SQLite.Exec(query)
	}

}

func (s SQLiteCache) Query(query string, args ...interface{}) (*sql.Rows, error) {
	s.Lock()
	defer s.Unlock()
	if len(args) > 0 {
		return s.SQLite.Query(query, args)
	} else {
		return s.SQLite.Query(query)
	}

}

func (s SQLiteCache) Prepare(query string) (*sql.Stmt, error) {
	s.Lock()
	defer s.Unlock()
	return s.SQLite.Prepare(query)

}

type PlainTextOutPut struct {
	SplitLine string
	IP        string
	Result    string
}

type ResultMap map[string]*Result

type JsonOutPut struct {
	FailsIp string      `json:"failsip"`
	Results []ResultMap `json:"results"`
}

type Result struct {
	Cmd        string            `json:"cmd"`
	Error      string            `json:"error"`
	I          string            `json:"i"`
	Index      int64             `json:"index"`
	Ip         string            `json:"ip"`
	Result     string            `json:"result"`
	ReturnCode int               `json:"return_code"`
	S          string            `json:"s"`
	Success    string            `json:"success"`
	TaskId     string            `json:"task_id"`
	Kw         map[string]string `json:"kw"`
}

type MiniHeartBeat struct {
	Salt     string `json:"salt"`
	Ip       string `json:"ip"`
	Utime    string `json:"utime"`
	Status   string `json:"status"`
	Platform string `json:"platform"`
	Uuid     string `json:"uuid"`
}

type MiniHeartBeatStatus struct {
	//	Salt   string `json:"salt"`
	Ip       string `json:"ip"`
	Utime    string `json:"utime"`
	Status   string `json:"status"`
	Platform string `json:"platform"`
	Uuid     string `json:"uuid"`
}

type CliServer struct {
	etcd_host     string
	etcdbasicauth string
	util          *Common
	rp            *redis.Pool
	etcdClent     client.Client
	zkdb          *zksdk.ZkSdk
	zkredis       *zksdk.ZkSdk
	kapi          client.KeysAPI
	etcdDelKeys   chan string
}

type EtcdConf struct {
	Prefix   string `json:"prefix"`
	User     string `json:"user"`
	Password string `json:"password"`
}

type ResultSet struct {
	IP     string  `json:"ip"`
	TaskId string  `json:"task_id"`
	Result *Result `json:"result"`
}

type CommonMap struct {
	sync.Mutex
	m map[string]interface{}
}

type SafeMap struct {
	sync.Mutex
	m map[string]*MiniHeartBeat
}

func NewPlainTextOutPut(ip, result string) *PlainTextOutPut {
	return &PlainTextOutPut{
		SplitLine: "--------------------------------------------------------------------------------",
		IP:        ip,
		Result:    result,
	}
}

func (t *PlainTextOutPut) String() string {
	return fmt.Sprintf("%s\n%s\n%s\n", t.SplitLine, t.IP, t.Result)
}

var (
	FileName string
	ptr      unsafe.Pointer
)

func Config() *GloablConfig {
	return (*GloablConfig)(atomic.LoadPointer(&ptr))
}

func ParseConfig(filePath string) {
	var (
		data []byte
	)

	if filePath == "" {
		data = []byte(strings.TrimSpace(cfgJson))
	} else {
		file, err := os.Open(filePath)
		if err != nil {
			panic(fmt.Sprintln("open file path:", filePath, "error:", err))
		}

		defer file.Close()

		FileName = filePath

		data, err = ioutil.ReadAll(file)
		if err != nil {
			panic(fmt.Sprintln("file path:", filePath, " read all error:", err))
		}
	}

	var c GloablConfig
	if err := json.Unmarshal(data, &c); err != nil {
		panic(fmt.Sprintln("file path:", filePath, "json unmarshal error:", err))
	}

	log.Info(c)

	atomic.StorePointer(&ptr, unsafe.Pointer(&c))

	log.Info("config parse success")
}

func (r *Result) String() string {
	return fmt.Sprintf("Cmd:%s, Error:%s, I:%s, Index:%d, Ip:%s, ReturnCode:%d, S:%s, Success:%s, TaskId:%s",
		r.Cmd,
		r.Error,
		r.I,
		r.Index,
		r.Ip,
		r.ReturnCode,
		r.S,
		r.Success,
		r.TaskId,
	)
}

func (s *SafeTokenMap) Put(k string, v *WBIPSMap) {
	s.Lock()
	defer s.Unlock()
	s.m[k] = v
}

func (s *CommonMap) GetValue(k string) (interface{}, bool) {
	s.Lock()
	defer s.Unlock()
	v, ok := s.m[k]
	return v, ok
}

func (s *CommonMap) Put(k string, v interface{}) {
	s.Lock()
	defer s.Unlock()
	s.m[k] = v
}

func (s *CommonMap) Add(key string) {
	s.Lock()
	defer s.Unlock()
	if _v, ok := s.m[key]; ok {
		v := _v.(int)
		v = v + 1
		s.m[key] = v
	} else {

		s.m[key] = 1

	}
}

func (s *CommonMap) Zero() {
	s.Lock()
	defer s.Unlock()
	for k, _ := range s.m {

		s.m[k] = 0
	}
}

func (s *CommonMap) Get() map[string]interface{} {
	s.Lock()
	defer s.Unlock()
	m := make(map[string]interface{})
	for k, v := range s.m {
		m[k] = v
	}
	return m
}

func (s *SafeTokenMap) GetValue(k string) (*WBIPSMap, bool) {
	s.Lock()
	defer s.Unlock()
	v, ok := s.m[k]
	return v, ok
}

func (s *SafeMap) Put(k string, v *MiniHeartBeat) {
	s.Lock()
	defer s.Unlock()
	if val, ok := s.m[k]; ok {
		if val.Utime < v.Utime {
			s.m[k] = v
		}
	} else {
		s.m[k] = v
	}
}

func (s *SafeMap) Get() map[string]*MiniHeartBeat {
	s.Lock()
	defer s.Unlock()
	m := make(map[string]*MiniHeartBeat)
	for k, v := range s.m {
		m[k] = v
	}
	return m
}

func (s *SafeMap) Del(k string) (*MiniHeartBeat, bool) {
	s.Lock()
	defer s.Unlock()
	v, ok := s.m[k]
	if ok {
		delete(s.m, k)
	}
	return v, ok
}

func (s *SafeMap) GetValue(k string) (*MiniHeartBeat, bool) {
	s.Lock()
	defer s.Unlock()
	v, ok := s.m[k]
	return v, ok
}

type SafeAuthMap struct {
	sync.Mutex
	m map[string]*TChAuth
}

func (s *SafeAuthMap) Put(k string, v *TChAuth) {
	s.Lock()
	defer s.Unlock()
	wb := WBIPSMap{}
	wb.blackips = cli.GetIpFromRange(v.FblackIps)
	wb.whiteips = cli.GetIpFromRange(v.FsudoIps)
	safeTokenMap.Put(v.Ftoken, &wb)
	s.m[k] = v
}

func (s *SafeAuthMap) Get() map[string]*TChAuth {
	s.Lock()
	defer s.Unlock()
	m := make(map[string]*TChAuth)
	for k, v := range s.m {
		m[k] = v
	}
	return m
}

func (s *SafeAuthMap) GetValue(k string) (*TChAuth, bool) {
	s.Lock()
	defer s.Unlock()
	v, ok := s.m[k]
	return v, ok
}

type Common struct {
}

func (this *Common) CheckPort(ip string, port int) bool {

	c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
	if err != nil {

		return false
	}
	c.Close()
	return true

}

func (this *Common) JsonEncode(v interface{}) string {

	if v == nil {
		return ""
	}
	jbyte, err := json.Marshal(v)
	if err == nil {
		return string(jbyte)
	} else {
		return ""
	}

}

func (this *Common) JsonDecode(jsonstr string) interface{} {

	var v interface{}
	err := json.Unmarshal([]byte(jsonstr), &v)
	if err != nil {
		return nil

	} else {
		return v
	}

}

func (this *Common) BuildSql(s string) string {

	patterns := []string{
		"[\\w\\.]+\\s*[=\\<\\>]+\\s*[\\w\\.\\:\\-\u4e00-\u9fa5]+",
		"[\\w\\.]+\\s+like\\s+[\\w\\.\\:\\-\u4e00-\u9fa5]+",
		"[\\w\\.]+\\s+in\\s+[\\w\\.\\:\\-\u4e00-\u9fa5\\(),]+",
		"[\\w\\.]+\\s+is\\s+null",
		"[\\w\\.]+\\s*[=\\<\\>]+\\s*[\\'\"][\\w\\.\\:\\-\\s\u4e00-\u9fa5]+[\\'\"]",
		"[\\w\\.]+\\[\\*\\]\\.[\\w\\.\\:\\-\\s\u4e00-\u9fa5]+[=\\<\\>]+\\s*[\\w\\.\\:\\-\u4e00-\u9fa5]+",
		"[\\w\\.]+\\[\\*\\]\\.[\\w\\.\\:\\-\\s\u4e00-\u9fa5]+\\s+like\\s+[\\w\\.\\:\\-\u4e00-\u9fa5]+",
	}

	replace := func(s string) string {

		dangers := []string{
			"drop",
			"delete",
			";",
		}
		s = strings.ToLower(s)
		if reg, err := regexp.Compile(strings.Join(dangers, "|")); err == nil {
			s = reg.ReplaceAllString(s, "")
		} else {
			for _, k := range dangers {
				s = strings.Replace(s, k, "", -1)
			}
		}

		fmt.Println(s)

		ops := []string{
			"<>",
			"=",
			">",
			"<",
			" like ",
			" in ",
			" is null",
		}

		for _, o := range ops {
			if strings.Index(s, o) > 0 {
				items := strings.Split(s, o)
				if len(items) > 1 {
					items[1] = strings.Replace(items[1], "\"", "", -1)
					items[1] = strings.Replace(items[1], "'", "", -1)
				}
				if o == " like " {
					return fmt.Sprintf("%s like '%%%s%%'", items[0], items[1])
				} else if o == "=" || o == "<>" || o == ">" || o == "<" {
					return fmt.Sprintf("%s %s '%s'", items[0], o, items[1])
				} else if o == " is null" {
					return fmt.Sprintf("(%s %s %s) or (%s %s '%s')", items[0], "=", "NULL", items[0], "=", "")
				} else if o == " in " {
					items[1] = strings.TrimSpace(items[1])
					if strings.HasPrefix(items[1], "(") && strings.HasSuffix(items[1], ")") {
						items[1] = items[1][1 : len(items[1])-1]
					}
					ins := []string{}
					for _, i := range strings.Split(items[1], ",") {
						ins = append(ins, fmt.Sprintf("'%s'", i))
					}
					return fmt.Sprintf("(%s %s (%s))", items[0], o, strings.Join(ins, ","))
				}

			}
		}
		return s

	}

	pats := strings.Join(patterns, "|")
	if re, err := regexp.Compile(pats); err != nil {
		log.Error(err)
	} else {
		s = re.ReplaceAllStringFunc(s, replace)
		return s
	}
	return ""

}

func (this *Common) GetMap(data map[string]string, key string, value string) string {
	if v, ok := data[key]; ok {
		return v
	} else {
		return value
	}
}

func (this *Common) Contains(obj interface{}, target interface{}) (bool, error) {
	targetValue := reflect.ValueOf(target)
	switch reflect.TypeOf(target).Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < targetValue.Len(); i++ {
			if targetValue.Index(i).Interface() == obj {
				return true, nil
			}
		}
	case reflect.Map:
		if targetValue.MapIndex(reflect.ValueOf(obj)).IsValid() {
			return true, nil
		}
	}
	return false, errors.New("not in")
}

func (this *Common) GetAllIps() []string {
	ips := []string{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		panic(err)
	}
	for _, addr := range addrs {
		ip := addr.String()
		pos := strings.Index(ip, "/")
		if match, _ := regexp.MatchString("(\\d+\\.){3}\\d+", ip); match {
			if pos != -1 {
				ips = append(ips, ip[0:pos])
			}
		}
	}
	return ips
}

func (this *Common) GetLocalIP() string {

	ips := this.GetAllIps()
	for _, v := range ips {
		if strings.HasPrefix(v, "10.") || strings.HasPrefix(v, "172.") || strings.HasPrefix(v, "192.") {
			return v
		}
	}
	return "127.0.0.1"

}

func (this *Common) SendToFalcon(metrics []*MetricValue) {
	url := Config().FalconURL
	if url == "" {
		return
	}
	request, err := httplib.Post(url).
		SetTimeout(3*time.Second, 3*time.Second).
		Header("Connection", "close").
		JSONBody(metrics)
	if err != nil {
		log.Error(err)
		return
	}
	_, err = request.String()
	if err != nil {
		log.Error(err)
		return
	}
}

func (this *Common) ParseZkInfo(conf string, dbtype string) (map[string]string, error) {
	data := make(map[string]string)

	db := ""
	host := ""
	passowrd := ""
	port := ""
	user := ""

	if dbtype == "mysql" {

		data["path"] = Config().ZkDB.Path
		data["cmd"] = Config().ZkDB.Cmd

		db = Config().ZkDB.DB
		host = Config().ZkDB.Host
		port = Config().ZkDB.Port
		passowrd = Config().ZkDB.Passowrd
		user = Config().ZkDB.User
		dbtype = Config().ZkDB.DBType

	}
	if dbtype == "redis" {

		data["path"] = Config().ZkRedis.Path
		data["cmd"] = Config().ZkRedis.Cmd

		db = Config().ZkRedis.DB
		host = Config().ZkRedis.Host
		port = Config().ZkRedis.Port
		passowrd = Config().ZkRedis.Passowrd
		user = Config().ZkRedis.User
		dbtype = Config().ZkRedis.DBType

	}

	dbconf := make(map[string]string)

	dbconf["db"] = db
	dbconf["password"] = passowrd
	dbconf["host"] = host
	dbconf["user"] = user
	dbconf["port"] = port
	dbconf["dbtype"] = dbtype

	var conf2 map[string]interface{}

	if err := json.Unmarshal([]byte(conf), &conf2); err != nil {
		log.Error("ParseDBConfig", err)
		return dbconf, err
	}

	if dbtype == "mysql" {

		if v, ok := conf2[Config().ZkDB.Host]; ok {
			host = v.(string)
			hosts := strings.Split(host, ",")
			host = hosts[0]

		}
		if v, ok := conf2[Config().ZkDB.Port]; ok {

			port = v.(string)
			ports := strings.Split(port, ",")
			port = ports[0]
		}
		if v, ok := conf2[Config().ZkDB.Passowrd]; ok {
			passowrd = v.(string)
		}

		if v, ok := conf2[Config().ZkDB.User]; ok {
			user = v.(string)
		}

		if v, ok := conf2[Config().ZkDB.DB]; ok {
			db = v.(string)
		}

		if v, ok := conf2[Config().ZkDB.DBType]; ok {
			dbtype = v.(string)
		}
	}
	if dbtype == "redis" {
		if v, ok := conf2[Config().ZkRedis.Host]; ok {
			host = v.(string)
			hosts := strings.Split(host, ",")
			host = hosts[0]
		}
		if v, ok := conf2[Config().ZkRedis.Port]; ok {
			port = v.(string)
			ports := strings.Split(port, ",")
			port = ports[0]
		}
		if v, ok := conf2[Config().ZkRedis.Passowrd]; ok {
			passowrd = v.(string)
		}

		if v, ok := conf2[Config().ZkRedis.User]; ok {
			user = v.(string)
		}

		if v, ok := conf2[Config().ZkRedis.DB]; ok {
			db = v.(string)
		}

		if v, ok := conf2[Config().ZkRedis.DBType]; ok {
			dbtype = v.(string)
		}
	}

	dbconf["db"] = db
	dbconf["password"] = passowrd
	dbconf["host"] = host
	dbconf["user"] = user
	dbconf["port"] = port
	dbconf["dbtype"] = dbtype
	return dbconf, nil
}

func (this *Common) SqliteCache(db *sql.DB, records []map[string]interface{}, table string, is_drop bool) error {
	hashKeys := map[string]struct{}{}

	for _, record := range records {
		for key, _ := range record {
			hashKeys[key] = struct{}{}
		}
	}

	keys := []string{}

	for key, _ := range hashKeys {
		keys = append(keys, key)
	}

	is_drop = true

	if is_drop {
		db.Exec(fmt.Sprintf("DROP TABLE %s", table))

		query := "CREATE TABLE %s (" + strings.Join(keys, ",") + ")"

		query = fmt.Sprintf(query, table)

		_, err := db.Exec(query)
		if err != nil {

			return log.Error(
				err, "can't create table",
			)
		}

	}

	query := "CREATE TABLE %s (" + strings.Join(keys, ",") + ")"

	query = fmt.Sprintf(query, table)

	db.Exec(query)

	CheckTableExist := func(table string) bool {
		query := fmt.Sprintf("select count(1) as cnt from sqlite_master  where type='table' and name='%s'", table)
		rows, err := db.Query(query)
		ret := false
		if err == nil {
			if rows.Next() {
				id := 0
				rows.Scan(&id)
				if id == 1 {
					return true
				} else {
					return false
				}
			}
		}
		return ret
	}

	_ = CheckTableExist

	GetTableCols := func(table string) ([]string, error) {
		query := fmt.Sprintf("select *  from %s where 1=0", table)

		rows, err := db.Query(query)

		fmt.Println(query)

		if err == nil {
			return rows.Columns()
		} else {
			return []string{}, err
		}

	}

	_ = GetTableCols

	for _, record := range records {
		recordKeys := []string{}
		recordValues := []string{}
		recordArgs := []interface{}{}

		for key, value := range record {
			recordKeys = append(recordKeys, key)
			recordValues = append(recordValues, "?")
			recordArgs = append(recordArgs, value)
		}

		query := "INSERT INTO data (" + strings.Join(recordKeys, ",") +
			") VALUES (" + strings.Join(recordValues, ", ") + ")"

		statement, err := db.Prepare(query)
		if err != nil {
			log.Error(
				err, "can't prepare query: %s", query,
			)
			continue
		}

		_, err = statement.Exec(recordArgs...)
		if err != nil {
			log.Error(
				err, "can't insert record",
			)
		}
		statement.Close()

	}

	return nil
}

func (this *Common) GetHttpHeader(r *http.Request, key string) string {
	val := ""
	if headers, ok := r.Header[key]; ok {
		val = headers[0]
	}
	return val

}

func (this *Common) Base64Encode(str string) string {

	return base64.StdEncoding.EncodeToString([]byte(str))
}

func (this *Common) GetClientIp(r *http.Request) string {

	client_ip := ""
	headers := []string{"X_Forwarded_For", "X-Forwarded-For", "X-Real-Ip",
		"X_Real_Ip", "Remote_Addr", "Remote-Addr"}
	for _, v := range headers {
		if _v, ok := r.Header[v]; ok {
			if len(_v) > 0 {
				client_ip = _v[0]
				break
			}
		}
	}
	if client_ip == "" {
		clients := strings.Split(r.RemoteAddr, ":")
		client_ip = clients[0]
	}
	return client_ip

}

func (this *Common) MD5(str string) string {

	md := md5.New()
	md.Write([]byte(str))
	return fmt.Sprintf("%x", md.Sum(nil))
}

func (this *Common) GetUUID() string {

	b := make([]byte, 48)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	id := this.MD5(base64.URLEncoding.EncodeToString(b))
	return fmt.Sprintf("%s-%s-%s-%s-%s", id[0:8], id[8:12], id[12:16], id[16:20], id[20:])

}

func (this *Common) IsExist(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil || os.IsExist(err)
}

func (this *Common) ReadFile(path string) string {
	if this.IsExist(path) {
		fi, err := os.Open(path)
		if err != nil {
			return ""
		}
		defer fi.Close()
		fd, err := ioutil.ReadAll(fi)
		return string(fd)
	} else {
		return ""
	}
}

func (this *Common) WriteFile(path string, content string) bool {
	var f *os.File
	var err error
	if this.IsExist(path) {
		f, err = os.OpenFile(path, os.O_RDWR, 0666)

	} else {
		f, err = os.Create(path)
	}
	if err == nil {
		defer f.Close()
		if _, err = io.WriteString(f, content); err == nil {
			return true
		} else {
			return false
		}
	} else {
		return false
	}

}

func (this *Common) CliRequest(url string, data map[string]string) string {
	body := "{}"

	if pdata, err := json.Marshal(data); err == nil {
		body = string(pdata)
	}
	req := httplib.Post(url)

	req.Param("param", body)
	req.SetTimeout(time.Second*10, time.Second*60)
	str, err := req.String()
	if err != nil {
		log.Error(err)
		return err.Error()
	}
	return str
}

func (this *Common) Ssh(ip string, port int, user string, pwd string, cmd string, key string) (string, error) {

	PassWd := []ssh.AuthMethod{ssh.Password(pwd)}
	if key != "" {
		signer, err := ssh.ParsePrivateKey([]byte(key))
		if err == nil {
			if pwd != "" {
				PassWd = []ssh.AuthMethod{ssh.Password(pwd), ssh.PublicKeys(signer)}
			} else {
				PassWd = []ssh.AuthMethod{ssh.PublicKeys(signer)}
			}
		} else {
			return err.Error(), err
		}
	}

	Conf := ssh.ClientConfig{User: user, Auth: PassWd, Timeout: time.Second * 3, HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return nil
	}}
	addr := ip + ":" + fmt.Sprintf("%d", port)
	Client, err := ssh.Dial("tcp", addr, &Conf)

	if err != nil {

		message := err.Error() + "\t" + addr
		log.Error(message)
		return err.Error(), errors.New(message)
	}
	defer Client.Close()

	var bufOut bytes.Buffer
	if session, err := Client.NewSession(); err == nil {
		defer session.Close()
		session.Stdout = &bufOut
		session.Stderr = &bufOut

		modes := ssh.TerminalModes{
			ssh.ECHO:          1,     // disable echoing
			ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
			ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
		}

		if err := session.RequestPty("vt100", 80, 40, modes); err != nil {
			log.Error("RequestPty:" + err.Error() + "\t" + addr)
		}
		err := session.Run(cmd)

		if err != nil {
			message := err.Error() + "\t" + addr + "\tbufOut:" + bufOut.String()
			log.Error(message)
			return err.Error(), errors.New(message)

		} else {
			return string(bufOut.Bytes()), nil

		}
	} else {
		return err.Error(), err
	}

}

func (this *CliServer) GetAuthInfo(r *http.Request, body map[string]string) (*TChAuth, string) {

	token := this.util.GetHttpHeader(r, "Token")

	if token == "" {

		if body == nil {
			r.ParseForm()
			param := ""
			if _, ok := r.PostForm["param"]; ok {
				param = r.PostForm["param"][0]
			} else {
				return nil, "param is null"

			}

			body := make(map[string]string)
			if err := json.Unmarshal([]byte(param), &body); err == nil {
				if _token, ok := body["token"]; ok {
					token = _token
				}
			}

		} else {
			if _token, ok := body["token"]; ok {
				token = _token
			}
		}

	}

	if Config().Debug {
		log.Debug("token", token)
	}

	if token == "" {
		return nil, "token is null"
	} else {
		authBean, ok := safeAuthMap.GetValue(token)
		if ok {
			//			fmt.Println(authBean)
			return authBean, ""
		} else {
			return nil, "token not found"
		}
	}

}

func (this *CliServer) CheckApiPermit(r *http.Request, body map[string]string) (bool, string, *TChAuth) {
	user := ""
	ip := ""
	ips := ""
	flag := false

	if _user, ok := body["u"]; ok {
		user = _user
	} else {
		return false, "(error)-u(user) is required", nil
	}

	if _ips, ok := body["i"]; ok {
		ips = _ips
	} else {
		return false, "(error)ip is required", nil
	}

	ip = this.util.GetClientIp(r)

	var authBean *TChAuth

	if authBean, _ = this.GetAuthInfo(r, body); authBean != nil {

		if authBean.Fsudo == 0 && user != authBean.Fuser {
			log.Error("CheckApiPermit (error)invalid user", fmt.Sprintf("user:%v authBean:%v", user, authBean.Fuser))
			return false, "(error)invalid user", nil
		}
		for _, i := range strings.Split(authBean.Fip, ",") {

			if i == ip {
				flag = true
				break
			}

		}

		if !flag {
			log.Error("CheckApiPermit (error)ip not permit", fmt.Sprintf("ip:%v authBean:%v", ip, authBean.Fip))
			return false, "(error)ip not permit", nil
		}

		wb, ok := safeTokenMap.GetValue(authBean.Ftoken)
		//		fmt.Println(wb.blackips, wb.whiteips)
		if ok {

			ipset := mapset.NewSet()
			for _, i := range strings.Split(ips, ",") {
				ipset.Add(i)
			}
			bi := ipset.Intersect(wb.blackips)

			if bi.Cardinality() > 0 {
				return false, fmt.Sprintf("(error) ips:%s", bi.String()), nil
			}
			if wb.whiteips.Contains("*") {
				return true, "success", authBean
			}
			if wb.whiteips.Cardinality() > 0 {
				bi = ipset.Difference(wb.whiteips)
				if bi.Cardinality() > 0 {
					return false, fmt.Sprintf("(error) ips:%s", bi.String()), nil
				} else {
					return true, "success", authBean
				}
			}

		}
	} else {
		return false, "(error)token not exist", nil
	}

	if flag {
		return true, "success", authBean
	} else {
		return false, "(error)ip not in white list", nil
	}

}

func (this *CliServer) getEtcdServer(ip string) string {
	hosts := Config().EtcdGuest.Server
	hlen := len(hosts)
	ip_parts := strings.Split(ip, ".")
	last := 0
	if len(ip_parts) == 4 {
		if v, er := strconv.Atoi(ip_parts[3]); er == nil {
			last = v
		}
	}
	i := last % hlen
	return hosts[i]

}

func (this *CliServer) getEtcd(ip string) HeartBeatEtcd {
	etcdServers := []string{this.getEtcdServer(ip)}
	etcd := HeartBeatEtcd{}
	etcd.Password = Config().EtcdGuest.Password
	etcd.Prefix = Config().EtcdGuest.Prefix
	etcd.User = Config().EtcdGuest.User
	etcd.Server = etcdServers
	return etcd
}

func (this *CliServer) SendToMail(to, subject, body, mailtype string) error {
	host := Config().Mail.Host
	user := Config().Mail.User
	password := Config().Mail.Password
	hp := strings.Split(host, ":")
	auth := smtp.PlainAuth("", user, password, hp[0])
	var content_type string
	if mailtype == "html" {
		content_type = "Content-Type: text/" + mailtype + "; charset=UTF-8"
	} else {
		content_type = "Content-Type: text/plain" + "; charset=UTF-8"
	}

	msg := []byte("To: " + to + "\r\nFrom: " + user + ">\r\nSubject: " + "\r\n" + content_type + "\r\n\r\n" + body)
	send_to := strings.Split(to, ";")
	err := smtp.SendMail(host, auth, user, send_to, msg)
	return err
}

func (this *CliServer) Mail(w http.ResponseWriter, r *http.Request) {

	defer func(t time.Time) {
		log.Info("CostTime:", time.Since(t))
	}(time.Now())

	r.ParseForm()
	param := r.PostForm["param"][0]

	if Config().Debug {
		log.Info(param)
	}

	to := ""
	subject := ""
	content := ""
	mtype := "text"

	body := make(map[string]string)
	message := make(map[string]string)
	message["message"] = "ok"
	message["status"] = "fail"
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error(err)
		message["message"] = err.Error()
		w.Write([]byte(this.util.JsonEncode(message)))
		return
	}

	if _to, ok := body["t"]; ok {
		to = _to
	} else {
		message["message"] = "(error)-t(to) required"
		w.Write([]byte(this.util.JsonEncode(message)))
		return
	}
	if _to, ok := body["s"]; ok {
		subject = _to
	} else {
		message["message"] = "(error)-s(subject) required"
		w.Write([]byte(this.util.JsonEncode(message)))
		return
	}
	if _to, ok := body["c"]; ok {
		content = _to
	} else {
		message["message"] = "(error)-c(content) required"
		w.Write([]byte(this.util.JsonEncode(message)))
		return
	}

	if _to, ok := body["mail_type"]; ok {
		mtype = _to
	}

	if err := this.SendToMail(to, subject, content, mtype); err != nil {
		message["message"] = err.Error()
		w.Write([]byte(this.util.JsonEncode(message)))
		return
	} else {
		message["message"] = "ok"
		message["status"] = "ok"
		w.Write([]byte(this.util.JsonEncode(message)))
		return
	}
}

func (this *CliServer) ExecCmd(ip string, cmd string, kw map[string]string) (string, error) {

	defer func() {
		if re := recover(); re != nil {
			buffer := debug.Stack()
			log.Error("ExecCmd Eerror")
			log.Error(fmt.Sprintln("%s %s %v", ip, cmd, kw))
			log.Error(re)
			log.Error(string(buffer))
		}
	}()
	var wg sync.WaitGroup
	etcdMsg := make(chan *EtcdMsg, 1024)
	sT := time.Now()
	workers := len(strings.Split(ip, ","))
	if workers > 10 {
		workers = 10
	}
	if workers == 0 {
		workers = 1
	}

	for i := 0; i < workers; i++ {
		go workerEtcd(&wg, etcdMsg)
	}

	url_error := ""
	url_success := ""
	url := ""
	user := ""
	output := "text"
	timeout := 25
	async := "0"
	sudo := "0"
	callback := ""

	if _url, ok := kw["url"]; ok {
		url = _url
	}
	if _url_error, ok := kw["url_error"]; ok {
		url_error = _url_error
	}
	if _url_success, ok := kw["url_success"]; ok {
		url_success = _url_success
	}
	if _user, ok := kw["u"]; ok {
		user = _user
	}
	if _output, ok := kw["o"]; ok {
		output = _output
	}
	if _timeout, ok := kw["t"]; ok {
		timeout, _ = strconv.Atoi(_timeout)

	}
	if _async, ok := kw["async"]; ok {
		async = _async

	}
	if _sudo, ok := kw["sudo"]; ok {
		sudo = _sudo

	}

	if v, ok := kw["callback"]; ok {
		callback = v

	}

	//	 cmd=u"su '%s' -c \"%s\"" %(user, cmd.replace('"','\\"'))

	if sudo != "1" && user == "root" {

		return "(error) user root not permit", errors.New("(error) user root not permit")

	}

	if sudo == "0" && user != "" {
		cmd = fmt.Sprintf("su %s -c \"%s\"", user, strings.Replace(cmd, "\"", "\\\"", -1))
	}

	c := this.rp.Get()
	defer c.Close()

	failsip := []string{}
	ips := strings.Split(ip, ",")
	ipset := mapset.NewSet()
	for _, ip := range ips {
		ipset.Add(ip)
	}

	taskid2IP := map[string]string{}
	for _ip := range ipset.Iter() {

		ip := _ip.(string)

		hb, ok := safeMap.GetValue(ip)
		//		fmt.Println(ip, hb)
		if !ok {
			failsip = append(failsip, ip)
			continue
		}

		salt := hb.Salt
		uuid := hb.Uuid
		md5 := this.util.MD5(cmd + salt)

		task_id := this.util.MD5(this.util.GetUUID())

		data := make(map[string]interface{})
		data["md5"] = md5
		data["task_id"] = task_id
		data["cmd"] = cmd
		data["url"] = url
		data["ip"] = ip
		data["url_error"] = url_error
		data["url_success"] = url_success
		data["user"] = user
		data["ctime"] = time.Now().Unix()
		if callback != "" {
			data["unix_time"] = fmt.Sprintf("%d", time.Now().Unix())
		}
		for k, v := range kw {
			data[k] = v
		}
		data["i"] = ip
		if timeout > 3 {
			data["timeout"] = strconv.Itoa(timeout - 1)
		}

		jdata := this.util.JsonEncode(data)

		//		if callback != "" && strings.HasPrefix(callback, "http") {
		//			c.Do("hset", CONST_CALLBACK_PARAMETERS_KEY, task_id, jdata)
		//		}

		c.Do("lpush", CONST_RESULT_LIST_KEY, jdata)
		c.Do("sadd", CONST_TASK_LIST_KEY, task_id)

		etcdMsg <- &EtcdMsg{
			Url:           this.getEtcdServer(ip) + "/keeper/servers/" + uuid,
			Value:         jdata,
			Etcdbasicauth: this.etcdbasicauth,
		}

		taskid2IP[task_id] = ip
	}
	close(etcdMsg)
	wg.Wait()
	log.Info("Etcd CostTime:", time.Since(sT))

	context := []string{}
	results := map[string]*Result{}

	GetSyncResult := func() string {
		ok := make(chan int)
		exit := false
		go func() {

			//may be redis is PoolExhausted
			//			c := this.rp.Get()
			//			defer c.Close()
			for {
				num := 0

				for k, _ := range taskid2IP {
					key := CONST_RESULT_KEY_PREFIX + k
					c.Send("GET", key)
					num++
				}

				c.Flush()

				for i := 0; i < num; i++ {
					result, err := redis.Bytes(c.Receive())
					if err != nil {
						// log.Warn("Receive Error:", err)
						continue
					}
					var ret Result
					if err := json.Unmarshal(result, &ret); err != nil {
						log.Warn("Unmarshal Error:", err)
						continue
					}
					// resultSets[ret.TaskId].Result = &ret
					results[taskid2IP[ret.TaskId]] = &ret
					context = append(context, []string{
						"--------------------------------------------------------------------------------",
						taskid2IP[ret.TaskId],
						ret.Result,
					}...)

					delete(taskid2IP, ret.TaskId)
				}

				mLen := len(taskid2IP)
				if mLen == 0 {
					ok <- 1
					break
				}

				if exit {
					ok <- 1
					break
				}

				time.Sleep(time.Millisecond * time.Duration(300))
			}
		}()

		select {
		case <-ok:
		case <-time.After(time.Duration(timeout) * time.Second):
			exit = true
			<-ok
			log.Info("timeout:", timeout)
		}

		for k, v := range taskid2IP {
			context = append(context, []string{
				"--------------------------------------------------------------------------------",
				v,
				"(error) timeout feedback results",
			}...)
			var uuid string
			hb, ok := safeMap.GetValue(v)
			if ok {
				uuid = hb.Uuid
			}
			results[v] = &Result{
				Cmd:        cmd,
				Error:      "(error) timeout feedback results",
				I:          v,
				Ip:         uuid,
				ReturnCode: -1,
				Result:     "(error) timeout feedback results",
				TaskId:     k,
			}
		}

		data3 := make([]interface{}, 0)

		for k, v := range results {

			data1 := map[string]interface{}{
				"cmd":         v.Cmd,
				"error":       v.Error,
				"i":           k,
				"index":       v.Index,
				"ip":          v.Ip,
				"result":      v.Result,
				"return_code": v.ReturnCode,
				"s":           v.S,
				"success":     v.Success,
				"task_id":     v.TaskId,
			}
			data3 = append(data3, map[string]interface{}{
				k: data1,
			})
		}
		resultsBody := ""
		if output == "json" {
			r, err := json.Marshal(map[string]interface{}{
				"failsip": strings.Join(failsip, ","),
				//				"results":  []map[string]*Result{results},
				"results": data3,
			})
			if err != nil {
				fmt.Println(err)
			}
			//			fmt.Println(string(r))
			resultsBody = string(r)

		} else {
			resultsBody = strings.Join(context, "\n")
			resultsBody += "\nfails:\n" + strings.Join(failsip, "\n")
		}

		return resultsBody

	}

	GetASyncResult := func(output string) string {

		if output == "json" {
			results := []ResultMap{}
			for result, ip := range taskid2IP {
				hb, ok := safeMap.GetValue(ip)
				if ok {
					_result := ResultMap{}
					_result[ip] = &Result{
						Cmd:        cmd,
						Error:      "",
						I:          ip,
						Ip:         hb.Uuid,
						ReturnCode: -1,
						Result:     result,
						TaskId:     result,
					}
					results = append(results, _result)
				}
			}
			jsonResults := JsonOutPut{}
			jsonResults.Results = results
			jsonResults.FailsIp = strings.Join(failsip, ",")
			r, _ := json.Marshal(&jsonResults)
			return string(r)

		} else {
			textResults := []string{}
			for result, ip := range taskid2IP {
				out := NewPlainTextOutPut(ip, result)
				textResults = append(textResults, out.String())
			}
			return fmt.Sprintf("%s\nfails:\n%s", strings.Join(textResults, ""), strings.Join(failsip, "\n"))
		}
	}

	result := ""

	if async == "1" {
		result = GetASyncResult(output)

	} else {
		result = GetSyncResult()

	}

	return result, nil
}

func (this *CliServer) SaveIntervalCmd(ip string, cmd string, kw map[string]string, interval int) {
	c := this.rp.Get()
	defer c.Close()
	ips := strings.Split(ip, ";")
	now := time.Now().Unix()
	for i, v := range ips {
		var data IntervalCmd
		data.Ip = v
		data.Kw = kw
		data.Cmd = cmd
		delta, _ := strconv.ParseInt(fmt.Sprintf("%d", interval+i*interval), 10, 64)
		data.EndTime = now + delta
		c.Do("lpush", CONST_INTERVAL_CMDS_LIST_KEY, this.util.JsonEncode(data))
	}

}

func (this *CliServer) V2Api(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()

	param := make(map[string]string)

	if _, ok := r.PostForm["param"]; !ok {

		for k, v := range r.Form {
			if len(r.Form[k]) > 1 {
				param[k] = strings.Join(v, "")
			} else {
				param[k] = v[0]
			}

		}
		r.Form["param"][0] = this.util.JsonEncode(param)
	}

	//	fmt.Print(r.Po["param"][0])

}

func (this *CliServer) Api(w http.ResponseWriter, r *http.Request) {

	if Config().UseGor {
		w.Write([]byte("please set use_gor=false"))
		return
	}

	defer func(t time.Time) {
		log.Info("CostTime:", time.Since(t))
	}(time.Now())

	r.ParseForm()
	param := r.PostForm["param"][0]

	if Config().Debug {
		log.Info(param)
	}

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	}

	//	msg := make(map[string]string)

	addr := strings.Split(r.RemoteAddr, ":")
	if len(addr) != 2 {
		w.Write([]byte("remote addr error"))
		return
	}

	//	isWhitel := false
	//	for _, _ip := range Config().WhitelIps {
	//		if strings.EqualFold(addr[0], string(_ip)) {
	//			isWhitel = true
	//			break
	//		}
	//	}

	//	if !isWhitel {
	//		log.Info("ip not in whitel list")
	//		w.Write([]byte("ip not in whitel list"))
	//		return
	//	}

	cmd := ""
	ip := ""

	interval := 30

	if _cmd, ok := body["c"]; ok {
		cmd = _cmd
	} else {
		w.Write([]byte("-c(cmd) is reqiured"))
		return
	}

	if _ip, ok := body["i"]; ok {
		ip = _ip
	} else {
		w.Write([]byte("-i(ip) is reqiured"))
		return
	}

	if v, ok := body["interval"]; ok {
		interval, _ = strconv.Atoi(v)
		ips := strings.Split(ip, ";")
		if len(ips) > 1 {
			ip = ips[0]
			this.SaveIntervalCmd(strings.Join(ips[1:], ";"), cmd, body, interval)
		}

	}

	var authBean *TChAuth
	var ok bool
	var msg string
	if ok, msg, authBean = this.CheckApiPermit(r, body); !ok {

		w.Write([]byte(msg))
		return
	}
	if authBean != nil {
		this.apiTokenHit(authBean.Ftoken, true)
	}
	this.LogReqToRedis(r, "API", "system", nil)

	result, _ := this.ExecCmd(ip, cmd, body)

	w.Write([]byte(result))

}
func (this *CliServer) apiTokenHit(token string, is_success bool) {

	if is_success {
		tokenCounterMap.Add(token)
	}

}

func (this *CliServer) GetIpFromRange(iprange string) mapset.Set {
	GetIPS := func(iprange string) mapset.Set {
		ipset := mapset.NewSet()
		if iprange == "" {
			return ipset
		}
		if iprange == "*" {
			ipset.Add("*")
			return ipset
		}
		ips := strings.Split(iprange, ".")
		if len(ips) == 4 && ips[3] == "0" {
			prefix := strings.Join(ips[0:3], ".")
			for i := 0; i < 255; i++ {

				ipset.Add(prefix + "." + strconv.Itoa(i))
			}
		} else if (len(ips) == 4) && strings.Contains(ips[3], "-") {
			prefix := strings.Join(ips[0:3], ".")
			segs := strings.Split(ips[3], "-")
			start, _ := strconv.Atoi(segs[0])
			end, _ := strconv.Atoi(segs[1])
			for i := start; i < end+1; i++ {
				ipset.Add(prefix + "." + strconv.Itoa(i))
			}

		} else if len(ips) == 4 {
			ipset.Add(iprange)
			return ipset
		}

		return ipset

	}

	ipset := mapset.NewSet()

	segs := strings.Split(iprange, ",")
	for _, seg := range segs {
		ipset = ipset.Union(GetIPS(seg))
	}
	return ipset

}

func (this *CliServer) RefreshMachineInfo() {
	defer func() {
		if re := recover(); re != nil {
			fmt.Println("RefreshMachineInfo", re)
			log.Error("RefreshMachineInfo", re)
		}
	}()

	c := this.rp.Get()
	defer c.Close()
	uuids, _ := redis.Strings(c.Do("SMEMBERS", CONST_UUIDS_KEY))

	for _, v := range uuids {
		c.Send("GET", v)
	}
	c.Flush()
	for i := 0; i < len(uuids); i++ {
		if result, ok := c.Receive(); result != nil && ok == nil {
			var obj MiniHeartBeat
			if err := json.Unmarshal(result.([]byte), &obj); err != nil {
				continue
			}

			safeMap.Put(obj.Ip, &obj)

		}
	}

	authBeans := make([]TChAuth, 0)
	err := engine.Where("1=1").Find(&authBeans)

	if err == nil {
		for i, v := range authBeans {
			safeAuthMap.Put(v.Ftoken, &authBeans[i])
			if Config().Debug {
				//				log.Debug(v)
			}
		}
	} else {
		log.Error(err)

	}

}

type EtcdMsg struct {
	Url           string
	Value         string
	Etcdbasicauth string
}

func workerEtcd(wg *sync.WaitGroup, etcdMsg <-chan *EtcdMsg) {

	defer func() {
		if re := recover(); re != nil {
			log.Error(re)
			buffer := debug.Stack()
			log.Error(string(buffer))
		}
	}()

	wg.Add(1)
	defer wg.Done()

	for {
		msg, ok := <-etcdMsg
		if ok {

			if USE_ETCD_CLINET {

				kapi := cli.kapi
				paths := strings.Split(msg.Url, CONST_ETCD_PREFIX)
				if len(paths) == 2 {
					fmt.Println("Set:", paths[1], msg.Value)
					_, err := kapi.CreateInOrder(context.Background(), paths[1], msg.Value, nil)
					if err != nil {
						fmt.Println("Set error:", err)
						//						fmt.Println("resp:", *resp)
					}
					//				fmt.Println("resp:", *resp)
				}

			} else {

				req := httplib.Post(msg.Url)
				req.Header("Authorization", msg.Etcdbasicauth)
				req.Param("value", msg.Value)
				req.Param("ttl", "600")

				req.SetTimeout(3*time.Second, 3*time.Second)

				_, err := req.String()
				if err != nil {
					log.Error(msg.Url, err.Error(), msg.Value)
				}

				/*
					res, err := req.Response()


					if res.Body != nil {
						defer res.Body.Close()
					}

					if err != nil {
						log.Error("wokerEtcd Error:", err, msg)
					} else {

						if res.StatusCode != 200 && res.StatusCode != 201 {
							data, er := ioutil.ReadAll(res.Body)
							if er == nil {
								//						fmt.Println(string(data))
								log.Error(string(data))
							} else {
								log.Error(er.Error())
							}

						}
					}
				*/
			}

		} else {
			break
		}
	}

}

func (this *CliServer) WriteEtcd(url string, value string) string {

	req := httplib.Post(url)

	req.Header("Authorization", this.etcdbasicauth)
	req.Param("value", value)
	req.SetTimeout(time.Second*10, time.Second*60)
	str, err := req.String()
	//	fmt.Println(str)
	if err != nil {
		log.Error(err)
		print(err)
	}
	return str

}

func (this *CliServer) WaitForResult() {

}

func (this *CliServer) AutoRepair() {

	defer func() {
		if re := recover(); re != nil {
			buffer := debug.Stack()
			log.Error(string(buffer))
		}
	}()

	sts := this._getStatus("offline")

	c := this.rp.Get()
	defer c.Close()

	ips, err := redis.Strings(c.Do("SMEMBERS", CONST_REMOVE_IPLIST_KEY))

	for _, v := range sts {
		if err == nil {
			if ok, _ := this.util.Contains(v.Ip, ips); !ok {
				this._repair(v.Ip)
			}
		} else {
			this._repair(v.Ip)
		}
	}

}

func (this *CliServer) ReportStatus() {

	defer func() {
		if re := recover(); re != nil {

			buffer := debug.Stack()
			log.Error(string(buffer))
		}
	}()

	data := this.checkstatus()

	log.Info(this.util.JsonEncode(data))

	values := []*MetricValue{}
	for k, v := range data {
		_v := 0
		if v == "ok" {
			_v = 1
		}
		val := &MetricValue{
			Endpoint: this.util.GetLocalIP(),
			Metric:   fmt.Sprintf("cli.middleware.%s", k),
			Value:    _v,
			Step:     60,
			Type:     "GAUGE",
		}

		values = append(values, val)

	}

	for k, v := range qpsMap.Get() {

		val := &MetricValue{
			Endpoint: this.util.GetLocalIP(),
			Metric:   fmt.Sprintf("cli.http.%s", k),
			Value:    v,
			Step:     60,
			Type:     "GAUGE",
		}

		values = append(values, val)

	}

	qpsMap.Zero()

	if len(values) > 0 {

		this.util.SendToFalcon(values)
	}

}

func (this *CliServer) Init() {
	this.etcd_host = Config().Etcd.Host
	etcdconf := &EtcdConf{User: Config().Etcd.User, Password: Config().Etcd.Pwd}
	this.util = &Common{}
	str := etcdconf.User + ":" + etcdconf.Password
	this.etcdbasicauth = "Basic " + this.util.Base64Encode(str)

	if !this.util.IsExist(CONST_UPLOAD_DIR) {
		os.Mkdir(CONST_UPLOAD_DIR, 777)
	}

	go func() {
		time.Sleep(time.Second * 2)
		ticker := time.NewTicker(time.Minute)
		for {
			this.RefreshMachineInfo()
			<-ticker.C
		}
	}()

	go func() {
		time.Sleep(time.Second * 2)

		status := cli.checkstatus()
		log.Info(cli.util.JsonEncode(status))
		fmt.Println(cli.util.JsonEncode(status))

		ticker := time.NewTicker(time.Minute)
		for {
			this.ReportStatus()
			<-ticker.C
		}
	}()

	if Config().AutoRepair {

		go func() {
			time.Sleep(time.Second * 2)
			ticker := time.NewTicker(time.Minute * 2)
			for {
				this.AutoRepair()
				<-ticker.C
			}
		}()

	}

	if Config().Result2DB {
		go cli.InsertResults()
	}

	go cli.DeleteResults()

	go cli.CallBacks()

	go cli.InsertLogAndUpdateHits()

	go cli.DispachIntervalCmds()

	go cli.BackendDeleteEtcdKeys()

}

func (this *CliServer) Feedback(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	param := r.PostForm["param"][0]

	//	fmt.Println(param)

	if Config().Debug {
		log.Info(param)
	}

	task_id := ""
	return_code := -1

	body := make(map[string]interface{})
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error("Feedback Unmarshal Error:", err)
		return
	}

	if _return_code, ok := body["return_code"]; ok {
		switch code := _return_code.(type) {
		case string:
			//			return_code, _ = strconv.Atoi(_return_code.(string))
			return_code, _ = strconv.Atoi(code)
		case int8:
			//			return_code = _return_code.(int)
			return_code = int(code)
		case int:
			//			return_code = _return_code.(int)
			return_code = code
		case int32:
			//			return_code = _return_code.(int32)
			return_code = int(code)
		case int64:
			//			return_code = _return_code.(int64)
			return_code = int(code)
		case float32:
			return_code = int(code)
		case float64:
			return_code = int(code)
		default:
			log.Error("other _return_code.(type):", code, reflect.TypeOf(_return_code).Name())
		}

	}
	body["return_code"] = return_code

	if _task_id, ok := body["task_id"]; ok {
		task_id = _task_id.(string)
	}

	dd := map[string]interface{}{}

	dd["utime"] = time.Now().Unix()
	dd["task_id"] = task_id

	if body["result"] == "1380013800" {
		dd["result"] = "(error) timeout"
	} else if _, ok := body["error"]; ok {
		dd["result"] = body["result"].(string) + body["error"].(string)
	} else {
		dd["result"] = body["result"]
	}

	jdd, err := json.Marshal(dd)
	if err != nil {
		log.Error("Marshal Error:", err, dd)
		return
	}

	c := this.rp.Get()
	defer c.Close()

	//	bflag, _ := redis.Bool(c.Do("HEXISTS", CONST_CALLBACK_PARAMETERS_KEY, task_id))

	if v, ok := body["kw"]; ok {

		switch v.(type) {
		case map[string]interface{}, map[string]string:
			if cb, o := v.(map[string]interface{})["callback"]; o {
				if cb != nil {
					callback := cb.(string)
					if strings.HasPrefix(callback, "http") {

						if data, err := json.Marshal(body); err == nil {
							c.Send("LPUSH", CONST_CALLBACK_LIST_KEY, string(data))
							c.Send("ltrim", CONST_CALLBACK_LIST_KEY, 0, 20000)
						}

					}
				}
			}
		}
		delete(body, "kw")

	}

	if data, err := json.Marshal(body); err == nil {
		c.Send("SETEX", CONST_RESULT_KEY_PREFIX+task_id, 60*5, string(data))
	}
	//	if bflag {
	//		c.Send("LPUSH", CONST_CALLBACK_LIST_KEY, task_id)
	//		c.Send("ltrim", CONST_CALLBACK_LIST_KEY, 0, 20000)
	//	}
	c.Send("LPUSH", CONST_RESULT_LIST_KEY, string(jdd))
	c.Send("ltrim", CONST_RESULT_LIST_KEY, 0, 20000)
	c.Send("SREM", CONST_TASK_LIST_KEY, task_id)
	c.Flush()
	w.Write([]byte("ok"))
}

func (this *CliServer) Help(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Sevice is ok"))
}

func (this *CliServer) Index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}

func (this *CliServer) getParam(r *http.Request) map[string]string {

	r.ParseForm()

	var body map[string]string

	if v, ok := r.PostForm["param"]; ok {
		if len(v) > 0 {
			json.Unmarshal([]byte(v[0]), &body)
		}
	}

	return body

}

func (this *CliServer) LogReqToRedis(r *http.Request, message string, user string, data map[string]string) {

	param := ""
	if data == nil {
		param = this.util.JsonEncode(this.getParam(r))
	} else {
		param = this.util.JsonEncode(data)
	}
	ip := this.util.GetClientIp(r)
	var lg TChLog
	lg.Fip = ip
	lg.Fparams = param
	lg.Furl = r.RequestURI
	lg.Fmessage = message
	lg.Fuser = user
	c := this.rp.Get()
	defer c.Close()

	c.Do("lpush", CONST_ASYNC_LOG_KEY, this.util.JsonEncode(lg))

}

func (this *CliServer) Register(w http.ResponseWriter, r *http.Request) {

	defer func(t time.Time) {
		log.Info("CostTime:", time.Since(t))
	}(time.Now())

	r.ParseForm()
	param := r.PostForm["param"][0]

	if Config().Debug {
		log.Info(param)
	}

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	}

	user := ""
	password := ""
	if _user, ok := body["u"]; ok {
		user = _user
	}
	if _pwd, ok := body["p"]; ok {
		password = _pwd
	}

	userBean := new(TChUser)
	engine.Find(userBean)
	has, err := engine.Where("Fuser=?", user).Get(userBean)
	if err != nil {
		return
	}
	if has {
		w.Write([]byte("(error)user exist"))
	} else {
		userBean.Fuser = user
		userBean.Fstatus = 0
		userBean.Fpwd = this.util.MD5(password)
		engine.Insert(userBean)
		w.Write([]byte("success"))

	}

}

func (this *CliServer) ListToken(w http.ResponseWriter, r *http.Request) {
	if !this.IsAdminFromHttp(r) {
		w.Write([]byte("(error)permit deny"))
		return
	}
	where := "1=1"
	body := this.getParam(r)
	if v, ok := body["t"]; ok {
		where = fmt.Sprintf("Ftoken='%s'", v)
	}
	authBeans := make([]TChAuth, 0)
	if err := engine.Where(where).Find(&authBeans); err != nil {
		w.Write([]byte(err.Error()))
		return
	}
	w.Write([]byte(this.util.JsonEncode(authBeans)))
}

func (this *CliServer) AddToken(w http.ResponseWriter, r *http.Request) {

	if !this.IsAdminFromHttp(r) {
		w.Write([]byte("(error)permit deny"))
		return
	}
	r.ParseForm()
	param := r.PostForm["param"][0]

	if Config().Debug {
		log.Info(param)
	}

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	}

	user := ""
	token := ""
	sudo := 0
	suod_ips := "*"
	ip := "127.0.0.1"
	desc := ""
	black_ips := ""
	url := "cli/api"
	if _user, ok := body["u"]; ok {
		user = _user
	} else {
		w.Write([]byte("(error)-u(user) is required"))
		return
	}

	if _ip, ok := body["i"]; ok {
		ip = ip + "," + _ip
	} else {
		w.Write([]byte("(error)-i(client_ip) is required"))
		return
	}

	if _token, ok := body["t"]; ok {
		token = _token
	} else {
		w.Write([]byte("(error)-t(token) is required"))
		return
	}

	if _desc, ok := body["d"]; ok {
		desc = _desc
	} else {
		w.Write([]byte("(error)-d(description,comment) is required"))
		return
	}
	if _black_ips, ok := body["b"]; ok {
		black_ips = _black_ips
	}

	if _sudo_ips, ok := body["w"]; ok {
		suod_ips = _sudo_ips
	}

	if _sudo, ok := body["s"]; ok {
		sudo, _ = strconv.Atoi(_sudo)
	}

	authBean := new(TChAuth)

	has, err := engine.Where("Ftoken=?", token).Get(authBean)
	if err != nil {
		w.Write([]byte("db error"))
		return
	}
	authBean.FblackIps = black_ips
	authBean.Fdesc = desc
	authBean.Fip = ip
	authBean.Fsudo = sudo
	authBean.Ftoken = token
	authBean.Fuser = user
	authBean.FsudoIps = suod_ips
	authBean.Furl = url
	fmt.Println(authBean.FsudoIps)
	if has {

		safeAuthMap.Put(token, authBean)
		engine.Cols("FblackIps", "Fdesc", "Fip", "Fsudo",
			"Ftoken", "Fuser", "Fblack_ips", "Fsudo_ips").Update(authBean, &TChAuth{Ftoken: token})
		w.Write([]byte("success"))

	} else {

		engine.Insert(authBean)
		w.Write([]byte("success"))

	}

}

func (this *CliServer) redisCache(body map[string]string) (string, error) {

	val := ""
	action := ""
	group := ""
	key := ""

	if _action, ok := body["a"]; ok {
		action = _action
	} else {
		return "", errors.New("-a(action) must be in get or set")

	}

	if _group, ok := body["g"]; ok {
		group = _group
	} else {
		return "", errors.New("-g(goup) is null")

	}

	if _key, ok := body["k"]; ok {
		key = _key
	} else {
		return "", errors.New("-k(key) is null")

	}
	if action != "get" && action != "set" && action != "flush" {

		return "", errors.New("-a(action) must be in get or set")

	}
	c := this.rp.Get()
	defer c.Close()
	cache_key := CONST_CACHE_KEY_PREFIX + group + "_" + key
	cache_group := CONST_CACHE_KEY_PREFIX + group
	if action == "get" {
		value, err := redis.String(c.Do("GET", cache_key))
		if err == nil {
			return value, nil
		} else {
			return "", err
		}

	} else if action == "set" {

		if _val, ok := body["v"]; ok {
			val = _val
		} else {
			return "", errors.New("-v(value) is required")

		}

		c.Do("sadd", cache_group, cache_key)

		_, err := c.Do("setex", cache_key, 60*60*12, val)
		if err == nil {
			return "success", nil

		} else {
			return "", err
		}
	} else if action == "flush" {
		keys, err := redis.Strings(c.Do("SMEMBERS", cache_group))
		if err == nil && len(keys) > 0 {
			for _, k := range keys {
				c.Send("DEL", k)
			}
			c.Flush()
			c.Do("DEL", cache_group)
			return "success", nil

		}

	} else {
		return "", errors.New("action not support")
	}
	return "", errors.New("action not support")

}

func (this *CliServer) GetCmdResult(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	param := r.PostForm["param"][0]

	if Config().Debug {
		log.Info(param)
	}
	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	}

	key := ""
	if _key, ok := body["k"]; ok {
		key = _key
	} else {
		w.Write([]byte("-k(key) is required"))
		return
	}
	c := this.rp.Get()
	defer c.Close()
	result, err := redis.String(c.Do("get", CONST_RESULT_KEY_PREFIX+key))
	if err != nil {
		w.Write([]byte(err.Error()))
	} else {
		w.Write([]byte(result))
	}

}

func (this *CliServer) RedisCache(w http.ResponseWriter, r *http.Request) {

	defer func(t time.Time) {
		log.Info("CostTime:", time.Since(t))
	}(time.Now())

	r.ParseForm()
	param := r.PostForm["param"][0]

	if Config().Debug {
		log.Info(param)
	}
	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	}

	result, err := this.redisCache(body)
	if err != nil {
		w.Write([]byte("{}"))
	} else {
		w.Write([]byte(result))
	}

}

func (this *CliServer) SSH(w http.ResponseWriter, r *http.Request) {

	defer func(t time.Time) {
		log.Info("CostTime:", time.Since(t))
	}(time.Now())

	r.ParseForm()
	param := r.PostForm["param"][0]

	if Config().Debug {
		log.Info(param)
	}

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	}
	ip := ""
	cmd := ""
	user := "root"
	pwd := "root"
	port := 22
	key := ""
	if _cmd, ok := body["c"]; ok {
		cmd = _cmd
	} else {
		w.Write([]byte("-c(cmd) is requred"))
		return
	}
	if _ip, ok := body["i"]; ok {
		ip = _ip
	} else {
		w.Write([]byte("-i(ip) is requred"))
		return
	}
	if _user, ok := body["u"]; ok {
		user = _user
	}
	if _pwd, ok := body["p"]; ok {
		pwd = _pwd
	}
	if _port, ok := body["P"]; ok {
		port_, err := strconv.Atoi(_port)
		if err != nil {
			w.Write([]byte("-P(port) must be number"))
			return
		} else {
			port = port_
		}
	}

	if v, ok := body["k"]; ok {
		key = v
	}

	if v, ok := body["key"]; ok {
		key = v
	}

	if result, err := this.util.Ssh(ip, port, user, pwd, cmd, key); err != nil {
		w.Write([]byte(err.Error()))
	} else {
		w.Write([]byte(result))
	}

}

func (this *CliServer) _repair(ip string) (string, error) {

	user := Config().Repair.User
	password := Config().Repair.Password
	port := Config().Repair.Port
	cmd := Config().Repair.Cmd
	keyfile := Config().Repair.KeyFile
	key := ""
	if this.util.IsExist(keyfile) {
		key = this.util.ReadFile(keyfile)
	} else {
		return "(error)keyfile not found", errors.New("(error)keyfile not found")
	}

	return this.util.Ssh(ip, port, user, password, cmd, key)
}

func (this *CliServer) Repair(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	param := r.PostForm["param"][0]

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	}

	ip := ""

	if v, ok := body["i"]; ok {
		ip = v
	} else {
		w.Write([]byte("-i(ip) is requred"))
		return
	}

	ips := strings.Split(ip, ",")
	for _, ip := range ips {
		if result, err := this._repair(ip); err != nil {
			w.Write([]byte(err.Error()))
		} else {
			w.Write([]byte(result))
		}
	}

}

func (this *CliServer) Shell(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	dir := r.PostForm.Get("dir")
	filename := r.PostForm.Get("file")
	dir = strings.Replace(dir, "..", "", -1)
	path := CONST_UPLOAD_DIR + "/" + dir + "/" + filename

	//	fmt.Println(path)
	if this.util.IsExist(path) {

		data, err := ioutil.ReadFile(path)
		if err == nil {
			w.Write(data)
		} else {
			//			w.Write([]byte("error"))
			w.Write([]byte(err.Error()))
		}

	} else {

		w.WriteHeader(404)
		w.Write([]byte("(error) file not found"))

	}
}

func (this *CliServer) ListFile(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()

	param := r.PostForm["param"][0]

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {

		w.Write([]byte(err.Error()))
		return
	}

	dir := ""
	if _dir, ok := body["d"]; ok {
		dir = _dir
	}
	dir = strings.Replace(dir, ".", "", -1)

	path := CONST_UPLOAD_DIR + "/" + dir + "/"

	dirlist, err := ioutil.ReadDir(path)
	if err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	}
	files := make([]string, 0)
	for _, v := range dirlist {
		files = append(files, v.Name())
	}
	w.Write([]byte(strings.Join(files, "\n")))

}

func (this *CliServer) Download(w http.ResponseWriter, r *http.Request) {

	queryForm, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {

		w.Write([]byte("param is error"))
		return
	}
	dir := queryForm["dir"][0]
	filename := queryForm["file"][0]
	dir = strings.Replace(dir, "..", "", -1)
	path := CONST_UPLOAD_DIR + "/" + dir + "/" + filename

	if this.util.IsExist(path) {

		data, err := ioutil.ReadFile(path)
		if err == nil {
			w.Write(data)
		} else {
			//			w.Write([]byte("error"))
			w.Write([]byte(err.Error()))
		}

	} else {
		if Config().UseFastDFS {
			var tchFile TChFiles
			engine.Where("Fuser=? and Fpath=?", dir, path).Get(&tchFile)
			if tchFile.Furl != "" {
				if this.DownLoadFromFastDFS(tchFile.Furl, path) {
					log.Info(fmt.Sprintf("DownLoadFromFastDFS:%s", path))
					data, err := ioutil.ReadFile(path)
					if err == nil {
						w.Write(data)
						return
					} else {
						//			w.Write([]byte("error"))
						w.Write([]byte(err.Error()))
						return
					}
				}
			}
		}
		w.WriteHeader(404)
		w.Write([]byte("(error) file not found"))

	}

}

func (this *CliServer) Login(w http.ResponseWriter, r *http.Request) {

	defer func(t time.Time) {
		log.Info("CostTime:", time.Since(t))
	}(time.Now())

	r.ParseForm()
	param := r.PostForm["param"][0]

	if Config().Debug {
		log.Info(param)
	}

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	}

	user := ""
	password := ""
	if _user, ok := body["u"]; ok {
		user = _user
	}
	if _pwd, ok := body["p"]; ok {
		password = _pwd
	}

	userBean := new(TChUser)

	has, err := engine.Where("Fuser=? and Fpwd=?", user, this.util.MD5(password)).Get(userBean)
	if err != nil {
		w.Write([]byte("db error"))
	}
	if has {
		c := this.rp.Get()
		defer c.Close()
		uuid := this.util.GetUUID()
		//		fmt.Println("login", user)
		c.Do("setex", CONST_LOGIN_PREFIX_KEY+uuid, 5*60, user)
		w.Write([]byte(uuid))
	} else {
		hasuser, err := engine.Where("Fuser=? ", user).Get(userBean)
		if err != nil {
			w.Write([]byte("db error"))
		}
		if hasuser {
			w.Write([]byte("(error) password is error"))
		} else {
			w.Write([]byte("(error) user is not found"))
		}

	}

}

func (this *CliServer) GetLoginUser(r *http.Request) (string, error) {
	uuid := ""
	if uuids, ok := r.Header["Auth-Uuid"]; ok {
		uuid = uuids[0]
	}
	c := this.rp.Get()
	defer c.Close()
	user, err := redis.String(c.Do("GET", CONST_LOGIN_PREFIX_KEY+uuid))
	return user, err

}

func (this *CliServer) GetLoginUserInfo(r *http.Request) (*TChUser, error) {
	uuid := ""

	if uuids, ok := r.Header["Auth-Uuid"]; ok {
		uuid = uuids[0]
	}
	c := this.rp.Get()
	defer c.Close()
	user, err := redis.String(c.Do("GET", CONST_LOGIN_PREFIX_KEY+uuid))
	userBean := new(TChUser)

	//	fmt.Println(uuid)

	if user != "" {
		_, err = engine.Where("Fuser=?", user).Get(userBean)
	}
	return userBean, err

}

func (this *CliServer) DelFile(w http.ResponseWriter, r *http.Request) {

	userBean, er := this.GetLoginUserInfo(r)

	//	fmt.Println(userBean)

	if userBean.Fuser != "" && userBean.Fstatus == 0 {

		w.Write([]byte("(error)user not permit"))

		return

	}

	if er != nil || userBean.Fuser == "" {
		w.Write([]byte("(error)unauthorize"))
		return

	} else {

		r.ParseForm()
		if "POST" == r.Method {

			param := r.PostForm["param"][0]

			body := make(map[string]string)
			if err := json.Unmarshal([]byte(param), &body); err != nil {

				w.Write([]byte(err.Error()))
				return
			}
			filename := ""
			if _filename, ok := body["f"]; ok {
				filename = _filename
			} else {
				w.Write([]byte("-f(filename) require"))
				return
			}
			dir := userBean.Fuser
			path := CONST_UPLOAD_DIR + "/" + dir + "/" + filename
			if this.util.IsExist(path) {
				err := os.Remove(path)
				if err == nil {
					w.Write([]byte("sucess"))
					return
				} else {
					w.Write([]byte(err.Error()))
					return
				}
			} else {
				w.Write([]byte("Not Found"))
			}

		}
	}
}

func (this *CliServer) UploadToFastDFS(file string) string {
	if Config().FastDFS.UploadURL == "" {
		log.Warn("please config fastdfs")
		return ""
	}
	req := httplib.Post(Config().FastDFS.UploadURL)
	req.PostFile("file", file)
	var result map[string]interface{}
	if err := req.ToJSON(&result); err != nil {
		log.Error(err)
		return ""
	}
	if v, ok := result[Config().FastDFS.ReturnKey]; ok {
		return v.(string)
	}
	return ""
}

func (this *CliServer) DownLoadFromFastDFS(url string, file string) bool {
	req := httplib.Get(url)
	if err := req.ToFile(file); err != nil {
		return false
	} else {
		return true
	}
}

func (this *CliServer) Upload(w http.ResponseWriter, r *http.Request) {

	userBean, er := this.GetLoginUserInfo(r)

	//	fmt.Println(userBean)

	if userBean.Fuser != "" && userBean.Fstatus == 0 {

		w.Write([]byte("(error)user not permit"))

		return

	}

	if er != nil || userBean.Fuser == "" {
		w.Write([]byte("(error)unauthorize"))
		return

	} else {

		r.ParseForm()
		if "POST" == r.Method {

			file, _, err := r.FormFile("file")
			filename := r.PostForm.Get("filename")
			filename = strings.Replace(filename, "..", "", -1)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			defer file.Close()
			path := CONST_UPLOAD_DIR + "/" + userBean.Fuser

			if !this.util.IsExist(path) {
				os.Mkdir(path, 777)
			}

			fpath := CONST_UPLOAD_DIR + "/" + userBean.Fuser + "/" + filename

			f, err := os.Create(fpath)
			defer f.Close()
			io.Copy(f, file)
			f.Seek(0, 0)
			md5h := md5.New()
			io.Copy(md5h, f)
			sum := fmt.Sprintf("%x", md5h.Sum(nil))
			data := make(map[string]string)
			data["filename"] = filename
			data["md5"] = sum
			this.LogReqToRedis(r, "upload", userBean.Fuser, data)
			url := ""
			if Config().UseFastDFS {
				url = this.UploadToFastDFS(fpath)
			}
			var tchFile TChFiles
			engine.Where("Fuser=? and Fpath=?", userBean.Fuser, fpath).Get(&tchFile)
			if tchFile.Furl == "" {
				tchFile.Furl = Config().FastDFS.Host + url
				tchFile.Fpath = fpath
				tchFile.Fuser = userBean.Fuser
				tchFile.Ffilename = filename
				tchFile.Fmd5 = sum
				tchFile.Fctime = time.Now().Format("2006-01-02 15:04:05")
				tchFile.Futime = tchFile.Fctime
				if _, err := engine.Insert(&tchFile); err != nil {
					log.Error(err)
				}
			} else {
				tchFile.Furl = url
				tchFile.Fpath = fpath
				tchFile.Fuser = userBean.Fuser
				tchFile.Ffilename = filename
				tchFile.Fmd5 = sum
				tchFile.Futime = time.Now().Format("2006-01-02 15:04:05")
				if _, err := engine.Update(&tchFile, &TChFiles{Fuser: userBean.Fuser, Fpath: fpath}); err != nil {
					log.Error(err)
				}
			}

			w.Write([]byte("success"))

		}
	}
}

func (this *CliServer) CheckPort(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()

	if len(r.PostForm["param"]) == 0 {
		w.Write([]byte("(error)param is required"))
		return
	}

	param := r.PostForm["param"][0]
	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {

		w.Write([]byte(err.Error()))
		return
	}
	ip := ""
	port := 0

	if v, ok := body["i"]; ok {
		ip = v
	}
	if v, ok := body["p"]; ok {
		if _port, err := strconv.Atoi(v); err != nil {

			w.Write([]byte("(error) -p(port) must be int"))
			return

		} else {
			port = _port
		}
	}

	flag := this.util.CheckPort(ip, port)
	if flag {
		w.Write([]byte("ok"))
	} else {
		w.Write([]byte("fail"))
	}
}

func (this *CliServer) DeleteEtcdKey(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	if _, ok := r.PostForm["host"]; !ok {
		w.Write([]byte("delete key error,host not found"))
		return
	}
	if _, ok := r.PostForm["key"]; !ok {
		w.Write([]byte("delete key error,key not found"))
		return
	}

	host := r.PostForm["host"][0]
	key := r.PostForm["key"][0]
	url := host + key

	bflag := false

	for _, v := range Config().EtcdGuest.Server {
		if len(v) > 15 && len(host) > 15 && v[0:15] == host[0:15] {
			bflag = true
			break
		}
	}

	if bflag {
		//		c := this.rp.Get()
		//		defer c.Close()
		//		c.Do("lpush", CONST_REMOVE_ETCD_LIST_KEY, url)
		//		cli.etcdDelKeys <- url
		//		w.Write([]byte("ok"))
	} else {
		w.Write([]byte("error"))
	}
	if bflag {
		req := httplib.Delete(url)
		req.Header("Authorization", this.etcdbasicauth)
		req.SetTimeout(time.Second*2, time.Second*2)
		_, err := req.String()
		if err != nil {
			log.Error(err)
		}
	}

}

func (this *CliServer) CheckTokenIp(r *http.Request) (bool, string) {

	ip := ""

	flag := false
	addr := strings.Split(r.RemoteAddr, ":")
	if len(addr) == 2 {
		ip = addr[0]
	}

	if authBean, _ := this.GetAuthInfo(r, nil); authBean != nil {

		for _, i := range strings.Split(authBean.Fip, ",") {

			if i == ip {
				flag = true
				break
			}

		}
	} else {
		return false, "(error)token not exist"
	}

	if flag {
		return true, "success"
	} else {
		return false, "(error)ip not in white list"
	}
}

func (this *CliServer) BenchMark(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	param := "{}"
	if _param, ok := r.PostForm["param"]; ok {
		param = _param[0]
	}
	body := make(map[string]string)
	kw := make(map[string]string)
	kw["t"] = "5"
	if err := json.Unmarshal([]byte(param), &body); err == nil {

		if _t, ok := body["t"]; ok {
			kw["t"] = _t
		}
	}

	if Config().BenchMark {
		ips := ""
		total := 0
		success := 0
		fail := 0
		for _, v := range safeMap.Get() {
			if len(v.Ip) == 36 {
				ips = ips + "," + v.Ip
				total = total + 1
			}
		}
		kw["o"] = "json"
		now := time.Now()
		result, _ := this.ExecCmd(ips, "echo ok", kw)
		var out JsonOutPut
		data := make(map[string]string)
		if err := json.Unmarshal([]byte(result), &out); err == nil {
			for _, resultMap := range out.Results {
				for _, v := range resultMap {
					if strings.TrimSpace(v.Result) == "ok" {
						success = success + 1
					} else {
						fail = fail + 1
					}
				}
			}
			cost := time.Since(now)
			data["cost"] = cost.String()
			data["success"] = strconv.Itoa(success)
			data["fail"] = strconv.Itoa(fail)
			data["total"] = strconv.Itoa(total)
			w.Write([]byte(this.util.JsonEncode(data)))

		} else {

			w.Write([]byte(result))
		}

	} else {
		w.Write([]byte("benchmark not support"))
	}

}

func (this *CliServer) IsExistGoogleCode(ga *TChGoogleAuth) (bool, *TChGoogleAuth) {
	tga := TChGoogleAuth{}
	if ok, _ := engine.Where("Fuser=? and Fplatform=?", ga.Fuser, ga.Fplatform).Get(&tga); ok {
		return true, &tga
	} else {
		return false, &tga
	}
}

func (this *CliServer) GoogleCodeAdd(ga *TChGoogleAuth) (bool, string) {

	if ga.Fseed == "" {
		return false, "seed is null"
	}
	if ga.Fuser == "" {
		return false, "user is null"
	}
	if ga.Fplatform == "" {
		return false, "platform is null"
	}

	tga := TChGoogleAuth{}

	bflag := false

	if ok, _ := engine.Where("Fuser=? and Fplatform=?", ga.Fuser, ga.Fplatform).Get(&tga); ok {
		num, er := engine.Update(ga, &tga)
		if num > 0 && er != nil {
			bflag = true
		}
	} else {
		num, er := engine.Insert(ga)
		if er != nil {
			fmt.Println(er)
		}
		if num > 0 && er != nil {
			bflag = true
		}
	}

	if bflag {
		return true, "ok"
	} else {
		return true, "fail"
	}
}

func (this *CliServer) VerifyGoogleCode(w http.ResponseWriter, r *http.Request) {

	data := make(map[string]string)
	data["status"] = "fail"
	data["message"] = "fail"

	if ok, msg := this.CheckTokenIp(r); !ok {
		data["message"] = msg
		ret := this.util.JsonEncode(data)
		w.Write([]byte(ret))
		return

	}
	r.ParseForm()
	param := r.PostForm["param"][0]
	code := ""
	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		data["message"] = "param is error ,not json format,{string:string}"
		ret := this.util.JsonEncode(data)
		w.Write([]byte(ret))
		return
	}
	if _code, ok := body["c"]; ok {
		code = _code
	} else {

		data["message"] = "(error)-c(code) required"
		ret := this.util.JsonEncode(data)
		w.Write([]byte(ret))
		return
	}

	if _, ok := body["p"]; !ok {
		data["message"] = "(error)-p(platform) required"
		ret := this.util.JsonEncode(data)
		w.Write([]byte(ret))
		return
	}
	if _, ok := body["u"]; !ok {
		data["message"] = "(error)-u(user) required"
		ret := this.util.JsonEncode(data)
		w.Write([]byte(ret))
		return
	}

	ga := TChGoogleAuth{}
	if err := json.Unmarshal([]byte(param), &ga); err != nil {
		log.Error("TChGoogleAuth Unmarshal Error:", err)
		return
	}

	if ok, tga := this.IsExistGoogleCode(&ga); ok {

		goauth := googleAuthenticator.NewGAuth()
		if ok, _ := goauth.VerifyCode(tga.Fseed, code, 5); ok {

			data["status"] = "ok"
			data["message"] = "ok"
			data["data"] = tga.Fseed //for jumpserver
			ret := this.util.JsonEncode(data)
			w.Write([]byte(ret))
			return
		}

	}
	ret := this.util.JsonEncode(data)
	w.Write([]byte(ret))

}

func (this *CliServer) GenGoogleAuth(w http.ResponseWriter, r *http.Request) {

	data := make(map[string]string)
	data["status"] = "fail"
	data["message"] = "fail"
	if ok, msg := this.CheckTokenIp(r); !ok {

		data["message"] = msg
		ret := this.util.JsonEncode(data)
		w.Write([]byte(ret))
		return

	}
	r.ParseForm()
	param := r.PostForm["param"][0]

	ga := TChGoogleAuth{}
	if err := json.Unmarshal([]byte(param), &ga); err != nil {
		data["message"] = err.Error()
		ret := this.util.JsonEncode(data)
		w.Write([]byte(ret))
		return
	}

	if ok, _ := this.IsExistGoogleCode(&ga); !ok {
		goauth := googleAuthenticator.NewGAuth()
		seed, er := goauth.CreateSecret(16)
		if er != nil {
			data["message"] = er.Error()
			ret := this.util.JsonEncode(data)
			w.Write([]byte(ret))
			return
		}
		ga.Fseed = seed
		_, msg := this.GoogleCodeAdd(&ga)
		data["message"] = msg
		ret := this.util.JsonEncode(data)
		w.Write([]byte(ret))
		return

	} else {
		data["message"] = "google key is exist"
		ret := this.util.JsonEncode(data)
		w.Write([]byte(ret))
		return
	}

}

func (this *CliServer) GoogleCodeSync(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	data := make(map[string]string)
	data["status"] = "fail"
	if ok, msg := this.CheckTokenIp(r); !ok {
		data["message"] = msg
		ret := this.util.JsonEncode(data)
		w.Write([]byte(ret))
		return

	}
	param := ""
	if _, ok := r.PostForm["param"]; ok {
		if len(r.PostForm["param"]) > 0 {
			param = r.PostForm["param"][0]
		} else {
			data["message"] = "param is null"
			ret := this.util.JsonEncode(data)
			w.Write([]byte(ret))
			return
		}
	}

	//	param := r.PostForm["param"][0]
	body := make(map[string]interface{})
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		data["message"] = err.Error()
		ret := this.util.JsonEncode(data)
		w.Write([]byte(ret))
		return
	}

	if _, ok := body["p"]; !ok {
		data["message"] = "(error)-p(platform) required"
		ret := this.util.JsonEncode(data)
		w.Write([]byte(ret))
		return
	}
	if _, ok := body["u"]; !ok {
		data["message"] = "(error)-u(user) required"
		ret := this.util.JsonEncode(data)
		w.Write([]byte(ret))
		return
	}

	if _, ok := body["s"]; !ok {
		data["message"] = "(error)-s(seed) required"
		ret := this.util.JsonEncode(data)
		w.Write([]byte(ret))
		return
	}

	ga := TChGoogleAuth{}
	if err := json.Unmarshal([]byte(param), &ga); err != nil {
		log.Error("TChGoogleAuth Unmarshal Error:", err)
		data["message"] = err.Error()
		ret := this.util.JsonEncode(data)
		w.Write([]byte(ret))
		return
	} else {
		ok, msg := this.GoogleCodeAdd(&ga)
		if ok {
			data["message"] = "ok"
			data["status"] = "ok"
			ret := this.util.JsonEncode(data)
			w.Write([]byte(ret))
			return
		} else {
			data["message"] = msg
			data["status"] = "fail"
			ret := this.util.JsonEncode(data)
			w.Write([]byte(ret))
			return
		}
	}

}

func (this *CliServer) GetIpByStatus(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	param := r.PostForm["param"][0]

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error("Heartbeat Unmarshal Error:", err)
		return
	}

	status := ""
	if _s, ok := body["s"]; ok {
		status = _s
	}
	if status != "online" && status != "offline" {
		w.Write([]byte("(error) -s(status) must be online or offline"))
		return
	}

	ipset := mapset.NewSet()
	now := time.Now().Unix()
	sts := safeMap.Get()
	for _, v := range sts {

		var _utime time.Time
		var err error

		if _utime, err = time.ParseInLocation("2006-01-02 15:04:05", v.Utime, time.Local); err != nil {
			continue
		}

		utime := _utime.Unix()

		if status == "online" && (now-utime) < CONST_MACHINE_OFFLINE_TIME {
			ipset.Add(v.Ip)
		} else if status == "offline" && (now-utime) > CONST_MACHINE_OFFLINE_TIME {
			ipset.Add(v.Ip)
		}
	}

	var ips []string
	for i := range ipset.Iter() {
		ips = append(ips, i.(string))
	}
	w.Write([]byte(strings.Join(ips, ",")))

}

func (this *CliServer) RunStatus(w http.ResponseWriter, r *http.Request) {
	data := make(map[string]string)

	data["num_goroutine"] = strconv.Itoa(runtime.NumGoroutine())

	data["num_cpu"] = strconv.Itoa(runtime.NumCPU())

	memStat := new(runtime.MemStats)

	runtime.ReadMemStats(memStat)

	data["Alloc"] = fmt.Sprintf("%d", memStat.Alloc)
	data["TotalAlloc"] = fmt.Sprintf("%d", memStat.TotalAlloc)
	data["HeapAlloc"] = fmt.Sprintf("%d", memStat.HeapAlloc)
	data["Frees"] = fmt.Sprintf("%d", memStat.Frees)
	data["HeapObjects"] = fmt.Sprintf("%d", memStat.HeapObjects)
	data["NumGC"] = fmt.Sprintf("%d", memStat.NumGC)
	data["GCCPUFraction"] = fmt.Sprintf("%f", memStat.GCCPUFraction)
	data["GCSys"] = fmt.Sprintf("%d", memStat.GCSys)

	w.Write([]byte(this.util.JsonEncode(data)))

}

func (this *CliServer) Cmdb(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	param := r.PostForm["param"][0]

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error("Heartbeat Unmarshal Error:", err)
		return
	}

	cols := "*"

	tag := ""
	group := ""
	if v, ok := body["t"]; ok {
		tag = v
	} else {

		w.Write([]byte("(error)-t(tag) is require,if -t is null then return 1 row"))
		return
	}

	if v, ok := body["c"]; ok {
		cols = v
	}

	if v, ok := body["g"]; ok {
		group = fmt.Sprintf("group by %s", v)
	}

	s := "select %s from data where 1=1 and %s %s"

	if tag == "" {
		tag = " limit 1"
		s = "select %s from data where 1=1   %s %s"
	}

	s = fmt.Sprintf(s, cols, this.util.BuildSql(tag), group)

	rows, err := sqliteCache.Query(s)

	if err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	}
	defer rows.Close()

	records := []map[string]interface{}{}
	for rows.Next() {
		record := map[string]interface{}{}

		columns, err := rows.Columns()
		if err != nil {
			log.Error(
				err, "unable to obtain rows columns",
			)
			continue
		}

		pointers := []interface{}{}
		for _, column := range columns {
			var value interface{}
			pointers = append(pointers, &value)
			record[column] = &value
		}

		err = rows.Scan(pointers...)
		if err != nil {
			log.Error(err, "can't read result records")
			continue
		}

		for key, value := range record {
			indirect := *value.(*interface{})
			if value, ok := indirect.([]byte); ok {
				record[key] = string(value)
			} else {
				record[key] = indirect
			}
		}

		records = append(records, record)
	}

	jsoned, err := json.MarshalIndent(records, "", "     ")
	if err != nil {
		log.Error(err, "can't encode output data into JSON")
		w.Write([]byte("can't encode output data into JSON"))
		return
	}

	w.Write(jsoned)

}

func (this *CliServer) LoadCmdb(w http.ResponseWriter, r *http.Request) {

	var value interface{}
	var file *os.File
	for _, p := range []string{"cmdb.json", "script/cmdb.json", "scripts/cmdb.json"} {

		if this.util.IsExist(p) {
			if _file, err := os.Open(p); err != nil {
				w.Write([]byte(err.Error()))
				return
			} else {
				defer _file.Close()
				file = _file
				break
			}

		}
	}

	err := json.NewDecoder(file).Decode(&value)
	if err != nil {
		log.Error(
			err, "invalid input data",
		)
		w.Write([]byte("invalid input data"))
		return
	}

	records := []map[string]interface{}{}

	switch value := value.(type) {
	case map[string]interface{}:
		records = []map[string]interface{}{value}

	case []interface{}:
		for _, subvalue := range value {
			if subvalue, ok := subvalue.(map[string]interface{}); ok {
				records = append(records, subvalue)
			} else {
				log.Error(
					errors.New("must be object or array of objects"),
					"invalid input data",
				)
			}
		}

	default:
		log.Error(
			errors.New("must be object or array of objects"),
			"invalid input data",
		)
	}

	Push := func(records []map[string]interface{}) error {
		hashKeys := map[string]struct{}{}

		for _, record := range records {
			for key, _ := range record {
				hashKeys[key] = struct{}{}
			}
		}

		keys := []string{}

		for key, _ := range hashKeys {
			keys = append(keys, key)
		}

		sqliteCache.Exec("DROP TABLE data")
		query := "CREATE TABLE data (" + strings.Join(keys, ",") + ")"
		if _, err := sqliteCache.Exec(query); err != nil {
			return err
		}

		for _, record := range records {
			recordKeys := []string{}
			recordValues := []string{}
			recordArgs := []interface{}{}

			for key, value := range record {
				recordKeys = append(recordKeys, key)
				recordValues = append(recordValues, "?")
				recordArgs = append(recordArgs, value)
			}

			query := "INSERT INTO data (" + strings.Join(recordKeys, ",") +
				") VALUES (" + strings.Join(recordValues, ", ") + ")"

			statement, err := sqliteCache.Prepare(query)
			if err != nil {
				log.Error(
					err, "can't prepare query: %s", query,
				)
				continue

			}

			_, err = statement.Exec(recordArgs...)
			if err != nil {
				log.Error(
					err, "can't insert record",
				)

			}
			statement.Close()
		}

		return nil
	}

	err = Push(records)

	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}

	w.Write([]byte("ok"))

}

func (this *CliServer) checkstatus() map[string]string {
	data := make(map[string]string)
	data["redis"] = "fail"
	data["db"] = "fail"
	data["etcd"] = "fail"

	if this.util.CheckEnginer(engine) {
		data["db"] = "ok"
	}
	if this.rp.ActiveCount() != this.rp.MaxActive {
		c := this.rp.Get()
		defer c.Close()
		c.Do("set", "hello", "world")
		if result, err := redis.String(c.Do("get", "hello")); err == nil && result == "world" {
			data["redis"] = "ok"
		}
	}
	url := Config().EtcdGuest.Server[0] + Config().EtcdGuest.Prefix + "/hello"
	val := this.WriteEtcd(url, "world")
	result := make(map[string]interface{})
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		data["etcd"] = "fail"
	}

	if val, ok := result["node"]; ok {
		switch node := val.(type) {
		case map[string]interface{}:
			if k, o := node["value"]; o {
				if k == "world" {
					data["etcd"] = "ok"
				}
			}

		}
	}

	return data

}

func (this *CliServer) CheckStatus(w http.ResponseWriter, r *http.Request) {
	data := this.checkstatus()
	w.Write([]byte(this.util.JsonEncode(data)))
}

func (this *CliServer) ConfirmOffline(w http.ResponseWriter, r *http.Request) {

	sts := this._getStatus("offline")
	c := this.rp.Get()
	defer c.Close()
	for _, v := range sts {
		c.Do("srem", CONST_UUIDS_KEY, v.Uuid)
		safeMap.Del(v.Ip)
	}
	w.Write([]byte("ok"))

}

func (this *CliServer) _getStatus(status string) []*MiniHeartBeatStatus {
	var sts = make([]*MiniHeartBeatStatus, 0)
	now := time.Now().Unix()

	for _, v := range safeMap.Get() {

		var _utime time.Time
		var err error
		if _utime, err = time.ParseInLocation("2006-01-02 15:04:05", v.Utime, time.Local); err != nil {
			continue
		}
		utime := _utime.Unix()
		if status == "online" && (now-utime) < CONST_MACHINE_OFFLINE_TIME {

			st := MiniHeartBeatStatus{Status: v.Status, Ip: v.Ip, Uuid: v.Uuid, Utime: v.Utime, Platform: v.Platform}
			sts = append(sts, &st)
		}
		if status == "offline" && (now-utime) >= CONST_MACHINE_OFFLINE_TIME {

			st := MiniHeartBeatStatus{Status: v.Status, Ip: v.Ip, Uuid: v.Uuid, Utime: v.Utime, Platform: v.Platform}
			sts = append(sts, &st)
		}

	}
	return sts
}

func (this *CliServer) GetStatus(w http.ResponseWriter, r *http.Request) {

	if _, err := this.GetLoginUser(r); err != nil {
		w.Write([]byte("(error)not permit"))
		return
	}
	r.ParseForm()
	param := r.PostForm["param"][0]

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error("Heartbeat Unmarshal Error:", err)
		return
	}
	status := ""
	p := strings.LastIndex(r.RequestURI, "/")
	if p > 0 {
		status = r.RequestURI[p+1:]

	}

	sts := this._getStatus(status)

	w.Write([]byte(this.util.JsonEncode(sts)))

}

func (this *CliServer) UnRepair(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	param := r.PostForm["param"][0]

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error("Heartbeat Unmarshal Error:", err)
		return
	}

	ip := ""
	action := "list"
	if _ip, ok := body["i"]; ok {
		ip = _ip
	} else {
		w.Write([]byte("(error)-i(ip) is required"))
		return
	}

	if v, ok := body["a"]; ok {
		action = v
	}

	c := this.rp.Get()
	defer c.Close()

	if action == "add" {
		c.Do("SADD", CONST_REMOVE_IPLIST_KEY, ip)
		w.Write([]byte(fmt.Sprintf("add %s success", ip)))
		return
	}
	if action == "del" {
		c.Do("SREM", CONST_REMOVE_IPLIST_KEY, ip)
		w.Write([]byte(fmt.Sprintf("del %s success", ip)))
		return
	}

	if action == "list" {
		if ips, err := redis.Strings(c.Do("SMEMBERS", CONST_REMOVE_IPLIST_KEY)); err != nil {
			w.Write([]byte(err.Error()))
			return
		} else {
			w.Write([]byte(this.util.JsonEncode(ips)))
			return
		}
	}
	w.Write([]byte("-a(action) must be 'add' or 'del' or 'list' "))

}

func (this *CliServer) Upgrade(w http.ResponseWriter, r *http.Request) {
	fn := "cli.mini"
	if this.util.IsExist(fn) {
		if cli, err := ioutil.ReadFile(fn); err == nil {
			w.Write(cli)
		}

	}

}

func (this *CliServer) Status(w http.ResponseWriter, r *http.Request) {
	total := 0
	online := 0
	offline := 0
	var status = make(map[string]int)
	now := time.Now().Unix()
	sts := safeMap.Get()
	for _, v := range sts {
		var _utime time.Time
		var err error
		if _utime, err = time.ParseInLocation("2006-01-02 15:04:05", v.Utime, time.Local); err != nil {
			continue
		}
		utime := _utime.Unix()
		total++
		if (now - utime) < CONST_MACHINE_OFFLINE_TIME {
			online++
		}
	}
	offline = total - online
	status["online"] = online
	status["offline"] = offline
	status["count"] = total
	if data, err := json.Marshal(status); err == nil {
		w.Write(data)
	}
}

func (this *CliServer) _SetUserStatus(user string, status int) (bool, error) {

	userBean := new(TChUser)

	has, err := engine.Where("Fuser=?", user).Get(userBean)
	if err != nil {
		return false, err
	}
	if has {
		userBean.Fuser = user
		userBean.Fstatus = status
		engine.Id(userBean.Fid).Update(userBean)

		return true, nil
	} else {

		return false, err
	}

}

func (this *CliServer) IsAdmin(user string) bool {

	if strings.Trim(user, " ") == "" {
		return false
	}

	for _, u := range Config().SuperAdmin {
		if u == user {
			return true

		}
	}
	return false

}

func (this *CliServer) CallBacks() {

	type CallBackParam struct {
		Url    string
		TaskId string
		Result Result
	}

	CallBckChannels := make(chan CallBackParam, 8196)

	Clean := func() {

		defer func() {
			if err := recover(); err != nil {
				fmt.Println(err)
				log.Error("Clean", err)
			}
		}()
		c := cli.rp.Get()
		defer c.Close()
		if keys, err := redis.Strings(c.Do("hkeys", CONST_CALLBACK_PARAMETERS_KEY)); err == nil {
			now := time.Now().Unix()
			for _, k := range keys {
				v, e := redis.String(c.Do("hget", CONST_CALLBACK_PARAMETERS_KEY, k))
				if e != nil {
					c.Do("hdel", CONST_CALLBACK_PARAMETERS_KEY, k)
					log.Error("lost callback", v)
					continue
				}
				var data map[string]string
				if er := json.Unmarshal([]byte(v), &data); er == nil {
					if snow, ok := data["unix_time"]; ok {
						if n, e := strconv.ParseInt(snow, 10, 64); e == nil {
							if now-n > 60*30 {
								c.Do("hdel", CONST_CALLBACK_PARAMETERS_KEY, k)
							}
						}
					}
				} else {
					log.Error(er, v)
				}
			}
		} else {
			log.Error(err)
		}

	}

	Dispatch := func() {

		cb := func() {
			defer func() {
				if err := recover(); err != nil {
					fmt.Println(err)
					log.Error("Dispatch", err)
				}
			}()

			param := <-CallBckChannels
			rjson := param.Result
			task_id := param.TaskId

			request := httplib.Post(param.Url).
				SetTimeout(5*time.Second, 10*time.Second).
				Header("Connection", "close").Param("cmd", rjson.Cmd).
				Param("i", rjson.I).Param("result", rjson.Result).
				Param("error", rjson.Error).Param("ip", rjson.Ip).
				Param("s", rjson.S).Param("return_code", fmt.Sprintf("%v", rjson.ReturnCode)).
				Param("success", rjson.Success).Param("task_id", task_id)

			_, err := request.String()
			if err != nil {
				fmt.Println(err)
				log.Error(err)

			}
		}

		for i := 0; i < 200; i++ {
			go func() {
				for {
					cb()
				}
			}()
		}

	}
	/*
		CallBack := func() {

			defer func() {
				if err := recover(); err != nil {
					fmt.Println(err)
					log.Error("CallBack", err)
				}
			}()

			c := cli.rp.Get()
			defer c.Close()

			for {

				var err error
				var rjson Result

				var params map[string]string
				task_id := ""
				json_str_param := ""
				json_str_result := ""

				task_id, err = redis.String(c.Do("rpop", CONST_CALLBACK_LIST_KEY))
				if err != nil || task_id == "" {
					break
				}

				if json_str_param, err = redis.String(c.Do("hget", CONST_CALLBACK_PARAMETERS_KEY, task_id)); err != nil {
					break
				}
				c.Do("hdel", CONST_CALLBACK_PARAMETERS_KEY, task_id)
				if err = json.Unmarshal([]byte(json_str_param), &params); err != nil {
					fmt.Println(err)
					break
				}

				if json_str_result, err = redis.String(c.Do("GET", CONST_RESULT_KEY_PREFIX+task_id)); err != nil {

					continue
				} else {

					if err := json.Unmarshal([]byte(json_str_result), &rjson); err != nil {
						continue
					}

					if url, ok := params["callback"]; ok {
						var callbackParam CallBackParam
						callbackParam.Url = url
						callbackParam.Result = rjson
						callbackParam.TaskId = task_id
						CallBckChannels <- callbackParam

					}

				}

			}

		}
	*/

	CallBack := func() {

		defer func() {
			if err := recover(); err != nil {
				fmt.Println(err)
				log.Error("CallBack", err)
			}
		}()

		c := cli.rp.Get()
		defer c.Close()
		var kw map[string]string

		for {

			var err error
			var rjson Result
			str_json := ""

			str_json, err = redis.String(c.Do("rpop", CONST_CALLBACK_LIST_KEY))
			if err != nil || str_json == "" {
				break
			}

			if err = json.Unmarshal([]byte(str_json), &rjson); err != nil {
				log.Error(err, str_json)
				continue
			}

			if url, ok := rjson.Kw["callback"]; ok {
				var callbackParam CallBackParam
				callbackParam.Url = url
				callbackParam.Result = rjson
				callbackParam.TaskId = rjson.TaskId
				rjson.Kw = kw
				CallBckChannels <- callbackParam

			}

		}

	}

	go func() {
		for {
			time.Sleep(time.Millisecond * 200)
			CallBack()
		}
	}()

	//	go func() {
	//		for {
	//			t := time.Tick(time.Minute * 20)
	//			<-t
	//			Clean()
	//		}
	//	}()

	_ = Clean
	go func() {
		Dispatch()
	}()

}

func (this *CliServer) InsertLogAndUpdateHits() {

	InsertLogAndUpdateHit := func() {
		defer func() {
			if err := recover(); err != nil {
				log.Error("InsertLogAndUpdateHits", err)
			}
		}()
		c := cli.rp.Get()
		defer c.Close()
		for {
			js, err := redis.String(c.Do("rpop", CONST_ASYNC_LOG_KEY))
			if err != nil || js == "" {
				break
			}
			var result TChLog
			err = json.Unmarshal([]byte(js), &result)
			if err != nil {
				log.Error(err)
				continue
			}
			_, err = engine.Insert(&result)
			if err != nil {
				log.Error(err)
				log.Error("js", js)

			}
		}

		data := tokenCounterMap.Get()
		for token, v := range data {
			if v.(int) > 0 {
				auth := new(TChAuth)
				engine.Where("Ftoken=?", token).Get(auth)
				auth.Fhit = auth.Fhit + v.(int)
				var au TChAuth
				au.Ftoken = token
				engine.Update(auth, &au)
			}
		}
		tokenCounterMap.Zero()

	}

	go func() {
		for {
			time.Sleep(time.Second * 10)
			InsertLogAndUpdateHit()

		}

	}()

}

func (this *CliServer) DispachIntervalCmds() {

	DispachIntervalCmd := func() {

		defer func() {
			if err := recover(); err != nil {
				log.Error("DispachIntervalCmd", err)
			}
		}()

		c := cli.rp.Get()
		defer c.Close()

		size, _ := redis.Int(c.Do("lpush", CONST_INTERVAL_CMDS_LIST_KEY))
		now := time.Now().Unix()

		for {
			js, err := redis.String(c.Do("rpop", CONST_INTERVAL_CMDS_LIST_KEY))
			if err != nil || js == "" {
				break
			}

			var result IntervalCmd
			err = json.Unmarshal([]byte(js), &result)
			if err != nil {
				log.Error(err)
				log.Error("DispachIntervalCmd redis.String", js)
				continue

			}

			if result.EndTime-now <= 0 {
				result.Kw["async"] = "1"
				this.ExecCmd(result.Ip, result.Cmd, result.Kw)
			} else {
				c.Do("lpush", CONST_INTERVAL_CMDS_LIST_KEY, this.util.JsonEncode(result))
			}

			size = size - 1
			if size <= 0 {
				break
			}

		}

	}

	go func() {
		for {
			time.Sleep(time.Second * 1)
			DispachIntervalCmd()

		}

	}()
}

func (this *CliServer) BackendDeleteEtcdKeys() {
	BackendDeleteEtcdKey := func() {
		defer func() {
			if err := recover(); err != nil {
				log.Error("BackendDeleteEtcdKey", err)
			}
		}()
		//		c := cli.rp.Get()
		//		defer c.Close()
		for {
			//			js, err := redis.String(c.Do("rpop", CONST_REMOVE_ETCD_LIST_KEY))
			//			if err != nil || js == "" {
			//				break
			//			}

			req := httplib.Delete(<-this.etcdDelKeys)
			req.Header("Authorization", this.etcdbasicauth)
			req.SetTimeout(time.Second*2, time.Second*2)
			req.Debug(true)
			_, err := req.String()
			if err != nil {
				log.Error(err)
			}
			//			fmt.Println("etcdDelKeys", len(this.etcdDelKeys))
		}
	}

	go func() {

		for i := 0; i < 100; i++ {
			go func() {
				for {

					BackendDeleteEtcdKey()
				}
			}()
		}

	}()

	go func() {
		for {
			t := time.Tick(time.Second * 10)
			<-t
			BackendDeleteEtcdKey()
		}
	}()

}

func (this *CliServer) DeleteResults() {

	DeleteHistory := func() {

		defer func() {
			if err := recover(); err != nil {
				log.Error("DeleteHistory", err)
			}
		}()

		history_retain := 3650

		if Config().HistoryRetain > 0 {
			history_retain = Config().HistoryRetain
		}

		timestamp := time.Now().Unix() - int64(history_retain)*60*60*24

		engine.Exec("delete from t_ch_results_history where Fctime<?", timestamp)
	}

	DeleteLog := func() {

		defer func() {
			if err := recover(); err != nil {
				log.Error("DeleteLog", err)
			}
		}()

		log_retain := 3650

		if Config().LogRetain > 0 {
			log_retain = Config().LogRetain
		}

		timestamp := time.Now().Unix() - int64(log_retain)*60*60*24

		engine.Exec("delete from t_ch_log where Ftime<?", timestamp)
	}

	DeleteResult := func() {

		defer func() {
			if err := recover(); err != nil {
				log.Error("DeleteResult", err)
			}
		}()

		for {

			results := make([]TChResults, 0)

			result_retain := 90

			if Config().ResultRetain > 0 {
				result_retain = Config().ResultRetain
			}

			timestamp := time.Now().Unix() - int64(result_retain)*60*60*24

			err := engine.Where("fctime < ? ", timestamp).Limit(100, 0).Find(&results)

			if err != nil {
				log.Error(err)
				continue
			}

			if len(results) <= 0 {
				break
			}

			for _, v := range results {

				history := new(TChResultsHistory)
				history.Fcmd = v.Fcmd
				history.Fctime = v.Fctime
				history.FopUser = v.FopUser
				history.Fip = v.Fip
				history.Futime = v.Futime
				history.FtaskId = v.FtaskId
				history.Fuuid = v.Fuuid
				history.Fresult = v.Fresult
				history.FmodifyTime = v.FmodifyTime
				history.Fversion = v.Fversion
				engine.Insert(history)

				sql_delete := "delete from t_ch_results where Ftask_id=?"

				_, er := engine.Exec(sql_delete, v.FtaskId)
				if er != nil {
					log.Error(er)
				}

			}
		}

	}

	go func() {
		for {
			DeleteResult()
			time.Sleep(time.Second * 60 * 60)
			DeleteLog()
			DeleteHistory()

		}

	}()

}

func (this *CliServer) InsertResults() {

	InsertResult := func() {

		defer func() {
			if err := recover(); err != nil {
				log.Error("InsertResult", err)
			}
		}()

		c := cli.rp.Get()
		defer c.Close()

		for {

			js, err := redis.String(c.Do("rpop", CONST_RESULT_LIST_KEY))

			if err != nil || js == "" {

				break

			}

			var result TChResults
			err = json.Unmarshal([]byte(js), &result)
			if err != nil {
				log.Error(err)
				log.Error("InsertResults redis.String", js)
				continue

			}

			if result.FopUser != "" {
				_, err := engine.Insert(&result)
				if err != nil {
					log.Error(err)
					log.Error("js", js)
				}

			} else {
				if result.FtaskId != "" {
					_, err := engine.Update(&result, TChResults{FtaskId: result.FtaskId})
					if err != nil {
						log.Error(err)
						log.Error(js)

					}
				} else {
					log.Error(js)
				}
			}

		}

	}

	InsertHeartBeat := func() {

		defer func() {
			if err := recover(); err != nil {
				log.Error("InsertHeartBeat", err)
			}
		}()

		c := cli.rp.Get()
		defer c.Close()

		for {

			js, err := redis.String(c.Do("rpop", CONST_HEARTBEAT_LIST_KEY))

			if err != nil || js == "" {

				break

			}

			var result TChHeartbeat
			err = json.Unmarshal([]byte(js), &result)
			if err != nil {
				log.Error(err)
				log.Error("InsertResults redis.String", js)
				continue

			}
			oldResult := new(TChHeartbeat)
			engine.Where("Fuuid=?", result.Fuuid).Get(oldResult)
			if oldResult.Fuuid == "" {
				_, err := engine.Insert(&result)
				if err != nil {
					log.Error(err)
					log.Error("js", js)
				}

			} else {
				_, err := engine.Update(&result, TChHeartbeat{Fuuid: result.Fuuid})
				if err != nil {
					log.Error(err)
					log.Error(js)
				}
			}

		}

		if ts, err := time.ParseDuration("-10m"); err == nil {

			past := time.Now().Add(ts).Format("2006-01-02 15:04:05")

			if _, err := engine.Exec("update t_ch_heartbeat set Fstatus=? where Futime<?", "offline", past); err != nil {
				log.Error(err)
			}

		}

	}

	go func() {
		for {
			time.Sleep(time.Second * 1)
			InsertResult()

		}

	}()

	go func() {
		for {
			time.Sleep(time.Second * 30)
			InsertHeartBeat()
		}

	}()

}

func (this *CliServer) IsAdminFromHttp(r *http.Request) bool {
	user, _ := this.GetLoginUser(r)
	if strings.TrimSpace(user) == "" {
		return false
	}
	for _, u := range Config().SuperAdmin {
		if u == user {
			return true
		}
	}
	return false
}

func (this *CliServer) EnableUser(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	param := r.PostForm["param"][0]

	if Config().Debug {
		log.Info(param)
	}

	super, _ := this.GetLoginUser(r)

	//	fmt.Println(super)

	if !this.IsAdmin(super) {

		w.Write([]byte("(error) not permit"))
		return

	}

	body := make(map[string]interface{})
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error("Heartbeat Unmarshal Error:", err)
		return
	}

	user := ""
	if _user, ok := body["u"]; ok {
		user = _user.(string)
	} else {

		w.Write([]byte(""))
		return
	}

	if user != "" {

		this._SetUserStatus(user, 1)
		w.Write([]byte("success"))

	}

}

func (this *CliServer) DisableUser(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	param := r.PostForm["param"][0]

	if Config().Debug {
		log.Info(param)
	}

	super, _ := this.GetLoginUser(r)

	if !this.IsAdmin(super) {

		w.Write([]byte("(error) not permit"))
		return

	}

	body := make(map[string]interface{})
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error("Heartbeat Unmarshal Error:", err)
		return
	}

	user := ""
	if _user, ok := body["u"]; ok {
		user = _user.(string)
	} else {

		w.Write([]byte(""))
		return
	}

	if user != "" {

		this._SetUserStatus(user, 0)
		w.Write([]byte("success"))
	}

}

func (this *CliServer) Heartbeat(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	param := r.PostForm["param"][0]

	if Config().Debug {
		log.Info(param)
	}

	body := make(map[string]interface{})
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		//		fmt.Println(err)
		log.Error("Heartbeat Unmarshal Error:", err)
		return
	}

	uuid := ""
	client_ip := ""
	salt := ""
	shell := ""
	platform := ""
	ips := ""
	hostname := ""
	system_status := "{}"

	if _ips, ok := body["ips"]; ok {
		ips, ok = _ips.(string)
	}

	if _uuid, ok := body["uuid"]; ok {
		uuid, ok = _uuid.(string)

	}

	if v, ok := body["status"]; ok {
		if reflect.TypeOf(v).Kind() == reflect.String {
			system_status, ok = v.(string)
		} else {
			system_status = this.util.JsonEncode(v)
			if system_status == "" {
				system_status = "{}"
			}
		}

	}

	if len(uuid) != 36 {

		w.Write([]byte("invalid request"))
		return
	}

	if _platform, ok := body["platform"]; ok {
		platform, ok = _platform.(string)
	}

	if _hostname, ok := body["hostname"]; ok {
		hostname, ok = _hostname.(string)
	}

	if _client_ip, ok := body["__client_ip__"]; ok {
		client_ip, ok = _client_ip.(string)
	} else {
		client_ip = cli.util.GetClientIp(r)
	}

	if Config().BenchMark {
		client_ip = uuid
	}

	if Config().UseGor {

		client_ip = ""

		for _, i := range strings.Split(ips, ",") {
			if strings.HasPrefix(i, "10.") || strings.HasPrefix(i, "172.") || strings.HasPrefix(i, "192.") {
				client_ip = i
				break
			}
		}

	}

	dd := map[string]interface{}{}
	c := this.rp.Get()
	defer c.Close()

	if hb, ok := safeMap.GetValue(client_ip); ok {
		salt = hb.Salt
	} else if heartbeatinfo, err := redis.String(c.Do("GET", uuid)); err == nil {
		hb := &MiniHeartBeat{}
		if er := json.Unmarshal([]byte(heartbeatinfo), hb); er == nil {
			salt = hb.Salt
		} else {

		}
	}

	if salt == "" {
		salt = this.util.GetUUID()

	}
	hb := &MiniHeartBeat{}
	hb.Ip = client_ip
	hb.Salt = salt
	hb.Utime = time.Now().Format("2006-01-02 15:04:05")
	hb.Uuid = uuid
	hb.Platform = platform
	hb.Status = "online"
	safeMap.Put(client_ip, hb)

	dd["ip"] = client_ip
	dd["utime"] = hb.Utime
	dd["time"] = time.Now().Unix()
	dd["status"] = "online"
	dd["platform"] = platform
	dd["ips"] = ips
	dd["salt"] = salt
	dd["hostname"] = hostname
	dd["uuid"] = uuid
	dd["system_status"] = system_status
	jdd, err := json.Marshal(dd)
	if err != nil {
		//		fmt.Println(err)
		log.Error("Marshal Error:", err, dd)
		return
	}

	c.Send("SET", uuid, string(jdd))
	//	fmt.Println(string(jdd))
	c.Send("HSET", CONST_HEARTBEAT_IP_MAP_UUID_KEY, client_ip, uuid)
	c.Send("HSET", CONST_HEARTBEAT_UUID_MAP_IP_KEY, uuid, client_ip)
	c.Send("LPUSH", CONST_HEARTBEAT_LIST_KEY, string(jdd))
	c.Send("ltrim", CONST_HEARTBEAT_LIST_KEY, 0, 20000)
	c.Send("ltrim", CONST_RESULT_LIST_KEY, 0, 20000)
	c.Send("SADD", CONST_UUIDS_KEY, uuid)
	c.Flush()

	result := HeartBeatResult{}
	result.Etcd = this.getEtcd(client_ip)
	result.Salt = salt
	result.shell = shell

	if data, ok := json.Marshal(&result); ok == nil {
		if Config().Debug {
			//fmt.Println("heartbeat ok", client_ip)
		}
		w.Write(data)
	} else {
		if Config().Debug {
			fmt.Println("heartbeat error", client_ip)
		}
		w.Write([]byte("error"))
	}

}

func (this *CliServer) Log(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()

	ip := ""
	num := 100

	param := r.PostForm["param"][0]

	if Config().Debug {
		log.Info(param)
	}

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		//fmt.Println(err)
		log.Error("VM Unmarshal Error:", err)
		return
	}

	if _ip, ok := body["i"]; ok {
		ip = _ip
	}
	if ip == "" {
		w.Write([]byte("-i(ip) is required"))
		return
	}
	if _num, ok := body["n"]; ok {
		num_, err := strconv.Atoi(_num)
		if err == nil {
			num = num_
		} else {
			w.Write([]byte("-n(num) must be int"))
			return
		}
	}
	if num > 1000 {
		num = 1000
	}

	//	 ret= self._cmd(ip, "tail -n %s /var/log/cli.log" %( n),kw={'log_to_file':'0'}, sudo=True)

	kw := make(map[string]string)
	kw["log_to_file"] = "0"
	kw["sudo"] = "1"

	result := make(map[string]interface{})

	ret, _ := this.ExecCmd(ip, fmt.Sprintf("tail -n %s /var/log/cli.log", strconv.Itoa(num)), kw)

	err := json.Unmarshal([]byte(ret), &result)
	if err == nil {
		w.Write([]byte(result["result"].(string)))

	} else {
		w.Write([]byte(ret))
	}
}

func (this *CliServer) Watch(w http.ResponseWriter, r *http.Request) {

	wait := false
	if params, err := url.ParseQuery(r.URL.RawQuery); err != nil {
		return
	} else {
		if v, ok := params["wait"]; ok {
			if v[0] == "true" {
				wait = true
			}
		}

	}
	var result EtcdResult
	var node EtcdNode
	nodes := make([]EtcdNodes, 1)
	result.Node = node
	result.Node.Dir = false
	result.Node.Nodes = nodes

	uuid := ""
	cmd := "{}"

	if reg, err := regexp.Compile("[\\w\\-]{36}"); err != nil {
		w.Write([]byte(this.util.JsonEncode(result)))
		return
	} else {
		uuid = reg.FindString(r.RequestURI)

	}

	if _, ok := cmds.Cmds[uuid]; !ok {

		cmds.Cmds[uuid] = make(chan string, 1024)
	}

	if wait {
		cmd = <-cmds.Cmds[uuid]
		nodes[0].Value = cmd
		w.Write([]byte(this.util.JsonEncode(result)))
		return
	} else {
		if cmd != "" {
			nodes[0].Value = cmd
			w.Write([]byte(this.util.JsonEncode(result)))
		} else {
			w.Write([]byte(this.util.JsonEncode(result)))
		}

	}

}

func (this *CliServer) Test(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	data := make(map[string]interface{})
	for k, v := range r.PostForm {
		if len(v) > 0 {
			data[k] = v[0]
		}
	}
	w.Write([]byte(this.util.JsonEncode(data)))
}

func (this *CliServer) GetObjs(w http.ResponseWriter, r *http.Request) {
	msg := make(map[string]string)
	msg["status"] = "fail"
	msg["message"] = ""
	r.ParseForm()
	if _, ok := r.PostForm["param"]; !ok {
		msg["message"] = "param is required"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}
	param := r.PostForm["param"][0]
	params := make(map[string]interface{})

	//	fmt.Println(param)
	if err := json.Unmarshal([]byte(param), &params); err != nil {
		msg["message"] = "Unmarshal Error"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}

	key := ""

	if v, ok := params["k"]; ok {
		key = v.(string)
	} else {
		msg["message"] = "(error)-k(key) is require"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}

	var obj TChObjs

	obj.Fkey = key

	_, err := engine.Where(&obj).Get(&obj)

	if err != nil {
		msg["message"] = err.Error()
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	} else {
		msg["data"] = obj.Fbody
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}

}

func (this *CliServer) AddObjs(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	param := r.PostForm["param"][0]
	params := make(map[string]interface{})
	msg := make(map[string]string)
	msg["status"] = "fail"
	msg["message"] = ""
	//	fmt.Println(param)
	if err := json.Unmarshal([]byte(param), &params); err != nil {
		msg["message"] = "Unmarshal Error"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}

	key := ""
	body := ""

	if v, ok := params["o"]; !ok {
		if v == "" {
			msg["message"] = "message can't be null"
		} else {
			msg["message"] = "(error)-o(type) is require"
		}
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}

	if v, ok := params["t"]; ok {

		switch v := v.(type) {
		case map[string]interface{}:
			body = this.util.JsonEncode(v)
		default:
			msg["message"] = "(error)-t(tag) is require,and must be json format"
			w.Write([]byte(this.util.JsonEncode(msg)))
			return

		}

	} else {
		msg["message"] = "(error)-t(tag) is require"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}

	if v, ok := params["k"]; ok {
		key = v.(string)
	}

	var obj TChObjs

	if err := json.Unmarshal([]byte(param), &obj); err != nil {

		msg["message"] = err.Error()
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}
	obj.Fbody = body
	if key == "" {
		key = this.util.GetUUID()
		obj.Fkey = key

		if _, err := engine.Insert(&obj); err != nil {
			msg["message"] = err.Error()
			w.Write([]byte(this.util.JsonEncode(msg)))
			return
		} else {
			msg["message"] = "ok"
			msg["status"] = "ok"
			w.Write([]byte(this.util.JsonEncode(msg)))
			return
		}

	} else {

		if _, err := engine.Update(&obj, TChObjs{Fkey: key}); err != nil {
			msg["message"] = err.Error()
			w.Write([]byte(this.util.JsonEncode(msg)))
			return
		} else {
			msg["message"] = "ok"
			msg["status"] = "ok"
			w.Write([]byte(this.util.JsonEncode(msg)))
			return

		}
	}

}

func (this *CliServer) Proc(data []byte, stat *zk.Stat, delFlag bool) {

	log.Info("update MySQL Config", string(data))

	if c, err := cli.util.ParseZkInfo(string(data), "mysql"); err == nil {
		if _enginer, er := cli.util.InitEngine(c); er == nil && _enginer != nil {
			if engine != nil {
				engine.Close()
			}
			engine = _enginer
			log.Info("update MySQL Config", string(data))
		}
	}

}

func (this *Common) Proc(data []byte, stat *zk.Stat, delFlag bool) {

	log.Info("update Redis Config", string(data))

	if c, err := cli.util.ParseZkInfo(string(data), "redis"); err == nil {
		if pool, er := cli.util.InitRedisPool(c); er == nil {
			cli.rp = pool
			log.Info("update Redis Config", string(data))
		}
	}

}

func (this *Common) CheckEnginer(engine *xorm.Engine) bool {
	ret := false
	s := "select 1"
	if rows, err := engine.Query(s); err == nil {
		if len(rows) > 0 {
			if v, ok := rows[0]["1"]; ok {

				if string(v) == "1" {
					return true
				} else {
					return false
				}

			}
		}
	} else {
		fmt.Println(err)
	}

	return ret

}

func (this *Common) InitEngine(c map[string]string) (*xorm.Engine, error) {

	url := "%s:%s@tcp(%s:%s)/%s?charset=utf8"
	url = fmt.Sprintf(url, c["user"], c["password"], c["host"], c["port"], c["db"])
	dbtype := c["dbtype"]

	if Config().Debug {
		fmt.Println(url)
		log.Info(url)
	}

	_enginer, er := xorm.NewEngine(dbtype, url)

	if er == nil /*&& this.CheckEnginer(_enginer)*/ {
		_enginer.SetConnMaxLifetime(time.Duration(60) * time.Second)
		_enginer.SetMaxIdleConns(0)
		//		_enginer.ShowSQL(true)
		return _enginer, nil
	} else {
		return nil, er
	}

}

func (this *Common) InitRedisPool(c map[string]string) (*redis.Pool, error) {

	if Config().UseZKRedis {

		host := cli.util.GetMap(c, "host", "127.0.0.1")
		port := cli.util.GetMap(c, "port", "6379")
		passowrd := cli.util.GetMap(c, "password", "")
		db := cli.util.GetMap(c, "db", "0")
		Config().Redis.Address = fmt.Sprintf("%v:%v", host, port)

		if v, err := strconv.Atoi(fmt.Sprintf("%v", db)); err == nil {
			Config().Redis.DB = v
		} else {
			Config().Redis.DB = 0
		}

		Config().Redis.MaxIdle = 50
		Config().Redis.MaxActive = 5000
		Config().Redis.IdleTimeout = 10
		Config().Redis.ConnectTimeout = 3
		Config().Redis.Pwd = passowrd

	}

	if Config().Debug {
		fmt.Println(fmt.Sprintf("%v", Config().Redis))
		log.Info(fmt.Sprintf("%v", Config().Redis))
	}

	pool := &redis.Pool{
		MaxIdle:     Config().Redis.MaxIdle,
		MaxActive:   Config().Redis.MaxActive,
		IdleTimeout: time.Duration(Config().Redis.IdleTimeout) * time.Second,
		Wait:        true,
		Dial: func() (redis.Conn, error) {
			conn, err := redis.Dial("tcp", Config().Redis.Address,
				redis.DialConnectTimeout(time.Duration(Config().Redis.ConnectTimeout)*time.Second),
				redis.DialPassword(Config().Redis.Pwd),
				redis.DialDatabase(Config().Redis.DB),
			)
			if err != nil {
				log.Error(err)
			}
			return conn, err

		},
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			_, err := c.Do("ping")
			if err != nil {
				log.Error(err)
				return err
			}
			return err
		},
	}
	return pool, nil

}

func (this *CliServer) Proxy(w http.ResponseWriter, r *http.Request) {

	if Config().URLProxy != "" {
		body := this.getParam(r)
		request := httplib.Post(Config().URLProxy).SetTimeout(time.Second*5, time.Second*10)
		request.Param("param", this.util.JsonEncode(body))
		for k, v := range r.Header {
			if len(v) > 0 {
				request.Header(k, v[0])
			}
		}
		if result, err := request.String(); err != nil {
			w.Write([]byte(err.Error()))
			return
		} else {
			w.Write([]byte(result))
			return
		}
	}

}

func (this *CliServer) Trans(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	url := ""
	keys := []string{"url", "callback"}
	for _, v := range keys {
		if _url, ok := r.PostForm[v]; ok {
			if len(_url) > 0 && strings.HasPrefix(_url[0], "http") {
				url = _url[0]
				break
			}
		}
	}
	if url == "" {
		body := this.getParam(r)
		for _, v := range keys {
			if _url, ok := body[v]; ok {
				if strings.HasPrefix(_url, "http") {
					url = _url
					break
				}
			}
		}
	}
	if url == "" {
		w.Write([]byte("url is null"))
		return
	}
	req := httplib.Post(url)
	for k, v := range r.PostForm {
		if len(v) > 0 {
			req.Param(k, v[0])
		}
	}
	for k, v := range r.Header {
		if len(v) > 0 {
			req.Header(k, v[0])
		}
	}
	req.SetTimeout(time.Second*5, time.Second*5)
	if resp, err := req.String(); err != nil {
		w.Write([]byte(err.Error()))
		return
	} else {
		w.Write([]byte(resp))
	}

}

func (this *CliServer) VM(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()

	param := r.PostForm["param"][0]

	msg := make(map[string]string)
	msg["status"] = "fail"
	msg["message"] = ""

	if Config().Debug {
		log.Info(param)
	}
	ip := ""
	phy_ip := ""
	async := "0"
	action := ""
	uuid := ""
	output := "text"
	task_id := this.util.GetUUID()
	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		fmt.Println(err)
		log.Error("VM Unmarshal Error:", err)
		return
	}
	if _param, ok := body["t"]; ok {
		param = _param
	} else {
		msg["message"] = "(error) -t(tag) is required,tag must be json format"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}

	if _param, ok := body["async"]; ok {
		async = _param
	}
	if _param, ok := body["o"]; ok {
		output = _param
	}
	body = make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		fmt.Println(err)
		log.Error("VM Unmarshal Error:", err)
		return
	}

	if _ip, ok := body["ip"]; ok {
		ip = _ip
	}
	if _phy_ip, ok := body["phy_ip"]; ok {
		phy_ip = _phy_ip
	}

	if _action, ok := body["action"]; ok {
		action = _action
	}

	if _uuid, ok := body["uuid"]; ok {
		uuid = _uuid
	}

	if phy_ip == "" {
		msg["message"] = "phy_ip is required"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}
	if action == "" {
		msg["message"] = "action is required"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}
	actions := []string{"create", "start", "stop", "destroy", "dumpxml"}
	bflag := false
	for _, a := range actions {
		if a == action {
			bflag = true
			break
		}
	}
	if !bflag {
		msg["message"] = "action must be in 'create','start','stop','dumpxml'"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}

	IP2UUID := func(ip string, phy_ip string) string {
		ip12 := ""
		phy12 := ""
		for _, i := range strings.Split(ip, ".") {
			i = i + "aa"
			ip12 = ip12 + i[0:3]
		}
		for _, i := range strings.Split(phy_ip, ".") {
			i = i + "aa"
			phy12 = phy12 + i[0:3]
		}
		id := ip12 + time.Now().Format("20060102") + phy12
		return id[0:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:32]
	}

	if action == "create" && uuid != "" {

		msg["message"] = "uuid must be null"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return

	} else if action == "create" {
		uuid = IP2UUID(ip, phy_ip)
	}

	if (action == "start" || action == "stop" || action == "dumpxml") && uuid == "" {
		msg["message"] = "uuid is required"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return

	}

	data := make(map[string]string)

	for k, v := range body {
		data[k] = v
	}
	data["ip"] = ip
	data["phy_ip"] = phy_ip
	data["action"] = action
	if uuid != "" {
		data["uuid"] = uuid
	}

	c := this.rp.Get()
	defer c.Close()
	cache_key := CONST_CACHE_KEY_PREFIX + "vm_" + task_id
	c.Do("setex", cache_key, 60*60*2, this.util.JsonEncode(data))

	kw := make(map[string]string)

	kw["async"] = async
	kw["sudo"] = "1"
	kw["o"] = output
	kw["t"] = "1800"
	result, _ := this.ExecCmd(phy_ip, fmt.Sprintf("cli shell -f vm -d jqzhang -u -t 1800 -a %s", task_id), kw)
	w.Write([]byte(result))

}

func init() {

	cfgPath := flag.String("c", "cfg.json", "json cfg")
	logFile := flag.String("log", "", "log config file")

	//	flag.Parse()

	if *logFile == "" {

		//		logger, err := log.Log
		logger, err := log.LoggerFromConfigAsBytes([]byte(logConfigStr))

		if err != nil {
			panic(err)
		}
		log.ReplaceLogger(logger)
	} else {

		logger, err := log.LoggerFromConfigAsFile(*logFile)
		if err != nil {
			panic(err)
		}
		log.ReplaceLogger(logger)
	}

	if *cfgPath == "cfg.json" {
		if !cli.util.IsExist("cfg.json") {
			//			fmt.Println("auto gen config file cfg.json")
			cli.util.WriteFile("cfg.json", string(cfgJson))
		}
	}

	ParseConfig(*cfgPath)

	var err error

	if _logacc, err := log.LoggerFromConfigAsBytes([]byte(logAccessConfigStr)); err == nil {
		logacc = _logacc
		log.Info("succes init log access")

	} else {
		log.Error(err.Error())
	}

	if err != nil {
		log.Error(err.Error())
	}

	cfg := client.Config{
		Endpoints:               []string{Config().Etcd.Host},
		Transport:               client.DefaultTransport,
		Username:                Config().Etcd.User,
		Password:                Config().Etcd.Pwd,
		HeaderTimeoutPerRequest: time.Second,
	}

	for i, v := range Config().EtcdGuest.Server {
		if strings.Index(v, "/v2/") <= 0 {
			Config().EtcdGuest.Server[i] = Config().EtcdGuest.Server[i] + CONST_ETCD_PREFIX
		}
	}
	c, err := client.New(cfg)
	if err != nil {
		log.Error(err)

	}
	cli.kapi = client.NewKeysAPI(c)

	cli.etcdClent = c

	if db, err := sql.Open("sqlite3", ":memory:"); err == nil {
		db.SetMaxOpenConns(1)
		sqliteCache.SQLite = db
	} else {
		log.Error(err.Error())
	}

	ZkDBInit :=
		func() {

			zkdb := &zksdk.ZkSdk{}
			zkdb.Init(Config().ZkDB.ZkHost, time.Second*5)

			cli.zkdb = zkdb

			zkdb.Start()

			flag := make(chan bool)

			if data, _, er := zkdb.GetMoreWX(Config().ZkDB.Path, flag, cli); er == nil {

				if Config().Debug {
					log.Info(string(data))
				}

				if c, err := cli.util.ParseZkInfo(string(data), "mysql"); err == nil {
					if _enginer, er := cli.util.InitEngine(c); er == nil && _enginer != nil {

						engine = _enginer

					}
				}

			} else {
				fmt.Println(er)
				log.Error("Connect to Zookeeper Error")
				os.Exit(1)
			}

		}

	ZkRedisInit :=
		func() {

			zkredis := &zksdk.ZkSdk{}
			zkredis.Init(Config().ZkRedis.ZkHost, time.Second*5)

			cli.zkredis = zkredis

			zkredis.Start()

			flag := make(chan bool)

			if data, _, er := zkredis.GetMoreWX(Config().ZkRedis.Path, flag, cli.util); er == nil {

				if Config().Debug {
					log.Info(string(data))
				}

				if c, err := cli.util.ParseZkInfo(string(data), "redis"); err == nil {
					if pool, err := cli.util.InitRedisPool(c); err == nil {

						cli.rp = pool

						if Config().Debug {

							log.Info(Config().Redis)

						}

					} else {
						panic("redis pool init error")
					}
				}

			} else {
				fmt.Println(er)
				log.Error("Connect Redis to Zookeeper Error")
				os.Exit(1)
			}

		}

	if Config().UseZkDB {
		ZkDBInit()
	} else {

		var err error

		engine, err = xorm.NewEngine(Config().Db.Type, Config().Db.Url)

		if err == nil {
			engine.SetConnMaxLifetime(time.Duration(60) * time.Second)
			engine.SetMaxIdleConns(0)
			fmt.Println(Config().Db)
		} else {
			fmt.Println(err)
			fmt.Println("Init engine Error")
			log.Error("Init engine Error", err)
			os.Exit(1)
		}
	}

	if Config().AutoCreatTable {
		if err := engine.Sync2(new(TChUser), new(TChAuth), new(TChResults),
			new(TChGoogleAuth), new(TChFiles), new(TChHeartbeat),
			new(TChLog), new(TChResults), new(TChObjs), new(TChResultsHistory)); err != nil {
			log.Error(err.Error())
		}
	}

	if Config().BuiltInRedis {

		CleanExpireKeys := func(redis *miniredis.Miniredis) {
			for {
				t := time.Tick(time.Second * 60)
				<-t
				redis.FastForward(time.Second * 60)
			}
		}
		RunRedisServer := func(port string) {

			redis_server := miniredis.NewMiniRedis()

			go CleanExpireKeys(redis_server)

			if Config().Redis.Pwd != "" {
				redis_server.RequireAuth(Config().Redis.Pwd)
				redis_server.StartAddr(":" + port)
			} else {
				redis_server.StartAddr(":" + port)
			}

		}

		infos := strings.Split(Config().Redis.Address, ":")
		if len(infos) <= 1 {
			panic("Redis address must be contain port")
		}
		Config().Redis.Address = "127.0.0.1:" + infos[1]
		go RunRedisServer(infos[1])
	}

	if Config().UseZKRedis {
		ZkRedisInit()
	} else {
		if pool, err := cli.util.InitRedisPool(make(map[string]string)); err == nil {
			cli.rp = pool
			fmt.Println(Config().Redis)

		} else {
			panic("redis pool init error")
		}
	}

}

func init() {

}

func Route(m *martini.ClassicMartini) martini.Handler {
	return func() {
		m.Group("/cli", func(r martini.Router) {
			m.Post("/api", cli.Api)
			m.Post("/feedback_result", cli.Feedback)
			m.Post("/heartbeat", cli.Heartbeat)
			m.Post("/del_etcd_key", cli.DeleteEtcdKey)
			m.Post("/get_cmd_result", cli.GetCmdResult)
			m.Post("/addtoken", cli.AddToken)
			m.Post("/upload", cli.Upload)
			m.Post("/download", cli.Download)
			m.Post("/shell", cli.Shell)
			m.Post("/login", cli.Login)
			m.Post("/register", cli.Register)
			m.Post("/enableuser", cli.EnableUser)
			m.Post("/disableuser", cli.DisableUser)
			m.Get("/help", cli.Help)
			m.Post("/gen_google_auth", cli.GenGoogleAuth)
			m.Post("/verify_google_code", cli.VerifyGoogleCode)
			m.Post("/google_code_sync", cli.GoogleCodeSync)
			m.Post("/ssh", cli.SSH)
			m.Post("/cache", cli.RedisCache)
			m.Post("/redis_cache", cli.RedisCache)
			m.Post("/status", cli.Status)
			m.Post("/log", cli.Log)
			m.Post("/vm", cli.VM)
			m.Post("/check_status", cli.CheckStatus)
			m.Post("/run_status", cli.RunStatus)
			m.Get("/run_status", cli.RunStatus)
			m.Post("/get_ip_by_status", cli.GetIpByStatus)
			m.Post("/benchmark", cli.BenchMark)
		})
	}
}

type HttpHandler struct {
}

func (HttpHandler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	status_code := "200"
	defer func(t time.Time) {
		logStr := fmt.Sprintf("[Access] %s | %v | %s | %s | %s | %s |%s",
			time.Now().Format("2006/01/02 - 15:04:05"),
			res.Header(),
			time.Since(t).String(),
			cli.util.GetClientIp(req),
			req.Method,
			status_code,
			req.RequestURI,
		)

		logacc.Info(logStr)
	}(time.Now())

	defer func() {
		if err := recover(); err != nil {
			status_code = "500"
			res.WriteHeader(500)
			buff := debug.Stack()
			log.Error(err)
			log.Error(string(buff))

		}
	}()

	url := req.RequestURI
	url = strings.Split(url, "?")[0]
	if strings.LastIndex(url, "/") > 0 {
		key := url[strings.LastIndex(url, "/")+1 : len(url)]
		qpsMap.Add(key)
		if ok, _ := cli.util.Contains(key, GET_METHODS); !ok {
			req.ParseForm()
			if _, ok := req.PostForm["param"]; !ok {
				log.Error(fmt.Sprintf("bad parameters ip:%s url:%s ", cli.util.GetClientIp(req), url))
				//res.Write([]byte("bad parameters"))
				//return
			}
		}
	}

	http.DefaultServeMux.ServeHTTP(res, req)
}

func (this *CliServer) Main() {

	defer log.Flush()

	cli.Init()

	http.HandleFunc("/", cli.Proxy)
	http.HandleFunc("/cli/trans", cli.Trans)
	http.HandleFunc("/cli/test", cli.Test)
	//	http.HandleFunc("/v2/keys/", cli.Watch)
	http.HandleFunc("/cli/api", cli.Api)
	http.HandleFunc("/cli/v2/api", cli.V2Api)
	http.HandleFunc("/cli/feedback_result", cli.Feedback)
	http.HandleFunc("/cli/heartbeat", cli.Heartbeat)
	http.HandleFunc("/cli/del_etcd_key", cli.DeleteEtcdKey)
	http.HandleFunc("/cli/get_cmd_result", cli.GetCmdResult)
	http.HandleFunc("/cli/addtoken", cli.AddToken)
	http.HandleFunc("/cli/listtoken", cli.ListToken)
	http.HandleFunc("/cli/upload", cli.Upload)
	http.HandleFunc("/cli/download", cli.Download)
	http.HandleFunc("/cli/delfile", cli.DelFile)
	http.HandleFunc("/cli/listfile", cli.ListFile)
	http.HandleFunc("/cli/shell", cli.Shell)
	http.HandleFunc("/cli/login", cli.Login)
	http.HandleFunc("/cli/register", cli.Register)
	http.HandleFunc("/cli/enableuser", cli.EnableUser)
	http.HandleFunc("/cli/disableuser", cli.DisableUser)
	http.HandleFunc("/cli/help", cli.Help)
	http.HandleFunc("/cli/gen_google_auth", cli.GenGoogleAuth)
	http.HandleFunc("/cli/verify_google_code", cli.VerifyGoogleCode)
	http.HandleFunc("/cli/google_code_sync", cli.GoogleCodeSync)
	http.HandleFunc("/cli/ssh", cli.SSH)
	http.HandleFunc("/cli/repair", cli.Repair)
	http.HandleFunc("/cli/cache", cli.RedisCache)
	http.HandleFunc("/cli/redis_cache", cli.RedisCache)
	http.HandleFunc("/cli/status", cli.Status)
	http.HandleFunc("/cli/log", cli.Log)
	http.HandleFunc("/cli/vm", cli.VM)
	http.HandleFunc("/cli/check_port", cli.CheckPort)
	http.HandleFunc("/cli/check_status", cli.CheckStatus)
	http.HandleFunc("/cli/run_status", cli.RunStatus)
	http.HandleFunc("/cli/confirm_offline", cli.ConfirmOffline)
	http.HandleFunc("/cli/get_ip_by_status", cli.GetIpByStatus)
	http.HandleFunc("/cli/benchmark", cli.BenchMark)
	http.HandleFunc("/cli/upgrade", cli.Upgrade)
	http.HandleFunc("/cli/unrepair", cli.UnRepair)
	http.HandleFunc("/cli/online", cli.GetStatus)
	http.HandleFunc("/cli/offline", cli.GetStatus)
	http.HandleFunc("/cli/load_cmdb", cli.LoadCmdb)
	http.HandleFunc("/cli/cmdb", cli.Cmdb)
	http.HandleFunc("/cli/mail", cli.Mail)
	http.HandleFunc("/cli/addobjs", cli.AddObjs)
	http.HandleFunc("/cli/getobjs", cli.GetObjs)
	//	http.HandleFunc("/ws", wsPage) // baidu search wsPage websocket
	err := http.ListenAndServe(Config().Addr, new(HttpHandler))
	if err != nil {
		fmt.Println(err)
		log.Error(err.Error())
	}
}

