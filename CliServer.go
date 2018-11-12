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
	"syscall"
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
	"os/signal"
	"strconv"

	math "math/rand"

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
	"github.com/coreos/etcd/etcdmain"
	"github.com/samuel/go-zookeeper/zk"
	"github.com/sjqzhang/googleAuthenticator"
	"github.com/sjqzhang/zksdk"
	//	"github.com/vmware/go-nfs-client/nfs"
	"github.com/Shopify/sarama"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/ssh"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary
var engine *xorm.Engine
var cli = &CliServer{util: &Common{}, etcdDelKeys: make(chan string, 20000)}
var safeMap = &SafeMap{m: make(map[string]*MiniHeartBeat)}
var safeTokenMap = &SafeTokenMap{m: make(map[string]*WBIPSMap)}
var safeAuthMap = &SafeAuthMap{m: make(map[string]*TChAuth)}
var safeUserMap = &CommonMap{m: make(map[string]interface{})}
var qpsMap = &CommonMap{m: make(map[string]interface{})}
var tokenCounterMap = &CommonMap{m: make(map[string]interface{})}
var logacc log.LoggerInterface
var sqliteCache = &SQLiteCache{}
var cmds = WatchChannels{Cmds: make(map[string]chan string)}
var shellContents = &ShellContents{}
var mgoSession *mgo.Session
var mgoPool *MongoPool

var mgoDB *mgo.Database

var USE_ETCD_CLINET = false

var GET_METHODS = []string{"download", "upgrade", "status",
	"run_status", "check_status", "help", "del_etcd_key", "confirm_offline",
	"upload", "download", "ip"}

const (
	CONST_RESULT_LIST_KEY           = "results"
	CONST_CALLBACK_PARAMETERS_KEY   = "callback_paramters"
	CONST_CALLBACK_LIST_KEY         = "callbacks"
	CONST_HEARTBEAT_LIST_KEY        = "heartbeats"
	CONST_ETCDFAIL_LIST_KEY         = "fails"
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
	CONST_REPORT_PREFIX_KEY         = "reports_"
	CONST_REMOVE_IPLIST_KEY         = "remove_ips"
	CONST_REMOVE_ETCD_LIST_KEY      = "remove_etcd_keys"
	CONST_ASYNC_LOG_KEY             = "asyn_db"
	CONST_ASYNC_API_HIT_KEY         = "asyn_api_counter"
	CONST_QUEUE_RESULT_SIZE         = 20000

	CONST_EXECUTE_API_COUNT_NAME = "cmdapi"

	CONST_HEARTBEAT_FILE_NAME = "heartbeat.json"
	CONST_AUTH_FILE_NAME      = "auth.json"
	CONST_DOC_FILE_NAME       = "doc.json"
	CONST_LOCAL_CFG_FILE_NAME = "cfg_local.json"

	CONST_NOT_FOUND = "not_found"

	CONST_UPLOAD_DIR = "files"

	CONST_ETCD_PREFIX = "/v2/keys"

	CONST_ANONYMOUS_FOLDER = "anonymous"

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
	"ip":"",
	"uuid":"",
	"only_etcd":false,
	"white_ips":  [
		"127.0.0.1"
	],
	"gateway_ips":[
	  "127.0.0.1" 
	],
	"db":{
		"type":"sqlite3",
		"url":"./cli.db"
	},
	"redis": {
		"address": "127.0.0.1:6380",
		"pwd": "%s",
		"maxIdle": 10,
		"maxActive": 100,
		"idleTimeout": 30,
		"connectTimeout": 2,
		"db": 0
	},
	"etcd_root": {
		"host": "http://%s:4002",
		"user": "root",
		"password": "%s"
	},
	"etcd": {
		"server": ["http://%s:4002/v2/keys"],
		"user": "guest",
		"password": "guest",
		"prefix":"/keeper"
	},
	"mongo": {
		"host": ["127.0.0.1:27017"],
		"db":"test",
		"user": "",
		"password": "",
		"mechanism":"",
		"max_pool":100,
		"table_prefix":""
	},
	"mail":{
		"user":"abc@163.com",
		"password":"abc",
		"host":"smtp.163.com:25"
	},
	"default_script_dir":"default",
	"group": "default",
	"debug": false,
	"delete_etcdkey_sync": false,
	"benchmark":false,
	"result2db":false,
	"auto_create_table":true,
	"api_overload_per_min":60000,
	"use_zk":false,
	"use_kafka":false,
	"etcd_value_expire":15,
	"use_api_salt":false,
	"auto_repair":true,
	"use_nfs":false,
	"use_mongo":false,
	"super_admin":["admin"],
	"result_retain":90,
	"history_retain":365,
	"log_retain":365,
	"queue_result_size":20000,
	"builtin_redis":true,
	"builtin_etcd":true,
	"auto_switch_loca_mode":false,
	"falcon_url":"http://127.0.0.1:1988/v1/push",
	"url_proxy":"",
	"proxy_etcd":false,
	"is_gateway":false,
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
		
	},
	"shell_filenames":{
		"windows":"",
		"linux":""
	},
	"nfs":{
		"host":"127.0.0.1",
		"machinename":"",
		"gid":1001,
		"uid":1001
	},
	"kafka":{
	   "servers":"",
	   "topics":{
		  "results":{"name":"results"},
		  "report":{"name":"report"}
	   }
	},
	"static_dir":"static"
}
`
	climini = `#!/usr/bin/env python
server_url='http://127.0.0.1:8005'
cli_group='default'
import zlib, base64
exec(zlib.decompress(base64.b64decode('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')))
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
	FmodifyTime time.Time `xorm:"updated index DATETIME"`
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
	Fgroup      string    `json:"group" xorm:"not null default '' VARCHAR(512)"`
	Fsalt       string    `json:"salt" xorm:"not null default '' VARCHAR(36)"`
	Ftoken      string    `json:"token" json:"token" xorm:"not null default '' unique VARCHAR(64)"`
	FsudoIps    string    `json:"white_ips" xorm:"TEXT"`
	Fhit        int       `json:"hit" xorm:"not null default 0 INT(10)"`
	FlastUpdate int       `json:"last_update" xorm:"updated"`
	Fdesc       string    `json:"desc" xorm:"not null default '' VARCHAR(1024)"`
	Fenv        string    `json:"env" xorm:"not null default '' VARCHAR(64)"`
	Fenable     int       `json:"enable" xorm:"not null default 1 INT(11)"`
	FmodifyTime time.Time `json:"modify_time" xorm:"updated index DATETIME"`
	Fversion    int       `json:"version" xorm:"not null default 0 INT(11)"`
}

type TChResults struct {
	Fid         int64     `json:"id" xorm:"not null pk autoincr BIGINT(20)"`
	FtaskId     string    `json:"task_id" xorm:"not null default '' unique VARCHAR(36)"`
	Fip         string    `json:"i" xorm:"not null default '' VARCHAR(16)"`
	Fcmd        string    `json:"cmd"  xorm:"TEXT"`
	Fresult     string    `json:"result" xorm:"TEXT"`
	Fctime      int       `json:"ctime" xorm:"not null default 0  index INT(11)"`
	Futime      int       `json:"utime" xorm:"created"`
	FopUser     string    `json:"user" xorm:"not null default '' VARCHAR(32)"`
	Fuuid       string    `json:"ip" xorm:"not null default '' index VARCHAR(36)"`
	FsysUser    string    `json:"sys_user" xorm:"not null default '' VARCHAR(32)"`
	FmodifyTime time.Time `json:"modifyTime" xorm:"created index DATETIME"`
	Fversion    int       `json:"version" xorm:"not null default 0 INT(11)"`
}

type TChResultsHistory struct {
	Fid         int64     `xorm:"not null pk autoincr BIGINT(20)"`
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
	FmodifyTime time.Time `xorm:"created index DATETIME"`
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
	FmodifyTime time.Time `xorm:"updated index DATETIME"`
	Fversion    int       `xorm:"not null default 0 INT(11)"`
}

type TChLog struct {
	Fid         int64     `xorm:"not null pk autoincr BIGINT(20)"`
	Furl        string    `json:"url" xorm:"not null default '' VARCHAR(2048)"`
	Fparams     string    `json:"params" xorm:"TEXT"`
	Fmessage    string    `json:"message" xorm:"not null default '' VARCHAR(255)"`
	Fip         string    `json:"ip" xorm:"not null default '' CHAR(15)"`
	Fuser       string    `json:"user" xorm:"not null default '' VARCHAR(64)"`
	Ftime       int       `xorm:"created not null default 0 index INT(11)"`
	FmodifyTime time.Time `xorm:"updated index DATETIME"`
	Fversion    int       `xorm:"not null default 0 INT(11)"`
}

type TChHeartbeat struct {
	Fuuid          string    `json:"uuid" xorm:"not null pk default '' VARCHAR(36)"`
	Fhostname      string    `json:"hostname" xorm:"not null default '' VARCHAR(255)"`
	Fip            string    `json:"ip" xorm:"not null default '' VARCHAR(32)"`
	Fgroup         string    `json:"group" xorm:"not null default '' VARCHAR(32)"`
	FserverUri     string    `json:"server_uri" xorm:"not null default '' VARCHAR(256)"`
	FetcdUri       string    `json:"etcd_uri" xorm:"not null default '' VARCHAR(256)"`
	Fsalt          string    `json:"salt" xorm:"not null default '' VARCHAR(36)"`
	Fplatform      string    `json:"platform" xorm:"not null default '' VARCHAR(36)"`
	Futime         string    `json:"utime"  xorm:"not null default '' VARCHAR(32)"`
	Fnettype       string    `json:"nettype" xorm:"not null default '' VARCHAR(16)"`
	Fstatus        string    `json:"status" xorm:"not null default '' VARCHAR(16)"`
	FsystemStatus  string    `json:"system_status" xorm:"TEXT"`
	FpythonVersion string    `json:"python_version" xorm:"not null default '' VARCHAR(16)"`
	FcliVersion    string    `json:"cli_version" xorm:"not null default '' VARCHAR(32)"`
	FmodifyTime    time.Time `xorm:"updated index DATETIME"`
	Fversion       int       `xorm:"not null default 0 INT(11)"`
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
	FmodifyTime time.Time `xorm:"updated index DATETIME"`
	Fversion    int       `xorm:"not null default 0 INT(11)"`
}

type TChDoc struct {
	Fid         int64     `json:"id" xorm:"not null pk autoincr BIGINT(20)"`
	Fcmd        string    `json:"cmd" xorm:"TEXT"`
	Fdoc        string    `json:"doc" xorm:"TEXT"`
	Fremark     string    `json:"remark" xorm:"not null default '' VARCHAR(512)"`
	FmodifyTime time.Time `json:"modifyTime" xorm:"updated index DATETIME"`
	Fversion    int       `json:"version" xorm:"not null default 0 INT(11)"`
}

type TChConfig struct {
	Fid         int       `json:"id" xorm:"not null pk autoincr INT(11)"`
	Fgroup      string    `json:"group" xorm:"not null default '' VARCHAR(36)"`
	Fip         string    `json:"ip" xorm:"not null default '' VARCHAR(32)"`
	Fuuid       string    `json:"uuid" xorm:"not null default '' VARCHAR(36)"`
	FisGateway  int       `json:"isGrateway" xorm:"not null default 0 TINYINT(1)"`
	Fconfig     string    `json:"config" xorm:"LONGTEXT"`
	FmodifyTime time.Time `json:"modifyTime" xorm:"updated index DATETIME"`
	Fversion    int       `json:"version" xorm:"not null default 0 INT(11)"`
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

type Response struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

type DispatchItem struct {
	ServerUri string   `json:"server_uri"`
	Ips       []string `json:"ips"`
	Group     string   `json:"group"`
}

type MongoConn struct {
	Host        []string `json:"host"`
	Database    string   `json:"db"`
	User        string   `json:"user"`
	Mechanism   string   `json:"mechanism"`
	Password    string   `json:"password"`
	MaxPool     int      `json:"max_pool"`
	TablePrefix string   `json:"table_prefix"`
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
	Shell string        `json:"shell"`
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

type NFS struct {
	Host        string `json:"host"`
	MachineName string `json:"machinename"`
	Gid         uint32 `json:"gid"`
	Uid         uint32 `json:"uid"`
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

type ShellFileNames struct {
	Windows string `json:"windows"`
	Linux   string `json:"linux"`
}

type ShellContents struct {
	Windows string `json:"windows"`
	Linux   string `json:"linux"`
}

type Kafka struct {
	Servers string                       `json:"servers"`
	Toptics map[string]map[string]string `json:"topics"`
}

type GloablConfig struct {
	Addr               string         `json:"addr"`
	Ip                 string         `json:"ip"`
	Uuid               string         `json:"uuid"`
	GatewayIps         []string       `json:"gateway_ips"`
	WhitelIps          []string       `json:"white_ips"`
	Redis              Redis          `json:"redis"`
	Etcd               Etcd           `json:"etcd_root"`
	Debug              bool           `json:"debug"`
	EtcdGuest          HeartBeatEtcd  `json:"etcd"`
	SuperAdmin         []string       `json:"super_admin"`
	Db                 DB             `json:"db"`
	BenchMark          bool           `json:"benchmark"`
	Result2DB          bool           `json:"result2db"`
	AutoCreatTable     bool           `json:"auto_create_table"`
	Group              string         `json:"group"`
	Mail               Mail           `json:"mail"`
	ZkDB               ZkInfo         `json:"zkdb"`
	ZkRedis            ZkInfo         `json:"zkredis"`
	UseZkDB            bool           `json:"use_zk_db"`
	UseZKRedis         bool           `json:"use_zk_redis"`
	FalconURL          string         `json:"falcon_url"`
	Repair             Repair         `json:"repair"`
	AutoRepair         bool           `json:"auto_repair"`
	UseGor             bool           `json:"use_gor"`
	URLProxy           string         `json:"url_proxy"`
	FastDFS            FastDFS        `json:"fastdfs"`
	UseFastDFS         bool           `json:"use_fastdfs"`
	BuiltInRedis       bool           `json:"builtin_redis"`
	BuiltInEtcd        bool           `json:"builtin_etcd"`
	UseApiSalt         bool           `json:"use_api_salt"`
	ResultRetain       int            `json:"result_retain"`
	HistoryRetain      int            `json:"history_retain"`
	LogRetain          int            `json:"log_retain"`
	QueueResultSize    int            `json:"queue_result_size"`
	ApiOverloadPerMin  int            `json:"api_overload_per_min"`
	ProxyEtcd          bool           `json:"proxy_etcd"`
	EtcdValueExpire    int            `json:"etcd_value_expire"`
	OnlyEtcd           bool           `json:"only_etcd"`
	ShellFileNames     ShellFileNames `json:"shell_filenames"`
	UseNFS             bool           `json:"use_nfs"`
	NFS                NFS            `json:"nfs"`
	Mongo              MongoConn      `json:"mongo"`
	UseMongo           bool           `json:"use_mongo"`
	IsGateWay          bool           `json:"is_gateway"`
	StaticDir          string         `json:"static_dir"`
	Kafka              Kafka          `json:"kafka"`
	UseKafka           bool           `json:"use_kafka"`
	DeleteEtcdkeySync  bool           `json:"delete_etcdkey_sync"`
	DefaultScriptDir   string         `json:"default_script_dir"`
	AutoSwitchLocaMode bool           `json:"auto_switch_loca_mode"`
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

type MongoPool struct {
	sync.Mutex
	Max     int
	Min     int
	pool    []*mgo.Session
	indexs  []bool
	Session *mgo.Session
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
	Salt          string `json:"salt"`
	Ip            string `json:"ip"`
	Utime         string `json:"utime"`
	Status        string `json:"status"`
	Platform      string `json:"platform"`
	Uuid          string `json:"uuid"`
	Group         string `json:"group"`
	ServerUri     string `json:"server_uri"`
	EtcdUri       string `json:"etcd_uri"`
	NetType       string `json:"nettype"`
	CliVersion    string `json:"cli_version"`
	PythonVersion string `json:"python_version"`
}

type MiniHeartBeatStatus struct {
	//	Salt   string `json:"salt"`
	Ip            string `json:"ip"`
	Utime         string `json:"utime"`
	Status        string `json:"status"`
	Platform      string `json:"platform"`
	Uuid          string `json:"uuid"`
	CliVersion    string `json:"cli_version"`
	PythonVersion string `json:"python_version"`
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
	kfp           sarama.AsyncProducer
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

func MongoPoolNew(max int) *MongoPool {

	return &MongoPool{
		Max:    max,
		pool:   make([]*mgo.Session, max),
		indexs: make([]bool, max),
	}

}

func (p *MongoPool) Get() *mgo.Session {

	p.Lock()
	defer p.Unlock()
	for {
		for i, v := range p.indexs {
			if !v {
				p.indexs[i] = true
				if p.pool[i] == nil {
					p.pool[i] = p.Session.Copy()
				}
				return p.pool[i]
			}
		}
	}

}

func (p *MongoPool) Release(session *mgo.Session) {
	p.Lock()
	defer p.Unlock()

	for i, v := range p.pool {
		if v == session {
			p.indexs[i] = false
		}
	}

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

func (s *CommonMap) AddCount(key string, count int) {
	s.Lock()
	defer s.Unlock()
	if _v, ok := s.m[key]; ok {
		v := _v.(int)
		v = v + count
		s.m[key] = v
	} else {
		s.m[key] = 1
	}
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

func (this *Common) GetPulicIP() string {
	conn, _ := net.Dial("udp", "8.8.8.8:80")
	defer conn.Close()
	localAddr := conn.LocalAddr().String()
	idx := strings.LastIndex(localAddr, ":")
	return localAddr[0:idx]
}

func (this *Common) IsPublicIP(IP net.IP) bool {
	if IP.IsLoopback() || IP.IsLinkLocalMulticast() || IP.IsLinkLocalUnicast() {
		return false
	}
	if ip4 := IP.To4(); ip4 != nil {
		switch true {
		case ip4[0] == 10:
			return false
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return false
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		default:
			return true
		}
	}
	return false
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

		//		fmt.Println(s)

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

func (this *Common) Contains(obj interface{}, arrayobj interface{}) bool {
	targetValue := reflect.ValueOf(arrayobj)
	switch reflect.TypeOf(arrayobj).Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < targetValue.Len(); i++ {
			if targetValue.Index(i).Interface() == obj {
				return true
			}
		}
	case reflect.Map:
		if targetValue.MapIndex(reflect.ValueOf(obj)).IsValid() {
			return true
		}
	}
	return false
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
		//		url = "http://127.0.0.1:1988/v1/push"
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

func (this *Common) GetClientIpReal(r *http.Request) string {
	client_ip := ""
	clients := strings.Split(r.RemoteAddr, ":")
	client_ip = clients[0]
	return client_ip
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

func (this *Common) ReadBinFile(path string) ([]byte, error) {
	if this.IsExist(path) {
		fi, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer fi.Close()
		return ioutil.ReadAll(fi)
	} else {
		return nil, errors.New("not found")
	}
}

func (this *Common) WriteBinFile(path string, data []byte) bool {
	if err := ioutil.WriteFile(path, data, 0666); err == nil {
		return true
	} else {
		return false
	}
}

func (this *Common) WriteFile(path string, content string) bool {
	if err := ioutil.WriteFile(path, []byte(content), 0666); err == nil {
		return true
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

func (this *Common) Ssh(ip string, port int, user string, pwd string, cmd string, key string, timeout time.Duration) (string, error) {

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

	Conf := ssh.ClientConfig{User: user, Auth: PassWd, Timeout: timeout, HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
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

	ip = this.util.GetClientIpReal(r)

	var authBean *TChAuth

	if authBean, _ = this.GetAuthInfo(r, body); authBean != nil {

		if authBean.Fenable != 1 {
			return false, "(error)token disable", nil
		}

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
		this.logRequest(r, param)
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

func (this *CliServer) redisDo(action string, args ...interface{}) (reply interface{}, err error) {
	c := this.rp.Get()
	defer c.Close()
	return c.Do(action, args...) //fuck
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
		go this.workerEtcd(&wg, etcdMsg)
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

	//	c := this.rp.Get()
	//	defer c.Close()

	failsip := []string{}
	ips := strings.Split(ip, ",")
	ipset := mapset.NewSet()
	for _, ip := range ips {
		ipset.Add(ip)
	}

	taskid2IP := map[string]string{}
	for _ip := range ipset.Iter() {

		var hb *MiniHeartBeat
		var ok bool = false

		ip := _ip.(string)

		if len(ip) == 36 {

			if heartbeatinfo, err := redis.String(this.redisDo("GET", ip)); err == nil {
				hb = &MiniHeartBeat{}
				if er := json.Unmarshal([]byte(heartbeatinfo), hb); er != nil {
					continue
				}
				ok = true
				ip = hb.Ip + fmt.Sprintf("(%s)", hb.Uuid)
			}

		} else {
			hb, ok = safeMap.GetValue(ip)
		}
		if !ok {
			failsip = append(failsip, ip)
			continue
		}
		etcd_uri := hb.EtcdUri
		if etcd_uri == "" {
			etcd_uri = this.getEtcdServer(hb.Ip)
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

		//		c.Do("lpush", CONST_RESULT_LIST_KEY, jdata)
		//		c.Do("sadd", CONST_TASK_LIST_KEY, task_id)

		this.redisDo("lpush", CONST_RESULT_LIST_KEY, jdata)
		this.redisDo("sadd", CONST_TASK_LIST_KEY, task_id)

		etcdMsg <- &EtcdMsg{
			//			Url:           this.getEtcdServer(ip) + "/keeper/servers/" + uuid,
			Url:           etcd_uri + "/keeper/servers/" + uuid,
			Value:         jdata,
			Etcdbasicauth: this.etcdbasicauth,
			TaskID:        task_id,
			Uuid:          uuid,
			Ip:            ip,
			Cmd:           cmd,
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
				c := this.rp.Get()
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

				c.Close()

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
			if output == "text" {
				context = append(context, []string{
					"--------------------------------------------------------------------------------",
					v,
					"(error) timeout feedback results",
				}...)
			}
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
		if output == "json" || output == "json2" {
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

				if output == "json" {
					data3 = append(data3, map[string]interface{}{
						k: data1,
					})
				}
				if output == "json2" {
					data3 = append(data3, data1)
				}
			}
		}
		resultsBody := ""
		if output == "json" || output == "json2" {
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

		} else if output == "json2" {

			//			results := []ResultMap{}
			results := make([]interface{}, 0)
			for result, ip := range taskid2IP {
				hb, ok := safeMap.GetValue(ip)
				if ok {

					_result := &Result{
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
			jsonResults := make(map[string]interface{})
			jsonResults["results"] = results
			jsonResults["failsip"] = strings.Join(failsip, ",")
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

func (this *CliServer) ResponseWriteJson(w http.ResponseWriter, data map[string]string) {

	if body, err := json.Marshal(data); err != nil {
		w.Write([]byte(err.Error()))
	} else {
		w.Write(body)
	}

}

func (this *CliServer) Dispatch(str_ips string) map[string]*DispatchItem {
	rmap := make(map[string]*DispatchItem)
	notFound := CONST_NOT_FOUND

	rmap[notFound] = &DispatchItem{
		Ips:       make([]string, 0),
		ServerUri: "",
		Group:     notFound,
	}

	ips := strings.Split(str_ips, ",")
	for _, v := range ips {
		if hb, ok := safeMap.GetValue(v); ok {
			if item, ok := rmap[hb.Group]; !ok {

				_item := &DispatchItem{
					Ips:       make([]string, 0),
					ServerUri: hb.ServerUri,
				}
				_item.Ips = append(_item.Ips, v)
				_item.Group = hb.Group
				rmap[hb.Group] = _item

			} else {
				item.Ips = append(item.Ips, v)

			}
		} else {
			rmap[notFound].Ips = append(rmap[notFound].Ips, v)
		}
	}
	return rmap
}

func (this *CliServer) GateWay(w http.ResponseWriter, r *http.Request) {

	msg := make(map[string]string)
	body := this.getParam(r)
	ip := ""

	if v, ok := body["i"]; !ok {
		msg["message"] = "-i(ip) is reqiured"
		this.ResponseWriteJson(w, msg)
		return
	} else {
		ip = v
	}

	if _, ok := body["c"]; !ok {
		msg["message"] = "-c(cmd) is reqiured"
		this.ResponseWriteJson(w, msg)
		return
	}

	if _, ok := body["u"]; !ok {
		msg["message"] = "-u(user) is reqiured"
		this.ResponseWriteJson(w, msg)
		return
	}

	if !Config().IsGateWay {
		msg["message"] = "(error) is_gateway is false,contact admin"
		this.ResponseWriteJson(w, msg)
		return
	}

	var authBean *TChAuth
	var ok bool
	var tip string
	if ok, tip, authBean = this.CheckApiPermit(r, body); !ok {
		msg["message"] = tip
		this.ResponseWriteJson(w, msg)
		return
	}

	if authBean == nil {
		msg["message"] = "(error)auth fail,please check token"
		this.ResponseWriteJson(w, msg)
		return
	}

	rmap := this.Dispatch(ip)

	var wg sync.WaitGroup

	results := make(chan string, len(rmap))

	wg.Add(len(rmap) - 1)

	for k, v := range rmap {

		SendToServer := func(wg *sync.WaitGroup, item *DispatchItem, r *http.Request, results chan string) {

			body := this.getParam(r)
			if _, ok := body["o"]; !ok {
				body["o"] = "text"
			}
			if _, ok := body["t"]; !ok {
				body["t"] = "25"
			}
			body["i"] = strings.Join(item.Ips, ",")
			request := httplib.Post(item.ServerUri + "/cli/api")
			request.Param("param", this.util.JsonEncode(body))
			for k, v := range r.Header {
				if len(v) > 0 {
					request.Header(k, v[0])
				}
			}
			var result string
			var err error
			if result, err = request.String(); err != nil {
				results <- err.Error()
			} else {
				results <- result
			}
			wg.Done()

		}

		if k == CONST_NOT_FOUND {
			continue
		}
		go SendToServer(&wg, v, r, results)

	}

	wg.Wait()

	TextHandler := func(rmap map[string]*DispatchItem, results chan string) string {
		allResult := make([]string, 0)

		for i := 0; i < len(rmap)-1; i++ {
			allResult = append(allResult, <-results)
		}

		allResult = append(allResult, "fails:\n")

		if len(rmap[CONST_NOT_FOUND].Ips) > 0 {
			allResult = append(allResult, strings.Join(rmap[CONST_NOT_FOUND].Ips, ","))
		}

		return strings.Join(allResult, "\n--------------------------------------------------------------------------------\n")
	}

	JsonHandler := func(rmap map[string]*DispatchItem, results chan string) string {

		allResult := make(map[string]interface{})

		for i := 0; i < len(rmap)-1; i++ {
			v := <-results
			var result map[string]interface{}
			if err := json.Unmarshal([]byte(v), &result); err != nil {
				fmt.Println(err.Error())
			} else {

				for k, v := range result {

					if k == "failsip" {
						if _, ok := allResult["failsip"]; !ok {
							if v.(string) != "" {
								allResult["failsip"] = v.(string) + "," + strings.Join(rmap[CONST_NOT_FOUND].Ips, ",")
							} else {
								allResult["failsip"] = strings.Join(rmap[CONST_NOT_FOUND].Ips, ",")
							}
						} else {
							if v.(string) != "" {
								allResult["failsip"] = allResult["failsip"].(string) + "," + v.(string)
							}
						}
					} else if k == "results" {
						switch v.(type) {

						case []interface{}:
							if _, ok := allResult["results"]; !ok {
								allResult["results"] = v
							} else {
								for _, _v := range v.([]interface{}) {
									allResult["results"] = append(allResult["results"].([]interface{}), _v)
								}
							}

						}
					} else if k == "message" {
						if _, ok := allResult["message"]; !ok {
							allResult["message"] = v
						} else {
							if v.(string) != "" {
								allResult["message"] = allResult["message"].(string) + "\n" + v.(string)
							}
						}

					}

				}

			}

		}

		return this.util.JsonEncode(allResult)
	}

	if o, ok := body["o"]; ok {
		if o == "json" {
			w.Write([]byte(JsonHandler(rmap, results)))
			return
		}
	}

	w.Write([]byte(TextHandler(rmap, results)))
	return

	//	w.Write([]byte(this.util.JsonEncode(allResult)))

}

func (this *CliServer) Params(w http.ResponseWriter, r *http.Request) {
	body := this.getParam(r)
	args := ""
	group := "rshell"
	if v, ok := body["k"]; ok {
		args = v
	} else {
		w.Write([]byte("(error) -k(key)param is require"))
		return

	}
	if v, ok := body["g"]; ok {
		group = v
	}
	rmap := make(map[string]string)
	rmap["a"] = "get"
	rmap["g"] = group
	rmap["k"] = args
	if js, er := this.redisCache(rmap); er != nil {
		log.Error(rmap)
		w.Write([]byte("{}"))
	} else {
		w.Write([]byte(js))
	}

}

func (this *CliServer) Rshell(w http.ResponseWriter, r *http.Request) {
	if Config().UseGor {
		w.Write([]byte("please set use_gor=false"))
		return
	}

	defer func(t time.Time) {
		log.Info("CostTime:", time.Since(t))
	}(time.Now())

	r.ParseForm()
	param := ""

	if v, ok := r.PostForm["param"]; ok {
		if len(v) > 0 {
			param = v[0]
		} else {
			w.Write([]byte("(error) param is require"))
			return
		}
	} else {
		w.Write([]byte("(error) param is require"))
		return
	}

	if Config().Debug {
		this.logRequest(r, param)
	}

	msg := make(map[string]string)
	msg["message"] = ""

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	}

	//	msg := make(map[string]string)

	addr := strings.Split(r.RemoteAddr, ":")
	if len(addr) != 2 {
		msg["message"] = "remote addr error"
		this.ResponseWriteJson(w, msg)
		return
	}

	ip := ""

	interval := 30

	filename := ""
	dir := ""

	args := ""

	if v, ok := body["d"]; ok {
		dir = v
	} else {
		msg["message"] = "-d(dir) is reqiured"
		this.ResponseWriteJson(w, msg)
		return
	}

	if v, ok := body["f"]; ok {
		filename = v
	} else {
		msg["message"] = "-f(filename) is reqiured"
		this.ResponseWriteJson(w, msg)
		return
	}

	var argv map[string]interface{}

	if v, ok := body["a"]; ok {
		args = v // strings.Replace(v, "'", "\'", -1)
		if err := json.Unmarshal([]byte(v), &argv); err == nil {

			rmap := make(map[string]string)
			rmap["a"] = "set"
			rmap["g"] = "rshell"
			args = this.util.GetUUID()
			rmap["k"] = args
			rmap["v"] = v
			this.redisCache(rmap)

		}
	}
	cmd := "cli shell -u -f '%s' -d '%s' -a \"%s\" "
	cmd = fmt.Sprintf(cmd, filename, dir, args)

	if _ip, ok := body["i"]; ok {
		ip = _ip
	} else {
		msg["message"] = "-i(ip) is reqiured"
		this.ResponseWriteJson(w, msg)
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
	var tip string
	if ok, tip, authBean = this.CheckApiPermit(r, body); !ok {
		msg["message"] = tip
		this.ResponseWriteJson(w, msg)
		return
	}
	if Config().UseApiSalt {
		if authBean.Fsalt != "" {
			sign := ""
			timestamp := ""

			if v, ok := body["sign"]; ok {
				sign = v
			}
			if v, ok := body["timestamp"]; ok {
				timestamp = v
				t, er := strconv.ParseInt(v, 10, 64)
				if er != nil {

					msg["message"] = "timestamp is error"
					this.ResponseWriteJson(w, msg)
					return
				}
				if t > time.Now().Unix()+10*60 || t < time.Now().Unix()-10*60 {
					msg["message"] = "timestamp is expire"
					this.ResponseWriteJson(w, msg)
					return
				}

			} else {
				msg["message"] = "timestamp is  require"
				this.ResponseWriteJson(w, msg)
				return
			}

			if this.util.MD5(cmd+authBean.Fsalt+timestamp) != sign {
				msg["message"] = "cmd sign error,cmd+salt+timestamp"
				this.ResponseWriteJson(w, msg)
				return
			}
		}
	}

	if authBean != nil {
		this.apiTokenHit(authBean.Ftoken, true)
	}

	if authBean.Fgroup != "" {
		groups := strings.Split(strings.ToLower(authBean.Fgroup), ",")
		group := strings.ToLower(Config().Group)
		if !this.util.Contains(group, groups) {
			msg["message"] = "(error) group not permit"
			this.ResponseWriteJson(w, msg)
			return
		}

	}
	this.LogReqToRedis(r, "API", "system", nil)

	if Config().ApiOverloadPerMin > 0 {

		if v, ok := qpsMap.GetValue(CONST_EXECUTE_API_COUNT_NAME); ok {

			if v.(int) > Config().ApiOverloadPerMin {
				log.Warn(fmt.Sprintf("server overload current:%d max:%d, param:%s", v, Config().ApiOverloadPerMin, param))
				msg["message"] = "(error) server overload"
				this.ResponseWriteJson(w, msg)
				return
			}

		}
	}
	qpsMap.AddCount(CONST_EXECUTE_API_COUNT_NAME, len(strings.Split(ip, ",")))

	result, _ := this.ExecCmd(ip, cmd, body)

	result = strings.TrimSpace(result)

	if strings.HasPrefix(result, "(error)") {
		msg["message"] = result
		this.ResponseWriteJson(w, msg)
	} else {
		w.Write([]byte(result))
	}
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
	param := ""

	if v, ok := r.PostForm["param"]; ok {
		if len(v) > 0 {
			param = v[0]
		} else {
			w.Write([]byte("(error) param is require"))
			return
		}
	} else {
		w.Write([]byte("(error) param is require"))
		return
	}

	if Config().Debug {
		this.logRequest(r, param)
	}

	msg := make(map[string]string)
	msg["message"] = ""

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	}

	//	msg := make(map[string]string)

	addr := strings.Split(r.RemoteAddr, ":")
	if len(addr) != 2 {
		msg["message"] = "remote addr error"
		this.ResponseWriteJson(w, msg)
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
		msg["message"] = "-c(cmd) is reqiured"
		this.ResponseWriteJson(w, msg)
		return
	}

	if _ip, ok := body["i"]; ok {
		ip = _ip
	} else {
		msg["message"] = "-i(ip) is reqiured"
		this.ResponseWriteJson(w, msg)
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
	var tip string
	if ok, tip, authBean = this.CheckApiPermit(r, body); !ok {
		msg["message"] = tip
		this.ResponseWriteJson(w, msg)
		return
	}
	if Config().UseApiSalt {
		if authBean.Fsalt != "" {
			sign := ""
			timestamp := ""

			if v, ok := body["sign"]; ok {
				sign = v
			}
			if v, ok := body["timestamp"]; ok {
				timestamp = v
				t, er := strconv.ParseInt(v, 10, 64)
				if er != nil {

					msg["message"] = "timestamp is error"
					this.ResponseWriteJson(w, msg)
					return
				}
				if t > time.Now().Unix()+10*60 || t < time.Now().Unix()-10*60 {
					msg["message"] = "timestamp is expire"
					this.ResponseWriteJson(w, msg)
					return
				}

			} else {
				msg["message"] = "timestamp is  require"
				this.ResponseWriteJson(w, msg)
				return
			}

			if this.util.MD5(cmd+authBean.Fsalt+timestamp) != sign {
				msg["message"] = "cmd sign error,cmd+salt+timestamp"
				this.ResponseWriteJson(w, msg)
				return
			}
		}
	}

	if authBean != nil {
		this.apiTokenHit(authBean.Ftoken, true)
	}

	if authBean.Fgroup != "" {
		groups := strings.Split(strings.ToLower(authBean.Fgroup), ",")
		group := strings.ToLower(Config().Group)
		if !this.util.Contains(group, groups) {
			msg["message"] = "(error) group not permit"
			this.ResponseWriteJson(w, msg)
			return
		}

	}
	this.LogReqToRedis(r, "API", "system", nil)

	if Config().ApiOverloadPerMin > 0 {

		if v, ok := qpsMap.GetValue(CONST_EXECUTE_API_COUNT_NAME); ok {

			if v.(int) > Config().ApiOverloadPerMin {
				log.Warn(fmt.Sprintf("server overload current:%d max:%d, param:%s", v, Config().ApiOverloadPerMin, param))
				msg["message"] = "(error) server overload"
				this.ResponseWriteJson(w, msg)
				return
			}

		}
	}
	qpsMap.AddCount(CONST_EXECUTE_API_COUNT_NAME, len(strings.Split(ip, ",")))

	result, _ := this.ExecCmd(ip, cmd, body)

	result = strings.TrimSpace(result)

	if strings.HasPrefix(result, "(error)") {
		msg["message"] = result
		this.ResponseWriteJson(w, msg)
	} else {
		w.Write([]byte(result))
	}

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

func (this *CliServer) GetGateWayIps() []string {
	ips := make([]string, 0)
	tchConfig := new(TChConfig)
	tchConfig.FisGateway = 1
	ips = append(ips, "127.0.0.1")
	return ips
}

func (this *CliServer) SaveConfig() {

	if Config().Uuid == "" {
		Config().Uuid = this.util.GetUUID()
		if cnf, err := json.MarshalIndent(Config(), "", "  "); err == nil {
			if !this.util.WriteBinFile("cfg.json", cnf) {
				Config().Uuid = ""
			}
		}
	} else {
		tchConfig := new(TChConfig)
		tchConfig.Fuuid = Config().Uuid
		if ok, err := engine.Get(tchConfig); err == nil {
			if ok {
				if cnf, err := json.MarshalIndent(Config(), "", "  "); err == nil {
					tchConfig.Fconfig = string(cnf)
					tchConfig.Fgroup = Config().Group
					if Config().IsGateWay {
						tchConfig.FisGateway = 1
					} else {
						tchConfig.FisGateway = 0
					}
					tchConfig.Fip = Config().Ip
					if _, err := engine.Update(tchConfig, &TChConfig{Fuuid: Config().Uuid}); err != nil {
						log.Error(err)
					}
				}
			} else {
				if cnf, err := json.MarshalIndent(Config(), "", "  "); err == nil {
					tchConfig.Fconfig = string(cnf)
					tchConfig.Fgroup = Config().Group
					if Config().IsGateWay {
						tchConfig.FisGateway = 1
					} else {
						tchConfig.FisGateway = 0
					}
					tchConfig.Fip = Config().Ip
					if _, err := engine.Insert(tchConfig); err != nil {
						log.Error(err)
					}
				}

			}
		} else {
			log.Error(err)
		}
	}
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
	uuids, er := redis.Strings(c.Do("SMEMBERS", CONST_UUIDS_KEY))
	if er != nil {
		fmt.Println(er)
	}

	for _, v := range uuids {
		c.Send("GET", v)
	}
	c.Flush()
	for i := 0; i < len(uuids); i++ {
		if result, ok := c.Receive(); result != nil && ok == nil {
			var obj MiniHeartBeat
			if err := json.Unmarshal(result.([]byte), &obj); err != nil {
				fmt.Println(err)
				continue
			}

			safeMap.Put(obj.Ip, &obj)

		}
	}

	authBeans := make([]TChAuth, 0)
	err := engine.Where("1=1").Find(&authBeans)

	if err == nil {
		for i, v := range authBeans {
			if Config().GatewayIps != nil && len(Config().GatewayIps) > 0 {
				authBeans[i].Fip = authBeans[i].Fip + "," + strings.Join(Config().GatewayIps, ",")
			}
			safeAuthMap.Put(v.Ftoken, &authBeans[i])
			if Config().Debug {
				//				log.Debug(v)
			}
		}
	} else {
		log.Error(err)

	}

	userBeans := make([]TChUser, 0)
	err = engine.Where("1=1").Find(&userBeans)

	if err == nil {
		for i, v := range userBeans {
			safeUserMap.Put(v.Fuser, &userBeans[i])
			if Config().Debug {
				//				log.Debug(v)
			}
		}
	} else {
		log.Error(err)

	}
	if Config().IsGateWay {
		this.refreshHeartbeats()
	}
	SaveHeartBeat := func() {
		hbs := safeMap.Get()

		if len(hbs) > 0 {
			if bhbs, err := json.Marshal(&hbs); err == nil {
				if !cli.util.WriteBinFile(CONST_HEARTBEAT_FILE_NAME, bhbs) {
					os.Remove(CONST_HEARTBEAT_FILE_NAME)
				}
			} else {
				log.Error(err)
			}
		}
	}
	SaveHeartBeat()

	SaveAuth := func() {
		auths := safeAuthMap.Get()
		if len(auths) > 0 {
			if bauths, err := json.Marshal(&auths); err == nil {
				if !cli.util.WriteBinFile(CONST_AUTH_FILE_NAME, bauths) {
					os.Remove(CONST_AUTH_FILE_NAME)
				}
			} else {
				log.Error(err)
			}
		}
	}
	SaveAuth()

}

type EtcdMsg struct {
	Url           string
	Value         string
	Etcdbasicauth string
	TaskID        string
	Uuid          string
	Ip            string
	Cmd           string
}

func (this *CliServer) refreshHeartbeats() {

	groups := make([]TChHeartbeat, 0)
	heartbeats := make([]TChHeartbeat, 0)
	if err := engine.GroupBy("Fgroup").Cols("Fgroup").Where("1=1").Find(&groups); err == nil {
		for _, g := range groups {
			if err := engine.Where("Fgroup=?", g.Fgroup).Find(&heartbeats); err == nil {
				for _, v := range heartbeats {
					safeMap.Put(v.Fip, &MiniHeartBeat{
						Ip:            v.Fip,
						Utime:         v.Futime,
						Status:        v.Fstatus,
						Group:         v.Fgroup,
						Uuid:          v.Fuuid,
						CliVersion:    v.FcliVersion,
						PythonVersion: v.FpythonVersion,
						NetType:       v.Fnettype,
						ServerUri:     v.FserverUri,
						Platform:      v.Fplatform,
						Salt:          v.Fsalt,
					})

				}
			}
			time.Sleep(time.Millisecond * 100)
		}

	}

}

func (this *CliServer) workerEtcd(wg *sync.WaitGroup, etcdMsg <-chan *EtcdMsg) {

	defer func() {
		if re := recover(); re != nil {
			log.Error(re)
			buffer := debug.Stack()
			log.Error(string(buffer))
		}
	}()

	wg.Add(1)
	defer wg.Done()

	errorHandler := func(msg *EtcdMsg, err error) {
		c := this.rp.Get()
		defer c.Close()
		r := Result{
			Cmd:        msg.Cmd,
			TaskId:     msg.TaskID,
			Error:      err.Error(),
			S:          "SERVER_ERROR",
			I:          msg.Ip,
			Ip:         msg.Uuid,
			ReturnCode: -1,
			Result:     "ETCD ERROR",
		}
		c.Do("SETEX", CONST_RESULT_KEY_PREFIX+msg.TaskID, 60*5, this.util.JsonEncode(r))
	}

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
						errorHandler(msg, err)
						fmt.Println("Set error:", err)
						//						fmt.Println("resp:", *resp)
					}
					//				fmt.Println("resp:", *resp)
				}

			} else {

				req := httplib.Post(msg.Url)
				req.Header("Authorization", msg.Etcdbasicauth)
				req.Param("value", msg.Value)
				ttl := 300
				if Config().EtcdValueExpire != 0 {
					ttl = Config().EtcdValueExpire
				}
				req.Param("ttl", strconv.Itoa(ttl))

				req.SetTimeout(5*time.Second, 5*time.Second)

				_, err := req.String()
				if err != nil {
					log.Error(msg.Url, err.Error(), msg.Value)
					if msgj, e := json.MarshalToString(msg); e == nil {
						this.redisDo("lpush", CONST_ETCDFAIL_LIST_KEY, msgj)
					}
					errorHandler(msg, err)
				}

			}

		} else {
			break
		}
	}

}

func (this *CliServer) WriteEtcd(url string, value string, ttl string) (string, error) {

	req := httplib.Post(url)

	req.Header("Authorization", this.etcdbasicauth)
	req.Param("value", value)
	req.Param("ttl", ttl)
	req.SetTimeout(time.Second*10, time.Second*5)
	str, err := req.String()
	//	fmt.Println(str)
	if err != nil {
		log.Error(err)
		print(err)
	}
	return str, err

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
		log.Info(fmt.Sprintf("repair ip:%s", v.Ip))
		if err == nil {
			if ok := this.util.Contains(v.Ip, ips); !ok {
				this._repair(v.Ip, strconv.Itoa(Config().Repair.Port), "")
			}
		} else {

			this._repair(v.Ip, strconv.Itoa(Config().Repair.Port), "")
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
	sw := false
	for k, v := range data {
		if v != "ok" && k != "db" {
			sw = true
			break
		}
	}
	if sw && Config().AutoSwitchLocaMode {
		msg := "AutoSwitchLocaMode"
		this.SwitchToLocal(CONST_LOCAL_CFG_FILE_NAME)
		fmt.Println(msg)
		log.Info(msg)
	}

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

func (this *CliServer) Init(action string) {

	this.InitComponent(action)

	this.etcd_host = Config().Etcd.Host
	etcdconf := &EtcdConf{User: Config().Etcd.User, Password: Config().Etcd.Pwd}
	this.util = &Common{}
	str := etcdconf.User + ":" + etcdconf.Password
	this.etcdbasicauth = "Basic " + this.util.Base64Encode(str)

	if !this.util.IsExist(CONST_UPLOAD_DIR) {
		os.Mkdir(CONST_UPLOAD_DIR, 777)
	}

	if Config().ApiOverloadPerMin == 0 {
		cnt := len(Config().EtcdGuest.Server)
		if cnt > 0 {
			Config().ApiOverloadPerMin = 800 * 60 * cnt
		}

	}

	go func() {

		LoadAuth := func() {
			defer func() {
				if re := recover(); re != nil {
					fmt.Println("LoadAuth", re)
					log.Error("LoadAuth", re)
				}
			}()
			if this.util.IsExist(CONST_AUTH_FILE_NAME) {
				json_auths, err := this.util.ReadBinFile(CONST_AUTH_FILE_NAME)
				var auths map[string]*TChAuth
				if err == nil {

					if er := json.Unmarshal(json_auths, &auths); er != nil {
						fmt.Println(er)
						log.Error("LoadAuth", er)
					}
					if len(auths) > 0 {
						for k, v := range auths {
							safeAuthMap.Put(k, v)
						}
						log.Info("LoadAuth success")
					}
				} else {
					log.Error("LoadAuth", err)
				}

			}
		}
		LoadAuth()

		LoadHeartBeat := func() {
			defer func() {
				if re := recover(); re != nil {
					fmt.Println("LoadHeartBeat", re)
					log.Error("LoadHeartBeat", re)
				}
			}()
			if this.util.IsExist(CONST_HEARTBEAT_FILE_NAME) {
				json_hbs, err := this.util.ReadBinFile(CONST_HEARTBEAT_FILE_NAME)
				if err == nil {
					var hbs map[string]*MiniHeartBeat
					if er := json.Unmarshal(json_hbs, &hbs); er != nil {
						fmt.Println(er)
						log.Error("LoadHeartBeat", er)
					}
					if len(hbs) > 0 {
						for k, v := range hbs {
							safeMap.Put(k, v)
						}
						log.Info("LoadHeartBeat success")
					}
				} else {
					log.Error("LoadHeartBeat", err)
				}

			}
		}
		LoadHeartBeat()

		time.Sleep(time.Second * 2)
		//		ticker := time.NewTicker(time.Minute)
		for {
			this.RefreshMachineInfo()
			//			<-ticker.C
			time.Sleep(time.Minute * 1)
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
			//			ticker := time.NewTicker(time.Minute * 2)
			for {
				this.AutoRepair()
				//				<-ticker.C
				time.Sleep(time.Minute * 2)
			}
		}()

	}

	go cli.InsertResults()

	go cli.RetryWriteEtcds()

	go cli.InsertHeartBeats()

	go cli.DeleteResults()

	go cli.CallBacks()

	go cli.InsertLogAndUpdateHits()

	go cli.DispachIntervalCmds()

	go cli.BackendDeleteEtcdKeys()

	go func() {
		time.Sleep(time.Second * 2)
		cli.InitEtcd()
		cli.InitUserAdmin()
	}()

}

func (this *CliServer) logRequest(r *http.Request, message string) {

	defer func() {
		if er := recover(); er != nil {
			log.Error("logRequest", er)
		}
	}()

	pc, _, line, ok := runtime.Caller(1)
	f := runtime.FuncForPC(pc)
	info := ""
	if ok {
		info = fmt.Sprintf("%s,Line:%d", f.Name(), line)
	}

	ip := this.util.GetClientIp(r)
	if message == "" {
		log.Info(fmt.Sprintf("ip:%s  info:%s param:%v", ip, info, this.util.JsonEncode(r.Form)))
	} else {
		log.Info(fmt.Sprintf("ip:%s  info:%s param:%v", ip, info, message))
	}
}

func (this *CliServer) Feedback(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	param := r.PostForm["param"][0]

	//	fmt.Println(param)

	if Config().Debug {
		this.logRequest(r, param)
	}

	cmd := ""
	task_id := ""
	return_code := -1
	ip := ""
	_uuid := ""

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

	if v, ok := body["cmd"]; ok {
		cmd = v.(string)
	}

	if v, ok := body["i"]; ok {
		ip = v.(string)
	}
	if v, ok := body["ip"]; ok {
		_uuid = v.(string)
	}

	dd := map[string]interface{}{}

	dd["cmd"] = cmd
	dd["utime"] = time.Now().Unix()
	dd["task_id"] = task_id
	dd["i"] = ip
	dd["uuid"] = _uuid
	dd["return_code"] = strconv.Itoa(return_code)

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
							c.Send("ltrim", CONST_CALLBACK_LIST_KEY, 0, Config().QueueResultSize)
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
	c.Send("ltrim", CONST_RESULT_LIST_KEY, 0, Config().QueueResultSize)
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

func (this *CliServer) Man(w http.ResponseWriter, r *http.Request) {

	userBean, _ := this.GetLoginUserInfo(r)

	if userBean.Fuser == "" {
		w.Write([]byte(""))
		return
	}

	if this.util.IsExist("help") {
		help := this.util.ReadFile("help")
		w.Write([]byte(help))
		return
	}

	help := `
	cli api -u user --sudo 0|1 -c cmd -i ip -o text|json --async 0|1
	cli get_cmd_result
	cli addtoken -t token -u user -s sudo -b blackip -w whiteip
	cli listtoken -t token
	cli upload -f filename 
	cli download -d username -f filename
	cli delfile -f filename
	cli listfile -d username
	cli shell -f filename -d username
	cli login -u username -p password
	cli register -u username -p password
	cli enableuser -u username
	cli disableuser -u username
	cli ip 
	cli gen_google_auth -u username -p platform
	cli verify_google_code -u username -p platform
	cli google_code_sync -u username -p platform -s seed
	cli ssh -c cmd -i ip -u user -p password -P port --key keyfile
	cli repair -i ip
	cli cache -k key -v value -a action(set|get) -g group
	cli status
	cli log -i ip
	cli vm  -t '{"phy_ip":"ip","ip":"vm_ip","mem":"1g","disk":"20g","action":"create","image_url":"","cpu":"2"}'
	cli check_port -i ip -p port 
	cli check_status
	cli run_status
	cli confirm_offline
	cli get_ip_by_status -s offline|online
	cli benchmark
	cli upgrade 
	cli unrepair -i ip
	cli online
	cli offline
	cli load_cmdb
	cli cmdb -t 'ip like 10.10.'
	cli doc -k(keyword|id) --file -a (add|del|dump|load|list)
	cli mail -t to -s subject -c content --mail_type text|html
	cli addobjs -o obj_type -t json
	cli getobjs -o obj_type -k key
	cli setconf -k debug -v true
	cli reload
`

	w.Write([]byte(help))
	return

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
		this.logRequest(r, param)
	}

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	}

	user := ""
	password := ""
	oldpwd := ""
	email := ""
	if _user, ok := body["u"]; ok {
		user = _user
	}
	if _pwd, ok := body["p"]; ok {
		password = _pwd
	}
	if _pwd, ok := body["o"]; ok {
		oldpwd = _pwd
	}
	if v, ok := body["e"]; ok {
		email = v
	}
	userBean := new(TChUser)
	if oldpwd != "" {
		has, er := engine.Where("Fuser=? and Fpwd=?", user, this.util.MD5(oldpwd)).Get(userBean)
		if er != nil {
			w.Write([]byte(er.Error()))
			return
		}
		if has {
			userBean.Flasttime = time.Now()
			userBean.Fip = this.util.GetClientIp(r)
			userBean.Femail = email
			userBean.Fuser = user
			userBean.Fstatus = 0
			userBean.Fpwd = this.util.MD5(password)
			if _, er := engine.Where("Fuser=? and Fpwd=?", userBean.Fuser, userBean.Fpwd).Update(userBean); er != nil {
				w.Write([]byte(er.Error()))
				return
			}
			w.Write([]byte("success"))
			return
		}

	}
	has, err := engine.Where("Fuser=?", user).Get(userBean)
	if err != nil {
		return
	}
	if has {
		w.Write([]byte("(error)user exist"))
	} else {
		userBean.Fuser = user
		userBean.Fstatus = 0
		userBean.Fip = this.util.GetClientIp(r)
		userBean.Flasttime = time.Now()
		userBean.Fpwd = this.util.MD5(password)

		if _, er := engine.Insert(userBean); er != nil {
			w.Write([]byte(er.Error()))
		} else {
			w.Write([]byte("success"))
		}

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
		this.logRequest(r, param)
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
	enable := 1
	black_ips := ""
	url := "cli/api"
	salt := ""
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

	if v, ok := body["e"]; ok {
		enable, _ = strconv.Atoi(v)
	}
	if v, ok := body["salt"]; ok {
		salt = v
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
	authBean.Fenable = enable
	if has {

		safeAuthMap.Put(token, authBean)
		engine.Cols("FblackIps", "Fdesc", "Fip", "Fsudo",
			"Ftoken", "Fuser", "Fblack_ips", "Fsudo_ips", "Fenable").Update(authBean, &TChAuth{Ftoken: token})
		w.Write([]byte("success"))

	} else {
		authBean.Fsalt = salt
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
		this.logRequest(r, param)
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
	if len(key) != 32 {
		w.Write([]byte("(error)key is not found"))
		return
	}
	c := this.rp.Get()
	defer c.Close()
	result, err := redis.String(c.Do("get", CONST_RESULT_KEY_PREFIX+key))
	if err != nil {

		tchresult := new(TChResults)
		tchresult.FtaskId = key
		if ok, errr := engine.Get(tchresult); errr == nil && ok {
			ret := this.TChResultsToResult(tchresult)
			if b, er := json.Marshal(ret); er == nil {
				w.Write(b)
			}
		} else {
			w.Write([]byte("(error)redis and db key not found"))
		}

	} else {
		w.Write([]byte(result))
	}

}

func (this *CliServer) TChResultsToResult(r *TChResults) *Result {
	ret := new(Result)
	ret.Cmd = r.Fcmd
	ret.I = r.Fuuid
	ret.Index = r.Fid
	ret.Ip = r.Fip
	ret.Result = r.Fresult
	ret.Error = ""
	ret.TaskId = r.FtaskId
	ret.Success = r.Fresult
	ret.S = "from db result"
	ret.ReturnCode = -1
	return ret
}

func (this *CliServer) RedisCache(w http.ResponseWriter, r *http.Request) {

	defer func(t time.Time) {
		log.Info("CostTime:", time.Since(t))
	}(time.Now())

	r.ParseForm()
	param := r.PostForm["param"][0]

	if Config().Debug {
		this.logRequest(r, param)
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

func (this *CliServer) SQL(w http.ResponseWriter, r *http.Request) {

	defer func(t time.Time) {
		log.Info("CostTime:", time.Since(t))
	}(time.Now())

	r.ParseForm()
	param := r.PostForm["param"][0]

	if Config().Debug {
		this.logRequest(r, param)
	}

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	}
	host := ""
	cmd := ""
	user := "root"
	pwd := "root"
	port := "3306"
	dbtype := "mysql"
	db := ""

	dsn := ""

	if v, ok := body["c"]; ok {
		cmd = v
	} else {
		w.Write([]byte("-c(cmd/sql) is requred"))
		return
	}

	if v, ok := body["dsn"]; ok {
		dsn = v

	}

	if dsn == "" {

		if v, ok := body["d"]; ok {
			db = v
		} else {
			w.Write([]byte("-d(db) is requred"))
			return
		}
		if v, ok := body["h"]; ok {
			host = v
		} else {
			w.Write([]byte("-h(host) is requred"))
			return
		}
		if v, ok := body["u"]; ok {
			user = v
		}
		if v, ok := body["p"]; ok {
			pwd = v
		}

		if v, ok := body["t"]; ok {
			dbtype = v
		}
		if v, ok := body["P"]; ok {
			port = v

		}
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", user, pwd, host, port, db)
	}

	msg := make(map[string]interface{})
	msg["data"] = nil
	msg["message"] = "ok"

	if v, ok := body["dsn"]; ok {
		dsn = v
	}

	if client, err := xorm.NewEngine(dbtype, dsn); err != nil {

		log.Error(err)
		msg["message"] = err.Error()

	} else {

		defer client.Close()
		if rows, er := client.QueryString(cmd); er != nil {
			log.Error(err)
			msg["message"] = er.Error()

		} else {
			msg["data"] = rows
			if b, e := json.Marshal(msg); e != nil {
				log.Error(err)
				msg["message"] = e.Error()
			} else {
				w.Write(b)
				return
			}
		}

	}
	var b []byte
	var err error
	if b, err = json.Marshal(msg); err != nil {

	}

	w.Write(b)

}

func (this *CliServer) Redis(w http.ResponseWriter, r *http.Request) {

	defer func(t time.Time) {
		log.Info("CostTime:", time.Since(t))
	}(time.Now())

	r.ParseForm()
	param := r.PostForm["param"][0]

	if Config().Debug {
		this.logRequest(r, param)
	}

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	}
	host := ""
	cmd := ""

	port := "3306"

	db := ""
	if v, ok := body["c"]; ok {
		cmd = v
	} else {
		w.Write([]byte("-c(cmd) is requred"))
		return
	}

	//	if v, ok := body["d"]; ok {
	//		db = v
	//	} else {
	//		w.Write([]byte("-d(db) is requred"))
	//		return
	//	}
	if v, ok := body["h"]; ok {
		host = v
	} else {
		w.Write([]byte("-h(host) is requred"))
		return
	}

	if v, ok := body["P"]; ok {
		port = v

	}

	_ = db

	dsn := fmt.Sprintf("%s:%s", host, port)

	c, err := redis.Dial("tcp", dsn)

	if err != nil {
		log.Error(err)
		return
	}
	defer c.Close()

	cmds := strings.Split(cmd, " ")
	args := make([]interface{}, len(cmds[1:]))
	for i, v := range cmds[1:] {
		args[i] = v
	}
	reply, err := c.Do(cmds[0], args...)
	if err != nil {
		log.Error(err)
		return
	}

	var buf []byte

	switch reply := reply.(type) {

	case string:
		buf, _ = json.Marshal(reply)
	case []byte:
		s, _ := redis.String(reply, nil)
		buf, _ = json.Marshal(s)

	case []interface{}:
		s, _ := redis.Strings(reply, nil)
		buf, _ = json.Marshal(s)

	case map[string]interface{}:
		s, _ := redis.StringMap(reply, nil)
		buf, _ = json.Marshal(s)

	default:
		s, _ := json.MarshalToString(reply)
		buf = []byte(s)
	}
	w.Write(buf)

}

func (this *CliServer) SSH(w http.ResponseWriter, r *http.Request) {

	defer func(t time.Time) {
		log.Info("CostTime:", time.Since(t))
	}(time.Now())

	r.ParseForm()
	param := r.PostForm["param"][0]

	if Config().Debug {
		this.logRequest(r, param)
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
	timeout := time.Second * 3
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

	if v, ok := body["t"]; ok {
		if _v, err := strconv.Atoi(v); err == nil {
			timeout = time.Second * time.Duration(_v)
		}
	}

	if v, ok := body["k"]; ok {
		key = v
	}

	if v, ok := body["key"]; ok {
		key = v
	}

	if result, err := this.util.Ssh(ip, port, user, pwd, cmd, key, timeout); err != nil {
		w.Write([]byte(err.Error()))
	} else {
		w.Write([]byte(result))
	}

}

func (this *CliServer) _repair(ip string, port string, key string) (string, error) {

	user := Config().Repair.User
	password := Config().Repair.Password

	_port := Config().Repair.Port

	if v, err := strconv.Atoi(port); err == nil {
		_port = v
	}

	cmd := Config().Repair.Cmd
	keyfile := Config().Repair.KeyFile

	if key == "" {
		if this.util.IsExist(keyfile) {
			key = this.util.ReadFile(keyfile)
		} else {
			return "(error)keyfile not found", errors.New("(error)keyfile not found")
		}
	}

	return this.util.Ssh(ip, _port, user, password, cmd, key, time.Second*3)
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

	key := ""

	port := fmt.Sprintf("%s", Config().Repair.Port)

	var wg sync.WaitGroup

	if v, ok := body["i"]; ok {
		ip = v
	} else {
		w.Write([]byte("-i(ip) is requred"))
		return
	}

	if v, ok := body["p"]; ok {
		port = v
	}

	if v, ok := body["file"]; ok {
		key = v
	}

	ips := strings.Split(ip, ",")

	wg.Add(len(ips))

	var results []string

	for _, ip := range ips {
		go func(ip string, wg *sync.WaitGroup, results *[]string) {
			defer wg.Done()
			if result, err := this._repair(ip, port, key); err != nil {
				//w.Write([]byte(err.Error()))
				*results = append(*results, fmt.Sprintf("***********(error)%s*********\n%s", ip, err.Error()))
			} else {
				//w.Write([]byte(result))
				*results = append(*results, fmt.Sprintf("***********(success)%s*********\n%s", ip, result))

			}
		}(ip, &wg, &results)
	}

	wg.Wait()

	w.Write([]byte(strings.Join(results, "\n")))

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
			if ok, err := engine.Where("Fuser=? and Fpath=?", dir, path).Get(&tchFile); err == nil && ok {
				if tchFile.Furl != "" && this.DownLoadFromFastDFS(tchFile.Furl, path) {
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
		this.logRequest(r, param)
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

	client_ip := this.util.GetClientIp(r)

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
		engine.Cols("Flogincount,Fip").Update(&TChUser{Flogincount: userBean.Flogincount + 1,
			Fip: client_ip}, TChUser{Fuser: user})
	} else {
		hasuser, err := engine.Where("Fuser=? ", user).Get(userBean)
		if err != nil {
			w.Write([]byte("db error"))
		}
		if hasuser {
			w.Write([]byte("(error) password is error"))
			engine.Cols("Ffailcount,Fip").Update(&TChUser{Ffailcount: userBean.Ffailcount + 1,
				Fip: client_ip}, TChUser{Fuser: user})
		} else {
			log.Error(fmt.Sprintln("maybe attach user:%s ip:%s", user, client_ip))
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

func (this *CliServer) IsLogin(r *http.Request) bool {
	if user, err := this.GetLoginUser(r); err != nil || user == "" {
		return false
	} else {
		return true
	}

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
			if v, ok := body["filename"]; ok {
				filename = v
			}

			if filename == "" {

				if v, ok := body["f"]; ok {
					filename = v
				} else {
					w.Write([]byte("-f(filename) require"))
					return
				}
			}
			dir := userBean.Fuser
			path := CONST_UPLOAD_DIR + "/" + dir + "/" + filename
			fmt.Println(path)
			if this.util.IsExist(path) {
				err := os.Remove(path)
				if err == nil {
					w.Write([]byte("success"))
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
	ret, err := req.String()
	if err != nil {
		return ""
	}
	if strings.HasPrefix(strings.TrimSpace(ret), "http") {
		return strings.TrimSpace(ret)
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(ret), &result); err != nil {
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

func (this *CliServer) RawDownload(w http.ResponseWriter, r *http.Request) {
	params, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.Write([]byte(err.Error()))
		return
	}
	filename := params.Get("file")
	path := CONST_UPLOAD_DIR + "/" + CONST_ANONYMOUS_FOLDER + "/" + filename
	if filename == "" {
		w.Write([]byte("file parameter is required"))
		return
	}
	if this.util.IsExist(path) {
		data, err := ioutil.ReadFile(path)
		if err == nil {

			w.Write(data)
			return
		} else {
			w.Write([]byte(err.Error()))
			return
		}
	}

}

func (this *CliServer) RawUpload(w http.ResponseWriter, r *http.Request) {
	userBean := TChUser{Fuser: CONST_ANONYMOUS_FOLDER}
	r.ParseForm()
	fmt.Println(r.RequestURI)
	fmt.Println(r.Host)
	if "POST" == r.Method {

		file, _, err := r.FormFile("file")
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		file.Seek(0, 0)
		md5h := md5.New()
		io.Copy(md5h, file)
		sum := fmt.Sprintf("%x", md5h.Sum(nil))
		filename := r.PostForm.Get("filename")
		if filename == "" {
			filename = time.Now().Format("20060102_150405")
		}
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer file.Close()
		path := CONST_UPLOAD_DIR + "/" + userBean.Fuser

		if !this.util.IsExist(path) {
			os.Mkdir(path, 777)
		}

		fpath := CONST_UPLOAD_DIR + "/" + userBean.Fuser + "/" + sum

		f, err := os.Create(fpath)
		defer f.Close()
		file.Seek(0, 0)
		io.Copy(f, file)
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
		download_url := fmt.Sprintf("http://%s/file/download?file=%s\n", r.Host, sum)
		w.Write([]byte(download_url))

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

			if this.util.IsExist(fpath) {
				w.Write([]byte("(error)file exists"))
				return
			}

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

	client_ip := this.util.GetClientIp(r)

	host := r.PostForm["host"][0]
	key := r.PostForm["key"][0]
	url := host + key

	etcd := this.getEtcd(client_ip)

	if Config().ProxyEtcd {

		url := etcd.Server[0] + key

		if _, err := httplib.Delete(url).SetTimeout(time.Second*3, time.Second*3).SetBasicAuth(etcd.User, etcd.Password).String(); err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
			return
		}

	} else {

		bflag := false

		for _, v := range Config().EtcdGuest.Server {
			if len(v) > 15 && len(host) > 15 && v[0:15] == host[0:15] {
				bflag = true
				break
			}
		}

		if !bflag {

			return
		}

		if Config().EtcdValueExpire != 0 && Config().EtcdValueExpire <= 30 {
			return
		}

		if Config().DeleteEtcdkeySync {

			//			c := this.rp.Get()
			//			defer c.Close()
			//			c.Do("lpush", CONST_REMOVE_ETCD_LIST_KEY, url)
			cli.etcdDelKeys <- url
			w.Write([]byte("ok"))

		} else {
			req := httplib.Delete(url)
			req.Header("Authorization", this.etcdbasicauth)
			req.SetTimeout(time.Second*3, time.Second*3)
			_, err := req.String()
			if err != nil {
				log.Error(err)
			}
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
			//			data["data"] = tga.Fseed //for jumpserver
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

	GetSeed := func(length int) string {
		seeds := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
		s := ""
		math.Seed(time.Now().UnixNano())
		for i := 0; i < length; i++ {
			s += string(seeds[math.Intn(32)])
		}
		return s
	}

	if ok, _ := this.IsExistGoogleCode(&ga); !ok {
		seed := GetSeed(16)
		ga.Fseed = seed
		bflag, msg := this.GoogleCodeAdd(&ga)
		if bflag {
			data["data"] = seed
			data["message"] = "ok"
			data["status"] = "ok"
		} else {
			data["message"] = msg
		}

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

	memStat := new(runtime.MemStats)

	runtime.ReadMemStats(memStat)
	data["Sys.num_goroutine"] = strconv.Itoa(runtime.NumGoroutine())
	data["Sys.num_cpu"] = strconv.Itoa(runtime.NumCPU())
	data["Sys.Alloc"] = fmt.Sprintf("%d", memStat.Alloc)
	data["Sys.TotalAlloc"] = fmt.Sprintf("%d", memStat.TotalAlloc)
	data["Sys.HeapAlloc"] = fmt.Sprintf("%d", memStat.HeapAlloc)
	data["Sys.Frees"] = fmt.Sprintf("%d", memStat.Frees)
	data["Sys.HeapObjects"] = fmt.Sprintf("%d", memStat.HeapObjects)
	data["Sys.NumGC"] = fmt.Sprintf("%d", memStat.NumGC)
	data["Sys.GCCPUFraction"] = fmt.Sprintf("%f", memStat.GCCPUFraction)
	data["Sys.GCSys"] = fmt.Sprintf("%d", memStat.GCSys)
	data["Redis.ActiveCount"] = fmt.Sprintf("%d", this.rp.ActiveCount())
	data["Redis.MaxActive"] = fmt.Sprintf("%d", this.rp.MaxActive)

	w.Write([]byte(this.util.JsonEncode(data)))

}

func (this *CliServer) Cmdb(w http.ResponseWriter, r *http.Request) {

	records := this._cmdb(w, r)

	if records != nil {
		jsoned, err := json.MarshalIndent(records, "", "     ")
		if err != nil {
			log.Error(err, "can't encode output data into JSON")
			w.Write([]byte("can't encode output data into JSON"))
			return
		}
		w.Write(jsoned)
	}

}

func (this *CliServer) SelectCmdb(w http.ResponseWriter, r *http.Request) {

	records := this._cmdb(w, r)

	if records != nil {
		ips := mapset.NewSet()
		for _, v := range *records {

			if ip, ok := v["ip"]; ok {

				ips.Add(ip)

			}

		}
		var _ips []string
		for ip := range ips.Iter() {
			switch ip.(type) {
			case string:
				_ips = append(_ips, ip.(string))
			}
		}
		w.Write([]byte(strings.Join(_ips, ",")))
	}

}

func (this *CliServer) _cmdb(w http.ResponseWriter, r *http.Request) *[]map[string]interface{} {

	r.ParseForm()
	param := r.PostForm["param"][0]

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error("Heartbeat Unmarshal Error:", err)
		return nil
	}

	cols := "*"

	tag := ""
	group := ""
	if v, ok := body["t"]; ok {
		tag = v
	} else {

		w.Write([]byte("(error)-t(tag) is require,if -t is null then return 1 row"))
		return nil
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
		return nil
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
	return &records

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

	if this.rp.ActiveCount() < this.rp.MaxActive {
		//		c := this.rp.Get()
		//		defer c.Close()
		//		c.Do("set", "hello", "world")
		this.redisDo("set", "hello", "world")
		if result, err := redis.String(this.redisDo("GET", "hello")); err == nil && result == "world" {
			data["redis"] = "ok"
		} else {
			fmt.Println(err)
		}
	}
	url := Config().EtcdGuest.Server[0] + Config().EtcdGuest.Prefix + "/hello"
	val, _ := this.WriteEtcd(url, "world", "10")
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

func (this *CliServer) Check(w http.ResponseWriter, r *http.Request) {
	data := this.checkstatus()
	body := this.getParam(r)
	ip := this.util.GetClientIp(r)
	if v, ok := body["i"]; ok {
		ip = v
	}
	data["server"] = this.GetServerURI(r)
	sts := make(map[string]*MiniHeartBeatStatus)
	for _, v := range this._getStatus("online") {
		sts[v.Ip] = v
	}
	for _, v := range this._getStatus("offline") {
		sts[v.Ip] = v
	}
	for _, i := range strings.Split(ip, ",") {
		if hb, ok := sts[i]; ok {
			data[i] = hb.Status + "," + hb.Utime
		} else {
			data[i] = fmt.Sprintf("offline,1970-01-01 00:00:00")
		}
	}
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

			st := MiniHeartBeatStatus{Status: v.Status, Ip: v.Ip, Uuid: v.Uuid, Utime: v.Utime, Platform: v.Platform,
				PythonVersion: v.PythonVersion, CliVersion: v.CliVersion}
			st.Status = "online"
			sts = append(sts, &st)
		}
		if status == "offline" && (now-utime) >= CONST_MACHINE_OFFLINE_TIME {

			st := MiniHeartBeatStatus{Status: v.Status, Ip: v.Ip, Uuid: v.Uuid, Utime: v.Utime, Platform: v.Platform,
				PythonVersion: v.PythonVersion, CliVersion: v.CliVersion}
			st.Status = "offline"
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

func (this *CliServer) Doc(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	param := r.PostForm["param"][0]

	body := make(map[string]string)
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		log.Error("Heartbeat Unmarshal Error:", err)
		return
	}

	action := "list"
	key := ""
	title := ""

	if v, ok := body["a"]; ok {
		action = v
	}
	if v, ok := body["k"]; ok {
		key = v
	}
	if v, ok := body["t"]; ok {
		title = v
	}

	if action == "add" {
		doc := ""
		if v, ok := body["file"]; ok {
			doc = v
		}
		if doc != "" && title != "" {
			var tdoc TChDoc
			tdoc.Fcmd = title
			tdoc.Fdoc = doc
			if id, er := strconv.ParseInt(key, 10, 64); er == nil {
				tdoc.Fid = id
			}
			if user, err := this.GetLoginUserInfo(r); err == nil && user.Fuser != "" {
				tdoc.Fremark = user.Fuser
				if tdoc.Fid != 0 {
					if _, er := engine.Update(&tdoc, &TChDoc{Fid: tdoc.Fid}); er != nil {
						w.Write([]byte(er.Error()))
						return
					}
					w.Write([]byte("success"))
					return
				}
				if _, er := engine.Insert(&tdoc); er != nil {
					w.Write([]byte(er.Error()))
					return
				}
				w.Write([]byte("success"))
				return
			} else {
				w.Write([]byte("(error) please login"))
				return
			}

		} else {
			w.Write([]byte("(error) -t(title) or --file(filename) is required"))
			return
		}

	}
	if action == "dump" {
		if this.IsLogin(r) {
			var err error
			docs := make([]TChDoc, 0)
			err = engine.Where("1=1").Find(&docs)
			if err != nil {
				w.Write([]byte("(error)" + err.Error()))
				return
			}
			if bdocs, er := json.Marshal(&docs); er == nil {

				this.util.WriteFile(CONST_DOC_FILE_NAME, string(bdocs))
				w.Write([]byte("success"))
				return
			} else {
				w.Write([]byte("(error)" + err.Error()))
				return
			}
		} else {
			w.Write([]byte("(error) please login"))
			return
		}
	}

	if action == "del" {

		if this.IsAdminFromHttp(r) {
			doc := new(TChDoc)
			if id, er := strconv.ParseInt(key, 10, 64); er == nil {
				doc.Fid = id
				if cnt, err := engine.Delete(doc); err == nil && cnt >= 0 {
					w.Write([]byte("success"))
					return
				} else {
					w.Write([]byte("(error)" + err.Error()))
					return
				}
			} else {
				w.Write([]byte("(error) -k(id) required"))
				return
			}
		} else {
			w.Write([]byte("(error) please login"))
			return
		}
	}

	if action == "load" {

		if this.IsAdminFromHttp(r) {
			sdocs := this.util.ReadFile(CONST_DOC_FILE_NAME)
			var docs []TChDoc
			if er := json.Unmarshal([]byte(sdocs), &docs); er == nil {
				for _, doc := range docs {
					doc.Fid = 0
					if _, err := engine.Insert(&doc); err != nil {
						w.Write([]byte(err.Error()))
					}
				}
				w.Write([]byte("success"))
				return
			} else {
				w.Write([]byte("(error)" + er.Error()))
				return
			}
		} else {
			w.Write([]byte("(error) just for admin user"))
			return
		}
	}

	if action == "list" {

		var titles []string
		var err error

		docs := make([]TChDoc, 0)

		if key == "" {
			err = engine.Where("1=1").Find(&docs)
		} else {

			if id, er := strconv.Atoi(key); er == nil {
				err = engine.Where("Fid=?", id).Find(&docs)
			} else {

				err = engine.Where("Fcmd like ? or Fdoc like ?", "%"+key+"%", "%"+key+"%").Find(&docs)
			}
		}

		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}

		if len(docs) == 0 {
			w.Write([]byte("(error) not found"))
			return
		}

		if len(docs) == 1 {
			w.Write([]byte(docs[0].Fdoc))
			return
		}

		for _, doc := range docs {
			titles = append(titles, fmt.Sprintf(" %d %s %s", doc.Fid, doc.Fcmd, doc.Fremark))
		}
		w.Write([]byte(strings.Join(titles, "\n")))
		return

	}
	w.Write([]byte("-a(action) must be 'add' or 'del' or 'list' or 'dump' or 'load' "))

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
		for _, i := range strings.Split(ip, ",") {
			i = strings.TrimSpace(i)
			if len(strings.Split(i, ".")) == 4 {
				c.Do("SADD", CONST_REMOVE_IPLIST_KEY, i)
				w.Write([]byte(fmt.Sprintf("add %s success\n", i)))
			} else {
				w.Write([]byte(fmt.Sprintf("add %s fail\n", i)))
			}
		}
		return
	}
	if action == "del" {
		for _, i := range strings.Split(ip, ",") {
			c.Do("SREM", CONST_REMOVE_IPLIST_KEY, i)
			w.Write([]byte(fmt.Sprintf("del %s success\n", i)))
		}
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
			clistr := strings.Replace(string(cli), "http://127.0.0.1:8005", this.GetServerURI(r), -1)
			clistr = strings.Replace(string(cli), "cli_group='default'", fmt.Sprintf("cli_group='%s'", Config().Group), -1)
			w.Write([]byte(clistr))
		}

	} else {
		content := strings.Replace(climini, "http://127.0.0.1:8005", this.GetServerURI(r), -1)
		content = strings.Replace(content, "cli_group='default'", fmt.Sprintf("cli_group='%s'", Config().Group), -1)
		w.Write([]byte(content))
	}

}

func (this *CliServer) Static(w http.ResponseWriter, r *http.Request) {
	fp := ""
	if len(r.RequestURI) == 0 {
		return
	}
	if len(r.RequestURI) > 0 {
		fp = r.RequestURI[1:]
		if !strings.HasPrefix(fp, Config().StaticDir) {
			w.WriteHeader(404)
			w.Write([]byte("not found,error dir"))
			return
		}

	}
	if strings.Index(fp, "?") != -1 {
		fp = fp[0:strings.Index(fp, "?")]
	}

	fp = "./" + fp

	if !this.util.IsExist(fp) {
		w.WriteHeader(404)
		w.Write([]byte("file not found"))
		return
	}
	if content, err := this.util.ReadBinFile(fp); err == nil {
		w.Write(content)
		return
	} else {
		w.Write([]byte(err.Error()))
		return
	}

}

func (this *CliServer) Report(w http.ResponseWriter, r *http.Request) {

	msg := make(map[string]interface{})
	msg["message"] = "ok"
	msg["data"] = nil
	r.ParseForm()
	strdata := ""
	topic := "default"

	queue := "redis"
	data := make(map[string]interface{})
	if v, ok := r.Form["data"]; !ok {
		msg["message"] = "parater data is require"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	} else {
		if len(v) > 0 {
			strdata = v[0]
		} else {
			msg["message"] = "parameter data is error"
			w.Write([]byte(this.util.JsonEncode(msg)))
			return
		}
	}

	if v, ok := r.Form["topic"]; ok {
		topic = v[0]
	}

	if v, ok := r.Form["queue"]; ok {
		queue = v[0]
	}

	if queue != "redis" || queue != "kafka" {
		msg["message"] = "parameter queue must be redis or kafka"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}

	if err := json.UnmarshalFromString(strdata, &data); err != nil {

		msg["message"] = "data must be json format"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}

	if queue == "redis" {

		c := this.rp.Get()
		defer c.Close()
		c.Send("LPUSH", CONST_REPORT_PREFIX_KEY+topic, string(strdata))
		c.Send("ltrim", CONST_REPORT_PREFIX_KEY+topic, 0, Config().QueueResultSize)
		if err := c.Flush(); err != nil {
			msg["message"] = "write data error"
			w.Write([]byte(this.util.JsonEncode(msg)))
			return
		}

	} else {

		message := &sarama.ProducerMessage{
			Topic: topic,
			Value: sarama.ByteEncoder(strdata),
		}
		cli.kfp.Input() <- message

	}

	w.Write([]byte(this.util.JsonEncode(msg)))

}

func (this *CliServer) GetReport(w http.ResponseWriter, r *http.Request) {
	group := "default"
	r.ParseForm()
	if v, ok := r.Form["group"]; ok {
		group = v[0]
	}
	c := this.rp.Get()
	defer c.Close()

	msg := make(map[string]interface{})
	msg["message"] = "ok"
	msg["data"] = nil
	if _data, err := redis.String(c.Do("RPOP", CONST_REPORT_PREFIX_KEY+group)); err != nil {
		msg["message"] = err.Error()
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	} else {
		var data map[string]interface{}
		if err := json.UnmarshalFromString(_data, &data); err != nil {
			msg["message"] = "UnmarshalFromString data error"
		} else {
			msg["data"] = data
		}
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
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
			if str_json == "" {
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
				log.Error("js", err)
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
			if v.(int) > 0 && token != "" {
				auth := new(TChAuth)
				if ok, err := engine.Where("Ftoken=?", token).Get(auth); err == nil && ok {
					if auth.Ftoken == token {
						auth.Fhit = auth.Fhit + v.(int)
						engine.Cols("Fhit").Update(auth, TChAuth{Ftoken: token})
					}
				}
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
			if js == "" {
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
			//				continue
			//			}

			//			req := httplib.Delete(js)

			url := <-this.etcdDelKeys
			req := httplib.Delete(url)
			req.Header("Authorization", this.etcdbasicauth)
			req.SetTimeout(time.Second*3, time.Second*3)
			//			req.Debug(true)
			_, err := req.String()

			time.Sleep(time.Millisecond * 1)
			if err != nil {
				log.Error(err)
			}
			//fmt.Println("etcdDelKeys", len(this.etcdDelKeys))
		}
	}

	go func() {

		for i := 0; i < 50; i++ {
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

				sql_delete := fmt.Sprintf("delete from t_ch_results where Ftask_id='%v'", v.FtaskId)

				_, er := engine.Exec(sql_delete)
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

func (this *CliServer) InsertHeartBeats() {
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
			//			fmt.Println("result", result.FetcdUri)
			oldResult := new(TChHeartbeat)
			if ok, err := engine.Where("Fuuid=?", result.Fuuid).Get(oldResult); err == nil && !ok {
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

			InsertHeartBeat()
			time.Sleep(time.Second * 30)
		}

	}()
}

func (this *CliServer) RetryWriteEtcds() {

	RetryWriteEtcd := func() {

		defer func() {
			if err := recover(); err != nil {
				log.Error("RetryWriteEtcd", err)
			}
		}()

		for {

			js, err := redis.String(this.redisDo("rpop", CONST_ETCDFAIL_LIST_KEY))
			if js == "" {
				break
			}
			var msg EtcdMsg
			err = json.Unmarshal([]byte(js), &msg)
			if err != nil {
				continue
			}
			if _, er := this.WriteEtcd(msg.Url, msg.Value, "300"); er != nil {
				//this.redisDo("lpush", CONST_ETCDFAIL_LIST_KEY, js)
				log.Error("RetryWriteEtcds", er)
			}

		}

	}

	go func() {
		for {
			time.Sleep(time.Second * 1)
			RetryWriteEtcd()
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

		topic := CONST_RESULT_LIST_KEY

		for k, v := range Config().Kafka.Toptics {

			if k == CONST_RESULT_LIST_KEY {
				if _v, ok := v["name"]; ok {
					topic = _v
				}

			}

		}

		for {

			js, err := redis.String(c.Do("rpop", CONST_RESULT_LIST_KEY))

			if js == "" {
				time.Sleep(time.Millisecond * 10) //hold redis connection ,don't break
			}

			var result TChResults
			err = json.Unmarshal([]byte(js), &result)
			if err != nil {
				continue
			}
			if Config().UseKafka && cli.kfp != nil && result.FopUser == "" {
				msg := &sarama.ProducerMessage{
					Topic: topic,
					Value: sarama.ByteEncoder(js),
				}
				cli.kfp.Input() <- msg
			}

			if !Config().Result2DB {
				if err == nil && js != "" {
					log.Info("InsertResults Result2DB:False", js)
				}
				continue
			}

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

	go func() {
		for {
			time.Sleep(time.Millisecond * 50)
			InsertResult()

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

func (this *CliServer) Reload(w http.ResponseWriter, r *http.Request) {
	if Config().BuiltInEtcd || Config().BuiltInRedis {

	}
	if this.IsAdminFromHttp(r) {
		fn := "cfg.json"
		params := this.getParam(r)
		if v, ok := params["c"]; ok {
			if this.util.IsExist(v) {
				fn = v
				cfgPath = &fn
			}
		} else if this.util.IsExist(fn) {
			cfgPath = &fn
		}
		_, msg := this.SwitchToLocal(fn)
		w.Write([]byte(msg))
	} else {
		w.Write([]byte("(error)not permit,just for admin"))
	}

}

func (this *CliServer) SwitchToLocal(fn string) (bool, string) {

	if this.util.IsExist(fn) {
		cfgPath = &fn
		if Config().BuiltInEtcd {
			go etcdmain.Main()
		}
		this.init()
		this.Init("reload")
		return true, "ok(" + fn + ")\nplease check service"

	} else {
		return false, "file name not found"
	}

}

func (this *CliServer) SetConf(w http.ResponseWriter, r *http.Request) {

	defer func() {
		if re := recover(); re != nil {
			w.Write([]byte("(error) set fail"))
		}
	}()

	if this.IsAdminFromHttp(r) {
		r.ParseForm()
		param := r.PostForm["param"][0]

		body := make(map[string]interface{})
		if err := json.Unmarshal([]byte(param), &body); err != nil {
			log.Error("Heartbeat Unmarshal Error:", err)
			return
		}

		cmap := make(map[string]string)
		obj := reflect.TypeOf(*Config())
		for i := 0; i < obj.NumField(); i++ {
			cmap[obj.Field(i).Name] = obj.Field(i).Name
			cmap[obj.Field(i).Tag.Get("json")] = obj.Field(i).Name
		}

		if key, ok := body["k"]; ok {
			if _, o := cmap[key.(string)]; !o {
				w.Write([]byte(fmt.Sprintf("(error)key \"%s\" not found", key)))
				return
			} else {
				body["k"] = cmap[key.(string)]
			}

		}

		if value, o := body["v"]; o {
			if key, ok := body["k"]; ok {
				obj := reflect.ValueOf(Config()).Elem()

				field := obj.FieldByName(key.(string))
				v := field.Interface()

				switch v.(type) {
				case int:
					if i, err := strconv.ParseInt(value.(string), 10, 64); err == nil {
						obj.FieldByName(key.(string)).SetInt(i)
					}
				case string:
					obj.FieldByName(key.(string)).SetString(value.(string))
				case bool:
					if b, err := strconv.ParseBool(value.(string)); err == nil {
						obj.FieldByName(key.(string)).SetBool(b)
					}

				}
				w.Write([]byte("ok"))
			}

		} else {

			for _, v := range cmap {
				w.Write([]byte(v + "\n"))
			}

			w.Write([]byte("(error)-k(key) and -v(value) is required"))
		}
	} else {
		w.Write([]byte("(error)not permit"))
	}

}

func (this *CliServer) DelUser(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	param := r.PostForm["param"][0]

	if Config().Debug {
		this.logRequest(r, param)
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

		engine.Delete(&TChUser{Fuser: user})
		w.Write([]byte("success"))

	}

}

func (this *CliServer) EnableUser(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	param := r.PostForm["param"][0]

	if Config().Debug {
		this.logRequest(r, param)
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
		this.logRequest(r, param)
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

func (this *CliServer) GetIp(w http.ResponseWriter, r *http.Request) {

	ip := this.util.GetClientIp(r)
	w.Write([]byte(ip))
}

func (this *CliServer) GetServerURI(r *http.Request) string {

	return "http://" + r.Host
}

func (this *CliServer) Heartbeat(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	param := r.PostForm["param"][0]

	if Config().Debug {
		this.logRequest(r, param)
	}

	body := make(map[string]interface{})
	if err := json.Unmarshal([]byte(param), &body); err != nil {
		//		fmt.Println(err)
		log.Error("Heartbeat Unmarshal Error:", err)
		return
	}
	client_ip := ""
	uuid := ""
	salt := ""
	shell := ""
	platform := ""
	ips := ""
	hostname := ""
	group := "default"
	system_status := "{}"
	nettype := "direct"
	python_version := "unknown"
	cli_version := "unknown"
	client_ip = cli.util.GetClientIp(r)
	etcd_uri := this.getEtcdServer(client_ip)

	if Config().Group != "" {
		group = Config().Group
	}

	if _ips, ok := body["ips"]; ok {
		ips, ok = _ips.(string)
	}

	if v, ok := body["python_version"]; ok {
		python_version, ok = v.(string)
	}
	if v, ok := body["cli_version"]; ok {
		cli_version, ok = v.(string)
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
		platform = strings.ToLower(platform)
	}

	if _hostname, ok := body["hostname"]; ok {
		hostname, ok = _hostname.(string)
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

	if ok := this.util.Contains(client_ip, strings.Split(ips, ",")); !ok {
		nettype = "nat"
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
	hb.Group = group
	hb.PythonVersion = python_version
	hb.CliVersion = cli_version
	hb.NetType = nettype
	hb.ServerUri = this.GetServerURI(r)
	hb.EtcdUri = etcd_uri
	safeMap.Put(client_ip, hb)
	if platform == "windows" {
		shell = shellContents.Windows
	} else if platform == "linux" {
		shell = shellContents.Linux
	}
	if system_status != "{}" {
		shell = ""
	}
	dd["ip"] = client_ip
	dd["utime"] = hb.Utime
	dd["time"] = time.Now().Unix()
	dd["status"] = "online"
	dd["platform"] = platform
	dd["ips"] = ips
	dd["salt"] = salt
	dd["hostname"] = hostname
	dd["uuid"] = uuid
	dd["nettype"] = nettype
	dd["group"] = group
	dd["etcd_uri"] = etcd_uri
	dd["cli_version"] = cli_version
	dd["python_version"] = python_version
	dd["server_uri"] = this.GetServerURI(r)
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
	c.Send("ltrim", CONST_HEARTBEAT_LIST_KEY, 0, Config().QueueResultSize)
	c.Send("ltrim", CONST_RESULT_LIST_KEY, 0, Config().QueueResultSize)
	if len(system_status) > 2 {
		c.Send("LPUSH", CONST_SYSTEM_STATUS_LIST_KEY, system_status)
		c.Send("ltrim", CONST_SYSTEM_STATUS_LIST_KEY, 0, Config().QueueResultSize)
	}
	c.Send("SADD", CONST_UUIDS_KEY, uuid)
	c.Flush()

	result := HeartBeatResult{}

	if Config().ProxyEtcd {
		result.Etcd = this.getEtcd(client_ip)
		result.Etcd.Password = ""
		result.Etcd.User = ""
		result.Etcd.Server[0] = this.GetServerURI(r)

	} else {
		result.Etcd = this.getEtcd(client_ip)
	}
	result.Salt = salt
	result.Shell = shell

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

	lang := ""
	FileName := ""

	param := r.PostForm["param"][0]

	if Config().Debug {
		this.logRequest(r, param)

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

	if v, ok := body["l"]; ok {
		lang = v
	}

	if v, ok := body["f"]; ok {
		FileName = v
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
	if num > 3000 {
		num = 3000
	}

	//	 ret= self._cmd(ip, "tail -n %s /var/log/cli.log" %( n),kw={'log_to_file':'0'}, sudo=True)

	kw := make(map[string]string)
	kw["log_to_file"] = "0"
	kw["sudo"] = "1"
	kw["t"] = "15"

	for k, v := range body {
		kw[k] = v
	}

	ret := ""

	result := make(map[string]interface{})
	PATH := "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin &&"
	if lang != "" {
		if FileName == "" {
			cmd := `%s ps aux|grep '%s'|awk '{print $2}'|xargs -n 1 lsof -p |grep -E "*.log$|debug.log$|cli.log$|info.log$|error.log$"|awk '{print $9}'|sort -r |uniq|grep -v '/var/log/cli.log'`
			ret, _ = this.ExecCmd(ip, fmt.Sprintf(cmd, PATH, lang), kw)
		} else {
			cmd := `%s ps aux|grep '%s'|awk '{print $2}'|xargs -n 1 lsof -p |grep -E "*.log$|debug.log$|cli.log$|info.log$|error.log$"|awk '{print $9}'|sort -r |uniq |grep -i -E '%s' |xargs -n 1 tail -n %s`
			ret, _ = this.ExecCmd(ip, fmt.Sprintf(cmd, PATH, lang, FileName, strconv.Itoa(num)), kw)
		}
	} else {
		ret, _ = this.ExecCmd(ip, fmt.Sprintf("%s tail -n %s /var/log/cli.log", PATH, strconv.Itoa(num)), kw)

	}

	err := json.Unmarshal([]byte(ret), &result)
	if err == nil {
		if _, ok := result["result"]; ok {
			w.Write([]byte(result["result"].(string)))
		} else {
			w.Write([]byte(ret))
		}

	} else {
		w.Write([]byte(ret))
	}
}

func (this *CliServer) ProxyEtcd(w http.ResponseWriter, r *http.Request) {

	client_ip := this.util.GetClientIp(r)
	etcd_server := ""
	etcd := this.getEtcd(client_ip)

	if len(etcd.Server) > 0 {
		etcd_server = etcd.Server[0]
	} else {
		log.Error("Etcd Server not set")
		w.Write([]byte("Etcd Server not set"))
		return
	}

	url := etcd_server + r.RequestURI

	timeout := time.Second * 3

	if strings.Index(url, "recursive") > 0 {
		timeout = time.Second * 10 * 60
	}

	if content, err := httplib.Get(url).SetTimeout(timeout, timeout).SetBasicAuth(etcd.User, etcd.Password).String(); err != nil {
		return
	} else {
		w.Write([]byte(content))
		return
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
	for k, v := range r.Form {
		if len(v) > 0 {
			data[k] = v[0]
		}
	}
	w.Write([]byte(this.util.JsonEncode(data)))
}
func (this *CliServer) GetObjsFromMongo(w http.ResponseWriter, r *http.Request) {
	msg := make(map[string]interface{})
	msg["status"] = "fail"
	msg["message"] = ""
	r.ParseForm()
	start := 0
	limit := 1000
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

	//	key := ""
	otype := ""

	query := ""

	//	if v, ok := params["k"]; ok {
	//		key = v.(string)
	//	} else {
	//		msg["message"] = "(error)-k(key) is require"
	//		w.Write([]byte(this.util.JsonEncode(msg)))
	//		return
	//	}

	if v, ok := params["start"]; ok {
		if n, e := strconv.Atoi(v.(string)); e == nil {
			start = n
		}
	}

	if v, ok := params["limit"]; ok {
		if n, e := strconv.Atoi(v.(string)); e == nil {
			limit = n
		}
	}

	if v, ok := params["q"]; ok {
		query = v.(string)
	} else {
		msg["message"] = "(error)-q(query json format) is require"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}

	if v, ok := params["o"]; ok {
		otype = v.(string)
	} else {
		msg["message"] = "(error)-o(otype) is require"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}

	var filter map[string]interface{}
	if err := bson.UnmarshalJSON([]byte(query), &filter); err != nil {
		msg["message"] = err.Error()
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}

	session := mgoSession.Copy()
	defer session.Close()
	mgoDB := session.DB(Config().Mongo.Database)

	var results []map[string]interface{}
	data := make(map[string]interface{})

	if v, ok := filter["_id"]; ok {
		v2 := fmt.Sprintf("%v", v)
		if bson.IsObjectIdHex(v2) {
			filter["_id"] = bson.ObjectIdHex(v2)
		}
	}

	if cnt, err := mgoDB.C(otype).Find(filter).Count(); err != nil {
		msg["message"] = err.Error()
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	} else {

		mgoDB.C(otype).Find(filter).Skip(start).Limit(limit).All(&results)
		data["count"] = cnt
		data["rows"] = results
		msg["status"] = "ok"
		msg["message"] = "ok"
		msg["data"] = data
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}

	//	var obj TChObjs

	//	obj.Fkey = key
	//	obj.Fotype = otype

	//	cnt, err := engine.Where(&obj).Get(&obj)

	//	if err != nil {
	//		msg["message"] = err.Error()
	//		w.Write([]byte(this.util.JsonEncode(msg)))
	//		return
	//	} else {

	//		if cnt {
	//			msg["status"] = "ok"
	//			msg["message"] = "ok"
	//			msg["data"] = obj.Fbody
	//		} else {
	//			msg["status"] = "fail"
	//			msg["message"] = "not found"
	//			msg["data"] = "{}"
	//		}

	//		w.Write([]byte(this.util.JsonEncode(msg)))
	//		return
	//	}

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
	otype := ""

	if v, ok := params["k"]; ok {
		key = v.(string)
	} else {
		msg["message"] = "(error)-k(key) is require"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}

	if v, ok := params["o"]; ok {
		otype = v.(string)
	} else {
		msg["message"] = "(error)-o(otype) is require"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}
	var obj TChObjs

	obj.Fkey = key
	obj.Fotype = otype

	cnt, err := engine.Where(&obj).Get(&obj)

	if err != nil {
		msg["message"] = err.Error()
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	} else {

		if cnt {
			msg["status"] = "ok"
			msg["message"] = "ok"
			msg["data"] = obj.Fbody
		} else {
			msg["status"] = "fail"
			msg["message"] = "not found"
			msg["data"] = "{}"
		}

		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}

}

func (this *CliServer) AddObjsToMongo(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	param := r.PostForm["param"][0]
	params := make(map[string]interface{})
	msg := make(map[string]interface{})
	msg["status"] = "fail"
	msg["message"] = ""
	//	fmt.Println(param)
	if err := json.Unmarshal([]byte(param), &params); err != nil {
		msg["message"] = "Unmarshal Error"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}
	table := ""
	key := ""
	body := ""
	where := ""
	all := "0"

	//	bodyobj := make(map[string]interface{})

	if v, ok := params["o"]; !ok {
		if v == "" {
			msg["message"] = "message can't be null"
		} else {
			msg["message"] = "(error)-o(type) is require"
		}
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	} else {
		table = v.(string)
	}

	if Config().Mongo.TablePrefix != "" {
		tps := strings.Split(Config().Mongo.TablePrefix, ",")

		for i, v := range tps {

			if strings.Index(table, v) == 0 {
				break
			}
			if i == len(tps)-1 {
				msg["message"] = "(error) -o(tye) must start with " + Config().Mongo.TablePrefix
				w.Write([]byte(this.util.JsonEncode(msg)))
				return
			}

		}
	}

	if v, ok := params["w"]; ok {
		where = v.(string)
	}

	if v, ok := params["all"]; ok {
		all = v.(string)
	}

	if v, ok := params["d"]; ok {
		body = v.(string)

	} else {
		msg["message"] = "(error)-d(data) is require"
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}

	if v, ok := params["k"]; ok {
		key = v.(string)
	}

	//	var obj TChObjs

	//	if err := json.Unmarshal([]byte(param), &obj); err != nil {

	//		msg["message"] = err.Error()
	//		w.Write([]byte(this.util.JsonEncode(msg)))
	//		return
	//	}
	//	obj.Fbody = body

	//	fmt.Println(body)

	var jsonData map[string]interface{}

	if err := bson.UnmarshalJSON([]byte(body), &jsonData); err != nil {
		msg["message"] = err.Error()
		w.Write([]byte(this.util.JsonEncode(msg)))
		return
	}

	session := mgoSession.Copy()
	defer session.Close()
	mgoDB := session.DB(Config().Mongo.Database)

	//	session := mgoPool.Get()
	//	defer mgoPool.Release(session)
	//	mgoDB := session.DB(Config().Mongo.Database)

	if key == "" {

		if where != "" {
			var jsonWhere map[string]interface{}
			if err := bson.UnmarshalJSON([]byte(where), &jsonWhere); err != nil {
				msg["message"] = err.Error()
				w.Write([]byte(this.util.JsonEncode(msg)))
				return
			}

			if v, ok := jsonWhere["_id"]; ok {
				v2 := fmt.Sprintf("%v", v)
				if bson.IsObjectIdHex(v2) {
					jsonWhere["_id"] = bson.ObjectIdHex(v2)
				}
			}

			if all == "1" {
				values := make(map[string]interface{})
				values["$set"] = jsonData
				if changeInfo, err := mgoDB.C(table).UpdateAll(jsonWhere, values); err != nil {
					msg["message"] = err.Error()
					w.Write([]byte(this.util.JsonEncode(msg)))
					return
				} else {
					if changeInfo.Updated > 0 || changeInfo.UpsertedId != nil {
						msg["message"] = "ok"
						msg["status"] = "ok"
						msg["data"] = changeInfo
						w.Write([]byte(this.util.JsonEncode(msg)))
						return
					}
				}
			} else {
				if changeInfo, err := mgoDB.C(table).Upsert(jsonWhere, jsonData); err != nil {
					msg["message"] = err.Error()
					w.Write([]byte(this.util.JsonEncode(msg)))
					return
				} else {
					if changeInfo.Updated > 0 || changeInfo.UpsertedId != nil {
						msg["message"] = "ok"
						msg["status"] = "ok"
						msg["data"] = changeInfo
						w.Write([]byte(this.util.JsonEncode(msg)))
						return
					}
				}
			}

		}

		id := bson.NewObjectId()
		jsonData["_id"] = id

		if err := mgoDB.C(table).Insert(jsonData); err != nil {
			msg["message"] = err.Error()
			w.Write([]byte(this.util.JsonEncode(msg)))
			return
		} else {
			msg["message"] = "ok"
			msg["status"] = "ok"
			msg["data"] = jsonData

			w.Write([]byte(this.util.JsonEncode(msg)))
			return
		}

		//		if _, err := engine.Insert(&obj); err != nil {
		//			msg["message"] = err.Error()
		//			w.Write([]byte(this.util.JsonEncode(msg)))
		//			return
		//		} else {
		//			msg["message"] = "ok"
		//			msg["status"] = "ok"
		//			msg["data"] = key
		//			w.Write([]byte(this.util.JsonEncode(msg)))
		//			return
		//		}

	} else {

		if !bson.IsObjectIdHex(key) {
			msg["message"] = "key is error"
			w.Write([]byte(this.util.JsonEncode(msg)))
			return
		}

		id := bson.ObjectIdHex(key)

		var old map[string]interface{}

		mgoDB.C(table).FindId(id).One(&old)

		if len(old) == 0 {
			msg["message"] = "not found"
			w.Write([]byte(this.util.JsonEncode(msg)))
			return
		}

		for k, _ := range jsonData {
			old[k] = jsonData[k]
		}

		if err := mgoDB.C(table).UpdateId(id, old); err != nil {
			msg["message"] = err.Error()
			w.Write([]byte(this.util.JsonEncode(msg)))
			return
		} else {
			msg["message"] = "ok"
			msg["status"] = "ok"
			msg["data"] = old
			w.Write([]byte(this.util.JsonEncode(msg)))
		}

		//		if cnt, err := engine.Update(&obj, TChObjs{Fkey: key}); err != nil {
		//			msg["message"] = err.Error()
		//			w.Write([]byte(this.util.JsonEncode(msg)))
		//			return
		//		} else {
		//			if cnt > 0 {
		//				msg["message"] = "ok"
		//				msg["status"] = "ok"
		//				w.Write([]byte(this.util.JsonEncode(msg)))
		//				return
		//			} else {
		//				msg["message"] = "key not found"
		//				msg["status"] = "fail"
		//				w.Write([]byte(this.util.JsonEncode(msg)))
		//				return
		//			}

		//		}
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

	bodyobj := make(map[string]interface{})

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

		case string:
			if er := json.Unmarshal([]byte(v), &bodyobj); er != nil {
				msg["message"] = er.Error()
				w.Write([]byte(this.util.JsonEncode(msg)))
				return
			}
			body = this.util.JsonEncode(bodyobj)
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

	fmt.Println(key)

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
			msg["data"] = key
			w.Write([]byte(this.util.JsonEncode(msg)))
			return
		}

	} else {

		if cnt, err := engine.Update(&obj, TChObjs{Fkey: key}); err != nil {
			msg["message"] = err.Error()
			w.Write([]byte(this.util.JsonEncode(msg)))
			return
		} else {
			if cnt > 0 {
				msg["message"] = "ok"
				msg["status"] = "ok"
				w.Write([]byte(this.util.JsonEncode(msg)))
				return
			} else {
				msg["message"] = "key not found"
				msg["status"] = "fail"
				w.Write([]byte(this.util.JsonEncode(msg)))
				return
			}

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
				fmt.Println(err)
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

	fmt.Println("xxx", r.RequestURI)

	log.Info("Proxy", r.RequestURI)

	if Config().URLProxy != "" {
		body := this.getParam(r)
		request := httplib.Post(Config().URLProxy+r.RequestURI).SetTimeout(time.Second*5, time.Second*10)
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

func (this *CliServer) InitUserAdmin() {
	userBean := new(TChUser)
	if ok, err := engine.Where("Fuser=?", "admin").Get(userBean); err == nil && !ok {
		userBean.Fuser = "admin"
		userBean.Femail = "admin@web.com"
		userBean.Fpwd = this.util.MD5("admin")
		userBean.Fip = "127.0.0.1"
		userBean.Fstatus = 1
		if cnt, er := engine.Insert(userBean); cnt > 0 {
			msg := "init admin user success,user=admin password=admin"
			log.Info(msg)
			fmt.Println(msg)
		} else {
			log.Error(er)
		}

	}
	auth := new(TChAuth)
	if ok, err := engine.Where("Fsalt=?", "abc").Get(auth); err == nil && !ok {
		auth.Fuser = "root"
		auth.Fsudo = 1
		auth.Fenable = 1
		auth.FsudoIps = "*"
		auth.Fdesc = "local test"
		auth.Ftoken = "abc"
		auth.Fip = "127.0.0.1"
		if cnt, er := engine.Insert(auth); cnt > 0 {
			msg := "init auth token abc success,ip=127.0.0.1 token=abc sudo=1"
			log.Info(msg)
			fmt.Println(msg)
		} else {
			log.Error(er)
		}

	}

}

func (this *CliServer) InitEtcd() {
	url := Config().Etcd.Host
	if strings.Index(url, "/v2") > 0 {
		url = url[0:strings.Index(url, "/v2")] + "/v2/"
	} else {
		url = url + "/v2/"
	}

	users := []string{Config().Etcd.User, Config().EtcdGuest.User}

	if !this.util.Contains("root", users) {
		msg := "etcd_root user must be root"
		log.Warn(msg)
		fmt.Println(msg)
		return
	}

	if Config().Etcd.Pwd == "" {
		msg := "etcd_root password must be not null"
		log.Warn(msg)
		fmt.Println(msg)
		return
	}

	for _, v := range users {
		data := "{\"role\":\"%s\",\"permissions\":{\"kv\":{\"read\":null,\"write\":null}}}"
		req := httplib.Put(url + fmt.Sprintf("auth/roles/%s", v))
		req.Body(fmt.Sprintf(data, v))
		log.Info(req.String())

	}
	for i, v := range users {
		data := "{\"user\":\"%s\",\"password\":\"%s\",\"roles\":[\"%s\"]}"
		req := httplib.Put(url + fmt.Sprintf("auth/users/%s", v))
		if i == 0 {
			req.Body(fmt.Sprintf(data, v, Config().Etcd.Pwd, v))
		} else {
			req.Body(fmt.Sprintf(data, v, Config().EtcdGuest.Password, v))
		}
		log.Info(req.String())
	}

	for i, v := range users {

		req := httplib.Put(url + fmt.Sprintf("auth/roles/%s", v))
		if i == 0 {
			data := "{\"role\":\"%s\",\"permissions\":{\"kv\":{\"read\":null,\"write\":null}},\"grant\":{\"kv\":{\"read\":[\"/keeper/*\"],\"write\":[\"/keeper/*\"]}}}"
			req.Body(fmt.Sprintf(data, v))
		} else {
			data := "{\"role\":\"%s\",\"permissions\":{\"kv\":{\"read\":null,\"write\":null}},\"grant\":{\"kv\":{\"read\":[\"/keeper/*\"],\"write\":null}}}"
			req.Body(fmt.Sprintf(data, v))
		}
		log.Info(req.String())
	}

	req := httplib.Put(url + "auth/enable")
	log.Info(req.String())

}

func (this *CliServer) VM(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()

	param := r.PostForm["param"][0]

	msg := make(map[string]string)
	msg["status"] = "fail"
	msg["message"] = ""

	if Config().Debug {
		this.logRequest(r, param)
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
		//		fmt.Println(err)
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
	script_dir := Config().DefaultScriptDir
	if script_dir == "" {
		script_dir = "jqzhang"
	}
	result, _ := this.ExecCmd(phy_ip, fmt.Sprintf("cli shell -f vm -d %s -t 1800 -u -a %s", script_dir, task_id), kw)
	w.Write([]byte(result))

}

var cfgPath *string = nil
var logFile *string = nil

func (this *CliServer) init() {
	if cfgPath == nil {
		cfgPath = flag.String("c", "cfg.json", "json cfg")
		logFile = flag.String("log", "", "log config file")
	}

	flag.Parse()

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
			ip := this.util.GetPulicIP()
			cfg := fmt.Sprintf(cfgJson, cli.util.GetUUID(), ip, cli.util.GetUUID(), ip)
			cli.util.WriteFile("cfg.json", string(cfg))
			if !cli.util.IsExist(CONST_LOCAL_CFG_FILE_NAME) {
				cli.util.WriteFile(CONST_LOCAL_CFG_FILE_NAME, string(cfg))
			}
		}

	}

	ParseConfig(*cfgPath)

}

func (this *CliServer) InitComponent(action string) {
	if Config().QueueResultSize == 0 {
		Config().QueueResultSize = CONST_QUEUE_RESULT_SIZE
	}

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

	if Config().UseNFS {
		//		if mount, err := nfs.DialMount(Config().NFS.Host); err != nil {
		//			panic(err)
		//		}
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
				if action == "init" {
					os.Exit(1)
				}
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
						if action == "init" {
							panic("redis pool init error")
						} else {
							log.Error("reload redis fail")
						}
					}
				}

			} else {
				fmt.Println(er)
				log.Error("Connect Redis to Zookeeper Error")
				if action == "init" {
					os.Exit(1)
				}
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
			if action == "init" {
				os.Exit(1)
			}
		}
	}

	if Config().AutoCreatTable {
		if err := engine.Sync2(new(TChUser), new(TChAuth), new(TChResults),
			new(TChGoogleAuth), new(TChFiles), new(TChHeartbeat),
			new(TChLog), new(TChObjs), new(TChResultsHistory), new(TChDoc), new(TChConfig)); err != nil {
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

			var er error

			redis_server.DB(Config().Redis.DB)

			if Config().Redis.Pwd != "" {
				redis_server.RequireAuth(Config().Redis.Pwd)

				er = redis_server.StartAddr(":" + port)
			} else {
				er = redis_server.StartAddr(":" + port)
			}
			if er != nil {
				fmt.Println(er)
				if action == "init" {
					os.Exit(1)
				}
			}

		}

		infos := strings.Split(Config().Redis.Address, ":")
		if len(infos) <= 1 {
			msg := "Redis address must be contain port"
			if action == "init" {
				panic(msg)
			} else {
				log.Error(msg)
			}
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
			msg := "redis pool init error"
			if action == "init" {
				panic(msg)
			} else {
				log.Error(msg)
			}

		}
	}

	if this.util.IsExist(Config().ShellFileNames.Linux) {
		shellContents.Linux = this.util.ReadFile(Config().ShellFileNames.Linux)
	}
	if this.util.IsExist(Config().ShellFileNames.Windows) {
		shellContents.Windows = this.util.ReadFile(Config().ShellFileNames.Windows)
	}

	dialInfo := &mgo.DialInfo{
		Addrs:     Config().Mongo.Host,
		Direct:    false,
		Timeout:   time.Second * 3,
		Database:  Config().Mongo.Database,
		Source:    "admin",
		Username:  Config().Mongo.User,
		Password:  Config().Mongo.Password,
		PoolLimit: Config().Mongo.MaxPool, // Session.SetPoolLimit
	}
	if Config().UseMongo {
		if mgoSession, err = mgo.DialWithInfo(dialInfo); err != nil {
			log.Error(err)
			fmt.Println(err)

		} else {
			//mgoSession.SetMode(mgo.Eventual, true)

			if Config().Mongo.Password != "" {
				if err := mgoSession.Login(&mgo.Credential{
					Username:  Config().Mongo.User,
					Password:  Config().Mongo.Password,
					Mechanism: Config().Mongo.Mechanism,
				}); err != nil {
					fmt.Println(err)
					log.Error(err)
				}
			}
			mgoPool = MongoPoolNew(Config().Mongo.MaxPool)

			mgoPool.Session = mgoSession
			//mgoPool.Session = mgoSession
			//mgoPool.Max = Config().Mongo.MaxPool

			//mgoDB = mgoSession.DB(Config().Mongo.Database)
		}
	}

	if Config().UseKafka {

		fmt.Println("start init kafka....")

		initKafka := func(cli *CliServer) {
			config := sarama.NewConfig()
			config.Producer.Return.Successes = true
			config.Producer.Timeout = 5 * time.Second
			kfp, err := sarama.NewAsyncProducer(strings.Split(Config().Kafka.Servers, ","), config)
			if err != nil {
				fmt.Println("start kafka error ", err)
				log.Error(err)
				if action == "init" {
					panic(err)
				}
				return
			}
			cli.kfp = kfp
			go func(p sarama.AsyncProducer) {
				errors := p.Errors()
				success := p.Successes()
				for {
					select {
					case err := <-errors:
						if err != nil {
							log.Error(err)
						}
					case <-success:
					}
				}
			}(cli.kfp)
		}
		initKafka(cli)
	}

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
			m.Post("/deluser", cli.DelUser)
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
			print(err)
			buff := debug.Stack()
			log.Error(err)
			log.Error(string(buff))

		}
	}()

	qpsMap.Add("qps")

	url := req.RequestURI
	url = strings.Split(url, "?")[0]
	if strings.LastIndex(url, "/") > 0 {
		key := url[strings.LastIndex(url, "/")+1 : len(url)]
		qpsMap.Add(key)
		if ok := cli.util.Contains(key, GET_METHODS); !ok {
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

func init() {
	cli.init()
}

func (this *CliServer) Main() {

	defer log.Flush()

	cli.Init("init")

	if cli.kfp != nil {
		defer cli.kfp.Close()
	}

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		for s := range c {
			switch s {
			case syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
				log.Info("退出", s)
				os.Exit(1)
			}
		}
	}()

	http.HandleFunc("/", cli.Proxy)
	http.HandleFunc("/cli/trans", cli.Trans)
	http.HandleFunc("/cli/test", cli.Test)
	http.HandleFunc("/keeper/", cli.ProxyEtcd)
	http.HandleFunc("/cli/api", cli.Api)
	http.HandleFunc("/cli/rshell", cli.Rshell)
	http.HandleFunc("/cli/params", cli.Params)
	http.HandleFunc("/cli/sql", cli.SQL)
	http.HandleFunc("/cli/redis", cli.Redis)
	http.HandleFunc("/cli/gateway", cli.GateWay)
	http.HandleFunc("/cli/feedback_result", cli.Feedback)
	http.HandleFunc("/cli/heartbeat", cli.Heartbeat)
	http.HandleFunc("/cli/del_etcd_key", cli.DeleteEtcdKey)
	http.HandleFunc("/cli/get_cmd_result", cli.GetCmdResult)
	http.HandleFunc("/cli/addtoken", cli.AddToken)
	http.HandleFunc("/cli/listtoken", cli.ListToken)
	http.HandleFunc("/cli/upload", cli.Upload)
	http.HandleFunc("/file/upload", cli.RawUpload)
	http.HandleFunc("/cli/download", cli.Download)
	http.HandleFunc("/file/download", cli.RawDownload)
	http.HandleFunc("/cli/delfile", cli.DelFile)
	http.HandleFunc("/cli/listfile", cli.ListFile)
	http.HandleFunc("/cli/shell", cli.Shell)
	http.HandleFunc("/cli/login", cli.Login)
	http.HandleFunc("/cli/register", cli.Register)
	http.HandleFunc("/cli/setconf", cli.SetConf)
	http.HandleFunc("/cli/reload", cli.Reload)
	http.HandleFunc("/cli/deluser", cli.DelUser)
	http.HandleFunc("/cli/enableuser", cli.EnableUser)
	http.HandleFunc("/cli/disableuser", cli.DisableUser)
	http.HandleFunc("/cli/help", cli.Help)
	http.HandleFunc("/cli/man", cli.Man)
	http.HandleFunc("/cli/ip", cli.GetIp)
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
	http.HandleFunc("/cli/doc", cli.Doc)
	http.HandleFunc("/cli/check_port", cli.CheckPort)
	http.HandleFunc("/cli/check_status", cli.CheckStatus)
	http.HandleFunc("/cli/check", cli.Check)
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
	http.HandleFunc("/cli/select", cli.SelectCmdb)
	http.HandleFunc("/cli/mail", cli.Mail)
	http.HandleFunc("/cli/report", cli.Report)
	http.HandleFunc("/cli/get_report", cli.GetReport)
	if Config().StaticDir != "" {
		http.HandleFunc(fmt.Sprintf("/%s/", Config().StaticDir), cli.Static)
	}
	if Config().UseMongo {
		http.HandleFunc("/cli/addobjs", cli.AddObjsToMongo)
		http.HandleFunc("/cli/getobjs", cli.GetObjsFromMongo)
	} else {
		http.HandleFunc("/cli/addobjs", cli.AddObjs)
		http.HandleFunc("/cli/getobjs", cli.GetObjs)
	}
	//	http.HandleFunc("/ws", wsPage) // baidu search wsPage websocket
	err := http.ListenAndServe(Config().Addr, new(HttpHandler))
	if err != nil {
		fmt.Println(err)
		log.Error(err.Error())
	}

}

